"""Loading game content from disk, safely.

Threat model for this module: a content file is *trusted-ish* -- it ships with
the package -- but it is still parsed input, and in a later phase a Lab will be
able to supply its own. So it is handled as if hostile from the start:

* JSON only. Never `pickle`, never `yaml.load`, never `eval`. Each of those can
  execute code from a data file.
* A byte-size cap before parsing, so a large or deeply nested file cannot be
  used to exhaust memory.
* Parsing into the frozen typed objects in `schema.py`, which reject unknown
  keys and out-of-range values.
* Cross-reference checks after parsing, so content is validated as a *set*, not
  only file by file.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Final

from ..security.validation import ValidationError
from .schema import Battlefield, Element, GameContent, Rank, Supremacy, TauntSet

__all__ = ["ContentError", "load_content", "load_content_from", "MAX_CONTENT_BYTES"]

#: Generous for our own files, small enough that a hostile Lab file cannot
#: exhaust memory during parsing.
MAX_CONTENT_BYTES: Final = 1 * 1024 * 1024

_DATA_PACKAGE: Final = "rivalforge.content"
_DATA_SUBDIR: Final = "data"


class ContentError(RuntimeError):
    """Raised when content fails to load or is internally inconsistent.

    Deliberately *not* a subclass of anything the engine catches. Content
    failure must stop the process at startup, not degrade into a default.
    """


def _read_json(path: Path) -> Any:
    """Read one JSON file with a size cap, or fail with a clear message."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ContentError(f"cannot stat content file {path.name}: {exc}") from exc

    if size > MAX_CONTENT_BYTES:
        raise ContentError(
            f"content file {path.name} is {size} bytes, over the {MAX_CONTENT_BYTES} byte limit"
        )

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ContentError(f"cannot read content file {path.name}: {exc}") from exc

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ContentError(f"content file {path.name} is not valid JSON: {exc}") from exc


def _expect_list(raw: Any, *, name: str) -> list[Any]:
    if not isinstance(raw, list):
        raise ContentError(f"{name} must be a JSON array, got {type(raw).__name__}")
    if not raw:
        raise ContentError(f"{name} must not be empty")
    return raw


def _check_unique_ids(items: tuple[Any, ...], *, name: str) -> None:
    seen: set[str] = set()
    for item in items:
        if item.id in seen:
            raise ContentError(f"{name} contains a duplicate id: {item.id!r}")
        seen.add(item.id)


def load_content_from(directory: Path) -> GameContent:
    """Load and validate the full content set from `directory`.

    Raises:
        ContentError: on any missing file, malformed value, duplicate id, or
            broken cross-reference. There is no partial success.
    """
    try:
        battlefields = tuple(
            Battlefield.parse(entry)
            for entry in _expect_list(_read_json(directory / "battlefields.json"), name="battlefields")
        )
        supremacies = tuple(
            Supremacy.parse(entry)
            for entry in _expect_list(_read_json(directory / "supremacies.json"), name="supremacies")
        )
        ranks = tuple(
            Rank.parse(entry)
            for entry in _expect_list(_read_json(directory / "ranks.json"), name="ranks")
        )
        taunts_raw = _read_json(directory / "taunts.json")
        if not isinstance(taunts_raw, dict):
            raise ContentError("taunts must be a JSON object")
        taunts = TauntSet.parse(taunts_raw)
    except ValidationError as exc:
        raise ContentError(f"invalid content -- {exc}") from exc

    _check_unique_ids(battlefields, name="battlefields")
    _check_unique_ids(supremacies, name="supremacies")
    _check_unique_ids(ranks, name="ranks")

    # --- Cross-reference and completeness checks -------------------------
    # Every element must have exactly one home arena. Without this, an element
    # could be drawn for a fighter that no battlefield ever favours, which is
    # invisible in any single-file check and reads in play as "this element is
    # worse" for no stated reason.
    arena_elements = [arena.element for arena in battlefields]
    for element in Element:
        count = arena_elements.count(element)
        if count != 1:
            raise ContentError(
                f"element {element.value!r} is the home element of {count} battlefields, expected exactly 1"
            )

    ranks = tuple(sorted(ranks, key=lambda r: r.points_required))
    if ranks[0].points_required != 0:
        raise ContentError("the lowest rank must have points_required == 0")

    thresholds = [r.points_required for r in ranks]
    if len(set(thresholds)) != len(thresholds):
        raise ContentError("two ranks share a points_required threshold")

    modifiers = [r.damage_modifier for r in ranks]
    if modifiers != sorted(modifiers):
        raise ContentError("rank damage_modifier must not decrease as points_required rises")

    if len(supremacies) < 2:
        raise ContentError("at least two supremacies are required to draw fighters")

    return GameContent(
        battlefields=battlefields, supremacies=supremacies, ranks=ranks, taunts=taunts
    )


@lru_cache(maxsize=1)
def load_content() -> GameContent:
    """Load the content that ships with the package.

    Cached, because content is immutable and every caller should see the same
    object. Failure here is fatal by design -- an unplayable build should not
    reach a player.
    """
    # `data/` is a resource directory, not a package -- it holds no Python and
    # should not be importable. Resolving it through the parent package keeps
    # it that way and still works from a wheel, a zip, or an editable install.
    with resources.as_file(resources.files(_DATA_PACKAGE) / _DATA_SUBDIR) as data_dir:
        return load_content_from(Path(data_dir))
