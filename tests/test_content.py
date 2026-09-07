"""Tests for content loading.

The point of this module is that content drift is a *loud* failure. Each test
below corresponds to a way the previous codebase failed silently.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rivalforge.content.loader import (
    MAX_CONTENT_BYTES,
    ContentError,
    load_content,
    load_content_from,
)
from rivalforge.content.schema import (
    Element,
    SoulEffect,
    Stance,
    beats,
    element_multiplier,
    stance_multiplier,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "src" / "rivalforge" / "content" / "data"


@pytest.fixture
def content():
    return load_content()


@pytest.fixture
def scratch(tmp_path):
    """A writable copy of the shipped content, for corruption tests."""
    for name in ("battlefields.json", "supremacies.json", "ranks.json", "taunts.json"):
        (tmp_path / name).write_text((DATA_DIR / name).read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def _rewrite(directory: Path, name: str, mutate):
    path = directory / name
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")


class TestShippedContentLoads:
    def test_loads(self, content):
        assert len(content.battlefields) == 6
        assert len(content.supremacies) == 6
        assert len(content.ranks) == 7

    def test_is_cached(self):
        assert load_content() is load_content()

    def test_every_element_has_exactly_one_home_arena(self, content):
        homes = [a.element for a in content.battlefields]
        for element in Element:
            assert homes.count(element) == 1, f"{element} has {homes.count(element)} arenas"

    def test_ranks_are_sorted_and_start_at_zero(self, content):
        thresholds = [r.points_required for r in content.ranks]
        assert thresholds == sorted(thresholds)
        assert thresholds[0] == 0


class TestSchemaRejectsDrift:
    """Regression tests for AUDIT F2 -- a renamed content key silently read as
    None for the life of the previous project."""

    def test_a_renamed_key_is_a_hard_error(self, scratch):
        def rename(data):
            data[0]["attunement_boost"] = data[0].pop("attunement_bonus")

        _rewrite(scratch, "battlefields.json", rename)
        with pytest.raises(ContentError) as exc:
            load_content_from(scratch)
        # Both halves of the rename must be reported, or the message points at
        # the wrong bug.
        assert "attunement_bonus" in str(exc.value)
        assert "attunement_boost" in str(exc.value)

    def test_a_missing_key_is_a_hard_error(self, scratch):
        _rewrite(scratch, "battlefields.json", lambda d: d[0].pop("soul_effect"))
        with pytest.raises(ContentError, match="soul_effect"):
            load_content_from(scratch)

    def test_an_unexpected_key_is_a_hard_error(self, scratch):
        _rewrite(scratch, "battlefields.json", lambda d: d[0].update(legacy_field=1))
        with pytest.raises(ContentError, match="legacy_field"):
            load_content_from(scratch)

    def test_an_out_of_range_value_is_a_hard_error(self, scratch):
        _rewrite(scratch, "battlefields.json", lambda d: d[0].update(attunement_bonus=9.0))
        with pytest.raises(ContentError, match="attunement_bonus"):
            load_content_from(scratch)

    def test_an_unknown_element_is_a_hard_error(self, scratch):
        """Regression test for AUDIT F3 -- three incompatible element
        vocabularies with an empty intersection."""
        _rewrite(scratch, "battlefields.json", lambda d: d[0].update(element="Fire God"))
        with pytest.raises(ContentError, match="element"):
            load_content_from(scratch)

    def test_an_unknown_soul_effect_is_a_hard_error(self, scratch):
        _rewrite(scratch, "battlefields.json", lambda d: d[0].update(soul_effect="explode"))
        with pytest.raises(ContentError, match="soul_effect"):
            load_content_from(scratch)


class TestCrossReferenceChecks:
    def test_a_duplicate_id_is_rejected(self, scratch):
        _rewrite(scratch, "battlefields.json", lambda d: d.append(dict(d[0])))
        with pytest.raises(ContentError, match="duplicate"):
            load_content_from(scratch)

    def test_an_element_without_a_home_arena_is_rejected(self, scratch):
        # Copy fire onto the light arena, so light has no home and fire has two.
        _rewrite(scratch, "battlefields.json", lambda d: d[5].update(element="fire"))
        with pytest.raises(ContentError, match="home element"):
            load_content_from(scratch)

    def test_ranks_must_not_get_weaker_as_they_rise(self, scratch):
        _rewrite(scratch, "ranks.json", lambda d: d[6].update(damage_modifier=1.0))
        with pytest.raises(ContentError, match="must not decrease"):
            load_content_from(scratch)

    def test_the_lowest_rank_must_start_at_zero(self, scratch):
        _rewrite(scratch, "ranks.json", lambda d: d[0].update(points_required=10))
        with pytest.raises(ContentError, match="points_required == 0"):
            load_content_from(scratch)


class TestMalformedFiles:
    def test_missing_file(self, tmp_path):
        with pytest.raises(ContentError, match="cannot stat"):
            load_content_from(tmp_path)

    def test_not_json(self, scratch):
        (scratch / "ranks.json").write_text("{not json", encoding="utf-8")
        with pytest.raises(ContentError, match="not valid JSON"):
            load_content_from(scratch)

    def test_wrong_top_level_type(self, scratch):
        (scratch / "ranks.json").write_text('{"a": 1}', encoding="utf-8")
        with pytest.raises(ContentError, match="must be a JSON array"):
            load_content_from(scratch)

    def test_empty_array(self, scratch):
        (scratch / "ranks.json").write_text("[]", encoding="utf-8")
        with pytest.raises(ContentError, match="must not be empty"):
            load_content_from(scratch)

    def test_oversize_file_is_refused_before_parsing(self, scratch):
        # A hostile Lab content file must not be able to exhaust memory.
        (scratch / "ranks.json").write_text(" " * (MAX_CONTENT_BYTES + 1), encoding="utf-8")
        with pytest.raises(ContentError, match="over the"):
            load_content_from(scratch)


class TestElementTriangles:
    def test_every_element_beats_exactly_one_and_loses_to_exactly_one(self):
        for element in Element:
            wins = [o for o in Element if beats(element, o)]
            losses = [o for o in Element if beats(o, element)]
            assert len(wins) == 1, f"{element} beats {wins}"
            assert len(losses) == 1, f"{element} loses to {losses}"

    def test_no_element_beats_itself(self):
        for element in Element:
            assert not beats(element, element)
            assert element_multiplier(element, element) == 1.0

    def test_advantage_and_disadvantage_are_reciprocal(self):
        for a in Element:
            for b in Element:
                if beats(a, b):
                    assert element_multiplier(a, b) > 1.0
                    assert element_multiplier(b, a) < 1.0

    def test_the_two_triangles_are_disjoint(self):
        fire_cycle = {Element.FIRE, Element.WIND, Element.WATER}
        light_cycle = {Element.LIGHT, Element.SHADOW, Element.TIME}
        assert not fire_cycle & light_cycle
        for a in fire_cycle:
            for b in light_cycle:
                assert element_multiplier(a, b) == 1.0


class TestStanceTriangle:
    def test_every_stance_beats_exactly_one(self):
        for stance in Stance:
            wins = [o for o in Stance if stance_multiplier(stance, o) > 1.0]
            losses = [o for o in Stance if stance_multiplier(stance, o) < 1.0]
            assert len(wins) == 1 and len(losses) == 1

    def test_mirror_matches_are_neutral(self):
        for stance in Stance:
            assert stance_multiplier(stance, stance) == 1.0


class TestSoulEffectsAreExhaustive:
    def test_every_declared_soul_effect_is_used_by_an_arena(self, content):
        """A SoulEffect the resolver handles but no arena uses is dead code;
        one an arena uses but the resolver does not handle would crash a match.
        The resolver side is covered in test_match.py."""
        used = {arena.soul_effect for arena in content.battlefields}
        unused = set(SoulEffect) - used
        assert not unused, f"soul effects with no arena: {sorted(e.value for e in unused)}"


class TestTaunts:
    def test_all_moments_present_and_non_empty(self, content):
        for moment in ("hit", "miss", "combo", "soul", "victory", "defeat"):
            assert len(content.taunts.lines[moment]) > 0
