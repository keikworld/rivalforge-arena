"""Explicit, seeded randomness.

The engine never touches the `random` module's global state. Every source of
chance is an `RNG` instance threaded through the call that needs it.

Three reasons, all of them practical:

1.  **Replay.** A match is fully described by its inputs plus a seed, so a
    disputed result can be re-run exactly. That matters the moment money is
    attached to an outcome.
2.  **Tests that mean something.** Combat can be asserted on exact numbers
    instead of ranges, so a balance change that was not intended shows up as a
    failing test rather than as a feeling.
3.  **No cross-match leakage.** Global RNG state makes one match's outcome
    depend on how many other matches ran first. That is unfixable by testing
    and is a genuine fairness bug once matches run concurrently.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Sequence, TypeVar

__all__ = ["RNG", "new_seed"]

T = TypeVar("T")

_MASK_64 = (1 << 64) - 1


def new_seed() -> int:
    """A fresh, cryptographically strong 64-bit seed for a new match.

    `secrets` rather than `random`: a predictable match seed would let a player
    who learns it know every hazard roll and damage roll in advance.
    """
    return secrets.randbits(64)


class RNG:
    """A small, deterministic, hash-based random source.

    Uses SPLITMIX64, which is fast, has a well-understood period, and -- unlike
    seeding `random.Random` -- produces the same stream on every Python version
    and platform. A golden-output test is only meaningful if the stream is
    stable across the machines that run it.

    Not for cryptographic use. `new_seed` handles the one place that matters.
    """

    __slots__ = ("_state", "_seed", "_calls")

    def __init__(self, seed: int) -> None:
        if not isinstance(seed, int) or isinstance(seed, bool):
            raise TypeError(f"seed must be an int, got {type(seed).__name__}")
        self._seed = seed & _MASK_64
        self._state = self._seed
        self._calls = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> "RNG":
        """Derive a seed by hashing arbitrary bytes.

        Used to turn a mint address into a stable fighter: same address, same
        stream, forever, on any machine.
        """
        digest = hashlib.blake2b(data, digest_size=8, person=b"rivalfrg").digest()
        return cls(int.from_bytes(digest, "big"))

    @property
    def seed(self) -> int:
        """The seed this stream started from. Enough to replay it exactly."""
        return self._seed

    @property
    def calls(self) -> int:
        """How many raw draws have been taken. Useful in divergence tests."""
        return self._calls

    def _next(self) -> int:
        """One SPLITMIX64 step."""
        self._calls += 1
        self._state = (self._state + 0x9E3779B97F4A7C15) & _MASK_64
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK_64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK_64
        return z ^ (z >> 31)

    def below(self, bound: int) -> int:
        """A uniform integer in ``[0, bound)``.

        Rejection-sampled rather than taken modulo, because modulo skews the
        distribution toward low values whenever `bound` does not divide 2**64.
        At our bounds the bias is tiny -- and it is exactly the kind of tiny
        that turns into "this arena's hazard fires more than the number says".
        """
        if bound <= 0:
            raise ValueError(f"bound must be positive, got {bound}")
        limit = _MASK_64 - (_MASK_64 % bound)
        while True:
            value = self._next()
            if value <= limit:
                return value % bound

    def unit(self) -> float:
        """A float in ``[0, 1)`` with 53 bits of resolution."""
        return (self._next() >> 11) / float(1 << 53)

    def chance(self, probability: float) -> bool:
        """True with the given probability.

        Clamped rather than validated: this is called from inside the resolver
        with values that are already schema-checked, and a hazard chance is not
        worth a second range check on every round.
        """
        if probability <= 0.0:
            return False
        if probability >= 1.0:
            return True
        return self.unit() < probability

    def between(self, low: float, high: float) -> float:
        """A float in ``[low, high]``."""
        if high < low:
            raise ValueError(f"high ({high}) must not be below low ({low})")
        return low + (high - low) * self.unit()

    def choice(self, items: Sequence[T]) -> T:
        """A uniform choice from a non-empty sequence."""
        if not items:
            raise ValueError("cannot choose from an empty sequence")
        return items[self.below(len(items))]

    def weighted_choice(self, items: Sequence[T], weights: Sequence[int]) -> T:
        """A choice from `items` with integer `weights`.

        Integer weights rather than float so the draw is exactly reproducible;
        accumulated floats are not bit-identical across platforms.
        """
        if len(items) != len(weights):
            raise ValueError(f"got {len(items)} items but {len(weights)} weights")
        total = sum(weights)
        if total <= 0:
            raise ValueError("weights must sum to a positive value")
        roll = self.below(total)
        upto = 0
        for item, weight in zip(items, weights):
            upto += weight
            if roll < upto:
                return item
        return items[-1]  # pragma: no cover - unreachable while weights are positive

    def fork(self, label: str) -> "RNG":
        """A derived, independent stream.

        Lets one part of the engine draw without shifting another part's
        stream, so adding a hazard roll does not change every damage roll that
        follows it. That property is what keeps golden tests stable while the
        game is still being tuned.
        """
        material = self._seed.to_bytes(8, "big") + label.encode("utf-8")
        return RNG.from_bytes(material)
