"""Timeouts, retries, circuit breaking and clean shutdown.

Every call that leaves this process goes through here. An RPC provider is
someone else's uptime, and the game has to keep working when it is having a bad
day.

Four guarantees, and the reasoning for each:

*   **Nothing waits forever.** Every outbound call carries a deadline. A hung
    socket with no timeout is how a game loop stops responding entirely, and it
    is invisible in testing because it needs a bad network to reproduce.
*   **Retries are bounded and backed off, with jitter.** Unbounded retries turn
    a provider's brief wobble into a self-inflicted denial of service. Jitter
    stops every client in the fleet retrying on the same tick.
*   **Only some failures are retried.** A timeout is worth retrying. A
    malformed address is not -- retrying it just costs latency and hits a rate
    limit for a request that can never succeed.
*   **A failing dependency is dropped, not hammered.** After enough
    consecutive failures the breaker opens and calls fail immediately, so the
    game degrades in milliseconds instead of stalling on every request.

None of this decides *policy*. The caller still chooses what a failure means,
which is why `OwnershipResult` distinguishes "not owned" from "could not
check".
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Callable, Final, Iterable, TypeVar

__all__ = [
    "RetryPolicy",
    "CircuitBreaker",
    "CircuitOpen",
    "TransientError",
    "PermanentError",
    "call_with_retries",
    "Deadline",
]

logger = logging.getLogger(__name__)

T = TypeVar("T")


class TransientError(RuntimeError):
    """A failure that might succeed if tried again: timeout, 5xx, rate limit."""


class PermanentError(RuntimeError):
    """A failure that will never succeed: bad input, 404, auth rejection.

    Never retried. Retrying a permanent failure spends the caller's latency
    budget and the provider's rate limit to get the same answer.
    """


class CircuitOpen(TransientError):
    """Raised when the breaker is open and the call was not attempted.

    A subclass of `TransientError` because that is what it is from the caller's
    side: try later, the request itself was fine.
    """


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """How hard to try, and how long to wait between attempts."""

    attempts: int = 3
    base_delay: float = 0.2
    max_delay: float = 2.0
    #: Full jitter. Without it, a fleet of clients retries in lockstep and
    #: recreates the spike that caused the failure.
    jitter: bool = True
    #: Total wall-clock budget across all attempts. The backstop that makes
    #: "no hanging" true even if an individual timeout is set too generously.
    total_timeout: float = 10.0

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError(f"attempts must be at least 1, got {self.attempts}")
        if self.base_delay < 0 or self.max_delay < 0:
            raise ValueError("delays must not be negative")
        if self.total_timeout <= 0:
            raise ValueError("total_timeout must be positive")

    def delay_for(self, attempt: int, rng: random.Random | None = None) -> float:
        """Exponential backoff for a 1-based attempt number."""
        raw = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
        if not self.jitter:
            return raw
        source = rng or random
        return source.uniform(0.0, raw)


class Deadline:
    """A wall-clock budget shared across the steps of one logical operation."""

    __slots__ = ("_expires_at",)

    def __init__(self, seconds: float) -> None:
        if seconds <= 0:
            raise ValueError(f"deadline must be positive, got {seconds}")
        self._expires_at = time.monotonic() + seconds

    @property
    def remaining(self) -> float:
        """Seconds left; never negative."""
        return max(0.0, self._expires_at - time.monotonic())

    @property
    def expired(self) -> bool:
        return self.remaining <= 0.0

    def check(self, what: str = "operation") -> None:
        if self.expired:
            raise TransientError(f"{what} exceeded its deadline")


class CircuitBreaker:
    """Stops calling a dependency that is consistently failing.

    Closed -> (too many consecutive failures) -> Open -> (after a cooldown)
    -> Half-open -> (one success) -> Closed.

    Thread-safe, because a provider is shared across concurrent matches.
    """

    __slots__ = ("_threshold", "_cooldown", "_failures", "_opened_at", "_lock", "_name")

    def __init__(self, name: str, *, threshold: int = 5, cooldown: float = 30.0) -> None:
        if threshold < 1:
            raise ValueError(f"threshold must be at least 1, got {threshold}")
        self._name = name
        self._threshold = threshold
        self._cooldown = cooldown
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._is_open_locked()

    def _is_open_locked(self) -> bool:
        if self._opened_at is None:
            return False
        if time.monotonic() - self._opened_at >= self._cooldown:
            # Cooldown elapsed: allow one probe through (half-open).
            self._opened_at = None
            self._failures = self._threshold - 1
            return False
        return True

    def before_call(self) -> None:
        with self._lock:
            if self._is_open_locked():
                raise CircuitOpen(
                    f"{self._name} is unavailable; not retried for another "
                    f"{self._cooldown:.0f}s"
                )

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold and self._opened_at is None:
                self._opened_at = time.monotonic()
                logger.warning(
                    "circuit for %s opened after %d consecutive failures",
                    self._name, self._failures,
                )

    def reset(self) -> None:
        """Force closed. For tests and for an operator's manual recovery."""
        with self._lock:
            self._failures = 0
            self._opened_at = None


def call_with_retries(
    operation: Callable[[], T],
    *,
    policy: RetryPolicy | None = None,
    breaker: CircuitBreaker | None = None,
    retry_on: Iterable[type[BaseException]] = (TransientError,),
    description: str = "operation",
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> T:
    """Run `operation`, retrying transient failures within a total budget.

    `sleep` and `rng` are injected so tests can exercise the backoff and the
    breaker without actually waiting -- a retry test that really sleeps is a
    test nobody runs.

    Raises:
        PermanentError: immediately, never retried.
        TransientError: when the attempts or the total budget are exhausted.
    """
    policy = policy or RetryPolicy()
    retryable = tuple(retry_on)
    deadline = Deadline(policy.total_timeout)
    last: BaseException | None = None

    for attempt in range(1, policy.attempts + 1):
        if deadline.expired:
            break
        if breaker is not None:
            # An open breaker is itself a transient failure; surface it rather
            # than burning the remaining attempts on a dependency we know is down.
            breaker.before_call()

        try:
            result = operation()
        except PermanentError:
            if breaker is not None:
                # A permanent failure is the caller's fault, not the
                # dependency's. Counting it toward the breaker would let one
                # bad request take a healthy provider offline for everyone.
                breaker.record_success()
            raise
        except retryable as exc:
            last = exc
            if breaker is not None:
                breaker.record_failure()
            if attempt == policy.attempts:
                break
            wait = min(policy.delay_for(attempt, rng), deadline.remaining)
            logger.debug(
                "%s failed (attempt %d/%d): %s; retrying in %.2fs",
                description, attempt, policy.attempts, exc, wait,
            )
            if wait > 0:
                sleep(wait)
        else:
            if breaker is not None:
                breaker.record_success()
            return result

    raise TransientError(
        f"{description} failed after {policy.attempts} attempt(s)"
        + (f": {last}" if last else "")
    ) from last
