"""Wallet authentication: challenge, session, audit.

We never request a transaction signature and never touch key material. See
`challenge.py` for the full statement of why this cannot drain a wallet.
"""

from .audit import AuditEvent, AuditRecord, AuditTrail, InMemoryAuditSink
from .challenge import AuthError, Challenge, ChallengeService, build_message
from .service import ConnectedWallet, OwnershipRequired, WalletService
from .session import Session, SessionService
from .store import CHALLENGE_STORES, InMemoryChallengeStore, RateLimitExceeded

__all__ = [
    "AuditEvent", "AuditRecord", "AuditTrail", "AuthError", "CHALLENGE_STORES",
    "Challenge", "ChallengeService", "ConnectedWallet", "InMemoryAuditSink",
    "InMemoryChallengeStore", "OwnershipRequired", "RateLimitExceeded",
    "Session", "SessionService", "WalletService", "build_message",
]
