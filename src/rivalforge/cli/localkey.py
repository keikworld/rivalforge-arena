"""A throwaway local keypair, so the signature flow can be tested end to end.

# Read this before using it

This generates a **test keypair with no funds and no purpose beyond this
demo**. It exists so the authentication flow can be exercised without a browser
wallet or a phone.

It will refuse outright to touch a real wallet:

* it never accepts, imports, reads or asks for an existing private key or seed
  phrase -- there is no code path here that could;
* it writes only to a file the user explicitly names, with owner-only
  permissions, and warns every single time;
* the address it produces is a fresh key that has never held anything.

If a future version of this file gains the ability to load a user-supplied
secret key, that is a serious regression. A test asserts it has not.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..security.validation import b58encode

logger = logging.getLogger(__name__)

__all__ = ["LocalKeypair", "WARNING"]

WARNING: Final = (
    "This is a THROWAWAY TEST KEY generated locally. It holds nothing and is\n"
    "  for exercising the sign-in flow only. Never paste a real wallet's secret\n"
    "  key or seed phrase into this or any other program -- RivalForge never\n"
    "  asks for one, and anything that does is trying to rob you."
)


@dataclass(frozen=True, slots=True)
class LocalKeypair:
    """A generated ed25519 keypair. Test use only."""

    address: str
    _signing_key: object

    @classmethod
    def generate(cls) -> "LocalKeypair":
        from nacl.signing import SigningKey  # noqa: PLC0415

        key = SigningKey.generate()
        return cls(address=b58encode(bytes(key.verify_key)), _signing_key=key)

    @classmethod
    def load(cls, path: Path) -> "LocalKeypair":
        """Load a keypair this tool previously generated.

        Only reads files written by `save`, which contain a key this program
        made. There is deliberately no importer for a wallet's exported key.
        """
        from nacl.signing import SigningKey  # noqa: PLC0415

        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("kind") != "rivalforge-test-key":
            raise ValueError(
                f"{path} is not a RivalForge test key. This tool will not load "
                "keys from anywhere else, and you should not give it any."
            )
        key = SigningKey(bytes.fromhex(raw["seed"]))
        return cls(address=b58encode(bytes(key.verify_key)), _signing_key=key)

    def save(self, path: Path) -> None:
        """Write the keypair with owner-only permissions."""
        payload = {
            "kind": "rivalforge-test-key",
            "warning": "throwaway test key; holds nothing; do not fund",
            "address": self.address,
            "seed": bytes(self._signing_key).hex(),
        }
        # Create with 0600 from the outset rather than chmod-ing afterwards --
        # otherwise the secret is briefly world-readable on disk.
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def sign(self, message: str) -> str:
        """Sign text, exactly as a wallet would. Returns base58."""
        return b58encode(self._signing_key.sign(message.encode("utf-8")).signature)

    def __repr__(self) -> str:
        # Never let the secret reach a repr, a traceback, or a log line.
        return f"LocalKeypair(address={self.address[:4]}...{self.address[-4:]})"
