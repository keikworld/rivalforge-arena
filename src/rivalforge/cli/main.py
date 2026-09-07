"""The playable terminal client.

Three modes:

    rivalforge play                     # you against an agent
    rivalforge watch --a adaptive --b aggressive
    rivalforge fighter <mint>           # what fighter does this NFT make?

This is the whole of Phase 1's user interface, and it exists to answer one
question before anything else gets built: *is the fight fun?* If it is not fun
in a terminal, no amount of Telegram polish or on-chain plumbing will save it.

I/O lives here and nowhere below. The engine emits events, `render.py` turns
them into strings, and this module is the only place that prints or reads.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Final

from ..agents.builtin import AGENT_REGISTRY, build_agent
from ..content.loader import ContentError, load_content
from ..content.schema import GameContent, Stance
from ..engine import balance
from ..engine.fighter import Fighter, derive_fighter, starter_fighter
from ..engine.match import Decision, Match, MatchView, Side, SupportsDecide
from ..engine.rng import RNG, new_seed
from ..auth.challenge import AuthError
from ..auth.service import OwnershipRequired
from ..auth.store import RateLimitExceeded
from ..plugins.registries import WALLET_PROVIDERS, wallet_provider
from ..plugins.toggles import Toggles, toggles
from .localkey import WARNING as LOCAL_KEY_WARNING
from .localkey import LocalKeypair
from .wiring import build_application
from ..security.redaction import install_redaction, short_address
from ..security.validation import ValidationError, validate_mint_address
from . import render

BANNER: Final = r"""
   ___  _            _ ___
  | _ \(_)_ ____ _| | __|__ _ _ __ _ ___
  |   /| \ V / _` | | _/ _ \ '_/ _` / -_)
  |_|_\|_|\_/\__,_|_|_|\___/_| \__, \___|
                               |___/
  sixty-second duels
"""

_STANCE_KEYS: Final = {"1": Stance.STRIKE, "2": Stance.GUARD, "3": Stance.FOCUS}
_SOUL_KEYS: Final = frozenset({"s", "soul"})


class HumanAgent(SupportsDecide):
    """A person at a prompt.

    Implements exactly the same interface as every scripted agent, which is the
    point: there is one match loop, not one for humans and one for bots.
    """

    name = "you"

    def __init__(self, content: GameContent, narrator: RNG) -> None:
        self._content = content
        self._narrator = narrator

    def decide(self, view: MatchView) -> Decision:
        print()
        print(render.render_board(view, balance.MAX_SOULS))
        prompt = "  [1] strike  [2] guard  [3] focus"
        if view.can_spend_soul:
            prompt += f"   [s] {view.arena.soul_name} ({view.arena.soul_cost} soul)"
        print(prompt)

        spend = False
        while True:
            try:
                raw = input("  > ").strip().lower()
            except EOFError:
                print("\n  (no input -- guarding)")
                return Decision(stance=Stance.GUARD, spend_soul=spend)

            if raw in ("q", "quit", "exit"):
                raise KeyboardInterrupt

            # Exact match, not a prefix: `startswith("s")` swallowed "strike",
            # so typing the stance name silently asked to spend soul instead.
            if raw in _SOUL_KEYS:
                if not view.can_spend_soul:
                    print("  Not enough soul for that yet.")
                    continue
                spend = True
                print(f"  {view.arena.soul_name} readied. Now pick a stance.")
                continue

            stance = _STANCE_KEYS.get(raw)
            if stance is None:
                # Also accept the full word, because people type "strike".
                try:
                    stance = Stance(raw)
                except ValueError:
                    print("  Pick 1, 2 or 3 (or s to spend soul, q to quit).")
                    continue
            return Decision(stance=stance, spend_soul=spend)


def _resolve_fighter(content: GameContent, mint: str | None, name: str | None) -> Fighter:
    """Build the player's fighter, with a wallet-free fallback.

    Requiring a wallet before the first match is the largest drop-off point in
    this genre, so `mint` is optional all the way down.
    """
    if mint is None:
        return starter_fighter(content, name=name or "Recruit")
    return derive_fighter(mint, content, name=name)


def _pick_arena(content: GameContent, arena_id: str | None, rng: RNG):
    if arena_id is None:
        return rng.choice(content.battlefields)
    try:
        return content.battlefield(arena_id)
    except KeyError:
        available = ", ".join(a.id for a in content.battlefields)
        raise SystemExit(f"unknown arena {arena_id!r}. available: {available}") from None


def _run_match(
    content: GameContent,
    fighter_a: Fighter,
    fighter_b: Fighter,
    arena,
    seed: int,
    deciders: dict[Side, SupportsDecide],
    viewer: Side | None,
    quiet: bool = False,
) -> None:
    """Drive one match and narrate it."""
    match = Match.create(fighter_a, fighter_b, arena, content, seed=seed)
    names = {Side.A: fighter_a.name, Side.B: fighter_b.name}
    # A separate stream, so narration never perturbs the match's own rolls.
    narrator = RNG(seed).fork("narration")

    print()
    print(render.render_arena(arena))
    print()
    print(f"  A  {render.render_fighter(fighter_a)}")
    print(f"  B  {render.render_fighter(fighter_b)}")
    print(f"\n  seed {seed}  (replays this match exactly)")

    while not match.is_over:
        decisions = {side: deciders[side].decide(match.view(side)) for side in match.awaiting}
        events = match.submit(decisions)
        if not quiet:
            for line in render.render_events(events, names, content, narrator):
                print(line)

    assert match.outcome is not None
    print(render.render_outcome(match.outcome, names, content, narrator, viewer))


def cmd_play(args: argparse.Namespace, content: GameContent) -> int:
    seed = args.seed if args.seed is not None else new_seed()
    rng = RNG(seed)
    arena = _pick_arena(content, args.arena, rng.fork("arena"))

    if args.mint and not args.unverified:
        # Validate the address *before* looking at auth state. A malformed
        # mint is malformed whether or not anyone is signed in, and answering
        # "connect a wallet first" to a typo sends the player down the wrong
        # path entirely. Input validation first, authorisation second.
        validate_mint_address(args.mint, field="mint")

        # Then the ownership gate: a live session, then a fresh ownership
        # check. Never a cached grant -- an NFT can be sold between matches.
        app = build_application()
        saved = _load_session()
        if saved is None:
            print("\n  Connect a wallet first:  rivalforge connect --key ./test-key.json",
                  file=sys.stderr)
            print("  Or pass --unverified to play it without an ownership check.",
                  file=sys.stderr)
            return 1
        try:
            you = app.wallets.fighter_for(saved[0], args.mint, name=args.name)
        except AuthError:
            print("\n  Session expired. Run connect again.", file=sys.stderr)
            return 1
        except OwnershipRequired as exc:
            print(f"\n  {exc}", file=sys.stderr)
            return 3
        print(f"\n  Ownership verified for {you.short_mint}")
    else:
        if args.mint and args.unverified:
            print("\n  !! --unverified: playing this NFT WITHOUT an ownership check.")
        you = _resolve_fighter(content, args.mint, args.name)
    opponent_mint = args.opponent_mint
    them = (
        derive_fighter(opponent_mint, content, name="Rival")
        if opponent_mint
        else starter_fighter(content, name="Rival")
    )

    print(BANNER)
    _run_match(
        content, you, them, arena, seed,
        {
            Side.A: HumanAgent(content, rng.fork("human")),
            Side.B: build_agent(args.opponent, RNG(seed).fork("opponent")),
        },
        viewer=Side.A,
    )
    return 0


def cmd_watch(args: argparse.Namespace, content: GameContent) -> int:
    """Agent versus agent. The same loop, with nobody at the keyboard."""
    seed = args.seed if args.seed is not None else new_seed()
    rng = RNG(seed)
    arena = _pick_arena(content, args.arena, rng.fork("arena"))

    fighter_a = _resolve_fighter(content, args.mint, args.a)
    fighter_b = (
        derive_fighter(args.opponent_mint, content, name=args.b)
        if args.opponent_mint
        else starter_fighter(content, name=args.b)
    )

    if args.rounds > 1:
        wins = {Side.A: 0, Side.B: 0, None: 0}
        for index in range(args.rounds):
            match = Match.create(fighter_a, fighter_b, arena, content, seed=seed + index)
            while not match.is_over:
                match.submit({
                    Side.A: build_agent(args.a, RNG(seed + index).fork("a")).decide(
                        match.view(Side.A)
                    ),
                    Side.B: build_agent(args.b, RNG(seed + index).fork("b")).decide(
                        match.view(Side.B)
                    ),
                })
            wins[match.outcome.winner] += 1
        print(f"\n{args.rounds} matches on {arena.name}")
        print(f"  {args.a:<12} {wins[Side.A]:>4}")
        print(f"  {args.b:<12} {wins[Side.B]:>4}")
        print(f"  {'draw':<12} {wins[None]:>4}")
        return 0

    print(BANNER)
    _run_match(
        content, fighter_a, fighter_b, arena, seed,
        {
            Side.A: build_agent(args.a, RNG(seed).fork("a")),
            Side.B: build_agent(args.b, RNG(seed).fork("b")),
        },
        viewer=None,
    )
    return 0


def cmd_fighter(args: argparse.Namespace, content: GameContent) -> int:
    """Show the fighter a mint derives to, without playing anything."""
    fighter = derive_fighter(args.mint, content, name=args.name)
    print()
    print(f"  {render.render_fighter(fighter)}")
    print(f"  {fighter.supremacy.name} -- {fighter.supremacy.description}")
    print(f"    strength: {fighter.supremacy.strength}")
    print(f"    weakness: {fighter.supremacy.weakness}")
    print(f"  rank: {content.rank_for(fighter.points).name}")
    print()
    print("  This is a pure function of the mint address: same NFT, same")
    print("  fighter, on any machine, forever.")
    return 0


def cmd_wallet(args: argparse.Namespace, content: GameContent) -> int:
    """Check a wallet connection and show the fighters its NFTs make.

    This is the command to run when configuring a deployment: it reports which
    provider is selected, whether it is configured, and what it can see --
    without ever printing a full address or the API key.
    """
    settings = toggles(wallet_verification=True) if args.force else toggles()

    print()
    print(f"  provider available: {', '.join(WALLET_PROVIDERS.names())}")
    if not settings.enabled("wallet_verification"):
        print("  wallet_verification is OFF.")
        print("  Enable it with RIVALFORGE_FEATURE_WALLET_VERIFICATION=1,")
        print("  or pass --force to override for this command only.")
        return 1

    provider = wallet_provider(settings)
    print(f"  provider selected : {getattr(provider, 'name', type(provider).__name__)}")
    endpoint = getattr(provider, "endpoint", None)
    if endpoint:
        print(f"  endpoint          : {endpoint}")
        print(f"  api key           : {'set' if getattr(provider, 'has_key', False) else 'none (not required)'}")

    try:
        validate_mint_address(args.wallet, field="wallet")
    except ValidationError as exc:
        print(f"  {exc}", file=sys.stderr)
        return 2
    print(f"  wallet            : {short_address(args.wallet)}")

    if args.mint:
        try:
            validate_mint_address(args.mint, field="mint")
        except ValidationError as exc:
            print(f"  {exc}", file=sys.stderr)
            return 2
        result = provider.verify_ownership(args.wallet, args.mint)
        print()
        if result.verified:
            print(f"  OWNED    {short_address(args.mint)}")
        elif result.checked:
            print(f"  NOT OWNED    {short_address(args.mint)} -- {result.reason}")
        else:
            # The distinction that matters: an outage is not a denial.
            print(f"  COULD NOT CHECK  -- {result.reason}")
            return 3
        return 0

    try:
        owned = provider.list_owned(args.wallet, limit=args.limit)
    except Exception as exc:  # provider errors are already typed and redacted
        print(f"\n  could not list holdings: {exc}", file=sys.stderr)
        return 3

    if not owned:
        # "Nothing found" and "nothing checked" must not look the same. The
        # null provider inspects nothing, so saying "no NFTs" would be a lie.
        if getattr(provider, "name", "") == "null":
            print("\n  Nothing was checked: the null provider is selected.")
            print("  Set RIVALFORGE_WALLET_PROVIDER=das (no API key needed).")
            return 3
        print("\n  No NFTs visible for this wallet.")
        return 0

    print(f"\n  {len(owned)} NFT(s):\n")
    for nft in owned:
        fighter = derive_fighter(nft.mint, content, name=nft.name)
        print(f"  {nft.name[:22]:<22} {nft.short_mint}")
        print(f"    -> {render.render_fighter(fighter)}")
    return 0


def cmd_features(args: argparse.Namespace, content: GameContent) -> int:
    """Report which features are on, and how to change them."""
    print("\nFeature toggles:\n")
    print(toggles().describe())
    print()
    return 0


# --------------------------------------------------------------------------
# Wallet connection (Phase 2)
# --------------------------------------------------------------------------


def _session_path() -> Path:
    """Where the CLI remembers a session token between commands.

    Owner-only, and it holds a short-lived session token -- never a key. Losing
    it costs a re-sign, nothing more.
    """
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "rivalforge" / "session.json"


def _save_session(token: str, wallet: str) -> Path:
    path = _session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"token": token, "wallet": wallet}, handle)
    return path


def _load_session() -> tuple[str, str] | None:
    path = _session_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw["token"], raw["wallet"]
    except (OSError, ValueError, KeyError):
        return None


def cmd_connect(args: argparse.Namespace, content: GameContent) -> int:
    """Connect a wallet by signing a challenge.

    Two modes:

    * `--key <file>` signs locally with a throwaway test key, so the whole flow
      can be exercised without a browser wallet;
    * without it, the challenge is printed for the player to sign in their own
      wallet and paste back.
    """
    app = build_application(overrides={"wallet_verification": True} if args.force else None)
    service = app.wallets

    if args.key:
        path = Path(args.key)
        if path.exists():
            keypair = LocalKeypair.load(path)
            print(f"\n  Loaded test key {keypair.address[:4]}...{keypair.address[-4:]}")
        else:
            keypair = LocalKeypair.generate()
            keypair.save(path)
            print(f"\n  Generated a test key at {path} (owner-only)")
        print(f"  !! {LOCAL_KEY_WARNING}")
        wallet_address = keypair.address
    else:
        keypair = None
        if not args.wallet:
            print("give --wallet <address>, or --key <file> to use a test key",
                  file=sys.stderr)
            return 2
        wallet_address = args.wallet

    try:
        challenge = service.begin(wallet_address)
    except RateLimitExceeded:
        print("\n  Too many sign-in attempts for that wallet. Wait a few minutes.",
              file=sys.stderr)
        return 4

    print("\n" + "-" * 62)
    print(challenge.message)
    print("-" * 62)

    if keypair is not None:
        signature = keypair.sign(challenge.message)
        print("\n  Signed locally with the test key.")
    else:
        print("\n  Sign the text above in your wallet, then paste the signature.")
        print("  RivalForge will NEVER ask for your private key or seed phrase.")
        try:
            signature = input("\n  signature (base58) > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.")
            return 130

    try:
        connected = service.complete(challenge.nonce, signature)
    except AuthError:
        # One generic message: distinguishing failures would be an oracle.
        print("\n  Authentication failed.", file=sys.stderr)
        return 4

    path = _save_session(connected.token, connected.wallet)
    print(f"\n  Connected as {connected.short_wallet}")
    print(f"  Session valid until {connected.expires_at.isoformat()}")
    print(f"  Token stored at {path} (owner-only; not a key)")
    return 0


def cmd_whoami(args: argparse.Namespace, content: GameContent) -> int:
    """Resolve the stored token against the live session store."""
    app = build_application(overrides={"wallet_verification": True} if args.force else None)
    saved = _load_session()
    if saved is None:
        print("\n  Not connected. Run: rivalforge connect --key ./test-key.json")
        return 1
    token, _ = saved
    try:
        wallet = app.wallets.wallet_for(token)
    except AuthError:
        print("\n  Session expired or revoked. Run connect again.")
        return 1
    print(f"\n  Connected as {wallet[:4]}...{wallet[-4:]}")
    if app.features.enabled("wallet_verification"):
        try:
            owned = app.wallets.roster(token, limit=args.limit)
        except RuntimeError as exc:
            print(f"  (could not read holdings: {exc})")
            return 0
        print(f"  {len(owned)} playable NFT(s):\n")
        for nft in owned:
            fighter = derive_fighter(nft.mint, content, name=nft.name)
            print(f"    {nft.short_mint}  {render.render_fighter(fighter)}")
    return 0


def cmd_audit(args: argparse.Namespace, content: GameContent) -> int:
    """Show the audit trail for this process."""
    app = build_application()
    records = app.audit_sink.records()
    print(f"\n  {len(records)} audit record(s) in this process\n")
    for record in records[-args.limit:]:
        print("  " + record.redacted())
    if not records:
        print("  (the in-memory sink starts empty each run)")
    return 0


def cmd_status(args: argparse.Namespace, content: GameContent) -> int:
    """What this deployment actually does. The operator's first command."""
    app = build_application()
    print("\nRivalForge status\n")
    print(app.describe())
    print("\nFeatures:\n")
    print(app.features.describe())
    print()
    return 0


def cmd_telegram(args: argparse.Namespace, content: GameContent) -> int:
    """Run the Telegram bot.

    Behind the `telegram_bot` toggle, like everything that reaches a third
    party. The token comes from the environment and is never an argument here:
    arguments are visible in `ps` and in shell history.
    """
    app = build_application()
    if not app.features.enabled("telegram_bot"):
        print(
            "\n  The telegram_bot feature is off. Turn it on with:\n"
            "    RIVALFORGE_FEATURE_TELEGRAM_BOT=1\n",
            file=sys.stderr,
        )
        return 1

    from ..telegram.api import TOKEN_ENV_VARS, TelegramAPI, read_token  # noqa: PLC0415
    from ..telegram.bot import run_forever  # noqa: PLC0415
    from ..telegram.handlers import BotHandlers  # noqa: PLC0415
    from ..telegram.security import CallbackSigner  # noqa: PLC0415

    try:
        token = read_token()
    except ValidationError as exc:
        print(f"\n  {exc}", file=sys.stderr)
        print(f"  Set one of: {', '.join(TOKEN_ENV_VARS)}\n", file=sys.stderr)
        return 2

    api = TelegramAPI(token)
    handlers = BotHandlers(app, signer=CallbackSigner(), opponent=args.opponent)

    print("\nRivalForge on Telegram\n")
    print(app.describe())
    print("\n  polling (ctrl-c to stop)\n")

    code = run_forever(api, handlers, poll_seconds=args.poll_seconds)
    if code != 0:
        # `run_forever` logs the reason at ERROR, which is above the default
        # level, so it is already on screen. Point at it rather than repeat it.
        print("\n  The bot stopped -- see the error above.\n", file=sys.stderr)
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rivalforge", description="Sixty-second NFT duels.")
    parser.add_argument("--verbose", action="store_true", help="show debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    play = sub.add_parser("play", help="play a match against an agent")
    play.add_argument("--mint", help="your NFT mint address (optional: a starter is provided)")
    play.add_argument("--name", help="your display name")
    play.add_argument("--opponent", default="adaptive", choices=sorted(AGENT_REGISTRY))
    play.add_argument("--opponent-mint", help="the opponent's NFT mint address")
    play.add_argument("--arena", help="arena id (default: random)")
    play.add_argument("--seed", type=int, help="replay a specific match")
    play.add_argument(
        "--unverified", action="store_true",
        help="skip the ownership check for --mint (local play only)",
    )
    play.set_defaults(func=cmd_play)

    watch = sub.add_parser("watch", help="watch two agents play")
    watch.add_argument("--a", default="adaptive", choices=sorted(AGENT_REGISTRY))
    watch.add_argument("--b", default="aggressive", choices=sorted(AGENT_REGISTRY))
    watch.add_argument("--mint", help="mint for side A")
    watch.add_argument("--opponent-mint", help="mint for side B")
    watch.add_argument("--arena", help="arena id (default: random)")
    watch.add_argument("--seed", type=int, help="replay a specific match")
    watch.add_argument(
        "--rounds", type=int, default=1,
        help="run this many matches and report a tally instead of narrating",
    )
    watch.set_defaults(func=cmd_watch)

    fighter = sub.add_parser("fighter", help="show the fighter a mint derives to")
    fighter.add_argument("mint", help="NFT mint address")
    fighter.add_argument("--name", help="display name")
    fighter.set_defaults(func=cmd_fighter)

    wallet = sub.add_parser("wallet", help="check a wallet connection and list its fighters")
    wallet.add_argument("wallet", help="wallet address to inspect")
    wallet.add_argument("--mint", help="verify ownership of one specific mint")
    wallet.add_argument("--limit", type=int, default=20, help="max NFTs to list")
    wallet.add_argument(
        "--force", action="store_true",
        help="enable wallet verification for this command only",
    )
    wallet.set_defaults(func=cmd_wallet)

    features = sub.add_parser("features", help="show which features are enabled")
    features.set_defaults(func=cmd_features)

    status = sub.add_parser("status", help="what this deployment is configured to do")
    status.set_defaults(func=cmd_status)

    connect = sub.add_parser("connect", help="connect a wallet by signing a challenge")
    connect.add_argument("--wallet", help="your wallet address (you sign in your own wallet)")
    connect.add_argument(
        "--key", metavar="FILE",
        help="sign locally with a THROWAWAY TEST key at FILE, generating one if absent",
    )
    connect.add_argument("--force", action="store_true",
                         help="enable wallet verification for this command only")
    connect.set_defaults(func=cmd_connect)

    whoami = sub.add_parser("whoami", help="show the stored session and its fighters")
    whoami.add_argument("--force", action="store_true")
    whoami.add_argument("--limit", type=int, default=10)
    whoami.set_defaults(func=cmd_whoami)

    telegram = sub.add_parser("telegram", help="run the Telegram bot (needs a token)")
    telegram.add_argument("--opponent", default="adaptive", choices=sorted(AGENT_REGISTRY),
                          help="which agent players face")
    telegram.add_argument("--poll-seconds", type=int, default=25,
                          help="how long each long poll waits")
    telegram.set_defaults(func=cmd_telegram)

    audit = sub.add_parser("audit", help="show this process's audit trail")
    audit.add_argument("--limit", type=int, default=40)
    audit.set_defaults(func=cmd_audit)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    # Attach the redaction filter before anything can log. Even at WARNING, a
    # stack trace can carry a wallet address into the terminal scrollback.
    install_redaction()

    try:
        content = load_content()
    except ContentError as exc:
        # Content failure is fatal by design: an unplayable build must not
        # reach a player, and it must say exactly which field is wrong.
        print(f"content error: {exc}", file=sys.stderr)
        return 2

    try:
        return args.func(args, content)
    except ValidationError as exc:
        print(f"invalid input -- {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n  Bowing out.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
