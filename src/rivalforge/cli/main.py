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
import logging
import sys
from typing import Final

from ..agents.builtin import AGENT_REGISTRY, build_agent
from ..content.loader import ContentError, load_content
from ..content.schema import GameContent, Stance
from ..engine import balance
from ..engine.fighter import Fighter, derive_fighter, starter_fighter
from ..engine.match import Decision, Match, MatchView, Side, SupportsDecide
from ..engine.rng import RNG, new_seed
from ..plugins.registries import WALLET_PROVIDERS, wallet_provider
from ..plugins.toggles import Toggles, toggles
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
