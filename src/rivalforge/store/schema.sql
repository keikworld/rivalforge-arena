-- RivalForge schema.
--
-- Six tables, not ninety-six. The previous codebase defined 96 and had no
-- canonical schema file at all, which is how a query ended up selecting a
-- column that was never created.
--
-- Data minimisation is a schema-level decision, so it is worth naming what is
-- deliberately absent: no IP addresses, no user agents, no device or browser
-- fingerprints, no geolocation, no email addresses, no real names. None is
-- needed to run a game or investigate abuse, and each would be a liability
-- with no matching benefit.
--
-- Every statement here is idempotent, so migration is "run the file".

-- ---------------------------------------------------------------------------
-- Players
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS players (
    player_id     TEXT PRIMARY KEY,
    -- The wallet is the identity. Nullable, because a player must be able to
    -- exist, fight and appear on a ladder before ever connecting one; that is
    -- the single largest drop-off point in this genre.
    wallet        TEXT UNIQUE,
    display_name  TEXT NOT NULL,
    points        INTEGER NOT NULL DEFAULT 0 CHECK (points >= 0),
    wins          INTEGER NOT NULL DEFAULT 0 CHECK (wins >= 0),
    losses        INTEGER NOT NULL DEFAULT 0 CHECK (losses >= 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The ladder query. Points descending, then name for a stable order, so two
-- players on equal points do not swap places between page loads.
CREATE INDEX IF NOT EXISTS players_ladder_idx
    ON players (points DESC, display_name ASC);

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sessions (
    -- SHA-256 of the token, never the token. A dump of this table yields no
    -- live sessions.
    token_hash    TEXT PRIMARY KEY,
    wallet        TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_wallet_idx  ON sessions (wallet);
-- Supports both the expiry sweep and "is this session still live".
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- Audit trail
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_events (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at            TIMESTAMPTZ NOT NULL,
    event         TEXT NOT NULL,
    wallet        TEXT,
    outcome       TEXT NOT NULL,
    reason        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_wallet_idx ON audit_events (wallet, at DESC);
CREATE INDEX IF NOT EXISTS audit_at_idx     ON audit_events (at DESC);

-- ---------------------------------------------------------------------------
-- Matches
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS matches (
    match_id      TEXT PRIMARY KEY,
    -- The seed makes a match reproducible from one row: replaying it settles a
    -- dispute exactly, which is what makes an audit trail worth keeping once
    -- anything of value rides on an outcome.
    seed          BIGINT NOT NULL,
    arena_id      TEXT NOT NULL,
    fighter_a     TEXT NOT NULL,
    fighter_b     TEXT NOT NULL,
    winner        TEXT,
    rounds        INTEGER NOT NULL CHECK (rounds > 0),
    reason        TEXT NOT NULL,
    played_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS matches_played_idx ON matches (played_at DESC);

-- ---------------------------------------------------------------------------
-- Schema version
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS schema_version (
    version       INTEGER PRIMARY KEY,
    applied_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
