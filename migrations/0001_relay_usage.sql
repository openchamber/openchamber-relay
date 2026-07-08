-- Optional per-server usage accounting. Only needed if you bind a D1 database in
-- wrangler.jsonc (see the commented `d1_databases` block). Apply with:
--   wrangler d1 migrations apply <your-db-name> --remote
-- Privacy: only serverId, coarse counters, and dates are stored — no IPs, no
-- per-request rows, no payload data.

CREATE TABLE IF NOT EXISTS relay_servers (
  server_id     TEXT PRIMARY KEY,
  first_seen_at INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  plan          TEXT NOT NULL DEFAULT 'free'
);

CREATE TABLE IF NOT EXISTS relay_daily_usage (
  usage_date              TEXT NOT NULL,        -- YYYY-MM-DD (UTC)
  server_id               TEXT NOT NULL,
  bytes_up                INTEGER NOT NULL DEFAULT 0,   -- client -> host
  bytes_down              INTEGER NOT NULL DEFAULT 0,   -- host -> client
  client_connects         INTEGER NOT NULL DEFAULT 0,
  peak_concurrent_clients INTEGER NOT NULL DEFAULT 0,
  messages                INTEGER NOT NULL DEFAULT 0,   -- Cloudflare DO-request unit
  PRIMARY KEY (usage_date, server_id)
);

CREATE INDEX IF NOT EXISTS idx_relay_daily_usage_server ON relay_daily_usage(server_id);
