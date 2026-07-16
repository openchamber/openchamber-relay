// Optional SQLite usage store for the Node adapter — the counterpart of the Worker's D1
// binding. Enabled by setting RELAY_USAGE_DB=/path/to/usage.sqlite; without it the relay runs
// fully and only the /usage endpoint and accounting are off (same contract as the Worker).
//
// Uses node:sqlite (built into Node >= 22.5) so the image needs no native build step. The
// schema is read from migrations/*.sql — the same files D1 applies — so the two backends can
// never drift.
//
// PRIVACY: only serverId, coarse daily counters, and dates are stored — no IPs, no payloads.

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { isUsageDeltaEmpty, utcUsageDate, type UsageDelta } from '../core/usage-accumulator';

export type UsageRow = {
  usage_date: string;
  bytes_up: number;
  bytes_down: number;
  client_connects: number;
  peak_concurrent_clients: number;
};

export type UsageStore = {
  flush(serverId: string, delta: UsageDelta): void;
  readUsage(serverId: string): UsageRow[];
  close(): void;
};

const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'migrations');

export const openUsageStore = (path: string): UsageStore => {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL;');

  for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort()) {
    db.exec(readFileSync(join(migrationsDir, file), 'utf8'));
  }

  const touchServer = db.prepare(
    'INSERT INTO relay_servers (server_id, first_seen_at, last_seen_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(server_id) DO UPDATE SET ' +
      'first_seen_at = MIN(first_seen_at, excluded.first_seen_at), ' +
      'last_seen_at = excluded.last_seen_at',
  );
  const upsertUsage = db.prepare(
    'INSERT INTO relay_daily_usage ' +
      '(usage_date, server_id, bytes_up, bytes_down, client_connects, peak_concurrent_clients, messages) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(usage_date, server_id) DO UPDATE SET ' +
      'bytes_up = bytes_up + excluded.bytes_up, ' +
      'bytes_down = bytes_down + excluded.bytes_down, ' +
      'client_connects = client_connects + excluded.client_connects, ' +
      'peak_concurrent_clients = MAX(peak_concurrent_clients, excluded.peak_concurrent_clients), ' +
      'messages = messages + excluded.messages',
  );
  const selectUsage = db.prepare(
    'SELECT usage_date, bytes_up, bytes_down, client_connects, peak_concurrent_clients ' +
      'FROM relay_daily_usage WHERE server_id = ? ORDER BY usage_date DESC',
  );

  return {
    flush(serverId: string, delta: UsageDelta): void {
      if (isUsageDeltaEmpty(delta)) return;
      const nowMs = Date.now();
      const nowSec = Math.floor(nowMs / 1000);
      touchServer.run(serverId, nowSec, nowSec);
      upsertUsage.run(
        utcUsageDate(nowMs),
        serverId,
        delta.bytesUp,
        delta.bytesDown,
        delta.clientConnects,
        delta.peakConcurrentClients,
        delta.messages,
      );
    },
    readUsage(serverId: string): UsageRow[] {
      return selectUsage.all(serverId) as UsageRow[];
    },
    close(): void {
      db.close();
    },
  };
};
