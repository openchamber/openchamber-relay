// OpenChamber private relay — Cloudflare Worker adapter (Layer 1 of the relay protocol).
// Thin routing layer: validates the upgrade request and host auth (shared core logic), then
// hands the raw request to the per-serverId Durable Object. Frame contents are never parsed
// or logged here.

import { Hono } from 'hono';
import { z } from 'zod';
import {
  buildUsagePayload,
  deriveServerId,
  isFreshTimestamp,
  parsePublicKeyParam,
  verifySignature,
} from '../core/relay-auth';
import { HEALTH_BODY } from '../core/protocol';
import { ID_PATTERN, validateWsUpgrade } from '../core/ws-query';
import { RelayDurableObject } from './relay-do';

export { RelayDurableObject };

type Env = {
  RELAY: DurableObjectNamespace;
  // Optional: bind a D1 database (+ apply migrations/) to enable per-server usage
  // accounting and the /usage endpoint. The relay runs fully without it.
  DB?: D1Database;
};

const app = new Hono<{ Bindings: Env }>();

app.get('/health', (c) => c.json(HEALTH_BODY));

app.get('/ws', async (c) => {
  const upgrade = c.req.header('Upgrade');
  if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
    return c.text('Expected WebSocket upgrade', 426);
  }

  const verdict = await validateWsUpgrade(new URL(c.req.url).searchParams);
  if (!verdict.ok) {
    return c.text(verdict.message, verdict.status as 400);
  }

  const id = c.env.RELAY.idFromName(`relay-v1:${verdict.query.serverId}`);
  const stub = c.env.RELAY.get(id);
  return stub.fetch(c.req.raw);
});

// Owner-facing usage read (pre-accounts). Authenticated with the same signed-request scheme hosts
// use for WS handshakes: the caller proves ownership of `serverId` by signing `${ts}.usage.${serverId}`
// with the ECDSA key whose public JWK hashes to that serverId. Privacy: returns only coarse daily
// counters for the caller's own serverId — no IPs, no per-request rows.
const usageQuerySchema = z.object({
  ts: z.string(),
  sig: z.string(),
  pk: z.string(),
});

app.get('/usage/:serverId', async (c) => {
  const db = c.env.DB;
  if (!db) {
    return c.text('Usage accounting is not enabled on this relay', 503);
  }
  const serverId = c.req.param('serverId');
  if (!ID_PATTERN.test(serverId)) {
    return c.text('Invalid serverId', 400);
  }

  const parsed = usageQuerySchema.safeParse({
    ts: c.req.query('ts'),
    sig: c.req.query('sig'),
    pk: c.req.query('pk'),
  });
  if (!parsed.success) {
    return c.text('Missing auth parameters', 401);
  }

  const ts = Number(parsed.data.ts);
  if (!isFreshTimestamp(ts)) {
    return c.text('Signature expired', 401);
  }
  const jwk = parsePublicKeyParam(parsed.data.pk);
  if (!jwk) {
    return c.text('Invalid public key', 403);
  }
  const expectedServerId = await deriveServerId(jwk);
  if (expectedServerId !== serverId) {
    return c.text('serverId mismatch', 403);
  }
  const valid = await verifySignature(jwk, buildUsagePayload(ts, serverId), parsed.data.sig);
  if (!valid) {
    return c.text('Invalid signature', 403);
  }

  const result = await db.prepare(
    'SELECT usage_date, bytes_up, bytes_down, client_connects, peak_concurrent_clients ' +
      'FROM relay_daily_usage WHERE server_id = ? ORDER BY usage_date DESC',
  )
    .bind(serverId)
    .all();

  return c.json({ serverId, usage: result.results ?? [] });
});

export default app;
