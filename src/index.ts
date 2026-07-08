// OpenChamber private relay worker — Layer 1 of the relay protocol.
// Thin routing layer: validates the upgrade request and host auth, then hands the raw request
// to the per-serverId Durable Object. Frame contents are never parsed or logged here.

import { Hono } from 'hono';
import { z } from 'zod';
import {
  buildSignaturePayload,
  buildUsagePayload,
  deriveServerId,
  isFreshTimestamp,
  parsePublicKeyParam,
  verifySignature,
} from './lib/relay-auth';
import { RelayDurableObject } from './relay-do';

export { RelayDurableObject };

type Env = {
  RELAY: DurableObjectNamespace;
  // Optional: bind a D1 database (+ apply migrations/) to enable per-server usage
  // accounting and the /usage endpoint. The relay runs fully without it.
  DB?: D1Database;
};

const ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

const wsQuerySchema = z
  .object({
    v: z.literal('1'),
    role: z.enum(['host-control', 'host-data', 'client']),
    serverId: z.string().regex(ID_PATTERN),
    connectionId: z.string().regex(ID_PATTERN).optional(),
    ts: z.string().optional(),
    sig: z.string().optional(),
    pk: z.string().optional(),
  })
  .refine((query) => query.role !== 'host-data' || !!query.connectionId, {
    message: 'connectionId is required for host-data',
  });

const app = new Hono<{ Bindings: Env }>();

app.get('/health', (c) => c.json({ ok: true, service: 'openchamber-relay' }));

app.get('/ws', async (c) => {
  const upgrade = c.req.header('Upgrade');
  if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
    return c.text('Expected WebSocket upgrade', 426);
  }

  const parsed = wsQuerySchema.safeParse({
    v: c.req.query('v'),
    role: c.req.query('role'),
    serverId: c.req.query('serverId'),
    connectionId: c.req.query('connectionId') || undefined,
    ts: c.req.query('ts') || undefined,
    sig: c.req.query('sig') || undefined,
    pk: c.req.query('pk') || undefined,
  });
  if (!parsed.success) {
    return c.text('Invalid query parameters', 400);
  }
  const query = parsed.data;

  // Host roles carry a signed handshake; clients connect without relay-level auth in v1
  // (E2EE gates actual access). An optional `grant` param is reserved and ignored in v1.
  if (query.role === 'host-control' || query.role === 'host-data') {
    if (!query.ts || !query.sig || !query.pk) {
      return c.text('Missing auth parameters', 401);
    }
    const ts = Number(query.ts);
    if (!isFreshTimestamp(ts)) {
      return c.text('Signature expired', 401);
    }
    const jwk = parsePublicKeyParam(query.pk);
    if (!jwk) {
      return c.text('Invalid public key', 403);
    }
    const expectedServerId = await deriveServerId(jwk);
    if (expectedServerId !== query.serverId) {
      return c.text('serverId mismatch', 403);
    }
    const payload = buildSignaturePayload(ts, query.serverId, query.role, query.connectionId);
    const valid = await verifySignature(jwk, payload, query.sig);
    if (!valid) {
      return c.text('Invalid signature', 403);
    }
  }

  const id = c.env.RELAY.idFromName(`relay-v1:${query.serverId}`);
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
