// Shared /ws upgrade-request validation for every relay adapter (Cloudflare Worker, Node).
// Layer 1 of the relay protocol: parse the query, and for host-* roles verify the signed
// handshake. Adapters translate the returned verdict into their own response/close mechanics.

import { z } from 'zod';
import {
  buildSignaturePayload,
  deriveServerId,
  isFreshTimestamp,
  parsePublicKeyParam,
  verifySignature,
} from './relay-auth';

export const ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

export const wsQuerySchema = z
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

export type WsQuery = z.infer<typeof wsQuerySchema>;

export type UpgradeVerdict =
  | { ok: true; query: WsQuery }
  | { ok: false; status: number; message: string };

// Parses raw query params (e.g. from URLSearchParams) into a WsQuery, or a 400 verdict.
export const parseWsQuery = (params: URLSearchParams): UpgradeVerdict => {
  const parsed = wsQuerySchema.safeParse({
    v: params.get('v') ?? undefined,
    role: params.get('role') ?? undefined,
    serverId: params.get('serverId') ?? undefined,
    connectionId: params.get('connectionId') || undefined,
    ts: params.get('ts') || undefined,
    sig: params.get('sig') || undefined,
    pk: params.get('pk') || undefined,
  });
  if (!parsed.success) {
    return { ok: false, status: 400, message: 'Invalid query parameters' };
  }
  return { ok: true, query: parsed.data };
};

// Host roles carry a signed handshake; clients connect without relay-level auth in v1
// (E2EE gates actual access). An optional `grant` param is reserved and ignored in v1.
export const authenticateWsQuery = async (query: WsQuery): Promise<UpgradeVerdict> => {
  if (query.role === 'host-control' || query.role === 'host-data') {
    if (!query.ts || !query.sig || !query.pk) {
      return { ok: false, status: 401, message: 'Missing auth parameters' };
    }
    const ts = Number(query.ts);
    if (!isFreshTimestamp(ts)) {
      return { ok: false, status: 401, message: 'Signature expired' };
    }
    const jwk = parsePublicKeyParam(query.pk);
    if (!jwk) {
      return { ok: false, status: 403, message: 'Invalid public key' };
    }
    const expectedServerId = await deriveServerId(jwk);
    if (expectedServerId !== query.serverId) {
      return { ok: false, status: 403, message: 'serverId mismatch' };
    }
    const payload = buildSignaturePayload(ts, query.serverId, query.role, query.connectionId);
    const valid = await verifySignature(jwk, payload, query.sig);
    if (!valid) {
      return { ok: false, status: 403, message: 'Invalid signature' };
    }
  }
  return { ok: true, query };
};

// Convenience: parse + authenticate in one call.
export const validateWsUpgrade = async (params: URLSearchParams): Promise<UpgradeVerdict> => {
  const parsed = parseWsQuery(params);
  if (!parsed.ok) return parsed;
  return authenticateWsQuery(parsed.query);
};
