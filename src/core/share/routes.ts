// HTTP routes for encrypted shares, shared by both adapters. Two audiences:
//
// - The owning host (an OpenChamber server) creates shares, reads their state and closes them.
//   Every host call is signed with the same ECDSA identity the host uses for relay WebSockets;
//   the headers carry `ts`, `sig` and `pk`, and the signature covers method, path, body hash and
//   the metadata header (`buildSharePayload`).
// - A browser opens `/p/:id#<key>`: it gets the viewer, proves the PIN with a value derived from
//   the key and the PIN, receives ciphertext and posts an encrypted answer. No session, no cookie.
//
// Storage is the adapter's: a `ShareBackend` keeps the page blob and runs the state machine
// (state.ts) one operation at a time per share. Each adapter calls `shareApp.fetch(request,
// { shares, SHARE_ORIGIN })` for paths under /p.

import { Hono, type Context } from 'hono';
import { z } from 'zod';
import {
  base64UrlFromBytes,
  buildSharePayload,
  deriveServerId,
  isFreshTimestamp,
  parsePublicKeyParam,
  verifySignature,
} from '../relay-auth';
import {
  MAX_ANSWER_CHARS,
  MAX_SHARE_BYTES,
  MAX_SHARE_LIFETIME_MS,
  MAX_STATE_BATCH,
  MIN_SHARE_LIFETIME_MS,
  SHARE_ID_PATTERN,
  SHARE_KINDS,
} from './limits';
import type { ShareOp, ShareOpReply } from './state';
import { VIEWER_HTML } from './viewer';

export type ShareBackend = {
  putBlob(id: string, body: ArrayBuffer): Promise<void>;
  // The page ciphertext, or null when it is gone.
  getBlob(id: string): Promise<ReadableStream<Uint8Array> | ArrayBuffer | null>;
  deleteBlob(id: string): Promise<void>;
  // Runs one state-machine operation on one share, serialized with every other one on it.
  op(id: string, op: ShareOp, body?: Record<string, unknown>): Promise<ShareOpReply>;
};

export type ShareBindings = {
  shares: ShareBackend;
  // Public origin for share links, e.g. https://share.example.com. Without it links use the
  // origin the host called.
  SHARE_ORIGIN?: string;
};

const HEADER_TS = 'x-openchamber-ts';
const HEADER_SIG = 'x-openchamber-sig';
const HEADER_PK = 'x-openchamber-pk';
const HEADER_META = 'x-openchamber-share';

const metaSchema = z.object({
  kind: z.enum(SHARE_KINDS),
  wantsAnswer: z.boolean(),
  expiresAt: z.number().int(),
  authHash: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});

const authSchema = z.object({ auth: z.string().regex(/^[A-Za-z0-9_-]{43}$/) });
const answerSchema = authSchema.extend({
  answer: z.string().regex(/^[A-Za-z0-9_-]+$/).max(MAX_ANSWER_CHARS),
});
const statesSchema = z.object({
  ids: z.array(z.string().regex(SHARE_ID_PATTERN)).min(1).max(MAX_STATE_BATCH),
});

// Request bodies are read with a cap before anything is parsed or hashed, so an oversized body is
// refused without being buffered whole.
const MAX_AUTH_BODY = 1024;
const MAX_ANSWER_BODY = MAX_ANSWER_CHARS + 1024;
const MAX_HOST_JSON_BODY = 16 * 1024;

type ShareContext = Context<{ Bindings: ShareBindings }>;

const sha256 = async (bytes: ArrayBuffer): Promise<string> =>
  base64UrlFromBytes(await crypto.subtle.digest('SHA-256', bytes));

const decodeBase64UrlText = (value: string): string | null => {
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
    const binary = atob(normalized + pad);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
};

const newShareId = (): string => base64UrlFromBytes(crypto.getRandomValues(new Uint8Array(16)).buffer);

const replyJson = ({ status, body }: ShareOpReply): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });

// Verifies a signed host call and returns the caller's serverId, or a refusal.
const verifyHost = async (
  c: ShareContext,
  body: ArrayBuffer,
): Promise<{ serverId: string } | Response> => {
  const ts = Number(c.req.header(HEADER_TS));
  const sig = c.req.header(HEADER_SIG);
  const pk = c.req.header(HEADER_PK);
  if (!sig || !pk || !Number.isFinite(ts)) return c.text('Missing auth headers', 401);
  if (!isFreshTimestamp(ts)) return c.text('Signature expired', 401);
  const jwk = parsePublicKeyParam(pk);
  if (!jwk) return c.text('Invalid public key', 403);
  const serverId = await deriveServerId(jwk);
  const path = new URL(c.req.url).pathname;
  const payload = buildSharePayload(ts, serverId, c.req.method, path, await sha256(body), c.req.header(HEADER_META) ?? '');
  if (!(await verifySignature(jwk, payload, sig))) return c.text('Invalid signature', 403);
  return { serverId };
};

export const readLimited = async (request: Request, max: number): Promise<ArrayBuffer | null> => {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > max) return null;
  if (!request.body) return new ArrayBuffer(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out.buffer;
};

// Browser calls must be JSON: a page can send text/plain without a CORS preflight, JSON it cannot.
const isJsonRequest = (c: ShareContext): boolean =>
  (c.req.header('content-type') ?? '').split(';')[0].trim().toLowerCase() === 'application/json';

const readJson = (body: ArrayBuffer): unknown => {
  try {
    return JSON.parse(new TextDecoder().decode(body));
  } catch {
    return null;
  }
};

export const VIEWER_SECURITY_HEADERS = {
  // The decrypted page runs in a sandboxed srcdoc frame, which inherits this policy, and the viewer
  // adds a stricter one inside the page with connect-src 'none' (viewer.ts, DOC_CSP). The page can
  // draw with inline script, styles and data: images; it cannot make requests, submit a form, or
  // navigate its frame (frame-src 'none' still allows the srcdoc). Answers leave only through the
  // viewer, to this relay.
  'content-security-policy': [
    "default-src 'none'",
    "script-src 'unsafe-inline'",
    "style-src 'unsafe-inline'",
    'img-src data: blob:',
    'font-src data:',
    'media-src data: blob:',
    "connect-src 'self'",
    "frame-src 'none'",
    "form-action 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join('; '),
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
};

export const shareApp = new Hono<{ Bindings: ShareBindings }>();

// Host: create a share. Body is the encrypted document; metadata travels in a signed header.
shareApp.post('/p', async (c) => {
  const body = await readLimited(c.req.raw, MAX_SHARE_BYTES);
  if (!body) return c.text('Share too large', 413);
  if (body.byteLength === 0) return c.text('Empty share', 400);

  const host = await verifyHost(c, body);
  if (host instanceof Response) return host;

  const metaText = decodeBase64UrlText(c.req.header(HEADER_META) ?? '');
  const meta = metaSchema.safeParse(metaText ? readJson(new TextEncoder().encode(metaText).buffer) : null);
  if (!meta.success) return c.text('Invalid share metadata', 400);
  const now = Date.now();
  if (meta.data.expiresAt < now + MIN_SHARE_LIFETIME_MS || meta.data.expiresAt > now + MAX_SHARE_LIFETIME_MS) {
    return c.text('Invalid expiry', 400);
  }

  const { shares } = c.env;
  const id = newShareId();
  await shares.putBlob(id, body);
  // Without a record nothing ever deletes the blob, so a failed create removes it here. On
  // Cloudflare a blob this misses is caught by the bucket's lifecycle rule (README).
  const created = await shares.op(id, '/create', { id, serverId: host.serverId, ...meta.data }).catch(() => null);
  if (created?.status !== 201) {
    await shares.deleteBlob(id).catch(() => {});
    return c.text('Could not create share', 503);
  }
  const origin = (c.env.SHARE_ORIGIN || new URL(c.req.url).origin).replace(/\/+$/, '');
  return c.json({ id, url: `${origin}/p/${id}`, expiresAt: meta.data.expiresAt }, 201);
});

// Host: state of several shares in one call, so polling costs one request.
shareApp.post('/p/states', async (c) => {
  const body = await readLimited(c.req.raw, MAX_HOST_JSON_BODY);
  if (!body) return c.text('Body too large', 413);
  const host = await verifyHost(c, body);
  if (host instanceof Response) return host;
  const parsed = statesSchema.safeParse(readJson(body));
  if (!parsed.success) return c.text('Invalid ids', 400);
  const states = await Promise.all(parsed.data.ids.map(async (id) => {
    const response = await c.env.shares.op(id, '/host/state', { serverId: host.serverId }).catch(() => null);
    if (response?.status === 404) return { id, status: 'missing' };
    if (!response || response.status < 200 || response.status >= 300) return { id, status: 'unavailable' };
    return response.body;
  }));
  return c.json({ states });
});

// Host: answer collected, or the share withdrawn. Deletes the page and the answer; a share closed
// before it was answered reads as withdrawn. The body is ignored.
shareApp.post('/p/:id/close', async (c) => {
  const id = c.req.param('id');
  if (!SHARE_ID_PATTERN.test(id)) return c.text('Invalid id', 400);
  const body = await readLimited(c.req.raw, MAX_HOST_JSON_BODY);
  if (!body) return c.text('Body too large', 413);
  const host = await verifyHost(c, body);
  if (host instanceof Response) return host;
  return replyJson(await c.env.shares.op(id, '/host/close', { serverId: host.serverId }));
});

// Browser: the viewer. It reads the key from the fragment, which never reaches this server.
shareApp.get('/p/:id', () => new Response(VIEWER_HTML, {
  headers: { 'content-type': 'text/html; charset=utf-8', ...VIEWER_SECURITY_HEADERS },
}));

shareApp.get('/p/:id/status', async (c) => {
  const id = c.req.param('id');
  if (!SHARE_ID_PATTERN.test(id)) return c.json({ status: 'missing' }, 404);
  return replyJson(await c.env.shares.op(id, '/status'));
});

// Browser: PIN proof in, ciphertext out.
shareApp.post('/p/:id/open', async (c) => {
  const id = c.req.param('id');
  if (!SHARE_ID_PATTERN.test(id)) return c.json({ status: 'missing' }, 404);
  if (!isJsonRequest(c)) return c.json({ error: 'invalid' }, 415);
  const body = await readLimited(c.req.raw, MAX_AUTH_BODY);
  if (!body) return c.json({ error: 'invalid' }, 413);
  const parsed = authSchema.safeParse(readJson(body));
  if (!parsed.success) return c.json({ error: 'invalid' }, 400);
  const opened = await c.env.shares.op(id, '/open', parsed.data);
  if (opened.status < 200 || opened.status >= 300) return replyJson(opened);
  const blob = await c.env.shares.getBlob(id);
  if (!blob) return c.json({ status: 'expired' }, 410);
  return new Response(blob, {
    headers: { 'content-type': 'application/octet-stream', 'cache-control': 'no-store' },
  });
});

// Browser: encrypted answer in. One per share.
shareApp.post('/p/:id/answer', async (c) => {
  const id = c.req.param('id');
  if (!SHARE_ID_PATTERN.test(id)) return c.json({ status: 'missing' }, 404);
  if (!isJsonRequest(c)) return c.json({ error: 'invalid' }, 415);
  const body = await readLimited(c.req.raw, MAX_ANSWER_BODY);
  if (!body) return c.json({ error: 'invalid' }, 413);
  const parsed = answerSchema.safeParse(readJson(body));
  if (!parsed.success) return c.json({ error: 'invalid' }, 400);
  return replyJson(await c.env.shares.op(id, '/answer', parsed.data));
});

// Paths this module serves; adapters route only these here.
export const isSharePath = (pathname: string): boolean => pathname === '/p' || pathname.startsWith('/p/');
