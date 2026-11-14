// The share state machine, shared by both adapters. One record per share holds expiry, the PIN
// gate, when it was opened and at most one encrypted answer; the page itself is a separate blob
// (R2 on Cloudflare, a file on Node). Everything here is a pure function over the record: the
// adapter reads the record, calls `applyShareOp`, writes back what it returns and then runs the
// side effects it names. The adapter must serialize ops per share (Durable Object input gate on
// Cloudflare, a per-share queue on Node), so two answers arriving together cannot both win.
//
// PRIVACY INVARIANT: nothing here ever sees a key. The browser proves the PIN with an `auth` value
// derived from the link key and the PIN; the record stores only SHA-256(auth).

import { MAX_PIN_FAILURES, MAX_RECORDED_OPENS, TOMBSTONE_MS, type ShareKind } from './limits';
import { base64UrlFromBytes } from '../relay-auth';

export type ShareStatus = 'open' | 'locked' | 'answered' | 'expired' | 'cancelled';

export type ShareRecord = {
  v: 1;
  id: string;
  serverId: string;
  kind: ShareKind;
  wantsAnswer: boolean;
  createdAt: number;
  expiresAt: number;
  purgeAt: number;
  authHash: string;
  pinFailures: number;
  locked: boolean;
  opens: number[];
  answer: string | null;
  answeredAt: number | null;
  // The host collected the answer (or the share was cancelled): the blob and answer are gone,
  // only this tombstone remains until purgeAt.
  closedAt: number | null;
  cancelled: boolean;
};

export type CreateShareInput = {
  id: string;
  serverId: string;
  kind: ShareKind;
  wantsAnswer: boolean;
  expiresAt: number;
  authHash: string;
};

// The operations a share route asks of the store. On Cloudflare they are the Durable Object's
// internal paths.
export const SHARE_OPS = ['/create', '/status', '/open', '/answer', '/host/state', '/host/close'] as const;
export type ShareOp = (typeof SHARE_OPS)[number];

export type ShareOpReply = { status: number; body: unknown };

export type ShareOpOutcome = ShareOpReply & {
  // Persist this record (create, or any change). Undefined: nothing to write.
  write?: ShareRecord;
  // Next time the store must look at this share again (expiry or purge).
  wakeAt?: number;
  // Tell the owner's live host-control socket that this share changed.
  nudge?: boolean;
  // Delete the page blob, after `write` is durable.
  deleteBlob?: boolean;
};

const base64UrlToBytes = (value: string): Uint8Array<ArrayBuffer> | null => {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  try {
    const binary = atob(normalized + pad);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
};

export const hashAuth = async (auth: string): Promise<string | null> => {
  const bytes = base64UrlToBytes(auth);
  if (!bytes || bytes.length !== 32) return null;
  return base64UrlFromBytes(await crypto.subtle.digest('SHA-256', bytes));
};

const sameString = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

export const shareStatus = (record: ShareRecord, now: number): ShareStatus => {
  if (record.cancelled) return 'cancelled';
  if (record.answeredAt !== null) return 'answered';
  if (now >= record.expiresAt) return 'expired';
  if (record.locked) return 'locked';
  return 'open';
};

// What anyone holding the link may learn before the PIN: nothing the page contains.
export const publicView = (record: ShareRecord, now: number) => ({
  status: shareStatus(record, now),
  kind: record.kind,
  wantsAnswer: record.wantsAnswer,
  expiresAt: record.expiresAt,
  answeredAt: record.answeredAt,
  attemptsLeft: Math.max(0, MAX_PIN_FAILURES - record.pinFailures),
});

// What the owning host sees.
export const hostView = (record: ShareRecord, now: number) => ({
  id: record.id,
  status: shareStatus(record, now),
  expiresAt: record.expiresAt,
  opens: record.opens,
  pinFailures: record.pinFailures,
  answer: record.answer,
  answeredAt: record.answeredAt,
  closed: record.closedAt !== null,
});

const reply = (status: number, body: unknown, extra: Omit<ShareOpOutcome, 'status' | 'body'> = {}): ShareOpOutcome => ({
  status,
  body,
  ...extra,
});

const create = (existing: ShareRecord | undefined, input: CreateShareInput | null, now: number): ShareOpOutcome => {
  if (!input) return reply(400, { error: 'invalid' });
  if (existing) return reply(409, { error: 'exists' });
  const record: ShareRecord = {
    v: 1,
    id: input.id,
    serverId: input.serverId,
    kind: input.kind,
    wantsAnswer: input.wantsAnswer,
    createdAt: now,
    expiresAt: input.expiresAt,
    purgeAt: input.expiresAt + TOMBSTONE_MS,
    authHash: input.authHash,
    pinFailures: 0,
    locked: false,
    opens: [],
    answer: null,
    answeredAt: null,
    closedAt: null,
    cancelled: false,
  };
  return reply(201, { ok: true }, { write: record, wakeAt: record.expiresAt });
};

// Checks the PIN proof and counts a failure. Returns null when the proof is right.
const checkAuth = (record: ShareRecord, hash: string | null, now: number): ShareOpOutcome | null => {
  const status = shareStatus(record, now);
  if (status !== 'open') {
    return reply(status === 'expired' ? 410 : status === 'locked' ? 423 : 409, publicView(record, now));
  }
  if (hash && sameString(hash, record.authHash)) return null;
  const next = { ...record, pinFailures: record.pinFailures + 1 };
  if (next.pinFailures >= MAX_PIN_FAILURES) next.locked = true;
  return reply(next.locked ? 423 : 403, { ...publicView(next, now), error: 'wrong-pin' }, { write: next });
};

const open = (record: ShareRecord, authHash: string | null, now: number): ShareOpOutcome => {
  const refused = checkAuth(record, authHash, now);
  if (refused) return refused;
  const next = { ...record, pinFailures: 0, opens: [...record.opens, now].slice(-MAX_RECORDED_OPENS) };
  return reply(200, { ok: true, ...publicView(next, now) }, { write: next, nudge: true });
};

const answer = (record: ShareRecord, body: Record<string, unknown> | null, authHash: string | null, now: number): ShareOpOutcome => {
  if (!record.wantsAnswer) return reply(400, { error: 'no-answer' });
  const refused = checkAuth(record, authHash, now);
  if (refused) return refused;
  if (typeof body?.answer !== 'string' || body.answer.length === 0) return reply(400, { error: 'invalid' });
  const next = { ...record, answer: body.answer, answeredAt: now };
  return reply(200, { ok: true, ...publicView(next, now) }, { write: next, nudge: true });
};

// The host collected the answer, or cancelled the share: drop the page and the answer, keep a
// tombstone so the link says it was answered or withdrawn instead of "not found".
const close = (record: ShareRecord, now: number): ShareOpOutcome => {
  // An answer that arrived after the host's last state read is handed over here, in the same
  // step that deletes it, so closing can never lose an answer the relay accepted.
  const collected = record.answer;
  if (record.closedAt !== null) return reply(200, { ...hostView(record, now), answer: collected });
  // The tombstone is written before the blob goes: requests the delete lets in must see the share
  // closed. A failed delete is retried at purgeAt.
  const next: ShareRecord = {
    ...record,
    answer: null,
    closedAt: now,
    // Closed before an answer arrived means the host withdrew it; no answer is taken after this.
    cancelled: record.answeredAt === null ? true : record.cancelled,
    purgeAt: Math.max(record.expiresAt, now) + TOMBSTONE_MS,
  };
  return reply(200, { ...hostView(next, now), answer: collected }, { write: next, wakeAt: next.purgeAt, deleteBlob: true });
};

// One operation on one share. `record` is the stored record (undefined when there is none),
// `authHash` the hash of the body's `auth` (computed by the caller before reading the record).
export const applyShareOp = (
  record: ShareRecord | undefined,
  op: string,
  body: Record<string, unknown> | null,
  authHash: string | null,
  now: number,
): ShareOpOutcome => {
  if (op === '/create') return create(record, body as CreateShareInput | null, now);
  if (!record) return reply(404, { status: 'missing' });
  switch (op) {
    case '/status':
      return reply(200, publicView(record, now));
    case '/open':
      return open(record, authHash, now);
    case '/answer':
      return answer(record, body, authHash, now);
    case '/host/state':
      if (body?.serverId !== record.serverId) return reply(403, { error: 'not-owner' });
      return reply(200, hostView(record, now));
    case '/host/close':
      if (body?.serverId !== record.serverId) return reply(403, { error: 'not-owner' });
      return close(record, now);
    default:
      return reply(404, { error: 'not-found' });
  }
};

// What the store does when a share's wake time comes (Durable Object alarm, Node sweep).
//   purge:  delete the blob and the record.
//   expire: delete the blob; an answer the host has not collected yet stays until purgeAt, so a
//           laptop that slept through the deadline still gets it. Look again at `wakeAt`.
//   wait:   nothing due yet; look again at `wakeAt`.
export type ShareWakeStep =
  | { action: 'purge' }
  | { action: 'expire'; wakeAt: number }
  | { action: 'wait'; wakeAt: number };

export const shareWakeStep = (record: ShareRecord, now: number): ShareWakeStep => {
  if (now >= record.purgeAt) return { action: 'purge' };
  if (now >= record.expiresAt) return { action: 'expire', wakeAt: record.purgeAt };
  return { action: 'wait', wakeAt: record.expiresAt };
};
