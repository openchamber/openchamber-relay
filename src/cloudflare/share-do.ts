// ShareDurableObject: one instance per share ("share-v1:{shareId}"), the Cloudflare store for
// encrypted shares. The record and its state machine are src/core/share/state.ts; the page
// ciphertext is in R2 (`shares/{shareId}`).
//
// Atomicity: every handler reads the record, decides and writes it back with no other I/O in
// between, so the object's input gate serializes them. Two answers arriving together cannot both
// win. Outside I/O (the R2 delete, the host nudge) runs only after the write.

import { SHARE_STATE_PATH, shareBlobKey, shareObjectName } from '../core/share/limits';
import type { ShareBackend } from '../core/share/routes';
import {
  applyShareOp,
  hashAuth,
  shareWakeStep,
  type ShareOp,
  type ShareOpReply,
  type ShareRecord,
} from '../core/share/state';

export type ShareEnv = {
  SHARES: R2Bucket;
  RELAY: DurableObjectNamespace;
};

const KEY_RECORD = 'record';

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

export class ShareDurableObject implements DurableObject {
  private readonly state: DurableObjectState;
  private readonly env: ShareEnv;

  constructor(state: DurableObjectState, env: ShareEnv) {
    this.state = state;
    this.env = env;
  }

  private read(): Promise<ShareRecord | undefined> {
    return this.state.storage.get<ShareRecord>(KEY_RECORD);
  }

  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);
    const body = request.method === 'POST' ? ((await request.json().catch(() => null)) as Record<string, unknown> | null) : null;
    // Hash the PIN proof before reading the record: from the read to the write a handler awaits
    // only storage, which keeps the input gate closed, so concurrent answers cannot interleave.
    const authHash = typeof body?.auth === 'string' ? await hashAuth(body.auth) : null;
    const now = Date.now();

    const outcome = applyShareOp(await this.read(), pathname, body, authHash, now);
    if (outcome.write) {
      await this.state.storage.put(KEY_RECORD, outcome.write);
      if (outcome.wakeAt !== undefined) await this.state.storage.setAlarm(outcome.wakeAt);
      if (outcome.deleteBlob) await this.env.SHARES.delete(shareBlobKey(outcome.write.id)).catch(() => {});
      if (outcome.nudge) await this.nudgeHost(outcome.write);
    }
    return json(outcome.body, outcome.status);
  }

  async alarm(): Promise<void> {
    const record = await this.read();
    if (!record) return;
    const step = shareWakeStep(record, Date.now());
    if (step.action === 'purge') {
      await this.env.SHARES.delete(shareBlobKey(record.id));
      await this.state.storage.deleteAll();
      return;
    }
    if (step.action === 'expire') await this.env.SHARES.delete(shareBlobKey(record.id));
    await this.state.storage.setAlarm(step.wakeAt);
  }

  private async nudgeHost(record: ShareRecord): Promise<void> {
    try {
      const stub = this.env.RELAY.get(this.env.RELAY.idFromName(`relay-v1:${record.serverId}`));
      await stub.fetch(`https://relay.internal${SHARE_STATE_PATH}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ shareId: record.id }),
      });
    } catch {
      // The host polls as well; a lost nudge only delays the update.
    }
  }
}

// The share routes' store on Cloudflare: blobs in R2, records in one Durable Object per share.
export const cloudflareShareBackend = (env: { SHARE: DurableObjectNamespace; SHARES: R2Bucket }): ShareBackend => ({
  putBlob: async (id, body) => {
    await env.SHARES.put(shareBlobKey(id), body);
  },
  getBlob: async (id) => (await env.SHARES.get(shareBlobKey(id)))?.body ?? null,
  deleteBlob: async (id) => {
    await env.SHARES.delete(shareBlobKey(id));
  },
  op: async (id: string, op: ShareOp, body?: Record<string, unknown>): Promise<ShareOpReply> => {
    const stub = env.SHARE.get(env.SHARE.idFromName(shareObjectName(id)));
    const response = await stub.fetch(`https://share.internal${op}`, body === undefined
      ? { method: 'GET' }
      : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  },
});
