// File-backed store for encrypted shares — the Node counterpart of the Cloudflare
// ShareDurableObject + R2 pair. One directory holds, per share:
//
//   <id>.json  the record (src/core/share/state.ts): expiry, PIN gate, opens, at most one answer
//   <id>.blob  the page ciphertext
//
// Both hold ciphertext and hashes only; the relay never sees a key. Writes go to a temp file that
// is synced and renamed over the target, so a crash leaves the old file or the new one, never a
// torn one. Operations on one share run one at a time (a per-share queue, the analogue of the
// Durable Object's input gate), so two answers arriving together cannot both win.
//
// Expiry is checked on every read, and a sweep (unref'd timer) deletes pages past their deadline,
// purges shares past their tombstone, and removes blobs whose share was never created.

import { randomBytes } from 'node:crypto';
import { mkdir, open, readdir, readFile, rename, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { SHARE_ID_PATTERN } from '../core/share/limits';
import type { ShareBackend } from '../core/share/routes';
import {
  applyShareOp,
  hashAuth,
  shareWakeStep,
  type ShareOp,
  type ShareOpReply,
  type ShareRecord,
} from '../core/share/state';

// A blob or temp file without a record older than this is left over from a failed create.
const ORPHAN_AGE_MS = 60 * 60 * 1000;
export const SHARE_SWEEP_MS = 15 * 60 * 1000;

export type FileShareStore = {
  backend: ShareBackend;
  // One pass over the directory; resolves when done. Exposed for tests.
  sweep(): Promise<void>;
  close(): void;
};

export type FileShareStoreOptions = {
  dir: string;
  // Tells the owner's live host-control socket that one of its shares changed.
  nudge: (serverId: string, shareId: string) => void;
  sweepMs?: number;
};

const isMissing = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'ENOENT';

const assertId = (id: string): void => {
  // Ids become file names; the routes validate them already, this keeps the store safe on its own.
  if (!SHARE_ID_PATTERN.test(id)) throw new Error('invalid share id');
};

export const openFileShareStore = async ({ dir, nudge, sweepMs = SHARE_SWEEP_MS }: FileShareStoreOptions): Promise<FileShareStore> => {
  await mkdir(dir, { recursive: true, mode: 0o700 });

  const recordPath = (id: string) => join(dir, `${id}.json`);
  const blobPath = (id: string) => join(dir, `${id}.blob`);

  // Makes a rename in the directory durable. Some platforms cannot fsync a directory (EISDIR,
  // EPERM, EINVAL, ...); there the rename stands without it rather than failing the write.
  const syncDir = async (): Promise<void> => {
    let handle;
    try {
      handle = await open(dir, 'r');
      await handle.sync();
    } catch {
      // Unsupported here; nothing more to do.
    } finally {
      await handle?.close().catch(() => {});
    }
  };

  const writeAtomic = async (target: string, data: Uint8Array | string): Promise<void> => {
    const temp = join(dir, `.${randomBytes(8).toString('hex')}.tmp`);
    try {
      const handle = await open(temp, 'w', 0o600);
      try {
        await handle.writeFile(data);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(temp, target);
    } catch (error) {
      // Whatever step failed, the temp file goes; the caller sees the original error.
      await rm(temp, { force: true }).catch(() => {});
      throw error;
    }
    await syncDir();
  };

  const readRecord = async (id: string): Promise<ShareRecord | undefined> => {
    let text: string;
    try {
      text = await readFile(recordPath(id), 'utf8');
    } catch (error) {
      if (isMissing(error)) return undefined;
      throw error;
    }
    try {
      return JSON.parse(text) as ShareRecord;
    } catch {
      console.log(`[relay] share record unreadable shareId=${id}`);
      return undefined;
    }
  };

  const deleteBlob = (id: string) => rm(blobPath(id), { force: true });

  // Cleanup that must never fail the operation around it: a blob that cannot be deleted now is
  // retried by the sweep.
  const deleteBlobLater = async (id: string): Promise<void> => {
    try {
      await deleteBlob(id);
    } catch (error) {
      console.log(`[relay] share blob delete failed shareId=${id}, retrying on the next sweep: ${error instanceof Error ? error.message : 'unknown'}`);
    }
  };

  // Per-share queue: each operation starts after the previous one on the same share settles.
  const queues = new Map<string, Promise<void>>();
  const serialize = <T>(id: string, task: () => Promise<T>): Promise<T> => {
    const previous = queues.get(id) ?? Promise.resolve();
    const run = previous.then(task);
    const tail = run.then(() => {}, () => {});
    queues.set(id, tail);
    void tail.then(() => {
      if (queues.get(id) === tail) queues.delete(id);
    });
    return run;
  };

  // Applies what is due at `now` (the Cloudflare alarm's work). Returns the record still standing.
  const settle = async (record: ShareRecord, now: number): Promise<ShareRecord | undefined> => {
    const step = shareWakeStep(record, now);
    if (step.action === 'purge') {
      // A blob left behind here has no record anymore; the sweep removes it as an orphan.
      await deleteBlobLater(record.id);
      await rm(recordPath(record.id), { force: true });
      return undefined;
    }
    if (step.action === 'expire') await deleteBlobLater(record.id);
    return record;
  };

  const backend: ShareBackend = {
    putBlob: async (id, body) => {
      assertId(id);
      await writeAtomic(blobPath(id), new Uint8Array(body));
    },
    getBlob: async (id) => {
      assertId(id);
      // Open first: a close or expiry that deletes the file after this still lets the read finish.
      let handle;
      try {
        handle = await open(blobPath(id), 'r');
      } catch (error) {
        if (isMissing(error)) return null;
        throw error;
      }
      return Readable.toWeb(handle.createReadStream()) as unknown as ReadableStream<Uint8Array>;
    },
    deleteBlob: async (id) => {
      assertId(id);
      await deleteBlob(id);
    },
    op: (id: string, op: ShareOp, body?: Record<string, unknown>): Promise<ShareOpReply> => {
      assertId(id);
      return serialize(id, async () => {
        const authHash = typeof body?.auth === 'string' ? await hashAuth(body.auth) : null;
        const now = Date.now();
        const stored = await readRecord(id);
        const record = stored ? await settle(stored, now) : undefined;
        const outcome = applyShareOp(record, op, body ?? null, authHash, now);
        if (outcome.write) {
          await writeAtomic(recordPath(id), JSON.stringify(outcome.write));
          // A failed delete is retried by the sweep at purge time.
          if (outcome.deleteBlob) await deleteBlobLater(id);
          if (outcome.nudge) {
            try {
              nudge(outcome.write.serverId, id);
            } catch {
              // The host polls as well; a lost nudge only delays the update.
            }
          }
        }
        return { status: outcome.status, body: outcome.body };
      });
    },
  };

  const sweep = async (): Promise<void> => {
    let names: string[];
    try {
      names = await readdir(dir);
    } catch (error) {
      console.log(`[relay] share sweep failed: ${error instanceof Error ? error.message : 'unknown'}`);
      return;
    }
    const present = new Set(names);
    const now = Date.now();
    for (const name of names) {
      try {
        const match = /^([A-Za-z0-9_-]{22})\.(json|blob)$/.exec(name);
        if (match?.[2] === 'json') {
          const id = match[1];
          await serialize(id, async () => {
            const record = await readRecord(id);
            if (record) await settle(record, Date.now());
          });
          continue;
        }
        const orphanBlob = match?.[2] === 'blob' && !present.has(`${match[1]}.json`);
        if (orphanBlob || name.endsWith('.tmp')) {
          const info = await stat(join(dir, name));
          if (now - info.mtimeMs < ORPHAN_AGE_MS) continue;
          if (orphanBlob) {
            const id = match![1];
            await serialize(id, async () => {
              if (!(await readRecord(id))) await deleteBlob(id);
            });
          } else {
            await rm(join(dir, name), { force: true });
          }
        }
      } catch (error) {
        if (!isMissing(error)) {
          console.log(`[relay] share sweep failed for ${name}: ${error instanceof Error ? error.message : 'unknown'}`);
        }
      }
    }
  };

  let sweeping: Promise<void> | null = null;
  const runSweep = (): void => {
    if (sweeping) return;
    sweeping = sweep().finally(() => {
      sweeping = null;
    });
  };
  const timer = setInterval(runSweep, sweepMs);
  timer.unref();
  runSweep();

  return {
    backend,
    sweep: async () => {
      await sweeping;
      await sweep();
    },
    close: () => clearInterval(timer),
  };
};
