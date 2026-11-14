// Encrypted shares on both adapters. Every scenario runs against the Cloudflare adapter (the
// Worker with in-memory stand-ins for the Durable Object and R2 bindings) and the Node adapter
// (the shared routes over the file store in a temp directory). A last test drives the real Node
// server over HTTP, across a restart.

import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { after, describe, test } from 'node:test';
import cloudflareApp from '../src/cloudflare/index';
import { ShareDurableObject } from '../src/cloudflare/share-do';
import { MAX_PIN_FAILURES, TOMBSTONE_MS, shareBlobKey } from '../src/core/share/limits';
import { shareApp } from '../src/core/share/routes';
import type { ShareRecord } from '../src/core/share/state';
import { openFileShareStore } from '../src/node/share-store';
import {
  DOCUMENT,
  createShare,
  deriveKeys,
  jsonBody,
  makeHost,
  metaHeader,
  sealAnswer,
  unseal,
  type Fetcher,
} from './share-helpers';

type States = { states: Array<Record<string, unknown>> };

type Harness = {
  fetch: Fetcher;
  nudges: string[];
  hasBlob(id: string): Promise<boolean>;
  blobCount(): Promise<number>;
  record(id: string): Promise<ShareRecord | undefined>;
  // Runs what the store does when the share's wake time comes, with the clock at `now`.
  wake(id: string, now: number): Promise<void>;
  // Holds the next blob delete until the returned release is called.
  holdBlobDelete(): () => void;
  // Whether the harness serializes concurrent operations on one share the way production does.
  serializes: boolean;
  dispose(): Promise<void>;
};

const withClock = async <T>(now: number, run: () => Promise<T>): Promise<T> => {
  const realNow = Date.now;
  Date.now = () => now;
  try {
    return await run();
  } finally {
    Date.now = realNow;
  }
};

// In-memory stand-ins for the Cloudflare bindings. Each share object gets its own storage, the way
// one Durable Object per share does in production.
const cloudflareHarness = async (): Promise<Harness> => {
  const blobs = new Map<string, ArrayBuffer>();
  const objects = new Map<string, { object: ShareDurableObject; storage: Map<string, unknown>; alarm: number | null }>();
  const nudges: string[] = [];
  let deleteGate: Promise<void> | null = null;

  const bucket = {
    put: async (key: string, value: ArrayBuffer) => { blobs.set(key, value); },
    get: async (key: string) => {
      const value = blobs.get(key);
      return value ? { body: new Blob([value]).stream() } : null;
    },
    delete: async (key: string) => {
      const gate = deleteGate;
      deleteGate = null;
      if (gate) await gate;
      blobs.delete(key);
    },
  } as unknown as R2Bucket;

  const relay = {
    idFromName: (name: string) => name,
    get: () => ({
      fetch: async (_url: string, init: RequestInit) => {
        nudges.push((JSON.parse(String(init.body)) as { shareId: string }).shareId);
        return new Response(null, { status: 204 });
      },
    }),
  } as unknown as DurableObjectNamespace;

  const env: Record<string, unknown> = { SHARES: bucket, RELAY: relay, SHARE_ORIGIN: 'https://share.example.test' };
  const entry = (name: string) => {
    let found = objects.get(name);
    if (!found) {
      const storage = new Map<string, unknown>();
      const holder = { storage, alarm: null as number | null, object: undefined as unknown as ShareDurableObject };
      const state = {
        storage: {
          get: async (key: string) => storage.get(key),
          put: async (key: string, value: unknown) => { storage.set(key, structuredClone(value)); },
          delete: async (key: string) => storage.delete(key),
          deleteAll: async () => { storage.clear(); },
          getAlarm: async () => holder.alarm,
          setAlarm: async (at: number) => { holder.alarm = at; },
          deleteAlarm: async () => { holder.alarm = null; },
        },
      } as unknown as DurableObjectState;
      holder.object = new ShareDurableObject(state, env as never);
      found = holder;
      objects.set(name, found);
    }
    return found;
  };
  env.SHARE = {
    idFromName: (name: string) => name,
    get: (name: string) => ({ fetch: (url: string, init?: RequestInit) => entry(name).object.fetch(new Request(url, init)) }),
  } as unknown as DurableObjectNamespace;

  return {
    fetch: (request) => cloudflareApp.fetch(request, env),
    nudges,
    hasBlob: async (id) => blobs.has(shareBlobKey(id)),
    blobCount: async () => blobs.size,
    record: async (id) => objects.get(`share-v1:${id}`)?.storage.get('record') as ShareRecord | undefined,
    wake: async (id, now) => {
      const found = objects.get(`share-v1:${id}`);
      assert.ok(found, 'share object exists');
      // The alarm fires at the time it was set for; the test asks for a later one.
      assert.ok(found.alarm !== null && found.alarm <= now, 'an alarm is due');
      await withClock(now, () => found.object.alarm());
    },
    holdBlobDelete: () => {
      let release: () => void = () => {};
      deleteGate = new Promise<void>((resolve) => { release = resolve; });
      return release;
    },
    // The stand-in has no input gate; production relies on the Durable Object's.
    serializes: false,
    dispose: async () => {},
  };
};

const nodeHarness = async (): Promise<Harness> => {
  const dir = await mkdtemp(join(tmpdir(), 'relay-shares-'));
  const nudges: string[] = [];
  const store = await openFileShareStore({ dir, nudge: (_serverId, shareId) => nudges.push(shareId) });
  await store.sweep();
  const blobFiles = async () => (await readdir(dir)).filter((name) => name.endsWith('.blob'));
  return {
    fetch: (request) => Promise.resolve(shareApp.fetch(request, { shares: store.backend, SHARE_ORIGIN: 'https://share.example.test' })),
    nudges,
    hasBlob: async (id) => (await blobFiles()).includes(`${id}.blob`),
    blobCount: async () => (await blobFiles()).length,
    record: async (id) => {
      try {
        return JSON.parse(await readFile(join(dir, `${id}.json`), 'utf8')) as ShareRecord;
      } catch {
        return undefined;
      }
    },
    wake: (_id, now) => withClock(now, () => store.sweep()),
    // The close deletes the blob inside the per-share queue, so an answer waits for it anyway.
    holdBlobDelete: () => () => {},
    serializes: true,
    dispose: async () => {
      store.close();
      await rm(dir, { recursive: true, force: true });
    },
  };
};

const adapters: Array<[string, () => Promise<Harness>]> = [
  ['cloudflare', cloudflareHarness],
  ['node', nodeHarness],
];

for (const [name, makeHarness] of adapters) {
  describe(`encrypted shares (${name})`, () => {
    const setup = async (t: { after: (fn: () => Promise<void>) => void }) => {
      const harness = await makeHarness();
      t.after(() => harness.dispose());
      const browser = (path: string, body?: unknown) => harness.fetch(new Request('https://share.example.test' + path, body === undefined
        ? { method: 'GET' }
        : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }));
      const host = () => makeHost('https://relay.example.test', harness.fetch);
      return { harness, browser, host };
    };

    test('a share opens with the right PIN, takes one answer, and the host collects it', async (t) => {
      const { harness, browser, host: newHost } = await setup(t);
      const host = await newHost();
      const { response, keys } = await createShare(host);
      assert.equal(response.status, 201);
      const { id, url } = await response.json() as { id: string; url: string };
      assert.equal(url, `https://share.example.test/p/${id}`);
      assert.equal(await harness.hasBlob(id), true);

      const status = await (await browser(`/p/${id}/status`)).json() as Record<string, unknown>;
      assert.equal(status.status, 'open');
      assert.equal(status.kind, 'questionnaire');
      assert.equal(status.wantsAnswer, true);
      assert.equal(status.attemptsLeft, MAX_PIN_FAILURES);
      assert.ok(!JSON.stringify(status).includes('Migration'));

      const wrong = await deriveKeys(crypto.getRandomValues(new Uint8Array(32)), '000000');
      const refused = await browser(`/p/${id}/open`, { auth: wrong.auth });
      assert.equal(refused.status, 403);
      const refusedBody = await refused.json() as Record<string, unknown>;
      assert.equal(refusedBody.error, 'wrong-pin');
      assert.equal(refusedBody.attemptsLeft, MAX_PIN_FAILURES - 1);

      const opened = await browser(`/p/${id}/open`, { auth: keys.auth });
      assert.equal(opened.status, 200);
      assert.deepEqual(await unseal(keys.key, new Uint8Array(await opened.arrayBuffer()), 'openchamber-share-v1 document'), DOCUMENT);
      assert.deepEqual(harness.nudges, [id]);

      const answer = await sealAnswer(keys.key, { v: 1, data: { pick: 'B' }, summary: 'Picked B' });
      assert.equal((await browser(`/p/${id}/answer`, { auth: keys.auth, answer })).status, 200);
      assert.equal((await browser(`/p/${id}/answer`, { auth: keys.auth, answer })).status, 409);
      assert.equal((await browser(`/p/${id}/open`, { auth: keys.auth })).status, 409);
      assert.deepEqual(harness.nudges, [id, id]);

      const states = await (await host.call('POST', '/p/states', jsonBody({ ids: [id] }))).json() as States;
      assert.equal(states.states[0].id, id);
      assert.equal(states.states[0].status, 'answered');
      assert.equal(states.states[0].answer, answer);
      assert.equal(states.states[0].closed, false);
      assert.equal((states.states[0].opens as number[]).length, 1);

      const closed = await host.call('POST', `/p/${id}/close`, jsonBody({}));
      assert.equal(closed.status, 200);
      const closedBody = await closed.json() as Record<string, unknown>;
      assert.equal(closedBody.status, 'answered');
      assert.equal(closedBody.answer, answer);
      assert.equal(closedBody.closed, true);
      const afterClose = await (await host.call('POST', '/p/states', jsonBody({ ids: [id] }))).json() as States;
      assert.equal(afterClose.states[0].status, 'answered');
      assert.equal(afterClose.states[0].answer, null);
      assert.equal(afterClose.states[0].closed, true);
      assert.equal(await harness.hasBlob(id), false);
      assert.equal((await (await browser(`/p/${id}/status`)).json() as Record<string, unknown>).status, 'answered');
    });

    test('five wrong PINs lock the link, and the right PIN no longer opens it', async (t) => {
      const { browser, host: newHost } = await setup(t);
      const host = await newHost();
      const { response, keys } = await createShare(host);
      const { id } = await response.json() as { id: string };
      const wrong = await deriveKeys(crypto.getRandomValues(new Uint8Array(32)), '111111');
      for (let i = 1; i < MAX_PIN_FAILURES; i += 1) {
        assert.equal((await browser(`/p/${id}/open`, { auth: wrong.auth })).status, 403);
      }
      const last = await browser(`/p/${id}/open`, { auth: wrong.auth });
      assert.equal(last.status, 423);
      const lastBody = await last.json() as Record<string, unknown>;
      assert.equal(lastBody.status, 'locked');
      assert.equal(lastBody.attemptsLeft, 0);
      assert.equal((await browser(`/p/${id}/open`, { auth: keys.auth })).status, 423);
    });

    test('another server cannot read or close a share', async (t) => {
      const { harness, host: newHost } = await setup(t);
      const owner = await newHost();
      const stranger = await newHost();
      const { response } = await createShare(owner);
      const { id } = await response.json() as { id: string };
      const states = await (await stranger.call('POST', '/p/states', jsonBody({ ids: [id] }))).json() as States;
      assert.deepEqual(states.states[0], { id, status: 'unavailable' });
      assert.equal((await stranger.call('POST', `/p/${id}/close`, jsonBody({}))).status, 403);
      assert.equal(await harness.hasBlob(id), true);
      const missing = await (await owner.call('POST', '/p/states', jsonBody({ ids: ['B'.repeat(22)] }))).json() as States;
      assert.deepEqual(missing.states[0], { id: 'B'.repeat(22), status: 'missing' });
    });

    test('a signature over different metadata or a stale timestamp is refused', async (t) => {
      const { harness, host: newHost } = await setup(t);
      const host = await newHost();
      const meta = metaHeader({ kind: 'page', wantsAnswer: false, expiresAt: Date.now() + 3_600_000, authHash: 'A'.repeat(43) });
      const swapped = await host.call('POST', '/p', new Uint8Array([1, 2, 3]).buffer, meta, (headers) => {
        headers['x-openchamber-share'] = metaHeader({ kind: 'page', wantsAnswer: true, expiresAt: Date.now() + 3_600_000, authHash: 'A'.repeat(43) });
      });
      assert.equal(swapped.status, 403);
      const stale = await host.call('POST', '/p', new Uint8Array([1, 2, 3]).buffer, meta, (headers) => {
        headers['x-openchamber-ts'] = String(Date.now() - 10 * 60_000);
      });
      assert.equal(stale.status, 401);
      assert.equal(await harness.blobCount(), 0);
    });

    test('an expiry beyond the limit is refused', async (t) => {
      const { harness, host: newHost } = await setup(t);
      const host = await newHost();
      const { response } = await createShare(host, { expiresAt: Date.now() + 30 * 86_400_000 });
      assert.equal(response.status, 400);
      assert.equal(await harness.blobCount(), 0);
    });

    test('expiry drops the page, keeps an uncollected answer for the host, then purges everything', async (t) => {
      const { harness, browser, host: newHost } = await setup(t);
      const host = await newHost();
      const { response, keys } = await createShare(host);
      const { id } = await response.json() as { id: string };
      const answer = await sealAnswer(keys.key, { v: 1, data: null, summary: 'ok' });
      assert.equal((await browser(`/p/${id}/answer`, { auth: keys.auth, answer })).status, 200);
      const record = await harness.record(id);
      assert.ok(record);
      assert.equal(record.purgeAt, record.expiresAt + TOMBSTONE_MS);

      await harness.wake(id, record.expiresAt + 1);
      assert.equal(await harness.hasBlob(id), false);
      const states = await withClock(record.expiresAt + 1, async () =>
        (await (await host.call('POST', '/p/states', jsonBody({ ids: [id] }))).json()) as States);
      assert.equal(states.states[0].status, 'answered');
      assert.equal(states.states[0].answer, answer);

      await harness.wake(id, record.purgeAt + 1);
      assert.equal(await harness.record(id), undefined);
      const gone = await withClock(record.purgeAt + 1, () => browser(`/p/${id}/status`));
      assert.equal(gone.status, 404);
    });

    test('an expired page cannot be opened even before the store wakes', async (t) => {
      const { browser, host: newHost } = await setup(t);
      const host = await newHost();
      const { response, keys } = await createShare(host);
      const { id, expiresAt } = await response.json() as { id: string; expiresAt: number };
      const opened = await withClock(expiresAt + 1, () => browser(`/p/${id}/open`, { auth: keys.auth }));
      assert.equal(opened.status, 410);
      assert.equal((await opened.json() as Record<string, unknown>).status, 'expired');
    });

    test('the viewer is served with a policy that keeps the page from reaching other hosts', async (t) => {
      const { browser } = await setup(t);
      const response = await browser('/p/AAAAAAAAAAAAAAAAAAAAAA');
      assert.equal(response.status, 200);
      const csp = response.headers.get('content-security-policy') ?? '';
      assert.ok(csp.includes("connect-src 'self'"));
      assert.ok(csp.includes("frame-src 'none'"));
      assert.ok(csp.includes("form-action 'none'"));
      assert.ok(csp.includes("frame-ancestors 'none'"));
      assert.equal(response.headers.get('x-frame-options'), 'DENY');
      const html = await response.text();
      assert.ok(html.includes('sandbox="allow-scripts allow-forms"'));
      assert.ok(!html.includes('__STRINGS__'));
    });

    test('an answer that arrives while the host closes the share is never silently dropped', async (t) => {
      const { harness, browser, host: newHost } = await setup(t);
      const host = await newHost();
      const { response, keys } = await createShare(host);
      const { id } = await response.json() as { id: string };
      // Hold the blob delete open, the way slow outside I/O lets other requests in.
      const release = harness.holdBlobDelete();
      const closing = host.call('POST', `/p/${id}/close`, jsonBody({}));
      await sleep(10);
      const answer = await sealAnswer(keys.key, { v: 1, data: null, summary: 'late' });
      const late = browser(`/p/${id}/answer`, { auth: keys.auth, answer });
      await sleep(10);
      release();
      const [closed, lateResponse] = await Promise.all([closing, late]);
      const closedBody = await closed.json() as Record<string, unknown>;
      if (lateResponse.status === 200) {
        // The answer won the race: the close handed it over.
        assert.equal(closedBody.answer, answer);
      } else {
        assert.equal(lateResponse.status, 409);
        assert.equal((await (await browser(`/p/${id}/status`)).json() as Record<string, unknown>).status, 'cancelled');
      }
    });

    test('two answers arriving together: exactly one wins', async (t) => {
      const { harness, browser, host: newHost } = await setup(t);
      if (!harness.serializes) {
        t.skip('the Durable Object input gate is not modelled by the stand-in');
        return;
      }
      const host = await newHost();
      const { response, keys } = await createShare(host);
      const { id } = await response.json() as { id: string };
      const answers = await Promise.all(['A', 'B', 'C'].map(async (pick) =>
        browser(`/p/${id}/answer`, { auth: keys.auth, answer: await sealAnswer(keys.key, { v: 1, data: { pick }, summary: pick }) })));
      assert.deepEqual(answers.map((r) => r.status).sort(), [200, 409, 409]);
    });

    test('browser calls must be JSON and small', async (t) => {
      const { harness, host: newHost } = await setup(t);
      const host = await newHost();
      const { response, keys } = await createShare(host);
      const { id } = await response.json() as { id: string };
      const plain = await harness.fetch(new Request(`https://share.example.test/p/${id}/open`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: JSON.stringify({ auth: keys.auth }) }));
      assert.equal(plain.status, 415);
      const huge = await harness.fetch(new Request(`https://share.example.test/p/${id}/answer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ auth: keys.auth, answer: 'A'.repeat(200 * 1024) }) }));
      assert.equal(huge.status, 413);
    });
  });
}

describe('Node share store under failing disk operations', () => {
  const openStore = async (t: { after: (fn: () => Promise<void>) => void }) => {
    const dir = await mkdtemp(join(tmpdir(), 'relay-shares-fail-'));
    const store = await openFileShareStore({ dir, nudge: () => {} });
    await store.sweep();
    t.after(async () => {
      store.close();
      await rm(dir, { recursive: true, force: true });
    });
    const fetcher: Fetcher = (request) => Promise.resolve(shareApp.fetch(request, { shares: store.backend }));
    return { dir, store, fetcher };
  };

  test('a failed write removes its temp file and reports the original error', async (t) => {
    const { dir, store } = await openStore(t);
    const id = 'C'.repeat(22);
    // A non-empty directory where the blob goes makes the rename fail.
    await mkdir(join(dir, `${id}.blob`));
    await writeFile(join(dir, `${id}.blob`, 'keep'), 'x');
    await assert.rejects(
      store.backend.putBlob(id, new Uint8Array([1, 2, 3]).buffer),
      (error: NodeJS.ErrnoException) => typeof error.code === 'string' && error.syscall === 'rename',
    );
    assert.deepEqual((await readdir(dir)).filter((name) => name.endsWith('.tmp')), []);
  });

  test('an expired page that cannot be deleted still leaves the answer readable', async (t) => {
    const { dir, store, fetcher } = await openStore(t);
    const host = await makeHost('https://relay.example.test', fetcher);
    const { response, keys } = await createShare(host);
    const { id, expiresAt } = await response.json() as { id: string; expiresAt: number };
    const answer = await sealAnswer(keys.key, { v: 1, data: null, summary: 'ok' });
    const answered = await fetcher(new Request(`https://relay.example.test/p/${id}/answer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ auth: keys.auth, answer }) }));
    assert.equal(answered.status, 200);
    // Replace the blob with a non-empty directory: deleting it fails from now on.
    await rm(join(dir, `${id}.blob`));
    await mkdir(join(dir, `${id}.blob`));
    await writeFile(join(dir, `${id}.blob`, 'keep'), 'x');

    const states = await withClock(expiresAt + 1, async () => {
      await store.sweep();
      return (await (await host.call('POST', '/p/states', jsonBody({ ids: [id] }))).json()) as States;
    });
    assert.equal(states.states[0].status, 'answered');
    assert.equal(states.states[0].answer, answer);

    // Once the disk recovers, the sweep finishes the cleanup.
    await rm(join(dir, `${id}.blob`), { recursive: true });
    await writeFile(join(dir, `${id}.blob`), 'ciphertext');
    await withClock(expiresAt + 1, () => store.sweep());
    assert.ok(!(await readdir(dir)).includes(`${id}.blob`));
  });
});

// ---------------------------------------------------------------------------
// The real Node server: HTTP bridge, streamed limits, and shares surviving a restart.
// ---------------------------------------------------------------------------

const freePort = (): Promise<number> => new Promise((resolve, reject) => {
  const probe = createServer();
  probe.once('error', reject);
  probe.listen(0, '127.0.0.1', () => {
    const address = probe.address();
    probe.close(() => resolve(typeof address === 'object' && address ? address.port : 0));
  });
});

const startServer = async (port: number, shareDir: string): Promise<ChildProcess> => {
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/node/server.ts'], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', RELAY_SHARE_DIR: shareDir, RELAY_USAGE_DB: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  for (let i = 0; i < 100; i += 1) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) return child;
    } catch {
      // not up yet
    }
    await sleep(100);
  }
  child.kill();
  throw new Error('node relay did not start');
};

const stopServer = (child: ChildProcess): Promise<void> => new Promise((resolve) => {
  if (child.exitCode !== null) return resolve();
  child.once('exit', () => resolve());
  child.kill('SIGTERM');
});

describe('encrypted shares over the Node server', () => {
  let child: ChildProcess | null = null;
  let shareDir = '';
  after(async () => {
    if (child) await stopServer(child);
    if (shareDir) await rm(shareDir, { recursive: true, force: true });
  });

  test('round trip over HTTP, oversized uploads refused, shares survive a restart', async () => {
    shareDir = await mkdtemp(join(tmpdir(), 'relay-shares-http-'));
    const port = await freePort();
    const base = `http://127.0.0.1:${port}`;
    child = await startServer(port, shareDir);

    const host = await makeHost(base, (request) => fetch(request));
    const { response, keys } = await createShare(host);
    assert.equal(response.status, 201);
    const { id, url } = await response.json() as { id: string; url: string };
    assert.equal(url, `${base}/p/${id}`);

    // Behind a TLS-terminating proxy the link carries the public scheme and host.
    const proxied = await createShare(await makeHost(base, (request) => {
      const headers = new Headers(request.headers);
      headers.set('x-forwarded-proto', 'https');
      headers.set('x-forwarded-host', 'relay.example.com');
      return fetch(new Request(request, { headers }));
    }));
    assert.match((await proxied.response.json() as { url: string }).url, /^https:\/\/relay\.example\.com\/p\//);

    // Declared too large: refused before the body is read.
    const declared = await new Promise<number>((resolve, reject) => {
      const request = httpRequest(`${base}/p`, { method: 'POST', headers: { 'content-length': String(40 * 1024 * 1024) } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      request.on('error', reject);
      request.write(new Uint8Array(16));
    });
    assert.equal(declared, 413);
    // Streamed past the limit without a length: the read stops at the cap.
    const chunk = new Uint8Array(1024 * 1024);
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent >= 40) return controller.close();
        sent += 1;
        controller.enqueue(chunk);
      },
    });
    const streamed = await fetch(`${base}/p`, { method: 'POST', body: stream, duplex: 'half' } as RequestInit);
    assert.equal(streamed.status, 413);
    assert.ok((await fetch(`${base}/health`)).ok, 'relay healthy after oversized uploads');
    assert.equal((await readdir(shareDir)).filter((name) => name.endsWith('.blob')).length, 2);

    const viewer = await fetch(`${base}/p/${id}`);
    assert.equal(viewer.status, 200);
    assert.ok((viewer.headers.get('content-security-policy') ?? '').includes("frame-ancestors 'none'"));
    assert.equal(viewer.headers.get('cache-control'), 'no-store');

    await stopServer(child);
    child = await startServer(port, shareDir);

    const status = await (await fetch(`${base}/p/${id}/status`)).json() as Record<string, unknown>;
    assert.equal(status.status, 'open');
    const opened = await fetch(`${base}/p/${id}/open`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ auth: keys.auth }) });
    assert.equal(opened.status, 200);
    assert.deepEqual(await unseal(keys.key, new Uint8Array(await opened.arrayBuffer()), 'openchamber-share-v1 document'), DOCUMENT);
    const answer = await sealAnswer(keys.key, { v: 1, data: { ok: true }, summary: 'ok' });
    const answered = await fetch(`${base}/p/${id}/answer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ auth: keys.auth, answer }) });
    assert.equal(answered.status, 200);
    const closed = await (await host.call('POST', `/p/${id}/close`, jsonBody({}))).json() as Record<string, unknown>;
    assert.equal(closed.answer, answer);
    assert.ok(!(await readdir(shareDir)).includes(`${id}.blob`));
  });
});
