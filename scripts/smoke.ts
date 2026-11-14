// Smoke test for either relay adapter. Run against a local server:
//
//   npm run dev                          # terminal 1 (or npm run dev:node)
//   npm run smoke                        # terminal 2
//
// Override the target with RELAY_URL=ws://127.0.0.1:8788 (no path).
//
// Simulates a host (control + data sockets, real ECDSA P-256 WebCrypto signing) and a client:
// - auth rejection with a garbage signature
// - `sync` on control connect and `connected` notification when a client arrives
// - frames buffered while host-data is absent, flushed in order when it attaches
// - bidirectional verbatim forwarding of text and binary frames
// - clean close propagation (client close -> host-data close + `disconnected` on control)
// Like the OpenChamber apps, every simulated socket closes itself on a `relay-retire` frame, which
// the Cloudflare adapter sends instead of a close, and reports the frame's code as its close code.
// Runs all four combinations of legacy/current host and client metadata.
//
// Then an encrypted share round trip: signed create, viewer, status, wrong PIN, open (with the
// `share-state` nudge on host-control), answer, batched states, close.

import {
  DOCUMENT,
  createShare,
  deriveKeys,
  jsonBody,
  makeHost,
  sealAnswer,
  unseal,
} from './share-helpers';

const BASE = process.env.RELAY_URL ?? 'ws://127.0.0.1:8788';
const HTTP_BASE = BASE.replace(/^ws/, 'http');

const b64url = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const textToB64url = (text: string): string => b64url(new TextEncoder().encode(text).buffer as ArrayBuffer);

type Jwk = { kty: string; crv: string; x: string; y: string };

const deriveServerId = async (jwk: Jwk): Promise<string> => {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return b64url(digest);
};

const generateHostKeys = async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Jwk;
  const publicJwk: Jwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  return { privateKey: pair.privateKey, publicJwk, serverId: await deriveServerId(publicJwk) };
};

const sign = async (privateKey: CryptoKey, payload: string): Promise<string> => {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(payload),
  );
  return b64url(sig);
};

const hostWsUrl = async (
  keys: Awaited<ReturnType<typeof generateHostKeys>>,
  role: 'host-control' | 'host-data',
  withMetadata: boolean,
  connectionId?: string,
  overrideSig?: string,
): Promise<string> => {
  const ts = Date.now();
  const payload = `${ts}.${keys.serverId}.${role}.${connectionId ?? ''}`;
  const sig = overrideSig ?? (await sign(keys.privateKey, payload));
  const pk = textToB64url(JSON.stringify(keys.publicJwk));
  const params = new URLSearchParams({ v: '1', role, serverId: keys.serverId, ts: String(ts), sig, pk });
  if (withMetadata) {
    params.set('appId', 'openchamber');
    params.set('appVersion', '1.23.0');
    params.set('platform', 'desktop');
  }
  if (connectionId) params.set('connectionId', connectionId);
  return `${BASE}/ws?${params}`;
};

const parseRetire = (text: string): { code: number; reason: string } | null => {
  try {
    const message = JSON.parse(text) as { type?: unknown; code?: unknown; reason?: unknown };
    if (message.type !== 'relay-retire' || typeof message.code !== 'number') return null;
    return { code: message.code, reason: typeof message.reason === 'string' ? message.reason : '' };
  } catch {
    return null;
  }
};

type Frame = { kind: 'text'; data: string } | { kind: 'binary'; data: Uint8Array };

class Socket {
  ws: WebSocket;
  frames: Frame[] = [];
  waiters: Array<() => void> = [];
  closed: Promise<{ code: number; reason: string }>;
  retiredWith: { code: number; reason: string } | null = null;
  openResult: Promise<'open' | 'failed'>;

  constructor(url: string) {
    this.ws = new WebSocket(url);
    this.ws.binaryType = 'arraybuffer';
    this.openResult = new Promise((resolve) => {
      this.ws.addEventListener('open', () => resolve('open'));
      this.ws.addEventListener('error', () => resolve('failed'));
      this.ws.addEventListener('close', () => resolve('failed'));
    });
    this.closed = new Promise((resolve) => {
      this.ws.addEventListener('close', (event) =>
        resolve(this.retiredWith ?? { code: event.code, reason: event.reason }),
      );
    });
    this.ws.addEventListener('message', (event) => {
      if (typeof event.data === 'string') {
        const retire = parseRetire(event.data);
        if (retire) {
          this.retiredWith = retire;
          this.ws.close(1000);
          return;
        }
        this.frames.push({ kind: 'text', data: event.data });
      } else {
        this.frames.push({ kind: 'binary', data: new Uint8Array(event.data as ArrayBuffer) });
      }
      for (const waiter of this.waiters.splice(0)) waiter();
    });
  }

  async open(): Promise<void> {
    const result = await withTimeout(this.openResult, 5000, 'socket open');
    if (result !== 'open') throw new Error(`socket failed to open: ${this.ws.url}`);
  }

  async nextFrame(timeoutMs = 5000): Promise<Frame> {
    if (this.frames.length > 0) return this.frames.shift() as Frame;
    await withTimeout(
      new Promise<void>((resolve) => this.waiters.push(resolve)),
      timeoutMs,
      'frame wait',
    );
    return this.frames.shift() as Frame;
  }

  close(code?: number, reason?: string): void {
    this.ws.close(code, reason);
  }
}

const withTimeout = <T>(promise: Promise<T>, ms: number, label: string): Promise<T> =>
  Promise.race([
    promise,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error(`timeout: ${label}`)), ms)),
  ]);

const assert = (condition: boolean, label: string): void => {
  if (!condition) throw new Error(`ASSERT FAILED: ${label}`);
  console.log(`  ok: ${label}`);
};

const runScenario = async (hostMetadata: boolean, clientMetadata: boolean) => {
  console.log(`Relay smoke test against ${BASE}: host=${hostMetadata ? 'current' : 'legacy'}, client=${clientMetadata ? 'current' : 'legacy'}`);

  // Health
  const healthUrl = BASE.replace(/^ws/, 'http') + '/health';
  const health = (await (await fetch(healthUrl)).json()) as { ok: boolean; service: string };
  assert(health.ok === true && health.service === 'openchamber-relay', 'GET /health');

  // Malformed URL encoding must be rejected without crashing the Node process.
  // Cloudflare without D1 returns 503 before inspecting the serverId.
  const malformedUsage = await fetch(BASE.replace(/^ws/, 'http') + '/usage/%');
  assert([400, 503].includes(malformedUsage.status), 'malformed usage URL rejected');
  assert((await fetch(healthUrl)).ok, 'relay remains healthy after malformed URL');

  const keys = await generateHostKeys();

  // 1. Auth rejection: garbage signature must not produce an open host socket.
  console.log('1. auth rejection');
  const badSock = new Socket(await hostWsUrl(keys, 'host-control', hostMetadata, undefined, textToB64url('garbage')));
  const badResult = await withTimeout(badSock.openResult, 5000, 'bad-auth open');
  assert(badResult === 'failed', 'garbage signature rejected');

  // 2. Valid host-control connect, receives sync.
  console.log('2. host-control connect + sync');
  const control = new Socket(await hostWsUrl(keys, 'host-control', hostMetadata));
  await control.open();
  const syncFrame = await control.nextFrame();
  assert(syncFrame.kind === 'text', 'sync is text');
  const sync = JSON.parse((syncFrame as { data: string }).data) as { type: string; connectionIds: string[] };
  assert(sync.type === 'sync' && Array.isArray(sync.connectionIds), 'sync message received');

  // 3. Client connects (own connectionId), control gets `connected`.
  console.log('3. client connect + connected notification');
  const connectionId = `conn_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const clientParams = new URLSearchParams({ v: '1', role: 'client', serverId: keys.serverId, connectionId });
  if (clientMetadata) {
    clientParams.set('appId', 'openchamber');
    clientParams.set('appVersion', '1.23.0');
    clientParams.set('platform', 'ios');
  }
  const client = new Socket(`${BASE}/ws?${clientParams}`);
  await client.open();
  const connectedFrame = await control.nextFrame();
  const connected = JSON.parse((connectedFrame as { data: string }).data) as { type: string; connectionId: string };
  assert(connected.type === 'connected' && connected.connectionId === connectionId, 'connected notification');

  // 4. Client frames buffered while host-data absent, flushed in order on attach.
  console.log('4. buffering + flush');
  client.ws.send('hello-1');
  client.ws.send(new Uint8Array([1, 2, 3]));
  client.ws.send('hello-3');
  await new Promise((resolve) => setTimeout(resolve, 300));

  const hostData = new Socket(await hostWsUrl(keys, 'host-data', hostMetadata, connectionId));
  await hostData.open();
  const f1 = await hostData.nextFrame();
  const f2 = await hostData.nextFrame();
  const f3 = await hostData.nextFrame();
  assert(f1.kind === 'text' && f1.data === 'hello-1', 'buffered text frame 1 flushed first');
  assert(f2.kind === 'binary' && f2.data.length === 3 && f2.data[1] === 2, 'buffered binary frame flushed second');
  assert(f3.kind === 'text' && f3.data === 'hello-3', 'buffered text frame 3 flushed third');

  // 5. Bidirectional forwarding, text and binary.
  console.log('5. bidirectional forwarding');
  hostData.ws.send('from-host');
  hostData.ws.send(new Uint8Array([9, 8, 7, 6]));
  const c1 = await client.nextFrame();
  const c2 = await client.nextFrame();
  assert(c1.kind === 'text' && c1.data === 'from-host', 'host->client text');
  assert(c2.kind === 'binary' && c2.data.length === 4 && c2.data[0] === 9, 'host->client binary');

  client.ws.send('from-client-live');
  const h1 = await hostData.nextFrame();
  assert(h1.kind === 'text' && h1.data === 'from-client-live', 'client->host live text');

  // 6. Close propagation: client close -> host-data closed + disconnected on control.
  console.log('6. close propagation');
  client.close(1000, 'done');
  const hostDataClose = await withTimeout(hostData.closed, 5000, 'host-data close');
  // Host-data ends with 1001, a close (Node) or a retire frame (Cloudflare); local wrangler dev
  // may surface a normalized clean code.
  assert(hostDataClose.code !== 1006, `host-data closed cleanly on client disconnect (code ${hostDataClose.code})`);
  const disconnectedFrame = await control.nextFrame();
  const disconnected = JSON.parse((disconnectedFrame as { data: string }).data) as { type: string; connectionId: string };
  assert(disconnected.type === 'disconnected' && disconnected.connectionId === connectionId, 'disconnected notification');

  control.close(1000, 'done');
};

const runShareScenario = async () => {
  console.log(`Encrypted shares against ${HTTP_BASE}`);
  const host = await makeHost(HTTP_BASE, (request) => fetch(request, { redirect: 'error' }));
  const browser = (path: string, body?: unknown) => fetch(HTTP_BASE + path, body === undefined
    ? { redirect: 'error' }
    : { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const nextJson = async (socket: Socket) => {
    const frame = await socket.nextFrame();
    return frame.kind === 'text' ? JSON.parse(frame.data) as Record<string, unknown> : {};
  };

  // The live host learns about opens and answers on its control socket.
  const control = new Socket(await hostWsUrl({ privateKey: host.privateKey, publicJwk: host.publicJwk, serverId: host.serverId }, 'host-control', true));
  await control.open();
  assert((await nextJson(control)).type === 'sync', 'share host control connected');

  console.log('1. create (signed)');
  const unsigned = await fetch(`${HTTP_BASE}/p`, { method: 'POST', body: new Uint8Array([1, 2, 3]) });
  assert(unsigned.status === 401, 'unsigned create refused');
  const { response, keys } = await createShare(host);
  assert(response.status === 201, `share created (status ${response.status})`);
  const { id, url } = await response.json() as { id: string; url: string };
  assert(/^[A-Za-z0-9_-]{22}$/.test(id) && url.endsWith(`/p/${id}`), 'create returns id and link');

  console.log('2. viewer + status');
  const viewer = await browser(`/p/${id}`);
  const csp = viewer.headers.get('content-security-policy') ?? '';
  assert(viewer.status === 200 && csp.includes("frame-src 'none'") && csp.includes("connect-src 'self'"), 'viewer served with its CSP');
  assert((await viewer.text()).includes('sandbox="allow-scripts allow-forms"'), 'viewer frames the page in a sandbox');
  const status = await (await browser(`/p/${id}/status`)).json() as Record<string, unknown>;
  assert(status.status === 'open' && status.attemptsLeft === 5, 'status open with five attempts');

  console.log('3. wrong PIN, open');
  const wrong = await deriveKeys(crypto.getRandomValues(new Uint8Array(32)), '000000');
  const refused = await browser(`/p/${id}/open`, { auth: wrong.auth });
  assert(refused.status === 403 && (await refused.json() as { error?: string }).error === 'wrong-pin', 'wrong PIN refused');
  const opened = await browser(`/p/${id}/open`, { auth: keys.auth });
  assert(opened.status === 200, 'right PIN opens');
  const document = await unseal(keys.key, new Uint8Array(await opened.arrayBuffer()), 'openchamber-share-v1 document');
  assert(JSON.stringify(document) === JSON.stringify(DOCUMENT), 'ciphertext decrypts to the shared page');
  const openNudge = await nextJson(control);
  assert(openNudge.type === 'share-state' && openNudge.shareId === id, 'host-control nudged on open');

  console.log('4. answer, states, close');
  const answer = await sealAnswer(keys.key, { v: 1, data: { pick: 'B' }, summary: 'Picked B' });
  assert((await browser(`/p/${id}/answer`, { auth: keys.auth, answer })).status === 200, 'answer accepted');
  assert((await browser(`/p/${id}/answer`, { auth: keys.auth, answer })).status === 409, 'second answer refused');
  const answerNudge = await nextJson(control);
  assert(answerNudge.type === 'share-state' && answerNudge.shareId === id, 'host-control nudged on answer');
  const states = await (await host.call('POST', '/p/states', jsonBody({ ids: [id] }))).json() as { states: Array<Record<string, unknown>> };
  assert(states.states[0]?.status === 'answered' && states.states[0]?.answer === answer, 'states carry the answer');
  const closed = await (await host.call('POST', `/p/${id}/close`, jsonBody({}))).json() as Record<string, unknown>;
  assert(closed.closed === true && closed.answer === answer, 'close hands over the answer');
  assert((await browser(`/p/${id}/open`, { auth: keys.auth })).status === 409, 'closed share no longer opens');
  const after = await (await browser(`/p/${id}/status`)).json() as Record<string, unknown>;
  assert(after.status === 'answered', 'link reads as answered after close');

  control.close(1000, 'done');
};

const main = async () => {
  for (const hostMetadata of [false, true]) {
    for (const clientMetadata of [false, true]) {
      await runScenario(hostMetadata, clientMetadata);
    }
  }
  await runShareScenario();
  console.log('\nAll smoke assertions passed.');
  process.exit(0);
};

main().catch((error) => {
  console.error('\nSMOKE FAILED:', error);
  process.exit(1);
});
