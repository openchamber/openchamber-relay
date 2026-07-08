// Smoke test for the relay worker. Run against a local `wrangler dev`:
//
//   bun run --cwd apps/relay dev          # terminal 1 (listens on :8788)
//   bun run --cwd apps/relay smoke        # terminal 2
//
// Override the target with RELAY_URL=ws://127.0.0.1:8788 (no path).
//
// Simulates a host (control + data sockets, real ECDSA P-256 WebCrypto signing) and a client:
// - auth rejection with a garbage signature
// - `sync` on control connect and `connected` notification when a client arrives
// - frames buffered while host-data is absent, flushed in order when it attaches
// - bidirectional verbatim forwarding of text and binary frames
// - clean close propagation (client close -> host-data close + `disconnected` on control)

const BASE = process.env.RELAY_URL ?? 'ws://127.0.0.1:8788';

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
  connectionId?: string,
  overrideSig?: string,
): Promise<string> => {
  const ts = Date.now();
  const payload = `${ts}.${keys.serverId}.${role}.${connectionId ?? ''}`;
  const sig = overrideSig ?? (await sign(keys.privateKey, payload));
  const pk = textToB64url(JSON.stringify(keys.publicJwk));
  const params = new URLSearchParams({ v: '1', role, serverId: keys.serverId, ts: String(ts), sig, pk });
  if (connectionId) params.set('connectionId', connectionId);
  return `${BASE}/ws?${params}`;
};

type Frame = { kind: 'text'; data: string } | { kind: 'binary'; data: Uint8Array };

class Socket {
  ws: WebSocket;
  frames: Frame[] = [];
  waiters: Array<() => void> = [];
  closed: Promise<{ code: number; reason: string }>;
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
        resolve({ code: event.code, reason: event.reason }),
      );
    });
    this.ws.addEventListener('message', (event) => {
      if (typeof event.data === 'string') {
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

const main = async () => {
  console.log(`Relay smoke test against ${BASE}`);

  // Health
  const healthUrl = BASE.replace(/^ws/, 'http') + '/health';
  const health = (await (await fetch(healthUrl)).json()) as { ok: boolean; service: string };
  assert(health.ok === true && health.service === 'openchamber-relay', 'GET /health');

  const keys = await generateHostKeys();

  // 1. Auth rejection: garbage signature must not produce an open host socket.
  console.log('1. auth rejection');
  const badSock = new Socket(await hostWsUrl(keys, 'host-control', undefined, textToB64url('garbage')));
  const badResult = await withTimeout(badSock.openResult, 5000, 'bad-auth open');
  assert(badResult === 'failed', 'garbage signature rejected');

  // 2. Valid host-control connect, receives sync.
  console.log('2. host-control connect + sync');
  const control = new Socket(await hostWsUrl(keys, 'host-control'));
  await control.open();
  const syncFrame = await control.nextFrame();
  assert(syncFrame.kind === 'text', 'sync is text');
  const sync = JSON.parse((syncFrame as { data: string }).data) as { type: string; connectionIds: string[] };
  assert(sync.type === 'sync' && Array.isArray(sync.connectionIds), 'sync message received');

  // 3. Client connects (own connectionId), control gets `connected`.
  console.log('3. client connect + connected notification');
  const connectionId = `conn_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const clientParams = new URLSearchParams({ v: '1', role: 'client', serverId: keys.serverId, connectionId });
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

  const hostData = new Socket(await hostWsUrl(keys, 'host-data', connectionId));
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
  // The DO closes host-data with 1001; local wrangler dev may surface a normalized clean code.
  assert(hostDataClose.code !== 1006, `host-data closed cleanly on client disconnect (code ${hostDataClose.code})`);
  const disconnectedFrame = await control.nextFrame();
  const disconnected = JSON.parse((disconnectedFrame as { data: string }).data) as { type: string; connectionId: string };
  assert(disconnected.type === 'disconnected' && disconnected.connectionId === connectionId, 'disconnected notification');

  control.close(1000, 'done');
  console.log('\nAll smoke assertions passed.');
  process.exit(0);
};

main().catch((error) => {
  console.error('\nSMOKE FAILED:', error);
  process.exit(1);
});
