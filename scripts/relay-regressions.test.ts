import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { setImmediate } from 'node:timers/promises';
import { test } from 'node:test';
import type { WebSocket } from 'ws';
import { RelayDurableObject } from '../src/cloudflare/relay-do';
import { CONTROL_LOSS_GRACE_MS } from '../src/core/protocol';
import { RelayRoom } from '../src/node/room';
import { openUsageStore } from '../src/node/usage-store';

class TestSocket extends EventEmitter {
  readonly sent: string[] = [];
  readonly closed: number[] = [];

  send(message: string): void {
    this.sent.push(message);
  }

  close(code: number): void {
    this.closed.push(code);
    // Real sockets deliver the close event after close() returns.
    queueMicrotask(() => this.emit('close'));
  }

  asWebSocket(): WebSocket {
    return this as unknown as WebSocket;
  }
}

test('control-loss grace closes paired data sockets and releases the room', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const room = new RelayRoom('grace-test');
  t.after(() => room.dispose());
  const control = new TestSocket();
  const client = new TestSocket();
  const data = new TestSocket();
  room.connectHostControl(control.asWebSocket());
  room.connectClient('conn', client.asWebSocket());
  room.connectHostData('conn', data.asWebSocket());

  control.close(1000);
  await setImmediate();
  t.mock.timers.tick(CONTROL_LOSS_GRACE_MS);
  await setImmediate();

  assert.deepEqual(client.closed, [1012]);
  assert.deepEqual(data.closed, [1001]);
  assert.equal(room.isEmpty(), true);
});

test('host-data loss runs client cleanup and notifies control', async (t) => {
  const room = new RelayRoom('data-loss-test');
  t.after(() => room.dispose());
  const control = new TestSocket();
  const client = new TestSocket();
  const data = new TestSocket();
  room.connectHostControl(control.asWebSocket());
  room.connectClient('conn', client.asWebSocket());
  room.connectHostData('conn', data.asWebSocket());

  data.close(1000);
  await setImmediate();

  assert.deepEqual(client.closed, [1012]);
  assert.deepEqual(JSON.parse(control.sent.at(-1)!), { type: 'disconnected', connectionId: 'conn' });
  control.close(1000);
  await setImmediate();
  assert.equal(room.isEmpty(), true);
});

test('failed usage writes retain counters and retry without double counting', (t) => {
  const room = new RelayRoom('usage-test');
  const store = openUsageStore(':memory:');
  t.after(() => { room.dispose(); store.close(); });
  room.connectClient('first', new TestSocket().asWebSocket());
  assert.throws(() => room.flushUsage(() => { throw new Error('database is locked'); }));
  room.connectClient('second', new TestSocket().asWebSocket());
  room.flushUsage((delta) => store.flush(room.serverId, delta));
  room.flushUsage(() => assert.fail('Already persisted usage must not be written again'));
  assert.equal(store.readUsage(room.serverId)[0].client_connects, 2);
  assert.equal(store.readUsage(room.serverId)[0].peak_concurrent_clients, 2);
});

const createDurableObject = (db?: ConstructorParameters<typeof RelayDurableObject>[1]['DB']) => {
  const values = new Map<string, unknown>([['serverId', 'alarm-test']]);
  let nextAlarm: number | null = null;
  const state = {
    storage: {
      get: async (key: string) => values.get(key),
      put: async (key: string, value: unknown) => { values.set(key, value); },
      delete: async (key: string) => values.delete(key),
      getAlarm: async () => nextAlarm,
      setAlarm: async (time: number) => { nextAlarm = time; },
      deleteAlarm: async () => { nextAlarm = null; },
    },
    getWebSockets: () => [],
  };
  const relay = new RelayDurableObject(
    state as unknown as ConstructorParameters<typeof RelayDurableObject>[0],
    { DB: db },
  );
  const socket = {
    deserializeAttachment: () => ({
      role: 'host-control', serverId: 'alarm-test', connectionId: null, createdAt: 0,
    }),
  } as unknown as Parameters<RelayDurableObject['webSocketMessage']>[0];
  return { relay, socket, alarm: () => nextAlarm };
};

test('Cloudflare without D1 stops idle alarms and re-arms on new traffic', async () => {
  const { relay, socket, alarm } = createDurableObject();
  await relay.webSocketMessage(socket, 'message');
  assert.notEqual(alarm(), null);
  await relay.alarm();
  assert.equal(alarm(), null);
  await relay.webSocketMessage(socket, 'next message');
  assert.notEqual(alarm(), null);
  await relay.alarm();
  assert.equal(alarm(), null);
});

test('Cloudflare with D1 still retries failed writes before stopping idle alarms', async () => {
  let fail = true;
  const messages: unknown[] = [];
  const statement = { bind: (...args: unknown[]) => args };
  const db = {
    prepare: () => statement,
    batch: async (statements: unknown[][]) => {
      if (fail) throw new Error('D1 unavailable');
      messages.push(statements[1][6]);
    },
  };
  const { relay, socket, alarm } = createDurableObject(
    db as unknown as ConstructorParameters<typeof RelayDurableObject>[1]['DB'],
  );
  await relay.webSocketMessage(socket, 'first');
  await relay.alarm();
  assert.notEqual(alarm(), null);
  await relay.webSocketMessage(socket, 'second');
  fail = false;
  await relay.alarm();
  assert.deepEqual(messages, [2]);
  assert.equal(alarm(), null);
});

// A close to a peer that is gone holds the Durable Object for minutes and is billed, so the
// Cloudflare adapter asks peers to close themselves with a relay-retire frame.
type FakeSocket = { ws: CloudflareSocket; sent: unknown[]; closed: number[]; attachment: () => unknown };
type CloudflareSocket = Parameters<RelayDurableObject['webSocketClose']>[0];

const fakeSocket = (attachment: Record<string, unknown>): FakeSocket => {
  const sent: unknown[] = [];
  const closed: number[] = [];
  let current: unknown = attachment;
  const ws = {
    send: (data: string) => { sent.push(JSON.parse(data)); },
    close: (code?: number) => { closed.push(code ?? 1000); },
    deserializeAttachment: () => current,
    serializeAttachment: (value: unknown) => { current = value; },
  } as unknown as CloudflareSocket;
  return { ws, sent, closed, attachment: () => current };
};

const durableObjectWith = (byTag: Record<string, CloudflareSocket[]>) => {
  const values = new Map<string, unknown>();
  const state = {
    getWebSockets: (tag?: string) => (tag ? byTag[tag] ?? [] : [...new Set(Object.values(byTag).flat())]),
    acceptWebSocket: (ws: CloudflareSocket, tags: string[]) => {
      for (const tag of tags) (byTag[tag] ??= []).push(ws);
    },
    storage: {
      get: async (key: string) => values.get(key),
      put: async (key: string, value: unknown) => { values.set(key, value); },
      delete: async (key: string) => values.delete(key),
      getAlarm: async () => null,
      setAlarm: async () => {},
      deleteAlarm: async () => {},
    },
    waitUntil: () => {},
  };
  const relay = new RelayDurableObject(
    state as unknown as ConstructorParameters<typeof RelayDurableObject>[0],
    {},
  );
  return { relay, values };
};

const retire = (code: number, reason: string) => ({ type: 'relay-retire', code, reason });

test('Cloudflare answers a peer close before reading the attachment', async () => {
  const socket = fakeSocket({});
  let closedFirst = false;
  const ws = {
    close: () => { socket.closed.push(1000); },
    deserializeAttachment: () => { closedFirst = socket.closed.length === 1; return null; },
  } as unknown as CloudflareSocket;
  const { relay } = durableObjectWith({});
  await relay.webSocketClose(ws, 1005, '', true);
  assert.equal(closedFirst, true);
});

test('Cloudflare retires the client of a host data socket that went away', async () => {
  const hostData = fakeSocket({ role: 'host-data', connectionId: 'c1', serverId: 's', createdAt: 1 });
  const client = fakeSocket({ role: 'client', connectionId: 'c1', serverId: 's', createdAt: 1 });
  const { relay } = durableObjectWith({ 'host-data:c1': [hostData.ws], 'client:c1': [client.ws], client: [client.ws] });
  await relay.webSocketClose(hostData.ws, 1006, '', false);
  assert.deepEqual(client.closed, []);
  assert.deepEqual(client.sent, [retire(1012, 'Host went away, reconnect')]);
});

test('Cloudflare retires a replaced control socket and stops routing to it', async () => {
  const old = fakeSocket({ role: 'host-control', connectionId: null, serverId: 's', createdAt: 1 });
  const client = fakeSocket({ role: 'client', connectionId: 'c1', serverId: 's', createdAt: 1 });
  const byTag: Record<string, CloudflareSocket[]> = { 'host-control': [old.ws], 'client:c1': [client.ws], client: [client.ws] };
  const { relay, values } = durableObjectWith(byTag);
  const handleConnect = (relay as unknown as { handleHostControlConnect: (serverId: string, appVersion?: string) => Promise<Response> }).handleHostControlConnect.bind(relay);
  const pair = globalThis as unknown as { WebSocketPair?: unknown; Response: typeof Response };
  const fresh = fakeSocket({});
  pair.WebSocketPair = class { 0 = {}; 1 = fresh.ws; };
  const realResponse = pair.Response;
  pair.Response = class { constructor(public body: unknown, public init: unknown) {} } as unknown as typeof Response;
  try {
    await handleConnect('s', '2.5.0');
  } finally {
    pair.Response = realResponse;
    delete pair.WebSocketPair;
  }
  assert.deepEqual(old.closed, []);
  assert.deepEqual(old.sent, [retire(4001, 'Control replaced')]);
  assert.equal((old.attachment() as { retired?: boolean }).retired, true);
  assert.deepEqual(fresh.sent, [{ type: 'sync', connectionIds: ['c1'] }]);

  // The retired socket's eventual close must not start the control-loss grace.
  await relay.webSocketClose(old.ws, 1006, '', false);
  assert.equal(values.has('controlGraceDeadline'), false);
});

test('Cloudflare retires a stuck control from 2.5.0 and still closes an older one', async () => {
  for (const [appVersion, retired] of [['2.5.0', true], ['2.4.0', false]] as const) {
    const control = fakeSocket({ role: 'host-control', connectionId: null, serverId: 's', createdAt: 1, appVersion });
    const client = fakeSocket({ role: 'client', connectionId: 'c1', serverId: 's', createdAt: 1 });
    const { relay, values } = durableObjectWith({ 'host-control': [control.ws], 'client:c1': [client.ws], client: [client.ws] });
    values.set('stuckDeadlines', { c1: 0 });
    await relay.alarm();
    if (retired) {
      assert.deepEqual(control.closed, []);
      assert.deepEqual(control.sent, [retire(4003, 'Control unresponsive')]);
      assert.equal(typeof values.get('controlGraceDeadline'), 'number');
    } else {
      assert.deepEqual(control.closed, [4003]);
      assert.deepEqual(control.sent, []);
    }
  }
});
