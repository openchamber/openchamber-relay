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
