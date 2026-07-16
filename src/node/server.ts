// OpenChamber private relay — standalone Node adapter (Layer 1 of the relay protocol).
// A single long-lived process holding one RelayRoom per serverId. Same wire contract as the
// Cloudflare Worker adapter: /health, /ws (validated + host-authenticated upgrades), and an
// optional signed /usage/:serverId read backed by SQLite instead of D1.
//
// Configuration (env):
//   PORT            listen port (default 8788)
//   HOST            bind address (default 0.0.0.0)
//   RELAY_USAGE_DB  path to a SQLite file to enable usage accounting (optional)
//
// Run behind a TLS-terminating reverse proxy (Caddy, Traefik, nginx) — OpenChamber hosts and
// clients connect over wss://.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { WebSocketServer } from 'ws';
import {
  buildUsagePayload,
  deriveServerId,
  isFreshTimestamp,
  parsePublicKeyParam,
  verifySignature,
} from '../core/relay-auth';
import { COUNTER_FLUSH_MS, HEALTH_BODY } from '../core/protocol';
import { isUsageDeltaEmpty } from '../core/usage-accumulator';
import { ID_PATTERN, validateWsUpgrade } from '../core/ws-query';
import { RelayRoom } from './room';
import { openUsageStore, type UsageStore } from './usage-store';

const PORT = Number(process.env.PORT ?? 8788);
const HOST = process.env.HOST ?? '0.0.0.0';

const rooms = new Map<string, RelayRoom>();
const usageStore: UsageStore | null = process.env.RELAY_USAGE_DB
  ? openUsageStore(process.env.RELAY_USAGE_DB)
  : null;

const getRoom = (serverId: string): RelayRoom => {
  let room = rooms.get(serverId);
  if (!room) {
    room = new RelayRoom(serverId);
    rooms.set(serverId, room);
  }
  return room;
};

// Periodic usage flush + empty-room eviction (the Node analogue of the DO's 60 s alarm).
const flushTimer = setInterval(() => {
  for (const [serverId, room] of rooms) {
    const delta = room.drainUsage();
    if (usageStore && !isUsageDeltaEmpty(delta)) {
      try {
        usageStore.flush(serverId, delta);
      } catch (error) {
        console.log(
          `[relay] usage flush failed serverId=${serverId}: ${error instanceof Error ? error.message : 'unknown'}`,
        );
      }
    }
    if (room.isEmpty()) {
      room.dispose();
      rooms.delete(serverId);
    }
  }
}, COUNTER_FLUSH_MS);
flushTimer.unref();

// ---------------------------------------------------------------------------
// HTTP routes
// ---------------------------------------------------------------------------

const sendText = (res: ServerResponse, status: number, body: string): void => {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
};

const sendJson = (res: ServerResponse, status: number, body: unknown): void => {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
};

const handleUsage = async (
  serverId: string,
  params: URLSearchParams,
  res: ServerResponse,
): Promise<void> => {
  if (!usageStore) {
    sendText(res, 503, 'Usage accounting is not enabled on this relay');
    return;
  }
  if (!ID_PATTERN.test(serverId)) {
    sendText(res, 400, 'Invalid serverId');
    return;
  }
  const tsParam = params.get('ts');
  const sig = params.get('sig');
  const pkParam = params.get('pk');
  if (!tsParam || !sig || !pkParam) {
    sendText(res, 401, 'Missing auth parameters');
    return;
  }
  const ts = Number(tsParam);
  if (!isFreshTimestamp(ts)) {
    sendText(res, 401, 'Signature expired');
    return;
  }
  const jwk = parsePublicKeyParam(pkParam);
  if (!jwk) {
    sendText(res, 403, 'Invalid public key');
    return;
  }
  if ((await deriveServerId(jwk)) !== serverId) {
    sendText(res, 403, 'serverId mismatch');
    return;
  }
  if (!(await verifySignature(jwk, buildUsagePayload(ts, serverId), sig))) {
    sendText(res, 403, 'Invalid signature');
    return;
  }
  sendJson(res, 200, { serverId, usage: usageStore.readUsage(serverId) });
};

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? '/', 'http://relay.local');

  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, HEALTH_BODY);
    return;
  }
  if (req.method === 'GET' && url.pathname === '/ws') {
    sendText(res, 426, 'Expected WebSocket upgrade');
    return;
  }
  const usageMatch = /^\/usage\/([^/]+)$/.exec(url.pathname);
  if (req.method === 'GET' && usageMatch) {
    void handleUsage(decodeURIComponent(usageMatch[1]), url.searchParams, res);
    return;
  }
  sendText(res, 404, 'Not found');
});

// ---------------------------------------------------------------------------
// WebSocket upgrades
// ---------------------------------------------------------------------------

const wss = new WebSocketServer({ noServer: true });

const rejectUpgrade = (socket: import('node:stream').Duplex, status: number, message: string): void => {
  const statusText =
    status === 400 ? 'Bad Request' : status === 401 ? 'Unauthorized' : status === 403 ? 'Forbidden' : 'Bad Request';
  socket.write(
    `HTTP/1.1 ${status} ${statusText}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(message)}\r\n\r\n${message}`,
  );
  socket.destroy();
};

server.on('upgrade', (req, socket, head) => {
  void (async () => {
    const url = new URL(req.url ?? '/', 'http://relay.local');
    if (url.pathname !== '/ws') {
      rejectUpgrade(socket, 400, 'Not found');
      return;
    }

    const verdict = await validateWsUpgrade(url.searchParams);
    if (!verdict.ok) {
      rejectUpgrade(socket, verdict.status, verdict.message);
      return;
    }
    const query = verdict.query;
    const room = getRoom(query.serverId);

    wss.handleUpgrade(req, socket, head, (ws) => {
      if (query.role === 'host-control') {
        room.connectHostControl(ws);
        return;
      }
      if (query.role === 'host-data') {
        // connectionId presence is enforced by the shared schema.
        room.connectHostData(query.connectionId as string, ws);
        return;
      }
      // client
      const connectionId =
        query.connectionId ?? `conn_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
      const rejection = room.clientRejectionReason();
      if (rejection) {
        room.rejectClient(connectionId, ws, rejection);
        return;
      }
      room.connectClient(connectionId, ws);
    });
  })().catch((error) => {
    console.log(`[relay] upgrade failed: ${error instanceof Error ? error.message : 'unknown'}`);
    socket.destroy();
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[relay] listening on http://${HOST}:${PORT} (ws endpoint: /ws)`);
  console.log(
    usageStore
      ? `[relay] usage accounting enabled (${process.env.RELAY_USAGE_DB})`
      : '[relay] usage accounting disabled (set RELAY_USAGE_DB to enable)',
  );
});

// Graceful shutdown: flush usage, then exit.
const shutdown = (): void => {
  console.log('[relay] shutting down');
  clearInterval(flushTimer);
  for (const [serverId, room] of rooms) {
    const delta = room.drainUsage();
    if (usageStore && !isUsageDeltaEmpty(delta)) {
      try {
        usageStore.flush(serverId, delta);
      } catch {
        // best effort on shutdown
      }
    }
    room.dispose();
  }
  usageStore?.close();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
