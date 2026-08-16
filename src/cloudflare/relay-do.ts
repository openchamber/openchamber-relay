// RelayDurableObject — one instance per serverId ("relay-v1:{serverId}"), the meeting point
// between a host (control + per-connection data sockets) and its clients. Implements Layer 1 of
// the private-relay protocol spec. Uses the WebSocket Hibernation API so idle DOs cost nothing.
//
// PRIVACY INVARIANT: this object never parses, logs, or stores forwarded frame contents.
// Logs contain serverId / connectionId / status codes only.

import {
  isUsageDeltaEmpty,
  nextPendingAfterFlush,
  recordConnect as recordConnectDelta,
  recordFrameDown,
  recordFrameUp,
  recordMessage,
  utcUsageDate,
  zeroUsageDelta,
  type UsageDelta,
} from '../core/usage-accumulator';
import {
  CLOSE_CONTROL_REPLACED,
  CLOSE_DUPLICATE_CLIENT,
  CLOSE_HOST_UNAVAILABLE,
  CLOSE_LIMIT_EXCEEDED,
  CLOSE_SERVICE_RESTART,
  CLOSE_STUCK_CONTROL,
  CONTROL_LOSS_GRACE_MS,
  COUNTER_FLUSH_MS,
  MAX_CLIENT_CONNECTS_PER_MIN,
  MAX_CONCURRENT_CLIENTS,
  PENDING_MAX_BYTES,
  PENDING_MAX_FRAMES,
  STUCK_CONTROL_MS,
} from '../core/protocol';

// The relay worker env visible to the DO. DB is the shared openchamber-metrics D1 (relay_* tables).
export type Env = {
  // Optional: usage accounting is written to D1 only when a `DB` binding is
  // present. Without it the relay runs fully (routing + abuse guards); the flush
  // is skipped. Bind a D1 database + apply migrations/ to enable per-server usage.
  DB?: D1Database;
};

// ---------------------------------------------------------------------------
// Constants (per spec)
// ---------------------------------------------------------------------------

// Upper bound on unflushed-to-D1 traffic retained across failed flushes. Beyond this, a sustained
// D1 outage would grow memory without limit, so we drop-with-log (loss is explicit, never silent).
const D1_PENDING_MAX_BYTES = 512 * 1024 * 1024; // 512 MiB

// Tags
const TAG_HOST_CONTROL = 'host-control';
const TAG_HOST_DATA_PREFIX = 'host-data:';
const TAG_CLIENT = 'client';
const TAG_CLIENT_PREFIX = 'client:';

// Storage keys
const KEY_COUNTERS = 'counters';
const KEY_CONTROL_GRACE = 'controlGraceDeadline';
const KEY_STUCK_DEADLINES = 'stuckDeadlines';
const KEY_BUFFERED_FLAGS = 'bufferedFlags';
// serverId owning this DO, persisted so the alarm (which has no socket attachment) can attribute
// D1 writes even after hibernation clears the in-memory copy.
const KEY_SERVER_ID = 'serverId';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SocketRole = 'host-control' | 'host-data' | 'client';

type SocketAttachment = {
  role: SocketRole;
  connectionId: string | null;
  serverId: string;
  createdAt: number;
};

export type UsageCounters = {
  bytesClientToHost: number;
  bytesHostToClient: number;
  clientConnects: number;
  peakConcurrentClients: number;
};

export type UsageSnapshot = UsageCounters & {
  concurrentClients: number;
};

type LimitDecision = { allowed: boolean; reason?: string };

type PendingBuffer = {
  frames: Array<string | ArrayBuffer>;
  bytes: number;
};

const zeroCounters = (): UsageCounters => ({
  bytesClientToHost: 0,
  bytesHostToClient: 0,
  clientConnects: 0,
  peakConcurrentClients: 0,
});

const frameByteSize = (message: string | ArrayBuffer): number =>
  typeof message === 'string' ? message.length : message.byteLength;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

const readAttachment = (ws: WebSocket): SocketAttachment | null => {
  try {
    const raw: unknown = ws.deserializeAttachment();
    if (!isRecord(raw)) return null;
    const role = raw.role;
    if (role !== 'host-control' && role !== 'host-data' && role !== 'client') return null;
    return {
      role,
      connectionId: typeof raw.connectionId === 'string' ? raw.connectionId : null,
      serverId: typeof raw.serverId === 'string' ? raw.serverId : '',
      createdAt: typeof raw.createdAt === 'number' ? raw.createdAt : 0,
    };
  } catch {
    return null;
  }
};

// Enforcement seam for future per-user plans. v1: always allowed. The two hard abuse guards
// (concurrent clients, connect rate) are enforced separately in handleClientConnect.
const checkLimits = (_snapshot: UsageSnapshot): LimitDecision => ({ allowed: true });

// ---------------------------------------------------------------------------
// Durable Object
// ---------------------------------------------------------------------------

export class RelayDurableObject implements DurableObject {
  private readonly state: DurableObjectState;
  private readonly env: Env;

  // In-memory only; lost on hibernation by design. A hibernation flush that drops buffered
  // frames closes the affected client (1012) via the persisted bufferedFlags marker instead of
  // silently losing frames.
  private pending = new Map<string, PendingBuffer>();

  // Counter deltas since the last flush to DO storage (flushed on 60 s alarm and close events).
  private counterDelta = zeroCounters();
  private counterDeltaDirty = false;

  // Rolling client-connect timestamps for the per-minute rate guard. In-memory only: under
  // active connect churn the DO does not hibernate, so the window survives where it matters.
  private clientConnectTimes: number[] = [];

  // Usage accumulated since the last *successful* D1 write (bytes_up/down, connects, peak). This is
  // SEPARATE from counterDelta (which flushes to DO storage as lifetime totals) — the two are
  // incremented at the same call sites but reset on independent schedules, so D1 is never double
  // counted. Flushed to relay_daily_usage on the 60 s alarm and on last-socket close; kept and
  // retried on failure. In-memory only, mirroring counterDelta: any traffic arms a flush alarm
  // within 60 s, and the last-socket-close flush captures the tail before hibernation. A DO that
  // hibernates in that sub-minute window loses at most one minute of deltas (undercount, bounded).
  private d1Pending: UsageDelta = zeroUsageDelta();

  // serverId owning this DO. Captured on first connect, persisted (KEY_SERVER_ID) so the alarm can
  // attribute D1 writes with no socket in hand.
  private serverId: string | null = null;

  // Whether we believe a flush alarm is currently set. In-memory only: reset to false by
  // hibernation, which is exactly when the next message must re-check storage.getAlarm().
  private flushAlarmEnsured = false;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  // -------------------------------------------------------------------------
  // Connect handling
  // -------------------------------------------------------------------------

  async fetch(request: Request): Promise<Response> {
    const upgrade = request.headers.get('Upgrade');
    if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket upgrade', { status: 426 });
    }

    const url = new URL(request.url);
    const role = url.searchParams.get('role');
    const serverId = url.searchParams.get('serverId') ?? '';
    const connectionId = (url.searchParams.get('connectionId') ?? '').trim();

    if (serverId) await this.rememberServerId(serverId);

    if (role === 'host-control') return this.handleHostControlConnect(serverId);
    if (role === 'host-data') return this.handleHostDataConnect(serverId, connectionId);
    if (role === 'client') return this.handleClientConnect(serverId, connectionId);
    return new Response('Invalid role', { status: 400 });
  }

  private acceptSocket(tags: string[], attachment: SocketAttachment): WebSocket {
    const pair = new WebSocketPair();
    const server = pair[1];
    this.state.acceptWebSocket(server, tags);
    server.serializeAttachment(attachment);
    return pair[0];
  }

  private upgradeResponse(clientSide: WebSocket): Response {
    return new Response(null, { status: 101, webSocket: clientSide });
  }

  private async handleHostControlConnect(serverId: string): Promise<Response> {
    // Exactly one active host-control per serverId; a new one replaces the old.
    for (const ws of this.state.getWebSockets(TAG_HOST_CONTROL)) {
      try {
        ws.close(CLOSE_CONTROL_REPLACED, 'Control replaced');
      } catch {
        // ignore
      }
    }
    await this.state.storage.delete(KEY_CONTROL_GRACE);

    const clientSide = this.acceptSocket([TAG_HOST_CONTROL], {
      role: 'host-control',
      connectionId: null,
      serverId,
      createdAt: Date.now(),
    });

    console.log(`[relay] host-control connected serverId=${serverId}`);

    // Tell the host which clients are already waiting so it can attach data sockets.
    const server = this.state.getWebSockets(TAG_HOST_CONTROL)[0];
    if (server) {
      try {
        server.send(JSON.stringify({ type: 'sync', connectionIds: this.listClientConnectionIds() }));
      } catch {
        // ignore
      }
    }

    await this.scheduleNextAlarm();
    return this.upgradeResponse(clientSide);
  }

  private async handleHostDataConnect(serverId: string, connectionId: string): Promise<Response> {
    if (!connectionId) {
      return new Response('connectionId required for host-data', { status: 400 });
    }

    // One host-data socket per connection; replace any stale one.
    for (const ws of this.state.getWebSockets(TAG_HOST_DATA_PREFIX + connectionId)) {
      try {
        ws.close(1008, 'Replaced by new connection');
      } catch {
        // ignore
      }
    }

    const clientSide = this.acceptSocket([TAG_HOST_DATA_PREFIX + connectionId], {
      role: 'host-data',
      connectionId,
      serverId,
      createdAt: Date.now(),
    });

    console.log(`[relay] host-data connected serverId=${serverId} connectionId=${connectionId}`);

    await this.clearStuckDeadline(connectionId);
    await this.flushPendingFrames(connectionId);
    await this.scheduleNextAlarm();
    return this.upgradeResponse(clientSide);
  }

  private async handleClientConnect(serverId: string, requestedConnectionId: string): Promise<Response> {
    const connectionId =
      requestedConnectionId || `conn_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

    const now = Date.now();
    const concurrentClients = this.countConcurrentClients();

    // Abuse guards (spec: violations -> close 4029). We must complete the upgrade to be able to
    // deliver a close code, so accept without tags and close immediately.
    this.clientConnectTimes = this.clientConnectTimes.filter((t) => now - t < 60_000);
    const rateExceeded = this.clientConnectTimes.length >= MAX_CLIENT_CONNECTS_PER_MIN;
    const concurrencyExceeded = concurrentClients >= MAX_CONCURRENT_CLIENTS;

    const snapshot = await this.getUsageSnapshot();
    const decision = checkLimits(snapshot);

    if (rateExceeded || concurrencyExceeded || !decision.allowed) {
      const reason = concurrencyExceeded
        ? 'Too many concurrent clients'
        : rateExceeded
          ? 'Too many connects'
          : (decision.reason ?? 'Limit exceeded');
      console.log(`[relay] client rejected serverId=${serverId} connectionId=${connectionId} code=${CLOSE_LIMIT_EXCEEDED}`);
      const pair = new WebSocketPair();
      const server = pair[1];
      server.accept();
      server.close(CLOSE_LIMIT_EXCEEDED, reason);
      return this.upgradeResponse(pair[0]);
    }

    this.clientConnectTimes.push(now);

    // Duplicate client with the same connectionId: close the old socket.
    for (const ws of this.state.getWebSockets(TAG_CLIENT_PREFIX + connectionId)) {
      try {
        ws.close(CLOSE_DUPLICATE_CLIENT, 'Duplicate client');
      } catch {
        // ignore
      }
    }

    const clientSide = this.acceptSocket([TAG_CLIENT, TAG_CLIENT_PREFIX + connectionId], {
      role: 'client',
      connectionId,
      serverId,
      createdAt: now,
    });

    console.log(`[relay] client connected serverId=${serverId} connectionId=${connectionId}`);

    this.counterDelta.clientConnects += 1;
    const concurrentAfter = this.countConcurrentClients();
    if (concurrentAfter > this.counterDelta.peakConcurrentClients) {
      this.counterDelta.peakConcurrentClients = concurrentAfter;
    }
    this.counterDeltaDirty = true;
    recordConnectDelta(this.d1Pending, concurrentAfter);

    this.notifyControl({ type: 'connected', connectionId });

    // Stuck-control detection: if no host-data socket appears for this client within 15 s,
    // force-close the control socket so the host reconnects.
    if (this.state.getWebSockets(TAG_HOST_DATA_PREFIX + connectionId).length === 0) {
      await this.setStuckDeadline(connectionId, now + STUCK_CONTROL_MS);
    }

    await this.scheduleNextAlarm();
    return this.upgradeResponse(clientSide);
  }

  // -------------------------------------------------------------------------
  // Message forwarding (verbatim; never parsed)
  // -------------------------------------------------------------------------

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const attachment = readAttachment(ws);
    if (!attachment) return;
    // Count every message the DO receives (all roles) — this is the unit Cloudflare bills as a
    // Durable Object request. Do it before any role-based early return so control messages count too.
    recordMessage(this.d1Pending);
    await this.ensureFlushAlarm();
    const { role, connectionId } = attachment;

    if (role === 'host-control') {
      // No client->relay control messages are defined in v1; ignore without parsing.
      return;
    }

    if (role === 'client' && connectionId) {
      this.counterDelta.bytesClientToHost += frameByteSize(message);
      this.counterDeltaDirty = true;
      recordFrameUp(this.d1Pending, frameByteSize(message));
      const targets = this.state.getWebSockets(TAG_HOST_DATA_PREFIX + connectionId);
      if (targets.length === 0) {
        await this.bufferFrame(connectionId, message, ws);
        return;
      }
      for (const target of targets) {
        try {
          target.send(message);
        } catch {
          console.log(`[relay] forward client->host failed connectionId=${connectionId}`);
        }
      }
      return;
    }

    if (role === 'host-data' && connectionId) {
      this.counterDelta.bytesHostToClient += frameByteSize(message);
      this.counterDeltaDirty = true;
      recordFrameDown(this.d1Pending, frameByteSize(message));
      for (const target of this.state.getWebSockets(TAG_CLIENT_PREFIX + connectionId)) {
        try {
          target.send(message);
        } catch {
          console.log(`[relay] forward host->client failed connectionId=${connectionId}`);
        }
      }
    }
  }

  private async bufferFrame(
    connectionId: string,
    message: string | ArrayBuffer,
    clientWs: WebSocket,
  ): Promise<void> {
    let buffer = this.pending.get(connectionId);

    if (!buffer) {
      // If a persisted buffered-flag exists but memory is empty, we hibernated with frames in
      // flight and lost them. Do not silently continue with a gap: close the client so it
      // reconnects fresh.
      const flags = await this.getBufferedFlags();
      if (flags[connectionId]) {
        console.log(`[relay] buffered frames lost to hibernation connectionId=${connectionId}`);
        await this.setBufferedFlag(connectionId, false);
        try {
          clientWs.close(CLOSE_SERVICE_RESTART, 'Buffered frames lost, reconnect');
        } catch {
          // ignore
        }
        return;
      }
      buffer = { frames: [], bytes: 0 };
      this.pending.set(connectionId, buffer);
      await this.setBufferedFlag(connectionId, true);
    }

    const size = frameByteSize(message);
    if (buffer.frames.length + 1 > PENDING_MAX_FRAMES || buffer.bytes + size > PENDING_MAX_BYTES) {
      console.log(`[relay] buffer overflow connectionId=${connectionId} code=${CLOSE_HOST_UNAVAILABLE}`);
      this.pending.delete(connectionId);
      await this.setBufferedFlag(connectionId, false);
      try {
        clientWs.close(CLOSE_HOST_UNAVAILABLE, 'host unavailable');
      } catch {
        // ignore
      }
      return;
    }

    buffer.frames.push(message);
    buffer.bytes += size;
  }

  private async flushPendingFrames(connectionId: string): Promise<void> {
    const buffer = this.pending.get(connectionId);
    const flags = await this.getBufferedFlags();

    if (!buffer && flags[connectionId]) {
      // Frames were buffered before hibernation and are gone. Close the client so it retries.
      await this.setBufferedFlag(connectionId, false);
      for (const clientWs of this.state.getWebSockets(TAG_CLIENT_PREFIX + connectionId)) {
        try {
          clientWs.close(CLOSE_SERVICE_RESTART, 'Buffered frames lost, reconnect');
        } catch {
          // ignore
        }
      }
      return;
    }

    if (!buffer) return;
    this.pending.delete(connectionId);
    await this.setBufferedFlag(connectionId, false);

    const targets = this.state.getWebSockets(TAG_HOST_DATA_PREFIX + connectionId);
    for (const frame of buffer.frames) {
      for (const target of targets) {
        try {
          target.send(frame);
        } catch {
          console.log(`[relay] flush failed connectionId=${connectionId}`);
          return;
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Close handling
  // -------------------------------------------------------------------------

  async webSocketClose(ws: WebSocket, code: number, _reason: string, _wasClean: boolean): Promise<void> {
    const attachment = readAttachment(ws);
    if (!attachment) return;
    const { role, connectionId, serverId } = attachment;

    console.log(
      `[relay] ${role}${connectionId ? ` connectionId=${connectionId}` : ''} closed serverId=${serverId} code=${code}`,
    );

    if (role === 'client' && connectionId) {
      // Another socket may have replaced this one (duplicate close 4002): only tear down when
      // no live client socket remains for the connectionId.
      const remaining = this.state
        .getWebSockets(TAG_CLIENT_PREFIX + connectionId)
        .some((socket) => socket !== ws);
      if (!remaining) {
        this.pending.delete(connectionId);
        await this.setBufferedFlag(connectionId, false);
        await this.clearStuckDeadline(connectionId);
        for (const hostWs of this.state.getWebSockets(TAG_HOST_DATA_PREFIX + connectionId)) {
          try {
            hostWs.close(1001, 'Client disconnected');
          } catch {
            // ignore
          }
        }
        this.notifyControl({ type: 'disconnected', connectionId });
      }
    }

    if (role === 'host-data' && connectionId) {
      const remaining = this.state
        .getWebSockets(TAG_HOST_DATA_PREFIX + connectionId)
        .some((socket) => socket !== ws);
      if (!remaining) {
        for (const clientWs of this.state.getWebSockets(TAG_CLIENT_PREFIX + connectionId)) {
          try {
            clientWs.close(CLOSE_SERVICE_RESTART, 'Host went away, reconnect');
          } catch {
            // ignore
          }
        }
      }
    }

    if (role === 'host-control') {
      const remaining = this.state.getWebSockets(TAG_HOST_CONTROL).some((socket) => socket !== ws);
      if (!remaining && this.countConcurrentClients() > 0) {
        // Grace window: leave clients up awaiting control reconnect, then close them all.
        await this.state.storage.put(KEY_CONTROL_GRACE, Date.now() + CONTROL_LOSS_GRACE_MS);
      }
    }

    await this.flushCountersToStorage();

    // Flush usage to D1 when the last socket is closing: the DO is about to go idle and may
    // hibernate, which would drop the in-memory d1Pending tail. `ws` is still listed here, so
    // "last socket" means no *other* socket remains.
    const otherSocketsOpen = this.state.getWebSockets().some((socket) => socket !== ws);
    if (!otherSocketsOpen) {
      await this.flushUsageToD1();
    }

    await this.scheduleNextAlarm();
  }

  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    const attachment = readAttachment(ws);
    console.log(
      `[relay] socket error role=${attachment?.role ?? 'unknown'} connectionId=${attachment?.connectionId ?? ''}`,
    );
  }

  // -------------------------------------------------------------------------
  // Alarm: timers (stuck control, control-loss grace) + counter flush
  // -------------------------------------------------------------------------

  async alarm(): Promise<void> {
    const now = Date.now();

    // Control-loss grace: if control has been gone for 30 s, close all clients 1012.
    const grace = await this.state.storage.get<number>(KEY_CONTROL_GRACE);
    if (typeof grace === 'number' && now >= grace) {
      await this.state.storage.delete(KEY_CONTROL_GRACE);
      if (this.state.getWebSockets(TAG_HOST_CONTROL).length === 0) {
        for (const clientWs of this.state.getWebSockets(TAG_CLIENT)) {
          try {
            clientWs.close(CLOSE_SERVICE_RESTART, 'Host went away, reconnect');
          } catch {
            // ignore
          }
        }
        this.pending.clear();
        await this.state.storage.delete(KEY_BUFFERED_FLAGS);
        await this.state.storage.delete(KEY_STUCK_DEADLINES);
      }
    }

    // Stuck-control detection: client waiting > 15 s with no host-data -> close control 4003.
    const stuck = await this.getStuckDeadlines();
    let stuckChanged = false;
    for (const [connectionId, deadline] of Object.entries(stuck)) {
      const clientPresent = this.state.getWebSockets(TAG_CLIENT_PREFIX + connectionId).length > 0;
      const hostDataPresent =
        this.state.getWebSockets(TAG_HOST_DATA_PREFIX + connectionId).length > 0;
      if (!clientPresent || hostDataPresent) {
        delete stuck[connectionId];
        stuckChanged = true;
        continue;
      }
      if (now >= deadline) {
        console.log(`[relay] stuck control reset connectionId=${connectionId} code=${CLOSE_STUCK_CONTROL}`);
        for (const controlWs of this.state.getWebSockets(TAG_HOST_CONTROL)) {
          try {
            controlWs.close(CLOSE_STUCK_CONTROL, 'Control unresponsive');
          } catch {
            // ignore
          }
        }
        delete stuck[connectionId];
        stuckChanged = true;
      }
    }
    if (stuckChanged) await this.state.storage.put(KEY_STUCK_DEADLINES, stuck);

    await this.flushCountersToStorage();
    await this.flushUsageToD1();
    await this.scheduleNextAlarm();
  }

  private async scheduleNextAlarm(): Promise<void> {
    const deadlines: number[] = [];

    const grace = await this.state.storage.get<number>(KEY_CONTROL_GRACE);
    if (typeof grace === 'number') deadlines.push(grace);

    const stuck = await this.getStuckDeadlines();
    for (const deadline of Object.values(stuck)) deadlines.push(deadline);

    // Keep waking on the flush cadence only while there is unflushed data: DO-storage counters,
    // or unflushed-to-D1 usage (e.g. a failed D1 write that must be retried). Open-but-idle
    // sockets deliberately do NOT hold an alarm — every wake defeats hibernation and bills
    // compute duration, and an idle socket produces nothing to flush. Traffic that dirties the
    // counters re-arms the alarm via ensureFlushAlarm() in webSocketMessage.
    if (this.counterDeltaDirty || !isUsageDeltaEmpty(this.d1Pending)) {
      deadlines.push(Date.now() + COUNTER_FLUSH_MS);
    }

    if (deadlines.length === 0) {
      await this.state.storage.deleteAlarm();
      this.flushAlarmEnsured = false;
      return;
    }
    await this.state.storage.setAlarm(Math.min(...deadlines));
    this.flushAlarmEnsured = true;
  }

  // Cheap per-message guard: after hibernation (or after the alarm chain went quiet) the first
  // frame must re-arm the flush alarm, otherwise dirty counters would sit in memory until a
  // socket closes. The in-memory flag keeps this to one storage.getAlarm() per wake, not per frame.
  private async ensureFlushAlarm(): Promise<void> {
    if (this.flushAlarmEnsured) return;
    this.flushAlarmEnsured = true;
    const existing = await this.state.storage.getAlarm();
    if (existing === null) {
      await this.state.storage.setAlarm(Date.now() + COUNTER_FLUSH_MS);
    }
  }

  // -------------------------------------------------------------------------
  // Accounting
  // -------------------------------------------------------------------------

  private async flushCountersToStorage(): Promise<void> {
    if (!this.counterDeltaDirty) return;
    const stored = (await this.state.storage.get<UsageCounters>(KEY_COUNTERS)) ?? zeroCounters();
    stored.bytesClientToHost += this.counterDelta.bytesClientToHost;
    stored.bytesHostToClient += this.counterDelta.bytesHostToClient;
    stored.clientConnects += this.counterDelta.clientConnects;
    stored.peakConcurrentClients = Math.max(
      stored.peakConcurrentClients,
      this.counterDelta.peakConcurrentClients,
    );
    await this.state.storage.put(KEY_COUNTERS, stored);
    this.counterDelta = zeroCounters();
    this.counterDeltaDirty = false;
  }

  // Push-based durable flush: DOs hibernate, so a Cron pull can't reach an idle DO — the write
  // must originate here (alarm + last-socket close). Additive UPSERT into relay_daily_usage;
  // touch relay_servers. On failure keep d1Pending for the next alarm (bounded, drop-with-log
  // beyond the cap). Never blocks frame forwarding. Only serverId, counts, and dates cross into D1.
  private async flushUsageToD1(): Promise<void> {
    if (isUsageDeltaEmpty(this.d1Pending)) return;

    const db = this.env.DB;
    if (!db) {
      // No binding (e.g. local dev without D1). Don't accumulate unbounded — apply the cap.
      const outcome = nextPendingAfterFlush(this.d1Pending, false, D1_PENDING_MAX_BYTES);
      if (outcome.dropped) {
        console.log('[relay] D1 usage dropped: no DB binding and pending exceeded cap');
      }
      this.d1Pending = outcome.pending;
      return;
    }

    const serverId = await this.resolveServerId();
    if (!serverId) {
      // Can't attribute the usage yet; keep it (bounded) and retry once serverId is known.
      const outcome = nextPendingAfterFlush(this.d1Pending, false, D1_PENDING_MAX_BYTES);
      if (outcome.dropped) {
        console.log('[relay] D1 usage dropped: unknown serverId and pending exceeded cap');
      }
      this.d1Pending = outcome.pending;
      return;
    }

    const nowMs = Date.now();
    const nowSec = Math.floor(nowMs / 1000);
    const usageDate = utcUsageDate(nowMs);
    const pending = this.d1Pending;

    let success = false;
    try {
      await db.batch([
        db
          .prepare(
            'INSERT INTO relay_servers (server_id, first_seen_at, last_seen_at) VALUES (?, ?, ?) ' +
              'ON CONFLICT(server_id) DO UPDATE SET ' +
              'first_seen_at = MIN(first_seen_at, excluded.first_seen_at), ' +
              'last_seen_at = excluded.last_seen_at',
          )
          .bind(serverId, nowSec, nowSec),
        db
          .prepare(
            'INSERT INTO relay_daily_usage ' +
              '(usage_date, server_id, bytes_up, bytes_down, client_connects, peak_concurrent_clients, messages) ' +
              'VALUES (?, ?, ?, ?, ?, ?, ?) ' +
              'ON CONFLICT(usage_date, server_id) DO UPDATE SET ' +
              'bytes_up = bytes_up + excluded.bytes_up, ' +
              'bytes_down = bytes_down + excluded.bytes_down, ' +
              'client_connects = client_connects + excluded.client_connects, ' +
              'peak_concurrent_clients = MAX(peak_concurrent_clients, excluded.peak_concurrent_clients), ' +
              'messages = messages + excluded.messages',
          )
          .bind(
            usageDate,
            serverId,
            pending.bytesUp,
            pending.bytesDown,
            pending.clientConnects,
            pending.peakConcurrentClients,
            pending.messages,
          ),
      ]);
      success = true;
    } catch (error) {
      console.log(
        `[relay] D1 usage flush failed serverId=${serverId} (retaining pending): ${
          error instanceof Error ? error.message : 'unknown'
        }`,
      );
    }

    const outcome = nextPendingAfterFlush(this.d1Pending, success, D1_PENDING_MAX_BYTES);
    if (outcome.dropped) {
      console.log(`[relay] D1 usage dropped: pending exceeded cap after failure serverId=${serverId}`);
    }
    this.d1Pending = outcome.pending;
  }

  private async rememberServerId(serverId: string): Promise<void> {
    if (this.serverId === serverId) return;
    this.serverId = serverId;
    await this.state.storage.put(KEY_SERVER_ID, serverId);
  }

  private async resolveServerId(): Promise<string | null> {
    if (this.serverId) return this.serverId;
    const stored = await this.state.storage.get<string>(KEY_SERVER_ID);
    if (stored) {
      this.serverId = stored;
      return stored;
    }
    // Last resort: read it off any live socket attachment.
    for (const ws of this.state.getWebSockets()) {
      const attachment = readAttachment(ws);
      if (attachment?.serverId) {
        this.serverId = attachment.serverId;
        return attachment.serverId;
      }
    }
    return null;
  }

  // Used by the (future) Phase 5 D1 flush pipeline and by checkLimits.
  async getUsageSnapshot(): Promise<UsageSnapshot> {
    const stored = (await this.state.storage.get<UsageCounters>(KEY_COUNTERS)) ?? zeroCounters();
    return {
      bytesClientToHost: stored.bytesClientToHost + this.counterDelta.bytesClientToHost,
      bytesHostToClient: stored.bytesHostToClient + this.counterDelta.bytesHostToClient,
      clientConnects: stored.clientConnects + this.counterDelta.clientConnects,
      peakConcurrentClients: Math.max(
        stored.peakConcurrentClients,
        this.counterDelta.peakConcurrentClients,
      ),
      concurrentClients: this.countConcurrentClients(),
    };
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private countConcurrentClients(): number {
    return this.listClientConnectionIds().length;
  }

  private listClientConnectionIds(): string[] {
    const out = new Set<string>();
    for (const ws of this.state.getWebSockets(TAG_CLIENT)) {
      const attachment = readAttachment(ws);
      if (attachment?.role === 'client' && attachment.connectionId) {
        out.add(attachment.connectionId);
      }
    }
    return Array.from(out);
  }

  private notifyControl(message: { type: string; connectionId?: string; connectionIds?: string[] }): void {
    const text = JSON.stringify(message);
    for (const ws of this.state.getWebSockets(TAG_HOST_CONTROL)) {
      try {
        ws.send(text);
      } catch {
        console.log('[relay] control send failed');
      }
    }
  }

  private async getStuckDeadlines(): Promise<Record<string, number>> {
    return (await this.state.storage.get<Record<string, number>>(KEY_STUCK_DEADLINES)) ?? {};
  }

  private async setStuckDeadline(connectionId: string, deadline: number): Promise<void> {
    const stuck = await this.getStuckDeadlines();
    stuck[connectionId] = deadline;
    await this.state.storage.put(KEY_STUCK_DEADLINES, stuck);
  }

  private async clearStuckDeadline(connectionId: string): Promise<void> {
    const stuck = await this.getStuckDeadlines();
    if (!(connectionId in stuck)) return;
    delete stuck[connectionId];
    await this.state.storage.put(KEY_STUCK_DEADLINES, stuck);
  }

  private async getBufferedFlags(): Promise<Record<string, boolean>> {
    return (await this.state.storage.get<Record<string, boolean>>(KEY_BUFFERED_FLAGS)) ?? {};
  }

  private async setBufferedFlag(connectionId: string, value: boolean): Promise<void> {
    const flags = await this.getBufferedFlags();
    if (value) {
      flags[connectionId] = true;
    } else {
      if (!(connectionId in flags)) return;
      delete flags[connectionId];
    }
    await this.state.storage.put(KEY_BUFFERED_FLAGS, flags);
  }
}
