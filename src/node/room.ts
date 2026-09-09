// RelayRoom — the Node counterpart of the Cloudflare RelayDurableObject: one instance per
// serverId, the meeting point between a host (control + per-connection data sockets) and its
// clients. Implements Layer 1 of the private-relay protocol spec.
//
// Simpler than the DO by design: a long-lived Node process never hibernates, so sockets,
// buffers, and timers just live in memory — no storage keys, no alarms, no buffered-flag
// recovery. The wire behavior (close codes, buffering limits, timers, abuse guards) is
// identical; scripts/smoke.ts passes unchanged against both adapters.
//
// PRIVACY INVARIANT: this object never parses, logs, or stores forwarded frame contents.
// Logs contain serverId / connectionId / status codes only.

import type { WebSocket } from 'ws';
import {
  CLOSE_CONTROL_REPLACED,
  CLOSE_DUPLICATE_CLIENT,
  CLOSE_HOST_UNAVAILABLE,
  CLOSE_LIMIT_EXCEEDED,
  CLOSE_SERVICE_RESTART,
  CLOSE_STUCK_CONTROL,
  CONTROL_LOSS_GRACE_MS,
  MAX_CLIENT_CONNECTS_PER_MIN,
  MAX_CONCURRENT_CLIENTS,
  PENDING_MAX_BYTES,
  PENDING_MAX_FRAMES,
  STUCK_CONTROL_MS,
} from '../core/protocol';
import {
  isUsageDeltaEmpty,
  recordConnect,
  recordFrameDown,
  recordFrameUp,
  recordMessage,
  zeroUsageDelta,
  type UsageDelta,
} from '../core/usage-accumulator';

type BufferedFrame = { data: Buffer; isBinary: boolean };
type PendingBuffer = { frames: BufferedFrame[]; bytes: number };

const safeClose = (ws: WebSocket, code: number, reason: string): void => {
  try {
    ws.close(code, reason);
  } catch {
    // ignore
  }
};

const safeSend = (ws: WebSocket, data: Buffer | string, isBinary: boolean): boolean => {
  try {
    ws.send(data, { binary: isBinary });
    return true;
  } catch {
    return false;
  }
};

export class RelayRoom {
  readonly serverId: string;

  private control: WebSocket | null = null;
  private readonly dataSockets = new Map<string, WebSocket>();
  private readonly clients = new Map<string, WebSocket>();
  private readonly pending = new Map<string, PendingBuffer>();

  private readonly stuckTimers = new Map<string, NodeJS.Timeout>();
  private controlGraceTimer: NodeJS.Timeout | null = null;

  // Rolling client-connect timestamps for the per-minute rate guard.
  private clientConnectTimes: number[] = [];

  // Usage accumulated since the last successful synchronous write.
  usageDelta: UsageDelta = zeroUsageDelta();

  constructor(serverId: string) {
    this.serverId = serverId;
  }

  isEmpty(): boolean {
    return this.control === null && this.dataSockets.size === 0 && this.clients.size === 0;
  }

  // Called by the server when the room is evicted so no timers keep the process alive.
  dispose(): void {
    for (const timer of this.stuckTimers.values()) clearTimeout(timer);
    this.stuckTimers.clear();
    if (this.controlGraceTimer) {
      clearTimeout(this.controlGraceTimer);
      this.controlGraceTimer = null;
    }
  }

  flushUsage(write: (delta: UsageDelta) => void): void {
    if (isUsageDeltaEmpty(this.usageDelta)) return;
    write(this.usageDelta);
    this.usageDelta = zeroUsageDelta();
  }

  // ---------------------------------------------------------------------------
  // Connect handling
  // ---------------------------------------------------------------------------

  connectHostControl(ws: WebSocket): void {
    // Exactly one active host-control per serverId; a new one replaces the old.
    if (this.control) {
      const old = this.control;
      this.control = null; // prevent the old socket's close handler from tearing anything down
      safeClose(old, CLOSE_CONTROL_REPLACED, 'Control replaced');
    }
    if (this.controlGraceTimer) {
      clearTimeout(this.controlGraceTimer);
      this.controlGraceTimer = null;
    }
    this.control = ws;

    console.log(`[relay] host-control connected serverId=${this.serverId}`);

    ws.on('message', (data: Buffer, isBinary: boolean) => {
      recordMessage(this.usageDelta);
      // No host->relay control messages are defined in v1; ignore without parsing.
      void data;
      void isBinary;
    });
    ws.on('close', () => this.onControlClose(ws));
    ws.on('error', () => console.log(`[relay] socket error role=host-control serverId=${this.serverId}`));

    // Tell the host which clients are already waiting so it can attach data sockets.
    try {
      ws.send(JSON.stringify({ type: 'sync', connectionIds: Array.from(this.clients.keys()) }));
    } catch {
      // ignore
    }
  }

  connectHostData(connectionId: string, ws: WebSocket): void {
    // One host-data socket per connection; replace any stale one.
    const stale = this.dataSockets.get(connectionId);
    if (stale) {
      this.dataSockets.delete(connectionId);
      safeClose(stale, 1008, 'Replaced by new connection');
    }
    this.dataSockets.set(connectionId, ws);

    console.log(`[relay] host-data connected serverId=${this.serverId} connectionId=${connectionId}`);

    this.clearStuckTimer(connectionId);

    ws.on('message', (data: Buffer, isBinary: boolean) => {
      recordMessage(this.usageDelta);
      recordFrameDown(this.usageDelta, data.length);
      const client = this.clients.get(connectionId);
      if (client && !safeSend(client, data, isBinary)) {
        console.log(`[relay] forward host->client failed connectionId=${connectionId}`);
      }
    });
    ws.on('close', () => this.onHostDataClose(connectionId, ws));
    ws.on('error', () => console.log(`[relay] socket error role=host-data connectionId=${connectionId}`));

    this.flushPendingFrames(connectionId);
  }

  // Returns a rejection reason when abuse guards fire; the caller completes the upgrade and
  // closes with 4029 so the client receives a proper close code (same as the DO adapter).
  clientRejectionReason(): string | null {
    const now = Date.now();
    this.clientConnectTimes = this.clientConnectTimes.filter((t) => now - t < 60_000);
    if (this.clients.size >= MAX_CONCURRENT_CLIENTS) return 'Too many concurrent clients';
    if (this.clientConnectTimes.length >= MAX_CLIENT_CONNECTS_PER_MIN) return 'Too many connects';
    return null;
  }

  rejectClient(connectionId: string, ws: WebSocket, reason: string): void {
    console.log(
      `[relay] client rejected serverId=${this.serverId} connectionId=${connectionId} code=${CLOSE_LIMIT_EXCEEDED}`,
    );
    safeClose(ws, CLOSE_LIMIT_EXCEEDED, reason);
  }

  connectClient(connectionId: string, ws: WebSocket): void {
    this.clientConnectTimes.push(Date.now());

    // Duplicate client with the same connectionId: close the old socket.
    const duplicate = this.clients.get(connectionId);
    if (duplicate) {
      this.clients.delete(connectionId);
      safeClose(duplicate, CLOSE_DUPLICATE_CLIENT, 'Duplicate client');
    }
    this.clients.set(connectionId, ws);

    console.log(`[relay] client connected serverId=${this.serverId} connectionId=${connectionId}`);

    recordConnect(this.usageDelta, this.clients.size);

    ws.on('message', (data: Buffer, isBinary: boolean) => {
      recordMessage(this.usageDelta);
      recordFrameUp(this.usageDelta, data.length);
      const target = this.dataSockets.get(connectionId);
      if (!target) {
        this.bufferFrame(connectionId, { data, isBinary }, ws);
        return;
      }
      if (!safeSend(target, data, isBinary)) {
        console.log(`[relay] forward client->host failed connectionId=${connectionId}`);
      }
    });
    ws.on('close', () => this.onClientClose(connectionId, ws));
    ws.on('error', () => console.log(`[relay] socket error role=client connectionId=${connectionId}`));

    this.notifyControl({ type: 'connected', connectionId });

    // Stuck-control detection: if no host-data socket appears for this client within 15 s,
    // force-close the control socket so the host reconnects.
    if (!this.dataSockets.has(connectionId)) {
      this.setStuckTimer(connectionId);
    }
  }

  // ---------------------------------------------------------------------------
  // Buffering (client frames while host-data is absent)
  // ---------------------------------------------------------------------------

  private bufferFrame(connectionId: string, frame: BufferedFrame, clientWs: WebSocket): void {
    let buffer = this.pending.get(connectionId);
    if (!buffer) {
      buffer = { frames: [], bytes: 0 };
      this.pending.set(connectionId, buffer);
    }

    if (
      buffer.frames.length + 1 > PENDING_MAX_FRAMES ||
      buffer.bytes + frame.data.length > PENDING_MAX_BYTES
    ) {
      console.log(`[relay] buffer overflow connectionId=${connectionId} code=${CLOSE_HOST_UNAVAILABLE}`);
      this.pending.delete(connectionId);
      safeClose(clientWs, CLOSE_HOST_UNAVAILABLE, 'host unavailable');
      return;
    }

    buffer.frames.push(frame);
    buffer.bytes += frame.data.length;
  }

  private flushPendingFrames(connectionId: string): void {
    const buffer = this.pending.get(connectionId);
    if (!buffer) return;
    this.pending.delete(connectionId);

    const target = this.dataSockets.get(connectionId);
    if (!target) return;
    for (const frame of buffer.frames) {
      if (!safeSend(target, frame.data, frame.isBinary)) {
        console.log(`[relay] flush failed connectionId=${connectionId}`);
        return;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Close handling
  // ---------------------------------------------------------------------------

  private onClientClose(connectionId: string, ws: WebSocket): void {
    // Another socket may have replaced this one (duplicate close 4002): only tear down when
    // this socket is still the registered one.
    if (this.clients.get(connectionId) !== ws) return;
    this.clients.delete(connectionId);
    console.log(`[relay] client connectionId=${connectionId} closed serverId=${this.serverId}`);

    this.pending.delete(connectionId);
    this.clearStuckTimer(connectionId);

    const hostData = this.dataSockets.get(connectionId);
    if (hostData) {
      this.dataSockets.delete(connectionId);
      safeClose(hostData, 1001, 'Client disconnected');
    }
    this.notifyControl({ type: 'disconnected', connectionId });
  }

  private onHostDataClose(connectionId: string, ws: WebSocket): void {
    if (this.dataSockets.get(connectionId) !== ws) return;
    this.dataSockets.delete(connectionId);
    console.log(`[relay] host-data connectionId=${connectionId} closed serverId=${this.serverId}`);

    const client = this.clients.get(connectionId);
    if (client) {
      safeClose(client, CLOSE_SERVICE_RESTART, 'Host went away, reconnect');
    }
  }

  private onControlClose(ws: WebSocket): void {
    if (this.control !== ws) return;
    this.control = null;
    console.log(`[relay] host-control closed serverId=${this.serverId}`);

    if (this.clients.size > 0 && !this.controlGraceTimer) {
      // Grace window: leave clients up awaiting control reconnect, then close them all.
      this.controlGraceTimer = setTimeout(() => {
        this.controlGraceTimer = null;
        if (this.control) return;
        // Let onClientClose remove each client and close its paired host-data socket.
        for (const client of this.clients.values()) {
          safeClose(client, CLOSE_SERVICE_RESTART, 'Host went away, reconnect');
        }
      }, CONTROL_LOSS_GRACE_MS);
    }
  }

  // ---------------------------------------------------------------------------
  // Timers + helpers
  // ---------------------------------------------------------------------------

  private setStuckTimer(connectionId: string): void {
    this.clearStuckTimer(connectionId);
    this.stuckTimers.set(
      connectionId,
      setTimeout(() => {
        this.stuckTimers.delete(connectionId);
        if (!this.clients.has(connectionId) || this.dataSockets.has(connectionId)) return;
        console.log(`[relay] stuck control reset connectionId=${connectionId} code=${CLOSE_STUCK_CONTROL}`);
        // Close without unregistering: onControlClose runs and starts the control-loss grace
        // window, mirroring the DO adapter's behavior after a 4003 reset.
        if (this.control) {
          safeClose(this.control, CLOSE_STUCK_CONTROL, 'Control unresponsive');
        }
      }, STUCK_CONTROL_MS),
    );
  }

  private clearStuckTimer(connectionId: string): void {
    const timer = this.stuckTimers.get(connectionId);
    if (timer) {
      clearTimeout(timer);
      this.stuckTimers.delete(connectionId);
    }
  }

  private notifyControl(message: { type: string; connectionId?: string }): void {
    if (!this.control) return;
    try {
      this.control.send(JSON.stringify(message));
    } catch {
      console.log('[relay] control send failed');
    }
  }
}
