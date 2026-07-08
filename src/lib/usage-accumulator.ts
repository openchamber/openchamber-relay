// Pure accounting helpers for the D1 usage flush pipeline. Extracted so the delta accumulation,
// reset-on-success / keep-on-failure retention, and the additive-UPSERT math can be unit-tested
// without a live Durable Object or D1 binding.
//
// PRIVACY: this module deals only in coarse counts (bytes, connects, peak concurrency). It never
// touches serverIds, payloads, IPs, or timestamps.

// Deltas accumulated since the last *successful* D1 write. Distinct from the DO-storage lifetime
// counters — this exists purely to be UPSERTed into relay_daily_usage and zeroed on success.
export type UsageDelta = {
  bytesUp: number; // client -> host
  bytesDown: number; // host -> client
  clientConnects: number;
  peakConcurrentClients: number; // running max since last write
  messages: number; // every WS message delivered to the DO — the Cloudflare DO-request billing unit
};

// A persisted relay_daily_usage row (or the zero row for a not-yet-seen date/server).
export type UsageRow = {
  bytesUp: number;
  bytesDown: number;
  clientConnects: number;
  peakConcurrentClients: number;
  messages: number;
};

export const zeroUsageDelta = (): UsageDelta => ({
  bytesUp: 0,
  bytesDown: 0,
  clientConnects: 0,
  peakConcurrentClients: 0,
  messages: 0,
});

export const isUsageDeltaEmpty = (delta: UsageDelta): boolean =>
  delta.bytesUp === 0 &&
  delta.bytesDown === 0 &&
  delta.clientConnects === 0 &&
  delta.peakConcurrentClients === 0 &&
  delta.messages === 0;

// A forwarded client -> host frame of `size` bytes.
export const recordFrameUp = (delta: UsageDelta, size: number): void => {
  delta.bytesUp += size;
};

// A forwarded host -> client frame of `size` bytes.
export const recordFrameDown = (delta: UsageDelta, size: number): void => {
  delta.bytesDown += size;
};

// One WS message delivered to the DO (any role/direction). Cloudflare bills each incoming
// WebSocket message to a Durable Object as a request, so this is the faithful per-server proxy
// for the DO-request line on the invoice.
export const recordMessage = (delta: UsageDelta): void => {
  delta.messages += 1;
};

// A newly accepted client connection; `concurrentAfter` is the live concurrency after accept.
export const recordConnect = (delta: UsageDelta, concurrentAfter: number): void => {
  delta.clientConnects += 1;
  if (concurrentAfter > delta.peakConcurrentClients) {
    delta.peakConcurrentClients = concurrentAfter;
  }
};

// Simulates the relay_daily_usage UPSERT (additive bytes/connects, MAX peak). The real write uses
// SQL `ON CONFLICT ... DO UPDATE SET bytes_up = bytes_up + excluded.bytes_up, ...,
// peak_concurrent_clients = MAX(peak_concurrent_clients, excluded.peak_concurrent_clients)`.
// Kept here so tests can assert the accumulation math the SQL is expected to produce.
export const applyUsageUpsert = (existing: UsageRow, delta: UsageDelta): UsageRow => ({
  bytesUp: existing.bytesUp + delta.bytesUp,
  bytesDown: existing.bytesDown + delta.bytesDown,
  clientConnects: existing.clientConnects + delta.clientConnects,
  peakConcurrentClients: Math.max(existing.peakConcurrentClients, delta.peakConcurrentClients),
  messages: existing.messages + delta.messages,
});

export type FlushOutcome = { pending: UsageDelta; dropped: boolean };

// Decides the retained pending delta after a D1 flush attempt:
//   - success            -> reset to zero (already durable in D1)
//   - failure, under cap -> keep the delta for retry on the next alarm
//   - failure, over cap  -> explicit drop (loss must never be silent; the caller logs it)
// The cap bounds `bytesUp + bytesDown` so a long D1 outage can't grow memory without limit.
export const nextPendingAfterFlush = (
  delta: UsageDelta,
  success: boolean,
  capBytes: number,
): FlushOutcome => {
  if (success) return { pending: zeroUsageDelta(), dropped: false };
  if (delta.bytesUp + delta.bytesDown > capBytes) {
    return { pending: zeroUsageDelta(), dropped: true };
  }
  return { pending: delta, dropped: false };
};

// UTC YYYY-MM-DD for the given epoch millis — the relay_daily_usage bucket key.
export const utcUsageDate = (nowMs: number): string => new Date(nowMs).toISOString().slice(0, 10);
