// Relay protocol constants shared by every adapter. These are part of the wire contract with
// OpenChamber hosts and clients — keep values in sync with the private-relay protocol spec.

// Close codes.
export const CLOSE_CONTROL_REPLACED = 4001;
export const CLOSE_DUPLICATE_CLIENT = 4002;
export const CLOSE_STUCK_CONTROL = 4003;
export const CLOSE_HOST_UNAVAILABLE = 4008;
export const CLOSE_LIMIT_EXCEEDED = 4029;
export const CLOSE_SERVICE_RESTART = 1012;

// Client->host frames buffered while the matching host-data socket is absent.
export const PENDING_MAX_FRAMES = 200;
export const PENDING_MAX_BYTES = 2 * 1024 * 1024; // 2 MiB

// Timers.
export const STUCK_CONTROL_MS = 15_000; // no host-data for a client -> reset control
export const CONTROL_LOSS_GRACE_MS = 30_000; // control gone -> close clients after grace
export const COUNTER_FLUSH_MS = 60_000; // usage flush cadence

// Abuse guards (the only limits enforced in v1).
export const MAX_CONCURRENT_CLIENTS = 16;
export const MAX_CLIENT_CONNECTS_PER_MIN = 60;

export const HEALTH_BODY = { ok: true, service: 'openchamber-relay' } as const;
