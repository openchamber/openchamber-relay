// Limits and shared names for encrypted shares (pages a host hands to another person by link).
// The relay stores only ciphertext; the key travels in the link fragment and is combined with a
// PIN in the browser, so nothing here can read a share.

export const SHARE_KINDS = ['questionnaire', 'walkthrough', 'page'] as const;
export type ShareKind = (typeof SHARE_KINDS)[number];

// Ciphertext of one shared document. Pages can embed up to 25 MB of images plus the renderer.
export const MAX_SHARE_BYTES = 32 * 1024 * 1024;
// Encrypted answer as base64url text: a page answer is at most ~16.5 KB of JSON before encryption.
export const MAX_ANSWER_CHARS = 96 * 1024;

export const MIN_SHARE_LIFETIME_MS = 5 * 60 * 1000;
// The app caps lifetime at two working days, which over a weekend spans four calendar days. The
// relay allows a little more so a host's clock skew never rejects a valid share.
export const MAX_SHARE_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
// After expiry, an answer the host has not collected yet (laptop asleep) and the "already answered"
// tombstone stay this long; then the share is deleted.
export const TOMBSTONE_MS = 7 * 24 * 60 * 60 * 1000;

export const MAX_PIN_FAILURES = 5;
export const MAX_RECORDED_OPENS = 20;
export const MAX_STATE_BATCH = 50;

// Internal path a ShareDurableObject posts to the owner's RelayDurableObject to nudge a live host
// (Cloudflare adapter; the Node adapter calls the room directly).
export const SHARE_STATE_PATH = '/internal/share-state';

export const SHARE_ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;

export const shareObjectName = (shareId: string): string => `share-v1:${shareId}`;
export const shareBlobKey = (shareId: string): string => `shares/${shareId}`;
