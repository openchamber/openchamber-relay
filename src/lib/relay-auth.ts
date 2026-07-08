// Host authentication for the data relay. Copied from apps/api/src/lib/relay-auth.ts (repo has
// no shared package layer — duplication is the convention). Each OpenChamber server has an ECDSA
// P-256 keypair; the SHA-256 of its canonical public JWK is its self-certifying `serverId`.
// Relay WS upgrades for host-* roles carry `ts`, `sig`, `pk` query params; the signature payload
// is `${ts}.${serverId}.${role}.${connectionId ?? ""}` and must be fresh within ±5 minutes.
// No secret is stored in the relay: the public key arrives with each connection and the serverId
// is derived from it.
//
// IMPORTANT: `deriveServerId` (canonical JWK serialization + SHA-256 + base64url) must stay
// byte-identical to apps/api/src/lib/relay-auth.ts — the same keypair must yield the same
// serverId for both the push relay and this data relay.

export type PublicKeyJwk = { kty: 'EC'; crv: 'P-256'; x: string; y: string };

const SIGNATURE_WINDOW_MS = 5 * 60 * 1000;

const base64UrlToBytes = (value: string): ArrayBuffer => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
};

const base64UrlFromBytes = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

// Fixed key order so the hash is stable regardless of incoming JSON field order.
const canonicalJwk = (jwk: PublicKeyJwk): string =>
  JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });

export const deriveServerId = async (jwk: PublicKeyJwk): Promise<string> => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalJwk(jwk)));
  return base64UrlFromBytes(digest);
};

export const isFreshTimestamp = (ts: number): boolean =>
  Number.isFinite(ts) && Math.abs(Date.now() - ts) <= SIGNATURE_WINDOW_MS;

// Relay WS signature payload. `connectionId` is empty for host-control.
export const buildSignaturePayload = (
  ts: number,
  serverId: string,
  role: string,
  connectionId?: string | null,
): string => `${ts}.${serverId}.${role}.${connectionId ?? ''}`;

// Signature payload for the authenticated `GET /usage/:serverId` read endpoint. The host signs
// `${ts}.usage.${serverId}` with the same ECDSA key it uses for WS handshakes.
export const buildUsagePayload = (ts: number, serverId: string): string =>
  `${ts}.usage.${serverId}`;

export const verifySignature = async (
  jwk: PublicKeyJwk,
  message: string,
  signatureB64Url: string,
): Promise<boolean> => {
  try {
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      base64UrlToBytes(signatureB64Url),
      new TextEncoder().encode(message),
    );
  } catch {
    return false;
  }
};

// Query params arrive as base64url(JSON(JWK)). Strict shape check; reject anything unexpected.
export const parsePublicKeyParam = (value: string): PublicKeyJwk | null => {
  try {
    const bytes = base64UrlToBytes(value);
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const jwk = parsed as Record<string, unknown>;
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') return null;
    if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return null;
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  } catch {
    return null;
  }
};
