// Test helpers for encrypted shares: the browser and host sides of the crypto contract
// (src/core/share/viewer.ts header) and a host identity that signs share calls the way an
// OpenChamber server does.

import { base64UrlFromBytes, buildSharePayload } from '../src/core/relay-auth';

const enc = new TextEncoder();

export const deriveKeys = async (linkKey: Uint8Array<ArrayBuffer>, pin: string) => {
  const base = await crypto.subtle.importKey('raw', linkKey, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const salt = enc.encode(pin);
  const auth = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('openchamber-share-v1 auth') }, base, 256);
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('openchamber-share-v1 enc') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return { auth: base64UrlFromBytes(auth), authBytes: new Uint8Array(auth), key };
};

export const seal = async (key: CryptoKey, value: unknown, aad: string): Promise<Uint8Array<ArrayBuffer>> => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, enc.encode(JSON.stringify(value))));
  const out = new Uint8Array(13 + cipher.length);
  out[0] = 1;
  out.set(iv, 1);
  out.set(cipher, 13);
  return out;
};

export const unseal = async (key: CryptoKey, bytes: Uint8Array<ArrayBuffer>, aad: string): Promise<unknown> =>
  JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(1, 13), additionalData: enc.encode(aad) }, key, bytes.slice(13))));

export type Fetcher = (request: Request) => Promise<Response>;

export const makeHost = async (base: string, fetcher: Fetcher) => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const serverId = base64UrlFromBytes(await crypto.subtle.digest('SHA-256', enc.encode(canonical)));
  const pk = base64UrlFromBytes(enc.encode(canonical).buffer as ArrayBuffer);
  const call = async (method: string, path: string, body: ArrayBuffer, meta = '', tamper?: (h: Record<string, string>) => void) => {
    const ts = Date.now();
    const bodyHash = base64UrlFromBytes(await crypto.subtle.digest('SHA-256', body));
    const sig = base64UrlFromBytes(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, enc.encode(buildSharePayload(ts, serverId, method, path, bodyHash, meta))));
    const headers: Record<string, string> = { 'x-openchamber-ts': String(ts), 'x-openchamber-sig': sig, 'x-openchamber-pk': pk };
    if (meta) headers['x-openchamber-share'] = meta;
    tamper?.(headers);
    return fetcher(new Request(base + path, { method, headers, body }));
  };
  return { serverId, privateKey: pair.privateKey, publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string }, call };
};

export type TestHost = Awaited<ReturnType<typeof makeHost>>;

export const metaHeader = (value: object): string => base64UrlFromBytes(enc.encode(JSON.stringify(value)).buffer as ArrayBuffer);
export const jsonBody = (value: unknown): ArrayBuffer => enc.encode(JSON.stringify(value)).buffer as ArrayBuffer;

export const DOCUMENT = { v: 1, title: 'Migration schema', html: '<p>Pick one</p>' };

export const createShare = async (host: TestHost, options: { wantsAnswer?: boolean; expiresAt?: number } = {}) => {
  const linkKey = crypto.getRandomValues(new Uint8Array(32));
  const pin = '482913';
  const keys = await deriveKeys(linkKey, pin);
  const blob = await seal(keys.key, DOCUMENT, 'openchamber-share-v1 document');
  const authHash = base64UrlFromBytes(await crypto.subtle.digest('SHA-256', keys.authBytes));
  const meta = metaHeader({ kind: 'questionnaire', wantsAnswer: options.wantsAnswer ?? true, expiresAt: options.expiresAt ?? Date.now() + 2 * 86_400_000, authHash });
  const response = await host.call('POST', '/p', blob.buffer, meta);
  return { response, linkKey, pin, keys };
};

export const sealAnswer = async (key: CryptoKey, value: unknown): Promise<string> =>
  base64UrlFromBytes((await seal(key, value, 'openchamber-share-v1 answer')).buffer);
