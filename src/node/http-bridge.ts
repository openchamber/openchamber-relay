// Bridges node:http to the Fetch API for routes shared with the Cloudflare adapter (the share
// routes are a Hono app over Request/Response).

import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const firstHeader = (value: string | string[] | undefined): string | undefined =>
  (Array.isArray(value) ? value[0] : value)?.split(',')[0]?.trim() || undefined;

// The origin the caller used. Behind a TLS-terminating proxy the socket is plain HTTP, so the
// proxy's X-Forwarded-Proto/-Host win. They only shape links handed back to the caller itself;
// SHARE_ORIGIN pins share links regardless.
const requestOrigin = (req: IncomingMessage): string => {
  const proto = firstHeader(req.headers['x-forwarded-proto']);
  const scheme = proto === 'https' || proto === 'http' ? proto : 'http';
  const host = firstHeader(req.headers['x-forwarded-host']) ?? req.headers.host ?? 'relay.local';
  return `${scheme}://${host}`;
};

// The request body as a web stream. Cancelling it (a route refused an oversized body) stops
// reading; `sendWebResponse` then closes the connection instead of draining the rest.
const bodyStream = (req: IncomingMessage): ReadableStream<Uint8Array> =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      req.on('data', (chunk: Buffer) => {
        controller.enqueue(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
        if ((controller.desiredSize ?? 0) <= 0) req.pause();
      });
      req.on('end', () => controller.close());
      req.on('error', (error) => controller.error(error));
      // A client that goes away mid-upload must not leave the route waiting for more.
      req.on('close', () => {
        if (req.complete) return;
        try {
          controller.error(new Error('request aborted'));
        } catch {
          // Already errored or cancelled.
        }
      });
      req.pause();
    },
    pull() {
      req.resume();
    },
    cancel() {
      req.pause();
    },
  }, { highWaterMark: 1 });

export const toWebRequest = (req: IncomingMessage): Request => {
  let url: URL;
  try {
    url = new URL(req.url ?? '/', requestOrigin(req));
  } catch {
    url = new URL(req.url ?? '/', 'http://relay.local');
  }
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const item of value) headers.append(name, item);
    else headers.set(name, value);
  }
  const method = req.method ?? 'GET';
  const hasBody = method !== 'GET' && method !== 'HEAD';
  return new Request(url, {
    method,
    headers,
    body: hasBody ? bodyStream(req) : undefined,
    // Required by Node's fetch for a streamed request body.
    ...(hasBody ? { duplex: 'half' } : {}),
  } as RequestInit);
};

export const sendWebResponse = async (req: IncomingMessage, res: ServerResponse, response: Response): Promise<void> => {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    headers[name] = value;
  });
  // A body the route did not read whole (refused as too large) is not drained: close afterwards.
  const unread = !req.complete;
  if (unread) headers.connection = 'close';
  res.writeHead(response.status, headers);
  if (!response.body || req.method === 'HEAD') {
    await response.body?.cancel().catch(() => {});
    res.end();
  } else {
    // pipeline tears down both sides when either ends early, so a browser that goes away
    // mid-download releases the blob's file handle.
    const body = Readable.fromWeb(response.body as unknown as import('node:stream/web').ReadableStream);
    await pipeline(body, res).catch(() => {});
  }
  if (unread) {
    if (res.writableFinished) req.destroy();
    else res.once('finish', () => req.destroy());
  }
};
