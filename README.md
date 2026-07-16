# OpenChamber Relay (self-hosted)

Run your own [OpenChamber](https://openchamber.dev) private relay — on Cloudflare, in Docker, or as a plain Node process. Your desktops, servers, and phones connect to *your* relay instead of the shared one; the traffic never touches OpenChamber-hosted infrastructure.

The relay is a thin, **stateless broker**: your OpenChamber instance dials outbound to it, your clients dial outbound to it, and it forwards the (already end-to-end-encrypted) frames between them. It **cannot read your traffic** — encryption happens between your instance and your client, not at the relay. It stores no secrets and requires none.

## Why self-host

- **Your own trust boundary.** The relay is blind either way (E2EE), but self-hosting keeps the metadata (which server ids connect, when) on infrastructure you control — including fully private networks where external services are off-limits.
- **Your own domain.** `wss://relay.example.com/ws` instead of the shared endpoint.
- **Your own quota.** Run a relay for yourself, friends, or a team without touching anyone else's limits.

## Pick a deployment

Both adapters implement the exact same wire protocol and pass the same conformance suite (`npm run smoke`).

| | Best for |
|---|---|
| [Cloudflare Workers](#option-a-cloudflare-workers) | Zero servers to run; free tier covers personal/team use; ~2 minutes |
| [Docker](#option-b-docker) | Enterprises and homelabs; fully private infrastructure |
| [Bare Node](#option-c-bare-node) | Anywhere Node ≥ 22.5 runs; no containers |

### Option A: Cloudflare Workers

You need a free [Cloudflare account](https://dash.cloudflare.com/sign-up) and [Node](https://nodejs.org) (or Bun).

```sh
git clone <this-repo> openchamber-relay && cd openchamber-relay
npm install
npx wrangler login          # opens the browser once
npx wrangler deploy         # deploys the worker
```

`wrangler deploy` prints your relay URL, e.g. `https://openchamber-relay.<your-account>.workers.dev`. Your relay WebSocket endpoint is that host with `/ws` and the `wss://` scheme:

```
wss://openchamber-relay.<your-account>.workers.dev/ws
```

Check it's alive: open `https://<that-host>/health` — it should return `{"ok":true,"service":"openchamber-relay"}`.

**Custom domain:** Cloudflare dashboard → **Workers & Pages → your worker → Settings → Domains & Routes → Add → Custom domain** (the domain must be on your Cloudflare account). Your endpoint becomes `wss://relay.example.com/ws`.

**Optional usage accounting (D1):**

```sh
npx wrangler d1 create openchamber-relay
# put the printed database_id into the d1_databases block in wrangler.jsonc (uncomment it)
npx wrangler d1 migrations apply openchamber-relay --remote
npx wrangler deploy
```

### Option B: Docker

```sh
docker run -d -p 8788:8788 --name openchamber-relay \
  ghcr.io/<owner>/openchamber-relay:latest
```

Or build locally: `docker build -t openchamber-relay . && docker run -d -p 8788:8788 openchamber-relay`.

The relay listens for plain HTTP/WS on port 8788 — **terminate TLS in front of it** (OpenChamber connects over `wss://`). [`deploy/docker-compose.yml`](deploy/docker-compose.yml) is a complete production setup with Caddy doing automatic Let's Encrypt certificates:

```sh
cd deploy
RELAY_DOMAIN=relay.example.com docker compose up -d
```

Your endpoint: `wss://relay.example.com/ws`. Health: `https://relay.example.com/health`.

**Optional usage accounting (SQLite):** set `RELAY_USAGE_DB=/data/usage.sqlite` and mount a volume at `/data` (the compose file already does this).

This image also runs as-is on any container platform — Fly.io, Railway, Render, Kubernetes (probe `/health`).

### Option C: Bare Node

Requires Node ≥ 22.5.

```sh
git clone <this-repo> openchamber-relay && cd openchamber-relay
npm install
npm start                    # listens on 0.0.0.0:8788
```

Environment: `PORT` (default 8788), `HOST` (default 0.0.0.0), `RELAY_USAGE_DB` (path to a SQLite file; enables usage accounting). Put a TLS-terminating reverse proxy (Caddy, nginx, Traefik) in front and forward `/ws`, `/health`, `/usage/*` to it — WebSocket upgrade support required.

## Point OpenChamber at your relay

On each machine that should be reachable through your relay, set the env var before starting OpenChamber:

```sh
OPENCHAMBER_RELAY_URL="wss://relay.example.com/ws"
```

That's all the server side needs. **Clients need no configuration** — when you enable the relay and generate a pairing QR/link in *Settings → Remote Instances*, the relay URL is embedded in it, so scanning devices automatically connect to your relay.

(If you can't set an env var in your setup, the same value can be passed to the relay enable API; the env var simply pins it and takes precedence.)

## Usage accounting (optional, both adapters)

The relay works fully without any database. With one bound (D1 on Cloudflare, SQLite elsewhere), it keeps per-server daily counters: bytes up/down, connects, peak concurrency, messages. A host can read its own usage from `GET /usage/<serverId>` (signed with its identity key). **No IPs or payloads are ever stored.**

## How it works (short version)

- One relay "room" per host instance, keyed by a self-certifying `serverId` (the hash of the host's public key). Hosts authenticate with a signed handshake; no accounts, no stored secrets. On Cloudflare a room is a Durable Object; on Node it's an in-memory object in a single long-lived process.
- Frames are forwarded verbatim and never parsed or logged. Confidentiality and integrity are provided end-to-end by the OpenChamber client and host, not by the relay.
- The protocol core (`src/core/`) — handshake validation, auth, accounting — is shared; `src/cloudflare/` and `src/node/` are thin adapters over it.

**Scaling note (Node adapter):** one process holds all rooms in memory. That comfortably covers a team — the relay only forwards frames. Running multiple instances would require routing by `serverId` (sticky hashing); if you need that, open an issue.

## Development

```sh
npm run dev        # Cloudflare adapter via wrangler dev (http://127.0.0.1:8788)
npm run dev:node   # Node adapter with reload
npm run check      # typecheck both adapters
npm test           # unit tests (bun)
npm run smoke      # conformance suite — run against either adapter:
                   #   RELAY_URL=ws://127.0.0.1:8788 npm run smoke
```

CI runs the same smoke suite against the Node server, `wrangler dev`, and the Docker image on every push.

## License

[Functional Source License, v1.1, Apache 2.0 future](LICENSE.md) (FSL-1.1-ALv2): free to use, self-host, modify, and redistribute for anything except offering a competing commercial relay service. Each release becomes Apache 2.0 two years after publication.
