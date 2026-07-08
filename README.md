# OpenChamber Relay (self-hosted)

Run your own [OpenChamber](https://openchamber.dev) private relay on your own Cloudflare account and domain. Your desktops, servers, and phones connect to *your* relay instead of the shared one — the traffic never touches OpenChamber-hosted infrastructure.

The relay is a thin, **stateless broker**: your OpenChamber instance dials outbound to it, your clients dial outbound to it, and it forwards the (already end-to-end-encrypted) frames between them. It **cannot read your traffic** — encryption happens between your instance and your client, not at the relay. It stores no secrets and requires none.

## Why self-host

- **Your own quota.** Cloudflare's free tier is generous; run a relay for yourself, friends, or a team without touching anyone else's limits.
- **Your own domain.** `wss://relay.example.com/ws` instead of the shared endpoint.
- **Your own trust boundary.** The relay is blind either way (E2EE), but self-hosting keeps the metadata (which server ids connect, when) on infrastructure you control.

## Deploy (about 2 minutes)

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

### Optional: a custom domain

In the Cloudflare dashboard → **Workers & Pages → your worker → Settings → Domains & Routes → Add → Custom domain**, add e.g. `relay.example.com` (the domain must be on your Cloudflare account). Your endpoint becomes `wss://relay.example.com/ws`.

## Point OpenChamber at your relay

On each machine that should be reachable through your relay, set the env var before starting OpenChamber:

```sh
OPENCHAMBER_RELAY_URL="wss://relay.example.com/ws"
```

That's all the server side needs. **Clients need no configuration** — when you enable the relay and generate a pairing QR/link in *Settings → Remote Instances*, the relay URL is embedded in it, so scanning devices automatically connect to your relay.

(If you can't set an env var in your setup, the same value can be passed to the relay enable API; the env var simply pins it and takes precedence.)

## Optional: usage accounting

The relay works fully without any database. If you want per-server traffic/device counters (useful for a team), bind a D1 database:

```sh
npx wrangler d1 create openchamber-relay
# put the printed database_id into the d1_databases block in wrangler.jsonc (uncomment it)
npx wrangler d1 migrations apply openchamber-relay --remote
npx wrangler deploy
```

Counters are written per server id (bytes up/down, connections, peak concurrency, messages). A host can read its own usage from `GET /usage/<serverId>` (signed with its identity key). No IPs or payloads are ever stored.

## How it works (short version)

- One Durable Object per host instance, keyed by a self-certifying `serverId` (the hash of the host's public key). Hosts authenticate to the relay with a signed handshake; no accounts, no stored secrets.
- WebSocket Hibernation keeps idle relays at near-zero cost; Cloudflare answers keepalive pings at the edge without waking the object.
- Frames are forwarded verbatim and never parsed or logged. Confidentiality and integrity are provided end-to-end by the OpenChamber client and host, not by the relay.

## Local development

```sh
npm run dev      # wrangler dev on http://127.0.0.1:8788
npm run smoke    # end-to-end smoke test against a local `wrangler dev`
npm run check    # typecheck
```

## License

Private. For your own and your team's use.
