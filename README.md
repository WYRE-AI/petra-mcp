# Petra Security MCP Server

Read-only MCP server for [Petra Security](https://www.petrasecurity.com/)'s public REST API, for AI assistants and the WYRE Conduit gateway. Petra detects and investigates Microsoft 365 account compromises (BEC, session hijacks). This server exposes its incidents, failed attacks, posture reports, tenants, usage and billable users.

## Authentication

A Petra **Admin** creates an API key at [app.petrasecurity.com](https://app.petrasecurity.com) under **Settings > API Keys**. The full key is shown only once, so store it in a secrets manager immediately. Full Members can see the key list but cannot create keys.

Every request goes to `https://api.petrasecurity.com` with `Authorization: Bearer <key>` and a `User-Agent` header (Petra returns 403 without one). The host is fixed and cannot be changed by request headers or tool arguments.

Petra rate-limits each route to **10 requests per minute**. A 429 comes back as a tool error that names the `Retry-After-public-api` wait. To spare that budget, successful responses are cached in memory per API key (keyed by a SHA-256 of the key) for 60 seconds, and `/v1/failed-attacks` for 5 minutes. Identical concurrent requests share one upstream call.

## Configuration

Copy [`.env.example`](.env.example) and set the variables below. The stdio transport reads `PETRA_API_KEY` and does not use `CONDUIT_S2S_SECRET`.

| Env var | Description |
|---|---|
| `PETRA_API_KEY` | Petra API key. Required for stdio and `AUTH_MODE=env`. Not read in gateway mode. |
| `MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `AUTH_MODE` | `env` (default, reads `PETRA_API_KEY`) or `gateway` (Docker image and Compose default). Gateway mode requires `X-Petra-Api-Key` on each `/mcp` request and never falls back to `PETRA_API_KEY`. |
| `CONDUIT_S2S_SECRET` | Required for HTTP. HMAC secret checked against `X-Gateway-S2S` on `/mcp`. Generate with `openssl rand -hex 32`. If empty or a known placeholder, the HTTP server logs an error and exits non-zero. The value is never logged. |
| `MCP_ALLOW_INSECURE_DEV` | Set to exactly `1` to start HTTP without `CONDUIT_S2S_SECRET`. Logs a warning, does not enforce `X-Gateway-S2S`, and binds `127.0.0.1` only. A non-loopback `MCP_HTTP_HOST` refuses to start. A known placeholder secret is still refused. Local development only. |
| `MCP_HTTP_HOST` | Bind address when `MCP_TRANSPORT=http`. Defaults to `127.0.0.1`. A configured `CONDUIT_S2S_SECRET` honors this value. The container image sets `0.0.0.0`. |
| `MCP_HTTP_PORT` | HTTP port. Defaults to `8080`. |
| `LOG_LEVEL` | `debug` \| `info` (default) \| `warn` \| `error`. |

`/health` and `/healthz` stay unauthenticated and do not read credentials.

### HTTP authentication

With `MCP_TRANSPORT=http` and `CONDUIT_S2S_SECRET` set, every `/mcp` request must include `X-Gateway-S2S`. The check is `verifyS2sHeader` in [`src/s2s-verify.ts`](src/s2s-verify.ts): the header value is `t=<unix seconds>,v1=<hex>`, where the hex is HMAC-SHA256 of the literal string `t=<unix seconds>` keyed with `CONDUIT_S2S_SECRET` (64 lowercase hex characters). The timestamp must be within 300 seconds of the server clock. A missing or invalid header is HTTP 401, before vendor credentials are read. An empty secret refuses to start unless `MCP_ALLOW_INSECURE_DEV=1`. A known placeholder (`replace-with-a-real-secret`, `your-s2s-secret`, `changeme`, `change-me`, `placeholder`, `secret`, `example`, `replace-me`, `s2s-secret`, any case) refuses to start even with that flag, so a copied example cannot forge the header.

```bash
TS=$(date +%s)
SIG=$(printf 't=%s' "$TS" | openssl dgst -sha256 -hmac "$CONDUIT_S2S_SECRET" -hex | awk '{print $NF}')
curl -sS http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "X-Gateway-S2S: t=${TS},v1=${SIG}" \
  -H "X-Petra-Api-Key: $PETRA_API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

In `AUTH_MODE=gateway`, `/mcp` also requires `X-Petra-Api-Key`. That header is the only credential source for the request. A request without it returns 401 and does not fall back to `PETRA_API_KEY` in the process environment.

`AUTH_MODE=env` still requires a valid `X-Gateway-S2S` header, then uses `PETRA_API_KEY` from the environment.

### Request limits

- HTTP request bodies are capped at 256 KiB (262144 bytes). After the `X-Gateway-S2S` check passes, a `Content-Length` above the cap returns 413 with a JSON-RPC error; bodies without `Content-Length` are capped by the MCP SDK transport. Unauthenticated requests still get 401 first.
- `tools/call` arguments are capped at 10,000 elements (every array item and object key at any depth). Larger inputs return an `isError` tool result and are never dispatched.

These limits address CVE-2026-111768 / GHSA-46jr-4wx8-v453 (memory exhaustion during validation) and GHSA-f897-62hf-6gxq (no request body / batch cap).

## Tools

Every tool is a `GET`, annotated `readOnlyHint: true` and `destructiveHint: false`. Where a tool takes `tenantId`, either the Petra tenant ID (e.g. `ZZk90t`, from `petra_list_tenants` or the `app.petrasecurity.com/tenant/<id>` URL) or the Microsoft tenant ID works.

### Tenants and billing
- `petra_list_tenants` - every client tenant with Petra and Microsoft tenant IDs, onboarding date and paused flag (`GET /v1/tenants`). Optional `nameContains` and `includePaused` filters.
- `petra_get_usage` - organization-wide billing snapshot per tenant: service, billable status, licensed and billable users, prorating, first billable date, plus totals (`GET /v1/usage`). Optional `asOf`, `includePaused` (set `false` so paused tenants don't inflate counts) and `billableStatus`.
- `petra_list_billable_users` - billable users for one tenant with UPN, mail, enabled flag and license SKUs (`GET /v1/billable-users`). Petra documents only the Petra tenant ID here, so a Microsoft tenant ID is resolved through `/v1/tenants` first. Optional `enabledOnly`.

### Security events
- `petra_list_incidents` - M365 compromise incidents, newest first, with user, remediation status, live flag, dwell time and phishing email (`GET /v1/incidents`). Omit `tenantId` for all tenants. `startDate` and `limit` (1-500) go to Petra; `remediationStatus`, `liveOnly`, `userPrincipalName` and `includePhishingEmail` are applied locally after the limit.
- `petra_get_incident` - one incident by ID. Petra has no single-incident route, so this searches the newest 500 (pass `tenantId` to reach older ones in a tenant).
- `petra_get_failed_attacks` - blocked-attack summary for one tenant: total, by country, daily by attack type, and most-targeted users (`GET /v1/failed-attacks`). Defaults to the last 30 days.
- `petra_list_posture_reports` - M365 posture reports: score and grade, control rollup, Global Admin review, top risks and every check with its suggested fix (`GET /v1/posture-reports`). Latest per tenant by default. Optional `includeChecks: false` for a compact view.

## Scope

This server covers the first five tools StackJack ships for Petra (`petra_list_tenants`, `petra_get_usage`, `petra_list_billable_users`, `petra_list_incidents`, `petra_get_failed_attacks`), with the same names, and adds `petra_get_incident` and `petra_list_posture_reports`.

Petra's public API has no write, remediation, pause or scan-trigger routes, so there is nothing to gate. `GET /v1/usage-xlsx` is left out on purpose: it returns a binary spreadsheet and needs a separate Multi-MSP API key.

The request and response shapes come from Petra's published OpenAPI spec (`/docs/api-reference/openapi.json`). Tests mock the API, and nothing has been tested against a live Petra key yet.

## Development

```bash
npm install
npm run build
npm test
npm run lint   # tsc --noEmit
```

## Docker

The image listens on `0.0.0.0` inside the container (`MCP_HTTP_HOST`) and defaults to `AUTH_MODE=gateway`. Startup still refuses to run without a real `CONDUIT_S2S_SECRET`. Publish the port on loopback. In gateway mode, the Petra key arrives on each request as a header and is not read from the environment.

```bash
docker build -t petra-mcp .
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -p 127.0.0.1:8080:8080 \
  petra-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset, defaults `AUTH_MODE` to `gateway`, publishes `127.0.0.1:8080:8080`, and does not set `PETRA_API_KEY` or `env_file`:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `PETRA_API_KEY`:

```bash
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e AUTH_MODE=env \
  -e PETRA_API_KEY=... \
  -p 127.0.0.1:8080:8080 \
  petra-mcp
```

Local HTTP without a secret is development-only. It binds `127.0.0.1` (including when `MCP_HTTP_HOST` is `localhost` or `::1`) and logs a warning. A non-loopback `MCP_HTTP_HOST` makes startup exit. The container image sets `MCP_HTTP_HOST=0.0.0.0`, so the bypass inside Docker also needs `-e MCP_HTTP_HOST=127.0.0.1`. Do not publish that port off loopback.

```bash
MCP_TRANSPORT=http MCP_ALLOW_INSECURE_DEV=1 npm run start:http
```
