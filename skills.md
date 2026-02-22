# Service Skills

## Version
- `1.1.0`

## Base URLs
- Local: `http://localhost:8080`
- Fly: `https://claimcheck.fly.dev`

## Authentication Model
- Anonymous/public test utility. No caller auth required.

## Provider Capabilities
| Provider | Mint | Review | JWKS | Discovery |
|---|---|---|---|---|
| `k8s-sa` (`Kubernetes Service Account` in UI) | yes | yes | yes | yes |

## Endpoints
### GET /
- Home UI with provider selection cards and well-known links.

### GET /providers/{provider}
- Provider workflow UI (claim token + decoded payload + copy/download).

### GET /skills
- JSON mirror for agent/tool consumption.

### GET /health
- Returns liveness and uptime JSON.

### GET /.well-known/jwks.json
- Returns Ed25519 JWKS for token verification.

### GET /.well-known/openid-configuration
- Returns issuer metadata and JWKS URI.

### GET /api/v1/providers
- Lists providers and capabilities.

### GET /api/v1/providers/{provider}/schema
- Returns machine-readable mint/review request schema and limits.

### POST /api/v1/providers/{provider}/mint
- Request JSON:
```json
{
  "namespace": "default",
  "serviceAccount": "build-bot",
  "audiences": ["kubernetes.default.svc"],
  "expirationSeconds": 900,
  "extraClaims": {
    "extra.env": "ci"
  }
}
```
- Response JSON:
```json
{
  "token": "<jwt>",
  "expirationTimestamp": "2026-02-20T12:00:00Z"
}
```

### POST /api/v1/providers/{provider}/review
- Request JSON:
```json
{
  "token": "<jwt>",
  "audiences": ["kubernetes.default.svc"]
}
```
- Response JSON includes `authenticated`, identity fields, and claims.

### POST /api/v1/namespaces/{namespace}/serviceaccounts/{name}/token
- Kubernetes-style TokenRequest wrapper around mint.

### POST /api/v1/tokenreviews
### POST /apis/authentication.k8s.io/v1/tokenreviews
- Kubernetes-style TokenReview wrappers around review.

## Kubernetes SA Testing Flows
1. Mint token via TokenRequest endpoint.
2. Pass token to TokenReview endpoint.
3. Validate token externally via JWKS endpoint.

## TypeScript jose Example
- Local demo path: `examples/typescript-jose-demo`
- Includes:
  - `src/server.ts`: local verifier server using `jose` + Claimcheck JWKS
  - `src/client.ts`: fetches `skills.md`, mints token, verifies token locally
  - `src/verify-token.ts`: verifies token from file
- Quick run:
```bash
cd examples/typescript-jose-demo
npm install
npm run server
# another terminal
npm run client
```

## Agent Quickstart
1. Call `GET /api/v1/providers`.
2. Call `GET /api/v1/providers/k8s-sa/schema`.
3. Call mint endpoint with namespace and service account.
4. Call review endpoint with returned token.
5. If external verification is needed, fetch `/.well-known/jwks.json`.

## Limits and Error Codes
- Rate limit: IP token bucket (`RATE_LIMIT_RPS`, `RATE_LIMIT_BURST`).
- Payload limit: `MAX_BODY_BYTES`.
- TTL bounds: `MIN_TTL_SECONDS`..`MAX_TTL_SECONDS`.
- Error shape:
```json
{"error":"<message>"}
```

## Future Providers
- API and UI are provider-driven.
- Add a provider by implementing the provider interface and registering it.
- Planned providers: AWS, GitHub, GitLab OIDC-style issuers.

## Change Log
- 2026-02-20: Initial agent-consumable skills contract.
- 2026-02-22: Updated for live domain, root/provider UI routes, `/skills` JSON endpoint, provider display naming, and TypeScript `jose` demo.
