# TypeScript + jose demo (Claimcheck)

Small local example with:
- `server`: local verifier API using `jose` + remote JWKS (`claimcheck.fly.dev`)
- `client`: fetches `skills.md`, mints a token from Claimcheck, sends token to local verifier

## Prerequisites
- Node.js 20+

## Install
```bash
cd examples/typescript-jose-demo
npm install
```

## Run verifier server
```bash
npm run server
```

## Run client flow (in another terminal)
```bash
npm run client
```

## Verify any token from file
```bash
npm run verify -- ./token.txt
```

## Optional env vars
- `CLAIMCHECK_BASE_URL` (default: `https://claimcheck.fly.dev`)
- `CLAIMCHECK_PROVIDER` (default: `k8s-sa`)
- `CLAIMCHECK_ISSUER` (default: same as base URL)
- `CLAIMCHECK_AUDIENCE` (default: `kubernetes.default.svc`)
- `LOCAL_SERVER_PORT` (default: `4040`)
