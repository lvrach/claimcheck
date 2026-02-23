# Code Restructure: Introduce Internal Packages

## Goal

Extract the provider abstraction and rate limiter into `internal/` packages to establish clean domain boundaries while keeping the overall footprint minimal.

## Final Layout

```
.
├── main.go                          # bootstrap (unchanged)
├── config.go                        # config loading (unchanged)
├── server.go                        # Server struct, Handler(), middleware, JSON helpers
├── handlers.go                      # route handlers (updated imports)
├── keys.go                          # key management (unchanged)
├── internal/
│   ├── provider/
│   │   ├── provider.go              # TokenProvider interface + shared types
│   │   ├── k8s.go                   # K8sSAProvider + JWT helpers
│   │   └── claims.go                # claim validation
│   └── ratelimit/
│       └── ratelimit.go             # IPLimiter + tokenBucket
├── server_test.go                   # updated imports
```

## What Moves

### `internal/provider/provider.go`
- `TokenProvider` interface
- `MintInput`, `MintOutput`, `ReviewInput`, `ReviewOutput`
- `ProviderSchema`, `SchemaField`

### `internal/provider/k8s.go`
- `K8sSAProvider` struct + `NewK8sSAProvider()`
- `Mint()`, `Review()`, `ID()`, `Description()`, `Schema()`
- `jwkFromKey()`, `parseAudience()`, `audIntersect()`, `parseServiceAccountSub()`, `splitN()`
- `errUnauthenticatedToken` sentinel

### `internal/provider/claims.go`
- `validateClaims()`, `validateClaimValue()`

### `internal/ratelimit/ratelimit.go`
- `IPLimiter` struct, `tokenBucket` struct
- `NewLimiter()` constructor
- `Allow()` method with sweep constants

## What Stays in `main`

- `main.go` — bootstrap, unchanged
- `config.go` — config loading, unchanged
- `keys.go` — key management, unchanged
- `server.go` — Server struct (now imports `provider` and `ratelimit`), routing, middleware, `clientIP()`, JSON helpers
- `handlers.go` — HTTP handlers (updated to use `provider.MintInput` etc.)

## Import Flow

```
main.go → config, keys, server
server.go → internal/provider, internal/ratelimit, keys, config
handlers.go → internal/provider
internal/provider/k8s.go → internal/provider (types), keys (KeyMaterial)
internal/ratelimit → stdlib only
```

## Key Decisions

- `keys.go` stays in `main` — it's only used at startup and passed as a value. Not worth a package.
- `config.go` stays in `main` — startup-only, no other package needs it directly.
- `claims.go` moves into `provider/` — it's only called by `K8sSAProvider.Mint()`.
- `KeyMaterial` stays in `main` (keys.go) — `provider/k8s.go` will accept it as a parameter. To avoid a circular import, `K8sSAProvider` will take the key fields it needs directly (private key + kid) rather than importing a `keys` package.

## Migration Strategy

1. Create `internal/provider/provider.go` with interface and types
2. Create `internal/provider/claims.go` (move from root)
3. Create `internal/provider/k8s.go` (extract from auth.go)
4. Create `internal/ratelimit/ratelimit.go` (extract from server.go)
5. Update `server.go` to import new packages
6. Update `handlers.go` to use `provider.*` types
7. Delete old `auth.go` and `claims.go`
8. Update `server_test.go`
9. Run tests, lint, verify
