# Agent Guidelines (Go Project)

## Purpose
This repository contains a Go-based token testing service focused on Kubernetes service account workflows, extensible provider APIs, and lightweight embedded UI.

## Development Commands
- Format: `make fmt`
- Lint: `make lint`
- Test: `make test`
- Security scan: `make sec`
- Quick test: `go test ./...`

## Go Conventions
- Prefer standard library first.
- Keep handlers small and dependency-explicit.
- Use structured logging (currently `log/slog`) and avoid ad-hoc stdout logging.
- Keep public API routes stable and additive.
- Write table-driven tests for auth and handler behavior.

## Project-Specific Rules
- UI canonical routes are `/` and `/providers/{provider}`.
- `/.well-known/jwks.json`, `/.well-known/openid-configuration`, and `/skills.md` are public contract endpoints.
- `skills.md` must remain agent-consumable and deterministic.
- New providers should plug into the provider registry without changing core route architecture.
- K8s-compatible endpoints (`/api/v1/tokenreviews`, `/apis/authentication.k8s.io/v1/tokenreviews`, `/api/v1/namespaces/.../token`) must use lenient JSON decoding (no `DisallowUnknownFields`) to accept `apiVersion`/`kind` fields.
- Rate limiter (`IPLimiter`) uses amortized sweep eviction — preserve this pattern when modifying.
- `clientIP()` trusts `Fly-Client-IP` first, then rightmost `X-Forwarded-For` — never use the leftmost XFF entry.

## Dependency Preferences
- Keep dependencies minimal and explicit.
- JWT: `github.com/golang-jwt/jwt/v5`.
- Add new third-party dependencies only with clear need and tests.

## Commit/PR Hygiene
- Keep changes scoped and reviewable.
- Run `make test` before merging.
- If API response shapes change, update tests and `skills.md` in the same PR.
- Gitleaks pre-commit hook is active — `.playwright-cli/` and `node_modules/` are gitignored.
- Before initial push, run `openai-review uncommitted` for a second-opinion code review.
