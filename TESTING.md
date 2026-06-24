# Testing

## Quick start

```bash
npm test                  # run all tests
npm run test:security    # security middleware tests only
npm run test:watch       # watch mode
```

## What we test

The security middleware in `src/api/security/securityMiddleware.ts` is the
primary test target. It's a **pure function** (`applySecurityMiddleware`)
that mounts helmet, rate-limit, body-parser, CORS, request-id, and the
error handler on an Express app. Because it has no runtime dependencies
(no Matrix client, no DB, no disk), it runs fast and reliably in CI.

Coverage areas:

| Area                  | Test                                                                 |
| --------------------- | -------------------------------------------------------------------- |
| Helmet headers        | X-Content-Type-Options, X-Frame-Options, Referrer-Policy, HSTS, CSP, X-Powered-By |
| CSP builder           | frame-ancestors, object-src, extension via security config          |
| CORS allowlist        | empty = no ACAO, matching origin = ACAO, non-matching = no ACAO      |
| Body-parser limit     | 2mb rejected with 413, normal JSON accepted                         |
| Request-id            | present, hex, >= 20 chars, unique per request                       |
| Error sanitisation   | 500 response references req.id, does not leak stack trace           |
| Rate limit            | up to N ok, N+1 → 429 with M_RATE_LIMITED, 0 = disabled              |
| 404 handler           | JSON 404 with errcode M_NOT_FOUND                                    |
| Password hashing      | scrypt roundtrip, wrong/malformed rejection, rehash detection        |
| Better-auth JWT       | HS256 roundtrip, wrong-secret rejection, expired rejection, tamper detection |

## Architecture decisions

- **No DB or network** — tests are pure function / supertest. Sequelize and
  matrix-bot-sdk are stubbed in the test setup.
- **Separate tsconfig.test.json** — the test CP is narrower than the
  backend's (excludes frontend-only files, types limited to node + jest)
  so compilation stays fast.
- **ts-jest diagnostics relaxed** — some third-party `@types/*` packages
  have minor TS-lib skews (e.g. `@types/supertest` vs the project's
  `lib` setting). We ignore those codes; source code is type-checked
  separately via `npx tsc --noEmit -p tsconfig.backend.json`.

## Running in CI

```bash
# Type-check source (including the security middleware extraction)
npx tsc --noEmit -p tsconfig.backend.json --types "node,body-parser,validator,express" \
  2>&1 | grep -E "Webserver\.ts|src/index\.ts|src/config\.ts|MatrixSecurity\.ts|securityMiddleware\.ts" \
  || echo "TYPE CHECK OK"

# Run tests
npm test

# Smoke-test headers against a running instance
tools/security-headers-check.sh http://localhost:8184
```

## Adding tests

New security tests go under `test/security/` and import from
`../../src/api/security/securityMiddleware.ts`. Use the `newApp()` helper
to create a fresh Express app with `applySecurityMiddleware` mounted.

Keep the `jest.mock("matrix-bot-sdk", ...)` at the top of every test file
so the SDK's LogService and related modules stay as no-ops.
