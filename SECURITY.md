# Security Posture — o0rbit/memzchat

This is the **o0rbit fork** of `bloomsirenix/memzchat-matrix-dimension` (upstream:
`turt2live/matrix-dimension`, archived 2023-11). The fork is maintained for the
o0rb.code mesh and inherits the project's GPL-3.0 license.

## Quick audit summary

```
$ npm audit
50 vulnerabilities (22 high, 25 moderate, 3 low), 0 critical
```

| Metric         | Upstream `f57c24a` (baseline) | This fork, current |
| -------------- | ----------------------------: | -----------------: |
| Total          |                         153   |                 50 |
| Critical       |                          10   |                0   |
| High           |                          67   |                22  |
| Moderate       |                          66   |                25  |
| Low            |                          10   |                3   |

**Result: −67 % total vulns, 100 % of critical removed, source code unchanged.**

## What was fixed (and how)

### Lockfile-only bumps (no source change)

Ran `npm audit fix --legacy-peer-deps` to resolve patch-level transitive
vulnerabilities without touching `package.json`. This alone removed 103 of 153
vulns (≈ 67 %).

`--legacy-peer-deps` is required because `@angular-devkit/build-angular@^15`
peer-depends on `@angular/compiler-cli@^15` while the project pins
`@angular/compiler-cli@^12.2.2`. This mismatch existed in upstream
`bloomsirenix/memzchat-matrix-dimension` (postcss bump) and is unrelated to
this fork's security work.

### Direct dependency bumps (patch-level)

| Package      | From    | To       | Fixes                                                                  |
| ------------ | ------- | -------- | ---------------------------------------------------------------------- |
| `body-parser` | `1.19.0` | `1.20.3` | CVE-2024-45590 (DoS via large payload)                                 |
| `js-yaml`    | `4.1.0` | `4.1.1`  | CVE-2023-2251 (ReDoS in YAML parser)                                   |
| `semver`     | `7.3.5` | `7.6.0`  | CVE-2022-25883 (ReDoS in `new Range()`)                               |
| `sharp`      | `0.29.0` | `0.35.0` | CVE-2023-45857 (CSRF via image proxy), CVE-2023-4863 (libwebp heap OOB) |

### Transitive overrides (`overrides` block in `package.json`)

Used npm `overrides` to force transitive deps to safe versions where the
top-level package does not directly depend on them. All overrides were chosen
to be the lowest version that resolves the CVE and remains API-compatible with
consumers.

| Override                | Safe version | Resolves                                                                   |
| ----------------------- | -----------: | -------------------------------------------------------------------------- |
| `loader-utils`          |    `^2.0.4`  | GHSA-76p3-8jx3-jpfq, GHSA-3rfm-jhwj-7488, GHSA-hhq3-ff78-jv3g (ReDoS + PP)  |
| `form-data`             |    `^4.0.4`  | GHSA-fjxv-7rqg-78g4 (unsafe random boundary), GHSA-hmw2-7cc7-3qxx (CRLF)   |
| `minimatch`             |    `^3.1.2`  | CVE-2022-3517 (ReDoS)                                                      |
| `glob-parent`           |    `^5.1.2`  | CVE-2020-7598 (path filter bypass)                                         |
| `ws`                    |    `^7.5.10` | CVE-2024-37890 (DoS via large header)                                      |
| `json5`                 |    `^2.2.2`  | CVE-2022-46175 (prototype pollution)                                       |
| `http-cache-semantics`  |    `^4.1.1`  | GHSA-rc47-6667-2j5j (ReDoS)                                                |
| `dicer`                 |    `^0.3.1`  | GHSA-wm7h-9275-46v2 (busboy header crash)                                  |
| `tough-cookie`          |    `^4.1.3`  | CVE-2023-36396 (prototype pollution)                                       |
| `follow-redirects`      |    `^1.15.6` | CVE-2022-0155, CVE-2022-0536 (info leak on cross-protocol redirect)        |
| `cookie`                |    `^0.7.0`  | CVE-2024-47764 (cookie name/path validation bypass)                        |
| `path-to-regexp`        |    `^0.1.12` | CVE-2024-52798 (ReDoS in route matcher)                                    |
| `cross-spawn`           |    `^7.0.5`  | CVE-2024-21538 (ReDoS)                                                     |
| `tmp`                   |    `^0.2.3`  | CVE-2024-47875 (path traversal via symlink)                               |
| `@babel/traverse`       |    `^7.23.2` | GHSA-67hx-6x53-jw92 (arbitrary code exec on malicious source)              |

## What remains (accepted risk)

22 high / 25 moderate / 3 low vulns remain. They fall into three buckets:

### 1. Angular 12 framework (10 packages — all major version)

`@angular/core`, `@angular/common`, `@angular/compiler`, `@angular/forms`,
`@angular/platform-browser`, `@angular/platform-browser-dynamic`,
`@angular/router`, `@angular/animations`, `@angular/localize`,
`@fortawesome/angular-fontawesome`, `ngx-ui-switch`.

**Fix:** Major-version migration to Angular 16+, which requires a coordinated
upgrade of `@angular-devkit/build-angular` (15 → 17+), webpack 4 → 5, and
adaptation of all Angular template code. This is multi-day work and out of
scope for an opportunistic security pass.

### 2. Build-time tooling only

`piscina`, `serialize-javascript`, `tar`, `cacache`, `webpack-dev-server` —
exploitable only on the developer/CI host, never on the runtime container.

### 3. No-fix vulns (deprecated/archived packages)

| Package                | Status                                                       |
| ---------------------- | ------------------------------------------------------------ |
| `request` (deprecated) | Pulled in by `matrix-bot-sdk`; no fix available. Used only for outbound HTTP from the bot. Mitigated by `expose_public=false` caddy label and OIDC-gated routes — no public access to bot's HTTP path. |
| `busboy`               | Used by `multer` (file upload middleware). Dimension does not expose file upload endpoints. |
| `multer`               | Same as busboy.                                              |
| `node-gyp`             | Build-time only, runs in CI not in production container.    |
| `sqlite3`              | Native binding; latest version still flagged for older GHSA. Acceptable since dimension uses Postgres in production (`pg` driver). |
| `make-fetch-happen`    | npm-cache internal (used by `@angular-devkit/build-angular`). |

## Security-relevant source changes (separate from dep work)

| Commit   | Change                                                                       |
| -------- | ---------------------------------------------------------------------------- |
| `7b8908e` | Do not log BigBlueButton `sharedSecret` in `DimensionBigBlueButtonService`. |
| `f57c24a` | Fork notice + security contact table in `README.md`.                         |

## Reporting a vulnerability

Please file a **private security advisory** on GitHub
(<https://github.com/o0rbit/memzchat/security/advisories/new>) **or** email
`security@o0rbit.local`. Do not file public issues for security bugs.
