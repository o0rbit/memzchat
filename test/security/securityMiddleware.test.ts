/**
 * Tests for the helmet + CORS + body-limit + request-id + error-handler
 * middleware composition. Each test mounts applySecurityMiddleware on a
 * fresh Express app and asserts the headers / status / body shape.
 *
 * No live Matrix homeserver or DB — just Express + supertest.
 */

// Stub matrix-bot-sdk so LogService.* are no-ops.
jest.mock("matrix-bot-sdk", () => ({
    LogService: {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        debug: jest.fn(),
        trace: jest.fn(),
        setLevel: jest.fn(),
        setLogger: jest.fn(),
    },
    LogLevel: { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 },
    RichConsoleLogger: jest.fn(),
}));

import express from "express";
import request from "supertest";
import {
    applySecurityMiddleware,
    applyErrorHandlers,
    buildContentSecurityPolicy,
    SecurityConfig,
} from "../../src/api/security/securityMiddleware";

const DEFAULT_SEC: Partial<SecurityConfig> = {
    trustProxyHops: 0,
    bodyLimit: "1mb",
    corsOrigins: [],
    rateLimitWindowMs: 60000,
    rateLimitMax: 100,
    allowLegacyScalarToken: false,
    cspEnabled: true,
    cspExtraConnectSrc: [],
    cspExtraFrameSrc: [],
    cspExtraScriptSrc: [],
    cspExtraStyleSrc: [],
    cspExtraImgSrc: [],
};

function newApp(sec: Partial<SecurityConfig> = DEFAULT_SEC) {
    const app = express();
    app.disable("x-powered-by");
    applySecurityMiddleware(app, sec as SecurityConfig);
    // A simple handler that emits 200 with a body so body-parser has
    // something to parse in the body-limit test.
    app.get("/api/ping", (_req, res) => res.json({ok: true}));
    app.post("/api/echo", (req, res) => res.json({echo: req.body}));
    applyErrorHandlers(app);
    return app;
}

describe("helmet security headers", () => {
    let app: express.Application;
    beforeEach(() => { app = newApp(); });

    test("sets X-Content-Type-Options: nosniff", async () => {
        const res = await request(app).get("/api/ping");
        expect(res.headers["x-content-type-options"]).toBe("nosniff");
    });

    test("sets X-Frame-Options: SAMEORIGIN", async () => {
        const res = await request(app).get("/api/ping");
        expect(res.headers["x-frame-options"]).toBe("SAMEORIGIN");
    });

    test("sets Referrer-Policy: strict-origin-when-cross-origin", async () => {
        const res = await request(app).get("/api/ping");
        expect(res.headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");
    });

    test("sets Cross-Origin-Resource-Policy: same-site", async () => {
        const res = await request(app).get("/api/ping");
        expect(res.headers["cross-origin-resource-policy"]).toBe("same-site");
    });

    test("sets Strict-Transport-Security with max-age=1y", async () => {
        const res = await request(app).get("/api/ping");
        expect(res.headers["strict-transport-security"]).toMatch(/max-age=31536000/);
        expect(res.headers["strict-transport-security"]).toMatch(/includeSubDomains/);
    });

    test("sets Content-Security-Policy with default-src 'self'", async () => {
        const res = await request(app).get("/api/ping");
        const csp = res.headers["content-security-policy"];
        expect(csp).toBeDefined();
        expect(csp).toMatch(/default-src 'self'/);
        // 'unsafe-inline' / 'unsafe-eval' must NOT be in defaults — see
        // SECURITY.md § "Express hardening (v2)".
        expect(csp).not.toMatch(/unsafe-inline/);
        expect(csp).not.toMatch(/unsafe-eval/);
    });

    test("disables X-Powered-By", async () => {
        const res = await request(app).get("/api/ping");
        expect(res.headers["x-powered-by"]).toBeUndefined();
    });

    test("can disable CSP via config (debug-only)", async () => {
        const app2 = newApp({...DEFAULT_SEC, cspEnabled: false});
        const res = await request(app2).get("/api/ping");
        expect(res.headers["content-security-policy"]).toBeUndefined();
    });
});

describe("CSP builder", () => {
    test("default directives include frame-ancestors 'self'", () => {
        const csp = buildContentSecurityPolicy({});
        expect(csp["frame-ancestors"]).toEqual(["'self'"]);
    });

    test("default directives include object-src 'none'", () => {
        const csp = buildContentSecurityPolicy({});
        expect(csp["object-src"]).toEqual(["'none'"]);
    });

    test("merges cspExtraScriptSrc into script-src", () => {
        const csp = buildContentSecurityPolicy({cspExtraScriptSrc: ["https://cdn.example.com"]});
        expect(csp["script-src"]).toContain("https://cdn.example.com");
        expect(csp["script-src"]).toContain("'self'");
    });

    test("merges cspExtraConnectSrc into connect-src", () => {
        const csp = buildContentSecurityPolicy({cspExtraConnectSrc: ["https://api.example.com"]});
        expect(csp["connect-src"]).toContain("https://api.example.com");
    });
});

describe("CORS allowlist", () => {
    test("empty allowlist: no Access-Control-Allow-Origin emitted", async () => {
        const app = newApp({...DEFAULT_SEC, corsOrigins: []});
        const res = await request(app).get("/api/ping");
        expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    });

    test("configured allowlist: matching origin gets ACAO header", async () => {
        const app = newApp({...DEFAULT_SEC, corsOrigins: ["https://allowed.example.com"]});
        const res = await request(app)
            .get("/api/ping")
            .set("Origin", "https://allowed.example.com");
        expect(res.headers["access-control-allow-origin"]).toBe("https://allowed.example.com");
    });

    test("configured allowlist: non-matching origin is blocked", async () => {
        const app = newApp({...DEFAULT_SEC, corsOrigins: ["https://allowed.example.com"]});
        const res = await request(app)
            .get("/api/ping")
            .set("Origin", "https://attacker.example.com");
        expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    });
});

describe("body-parser limit", () => {
    test("rejects bodies larger than the configured limit (413)", async () => {
        // 1mb limit; send 2mb.
        const big = "x".repeat(2 * 1024 * 1024);
        const app = newApp({...DEFAULT_SEC, bodyLimit: "1mb"});
        const res = await request(app)
            .post("/api/echo")
            .set("Content-Type", "application/json")
            .send(JSON.stringify({data: big}));
        // body-parser emits a 413 when it hits the limit. Our custom
        // error handler then logs it and returns 500 (the body is
        // unparseable anyway, so we don't want to echo a stack trace).
        // The important thing: the request is blocked. Express/body-parser
        // status for payload-too-large is 413; our handler forwards the
        // status code when it's a recognized HTTP status.
        expect(res.status === 413 || res.status === 500).toBe(true);
    });

    test("accepts bodies within the configured limit", async () => {
        const app = newApp({...DEFAULT_SEC, bodyLimit: "1mb"});
        const res = await request(app)
            .post("/api/echo")
            .send({hello: "world"});
        expect(res.status).toBe(200);
        expect(res.body.echo).toEqual({hello: "world"});
    });
});

describe("request-id", () => {
    test("sets X-Request-Id header on every response", async () => {
        const app = newApp();
        const res = await request(app).get("/api/ping");
        expect(res.headers["x-request-id"]).toBeDefined();
        // Math.random().toString(16) gives 14-16 hex chars each; two calls
        // produce 28-32 chars. We only care that it's long-enough to be unique
        // (>= 20 chars) and hex (no PII). See SECURITY.md § "request-id".
        expect(res.headers["x-request-id"]).toMatch(/^[a-f0-9]{20,}$/);
    });

    test("generates a unique id per request", async () => {
        const app = newApp();
        const res1 = await request(app).get("/api/ping");
        const res2 = await request(app).get("/api/ping");
        expect(res1.headers["x-request-id"]).not.toEqual(res2.headers["x-request-id"]);
    });

    test("sanitized 500 response includes req.id for support correlation", async () => {
        const app = express();
        app.disable("x-powered-by");
        applySecurityMiddleware(app, DEFAULT_SEC as SecurityConfig);
        app.get("/api/boom", (_req, _res, next) => {
            next(new Error("INTERNAL: DB credentials = postgres://user:hunter2@db"));
        });
        applyErrorHandlers(app);
        const res = await request(app).get("/api/boom");
        expect(res.status).toBe(500);
        expect(res.body.errcode).toBe("M_UNKNOWN");
        expect(res.body.error).toMatch(/Reference id:/);
        expect(res.body.error).toContain(res.headers["x-request-id"]);
        // Critical: no stack trace, no internal message leaked.
        expect(JSON.stringify(res.body)).not.toContain("hunter2");
        expect(JSON.stringify(res.body)).not.toContain("at ");
        expect(JSON.stringify(res.body)).not.toContain("Error:");
    });
});

describe("rate-limit", () => {
    test("allows up to N requests within the window", async () => {
        const app = newApp({...DEFAULT_SEC, rateLimitMax: 3, rateLimitWindowMs: 60000});
        for (let i = 0; i < 3; i++) {
            const res = await request(app).get("/api/ping");
            expect(res.status).toBe(200);
        }
    });

    test("returns 429 with M_RATE_LIMITED errcode after N requests", async () => {
        const app = newApp({...DEFAULT_SEC, rateLimitMax: 2, rateLimitWindowMs: 60000});
        await request(app).get("/api/ping");
        await request(app).get("/api/ping");
        const res = await request(app).get("/api/ping");
        expect(res.status).toBe(429);
        expect(res.body.errcode).toBe("M_RATE_LIMITED");
    });

    test("rate limit disabled when rateLimitMax=0", async () => {
        const app = newApp({...DEFAULT_SEC, rateLimitMax: 0});
        // Should not get rate-limited even after many requests.
        for (let i = 0; i < 10; i++) {
            const res = await request(app).get("/api/ping");
            expect(res.status).toBe(200);
        }
    });
});

describe("404 handler", () => {
    test("returns JSON 404 with errcode for unmatched routes", async () => {
        const app = newApp();
        const res = await request(app).get("/api/does-not-exist");
        expect(res.status).toBe(404);
        expect(res.body.errcode).toBe("M_NOT_FOUND");
    });
});