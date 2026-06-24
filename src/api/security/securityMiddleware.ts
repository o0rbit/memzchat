/**
 * Security middleware composition for Express.
 *
 * Extracted from Webserver so it can be unit-tested in isolation (see
 * test/security/*.test.ts). The composition is deterministic — given a
 * config object, the same middleware is mounted in the same order.
 *
 * Mount order matters:
 *   1. helmet (sets headers on every response, earliest so they survive)
 *   2. rate-limit (reject before doing any work)
 *   3. CORS (handle preflight, set ACAO on response)
 *   4. body-parser (parse before any handler runs)
 *   5. request-id (needed by access log + error handler)
 *   6. access log (uses request-id)
 *   7. error handler (LAST — catches everything before the client)
 *
 * Static-file serving (express.static) is intentionally NOT here. It's
 * a deployment concern (CDN vs same-origin), not a security primitive.
 */
import * as express from "express";
import * as bodyParser from "body-parser";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { LogService } from "matrix-bot-sdk";
import * as URL from "url";
import { DimensionConfig } from "../../config";

// Re-export the security-config shape so tests don't need to import
// the whole DimensionConfig just to type a partial.
export type SecurityConfig = DimensionConfig["security"];

/**
 * Build the helmet Content-Security-Policy directive map from config.
 * Exported so tests can assert on the directive shape directly.
 */
export function buildContentSecurityPolicy(sec: Partial<SecurityConfig>): { [k: string]: string[] } {
    return {
        "default-src": ["'self'"],
        // 'unsafe-inline' / 'unsafe-eval' intentionally NOT in defaults —
        // Angular emits nonced styles and doesn't need eval. If your deployment
        // needs either, add via cspExtraScriptSrc/cspExtraStyleSrc and audit first.
        "script-src": ["'self'", ...(sec.cspExtraScriptSrc ?? [])],
        "style-src": ["'self'", ...(sec.cspExtraStyleSrc ?? [])],
        "img-src": ["'self'", "data:", "blob:", "mxc://", ...(sec.cspExtraImgSrc ?? [])],
        "frame-src": ["'self'", ...(sec.cspExtraFrameSrc ?? [])],
        "frame-ancestors": ["'self'"],
        "connect-src": ["'self'", ...(sec.cspExtraConnectSrc ?? [])],
        "font-src": ["'self'", "data:"],
        "media-src": ["'self'", "blob:"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
    };
}

/**
 * Mount all security middleware on the given Express app.
 * Pure function: no globals, no side effects beyond mounting.
 */
export function applySecurityMiddleware(
    app: express.Application,
    sec: Partial<SecurityConfig>,
): void {
    // ----- Security headers (helmet) -----
    const csp = buildContentSecurityPolicy(sec);
    app.use(helmet({
        contentSecurityPolicy: sec.cspEnabled !== false ? {
            useDefaults: true,
            directives: csp,
        } : false,
        strictTransportSecurity: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: false,
        },
        frameguard: {action: "sameorigin"},
        noSniff: true,
        xssFilter: true,
        referrerPolicy: {policy: "strict-origin-when-cross-origin"},
        crossOriginEmbedderPolicy: false,
        crossOriginOpenerPolicy: false,
        crossOriginResourcePolicy: {policy: "same-site"},
    }));

    // ----- Per-IP rate limit on the API surface -----
    const rateLimitMax = sec.rateLimitMax ?? 100;
    const rateLimitWindowMs = sec.rateLimitWindowMs ?? 60000;
    if (rateLimitMax > 0) {
        const limiter = rateLimit({
            windowMs: rateLimitWindowMs,
            max: rateLimitMax,
            standardHeaders: true,
            legacyHeaders: false,
            skip: (req) => req.method === "GET" && req.path === "/",
            message: {errcode: "M_RATE_LIMITED", error: "Too many requests"},
        });
        app.use("/api", limiter);
        app.use("/_matrix", limiter);
    }

    // ----- Body parsing with config-driven limit -----
    const bodyLimit = sec.bodyLimit ?? "1mb";
    app.use(bodyParser.json({limit: bodyLimit}));
    app.use(bodyParser.urlencoded({extended: false, limit: bodyLimit}));

    // ----- Request ID -----
    app.use((req: express.Request & { id?: string }, res, next) => {
        req.id = (Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2)).slice(0, 32);
        res.setHeader("X-Request-Id", req.id);
        next();
    });

    // ----- Access log (with token redaction) -----
    app.use((req: express.Request & { id?: string }, _res, next) => {
        const parsedUrl = URL.parse(req.url, true);
        for (const k of ["scalar_token", "access_token"]) {
            if (parsedUrl.query && parsedUrl.query[k]) {
                parsedUrl.query[k] = "redacted";
                parsedUrl.search = undefined;
            }
        }
        LogService.info("Webserver", "[" + req.id + "] " + req.method + " " + URL.format(parsedUrl));
        next();
    });

    // ----- CORS (allowlist, default empty = same-origin only) -----
    const corsOrigins = sec.corsOrigins ?? [];
    if (corsOrigins.length > 0) {
        app.use(cors({
            origin: (origin, cb) => {
                if (!origin) return cb(null, true); // same-origin / curl
                if (corsOrigins.includes(origin)) return cb(null, true);
                return cb(new Error("CORS: origin " + origin + " not allowed"));
            },
            credentials: false,
            methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allowedHeaders: ["Content-Type", "Authorization"],
            maxAge: 600,
        }));
    }
    // else: no CORS headers at all — same-origin only.
}

/**
 * Default 404 + error handler. Mount this LAST on the app. Tests use this
 * to assert that unhandled errors don't leak stack traces to the client.
 */
export function applyErrorHandlers(app: express.Application): void {
    // 404 fallback — anything that didn't match a route above.
    app.use((_req, res) => {
        res.status(404).json({errcode: "M_NOT_FOUND", error: "Not found"});
    });

    // Error handler. Must be the very last middleware.
    app.use((err: any, req: express.Request & { id?: string }, res: express.Response, next: express.NextFunction) => {
        if (res.headersSent) return next(err);

        if (err instanceof Error && (err as any).jsonResponse && (err as any).statusCode) {
            const apiErr = err as any;
            LogService.warn("Webserver", "ApiError " + apiErr.statusCode + " " + req.id);
            res.setHeader("Content-Type", "application/json");
            res.status(apiErr.statusCode);
            res.json(apiErr.jsonResponse);
            return;
        }

        LogService.error("Webserver", "Unhandled error on " + req.method + " " + req.path + " (id=" + req.id + ")");
        LogService.error("Webserver", err && err.stack ? err.stack : String(err));
        res.status(500).json({
            errcode: "M_UNKNOWN",
            error: "An internal server error occurred. Reference id: " + req.id,
        });
    });
}