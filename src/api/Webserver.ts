import * as express from "express";
import * as path from "path";
import * as bodyParser from "body-parser";
import * as URL from "url";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { LogService } from "matrix-bot-sdk";
import { Server } from "typescript-rest";
import * as _ from "lodash";
import config, { DimensionConfig } from "../config";
import { ApiError } from "./ApiError";
import MatrixSecurity from "./security/MatrixSecurity";

/**
 * Web server for Dimension. Handles the API routes for the admin, scalar, dimension, and matrix APIs.
 *
 * Hardening (v2) — see SECURITY.md § "Express hardening (v2)":
 *   - helmet() sets CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
 *   - x-powered-by disabled (don't advertise Express to attackers).
 *   - body-parser limit is config-driven (default 1mb, was 512mb = DoS vector).
 *   - CORS restricted to a configured allowlist (default empty = same-origin only).
 *   - Per-IP rate limiting on /api (default 100/min, configurable).
 *   - Errors are sanitized: production responses don't include stack traces
 *     or internal messages. Full error is logged server-side only.
 *   - Each request gets an X-Request-Id for traceability in logs.
 */
export default class Webserver {

    private app: express.Application;
    private server: any; // http.Server, typed as any to avoid pulling @types/node into backend tsconfig

    constructor() {
        this.app = express();

        // Don't advertise Express version. (helmet does this too, but be explicit.)
        this.app.disable("x-powered-by");

        // Trust X-Forwarded-* headers from the configured number of reverse-proxy hops.
        // Default 1 for a single caddy/nginx in front. 0 disables trust entirely.
        this.app.set("trust proxy", config.security?.trustProxyHops ?? 1);

        this.configure();
        this.loadRoutes();
    }

    private loadRoutes() {
        // TODO: Rename services to controllers, and controllers to services. They're backwards.

        const apis = ["scalar", "dimension", "admin", "matrix"].map(a => path.join(__dirname, a, "*"));
        const router = express.Router();
        Server.registerAuthenticator(new MatrixSecurity());
        apis.forEach(a => Server.loadServices(router, [a]));
        const routes = _.uniq(router.stack.map(r => r.route.path));
        for (const route of routes) {
            this.app.options(route, (_req, res) => res.sendStatus(200));
            LogService.info("Webserver", "Registered route: " + route);
        }
        this.app.use(router);

        // We register the default route last to make sure we don't override anything by accident.
        // We'll pass off all other requests to the web app
        this.app.get(/(widgets\/|riot\/|element\/|\/)*/, (_req, res) => {
            res.sendFile(path.join(__dirname, "..", "..", "web", "index.html"));
        });

        // 404 fallback for anything that didn't match a route above
        this.app.use((_req, res) => {
            res.status(404).json({errcode: "M_NOT_FOUND", error: "Not found"});
        });

        // Set up the error handler — always LAST.
        this.app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
            if (res.headersSent) return next(err);

            if (err instanceof ApiError) {
                // Application-level errors are safe to surface verbatim.
                LogService.warn("Webserver", "ApiError " + err.statusCode + " " + req.id);
                res.setHeader("Content-Type", "application/json");
                res.status(err.statusCode);
                res.json(err.jsonResponse);
                return;
            }

            // Anything else: log full detail server-side, return sanitized response.
            LogService.error("Webserver", "Unhandled error on " + req.method + " " + req.path + " (id=" + req.id + ")");
            LogService.error("Webserver", err && err.stack ? err.stack : String(err));
            res.status(500).json({
                errcode: "M_UNKNOWN",
                error: "An internal server error occurred. Reference id: " + req.id,
            });
        });
    }

    private configure() {
        // ----- Security headers (helmet) -----
        const csp = this.buildContentSecurityPolicy();
        this.app.use(helmet({
            contentSecurityPolicy: config.security?.cspEnabled !== false ? {
                useDefaults: true,
                directives: csp,
            } : false,
            // HSTS: 1 year, include subdomains, allow preload list opt-in.
            strictTransportSecurity: {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: false,
            },
            // Don't allow our pages to be framed from another origin (clickjacking).
            frameguard: {action: "sameorigin"},
            // Don't allow MIME-type sniffing.
            noSniff: true,
            // XSS filter — legacy browsers only; modern ones ignore.
            xssFilter: true,
            // Referer policy — send origin only (not full URL) to other origins.
            referrerPolicy: {policy: "strict-origin-when-cross-origin"},
            // Disable COEP/COOP by default — they break legitimate integrations.
            crossOriginEmbedderPolicy: false,
            crossOriginOpenerPolicy: false,
            crossOriginResourcePolicy: {policy: "same-site"},
        }));

        // ----- Per-IP rate limit on the API surface -----
        const rateLimitMax = config.security?.rateLimitMax ?? 100;
        const rateLimitWindowMs = config.security?.rateLimitWindowMs ?? 60000;
        if (rateLimitMax > 0) {
            const limiter = rateLimit({
                windowMs: rateLimitWindowMs,
                max: rateLimitMax,
                standardHeaders: true,
                legacyHeaders: false,
                // Skip the static-asset fallback route — it serves index.html for
                // SPA deep links and is hit on every page load.
                skip: (req) => req.method === "GET" && req.path === "/",
                message: {errcode: "M_RATE_LIMITED", error: "Too many requests"},
            });
            this.app.use("/api", limiter);
            this.app.use("/_matrix", limiter);
        }

        // ----- Static assets with sensible caching -----
        // 1 day for hashed bundles (Angular emits `main.<hash>.js` etc.) — long,
        // safe because content-addressed. index.html gets no-cache so deploys
        // are picked up immediately.
        this.app.use(express.static(path.join(__dirname, "..", "..", "web"), {
            etag: true,
            lastModified: true,
            setHeaders: (res, filePath) => {
                if (filePath.endsWith("index.html")) {
                    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
                } else {
                    res.setHeader("Cache-Control", "public, max-age=86400, immutable");
                }
            },
        }));

        // ----- Body parsing with config-driven limit (was 512mb — DoS) -----
        const bodyLimit = config.security?.bodyLimit ?? "1mb";
        this.app.use(bodyParser.json({limit: bodyLimit}));
        this.app.use(bodyParser.urlencoded({extended: false, limit: bodyLimit}));

        // ----- Request ID + access log -----
        this.app.use((req: express.Request, _res, next) => {
            // 128-bit random hex; cheap, collision-resistant, loggable.
            req.id = (Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2)).slice(0, 32);
            _res.setHeader("X-Request-Id", req.id);
            next();
        });

        this.app.use((req: express.Request, _res, next) => {
            const parsedUrl = URL.parse(req.url, true);
            // Redact known-sensitive query params before logging.
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
        const corsOrigins = config.security?.corsOrigins ?? [];
        if (corsOrigins.length > 0) {
            this.app.use(cors({
                origin: (origin, cb) => {
                    if (!origin) return cb(null, true); // same-origin / curl
                    if (corsOrigins.includes(origin)) return cb(null, true);
                    return cb(new Error("CORS: origin " + origin + " not allowed"));
                },
                credentials: false, // bearer auth via header, not cookies
                methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                allowedHeaders: ["Content-Type", "Authorization"],
                maxAge: 600,
            }));
        } else {
            // No CORS allowlist configured — emit no Access-Control-* headers at all.
            // Browsers will block cross-origin XHR by default. This is the safest default.
        }
    }

    private buildContentSecurityPolicy(): { [k: string]: string[] } {
        // The security config is required to be present (default.yaml provides
        // safe defaults), but be defensive in case an operator strips it.
        const sec: Partial<DimensionConfig["security"]> = config.security ?? {};
        return {
            "default-src": ["'self'"],
            // 'unsafe-inline' / 'unsafe-eval' intentionally NOT in defaults — Angular
            // emits nonced styles and doesn't need eval. If your deployment needs
            // either, add via cspExtraScriptSrc/cspExtraStyleSrc and audit first.
            "script-src": ["'self'", ...(sec.cspExtraScriptSrc ?? [])],
            "style-src": ["'self'", ...(sec.cspExtraStyleSrc ?? [])],
            "img-src": ["'self'", "data:", "blob:", "mxc://", ...(sec.cspExtraImgSrc ?? [])],
            // Element widget embedding: parent docs must be allowed via frame-ancestors.
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
     * Starts the webserver, bootstrapping the various API handlers.
     * Binds the configured port/address and wires SIGTERM/SIGINT for graceful shutdown.
     */
    public async start(): Promise<void> {
        const sec = config.security ?? {};
        return new Promise<void>((resolve, reject) => {
            this.server = this.app.listen(config.web.port, config.web.address, () => {
                LogService.info("Webserver", "API and UI listening on " + config.web.address + ":" + config.web.port);
                this.installSignalHandlers();
                resolve();
            });
            this.server.on("error", (err: Error) => {
                LogService.error("Webserver", "Failed to bind: " + err.message);
                reject(err);
            });
            // Set socket-level timeouts so a single slow client can't tie up a worker.
            this.server.headersTimeout = 30_000;
            this.server.keepAliveTimeout = 5_000;
        });
    }

    private installSignalHandlers() {
        const shutdown = (signal: string) => {
            LogService.info("Webserver", "Received " + signal + ", closing server gracefully");
            if (!this.server) return;
            this.server.close((err: Error | undefined) => {
                if (err) {
                    LogService.error("Webserver", "Error during shutdown: " + err.message);
                    process.exit(1);
                }
                process.exit(0);
            });
            // Hard timeout — if connections don't drain in 10s, give up.
            setTimeout(() => {
                LogService.warn("Webserver", "Shutdown timeout exceeded, forcing exit");
                process.exit(1);
            }, 10_000).unref();
        };
        process.once("SIGTERM", () => shutdown("SIGTERM"));
        process.once("SIGINT", () => shutdown("SIGINT"));
    }
}
