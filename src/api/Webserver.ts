import * as express from "express";
import * as path from "path";
import { LogService } from "matrix-bot-sdk";
import { Server } from "typescript-rest";
import * as _ from "lodash";
import config from "../config";
import { applySecurityMiddleware, applyErrorHandlers, SecurityConfig } from "./security/securityMiddleware";
import MatrixSecurity from "./security/MatrixSecurity";

/**
 * Web server for Dimension. Handles the API routes for the admin, scalar,
 * dimension, and matrix APIs.
 *
 * Composition:
 *   - `applySecurityMiddleware` (from security/securityMiddleware.ts) mounts
 *     helmet, rate-limit, body-parser, request-id, access-log, CORS.
 *   - `applyErrorHandlers` (same module) mounts 404 + sanitized error handler.
 *   - `loadRoutes` wires the typescript-rest controllers.
 *
 * The middleware composition lives in its own module so it can be
 * unit-tested in isolation (test/security/*.test.ts). See SECURITY.md
 * § "Express hardening (v2)" for the policy.
 */
export default class Webserver {

    private app: express.Application;
    private server: any;

    constructor() {
        this.app = express();

        this.app.disable("x-powered-by");
        this.app.set("trust proxy", config.security?.trustProxyHops ?? 1);

        applySecurityMiddleware(this.app, config.security as SecurityConfig);
        this.loadRoutes();
        applyErrorHandlers(this.app);
    }

    private loadRoutes() {
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

        // SPA fallback — everything else serves index.html
        this.app.get(/(widgets\/|riot\/|element\/|\/)*/, (_req, res) => {
            res.sendFile(path.join(__dirname, "..", "..", "web", "index.html"));
        });
    }

    /**
     * Starts the webserver on the configured port/address, with
     * SIGTERM/SIGINT-driven graceful shutdown.
     */
    public async start(): Promise<void> {
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
            setTimeout(() => {
                LogService.warn("Webserver", "Shutdown timeout exceeded, forcing exit");
                process.exit(1);
            }, 10_000).unref();
        };
        process.once("SIGTERM", () => shutdown("SIGTERM"));
        process.once("SIGINT", () => shutdown("SIGINT"));
    }
}