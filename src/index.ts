import { LogLevel, LogService, RichConsoleLogger } from "matrix-bot-sdk";
import { DimensionStore } from "./db/DimensionStore";
import Webserver from "./api/Webserver";
import { CURRENT_VERSION } from "./version";
import { MatrixStickerBot } from "./matrix/MatrixStickerBot";
import User from "./db/models/User";
import { ILoggedInUser } from "./api/security/MatrixSecurity";

declare global {
    namespace Express {
        interface User extends ILoggedInUser {
            userId: string;
            token: string;
        }
        interface Request {
            // 32-hex-char request id, set by Webserver.configure(). Used in
            // logs and returned as X-Request-Id header for client-side reporting.
            id: string;
        }
    }
}

// Log level: DEBUG in dev, INFO in prod. Never run production with DEBUG.
// SECURITY.md § "Express hardening (v2)" — debug logging can leak tokens
// and internal state into log aggregators.
const logLevel = process.env.NODE_ENV === "production" ? LogLevel.INFO : LogLevel.DEBUG;
LogService.setLevel(logLevel);
LogService.setLogger(new RichConsoleLogger());
LogService.info("index", "Starting dimension " + CURRENT_VERSION + " (env=" + (process.env.NODE_ENV || "unset") + ")");

async function startup() {
    const schemas = await DimensionStore.updateSchema();
    LogService.info("DimensionStore", "Applied schemas: ", schemas);

    const webserver = new Webserver();
    await webserver.start();

    const userId = await MatrixStickerBot.getUserId();
    const users = await User.findAll({where: {userId: userId, isSelfBot: false}});
    if (users.length > 0) {
        LogService.error("index", "The access token configured for Dimension belongs to a user which is also " +
            "a user known to Dimension. This usually indicates that the access token is not a dedicated user " +
            "account for Dimension. To prevent potential confusion to this user, Dimension will refuse to start " +
            "until the access token given belongs to a dedicated user.");
        throw new Error("Access token belongs to a real user. See logs for details.");
    }

    LogService.info("index", "Sticker bot is using utility account, registered as " + userId);
    await MatrixStickerBot.start();
}

// Global safety nets — log unhandled rejections/exceptions but don't dump
// them to the client. SECURITY.md § "Express hardening (v2)".
process.on("unhandledRejection", (reason) => {
    LogService.error("index", "Unhandled promise rejection: " + (reason instanceof Error ? reason.stack : String(reason)));
});
process.on("uncaughtException", (err) => {
    LogService.error("index", "Uncaught exception: " + (err && err.stack ? err.stack : String(err)));
    // Exit non-zero so the supervisor (s6/systemd/docker) restarts us.
    // Continuing after uncaughtException is dangerous — DB connections may
    // be in unknown state.
    process.exit(1);
});

startup()
    .then(() => LogService.info("index", "Dimension is ready!"))
    .catch((e) => {
        // Don't echo raw error to console — could contain access tokens,
        // DB URIs, etc. Log via LogService (which can be wired to a sink
        // that scrubs PII) and exit.
        LogService.error("index", "Startup failed: " + (e instanceof Error ? e.stack : String(e)));
        process.exit(1);
    });
