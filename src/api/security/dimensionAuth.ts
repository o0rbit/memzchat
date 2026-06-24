/**
 * Auth middleware for the multi-user feature.
 *
 * Layered on top of the legacy MatrixSecurity flow (which authenticates
 * bots/services via the Matrix homeserver). The new layer reads a bearer
 * JWT (HS256 better-auth or RS256 OIDC) from the Authorization header or
 * a cookie, resolves the DimensionUser, and attaches:
 *
 *   req.user  — { userId, username, role }
 *   req.claims — AuthClaims
 *
 * Two routers are exposed:
 *
 *   requireAuth()   — sets req.user; passes through with 401 on failure
 *                     unless req.optional === true (used for /me endpoint)
 *   requireAdmin()  — depends on requireAuth; passes through with 403
 *                     if req.user.role !== "admin"
 *
 * The middleware does NOT block the legacy Matrix-token path — controllers
 * that still accept Matrix tokens will continue to work; controllers that
 * need admin-only access can stack requireAdmin() on top.
 */

import { Request, RequestHandler, Response, NextFunction } from "express";
import { LogService } from "matrix-bot-sdk";
import config from "../../config";
import { claimsFromBetter, verifyBetterToken } from "../../auth/jwt";
import DimensionUser from "../../db/models/DimensionUser";

declare global {
    namespace Express {
        interface DimensionAuthUser {
            userId: string;
            username: string;
            role: "user" | "admin";
        }
        interface Request {
            authUser?: DimensionAuthUser;
            authClaims?: import("../../auth/jwt").AuthClaims;
            authOptional?: boolean;
        }
    }
}

const BEARER = /^Bearer\s+(.+)$/i;

function extractToken(req: Request): string | null {
    const h = req.headers.authorization;
    if (typeof h === "string") {
        const m = h.match(BEARER);
        if (m) return m[1];
    }
    // Cookie fallback (HttpOnly set by the login endpoint in the future).
    const cookie = (req as any).cookies?.dimension_auth;
    if (typeof cookie === "string" && cookie.length > 0) return cookie;
    return null;
}

async function resolveDimensionUser(sub: string): Promise<DimensionUser | null> {
    try {
        // Lazy import to avoid circular dep with DimensionStore
        // (DimensionStore imports DimensionUser which would import jwt.ts)
        const user = await DimensionUser.findOne({where: {userId: sub}});
        if (!user || !(user as any).isActive) return null;
        return user;
    } catch (e) {
        LogService.warn("Auth", "resolveDimensionUser failed for sub=" + sub + ":", e);
        return null;
    }
}

export function requireAuth(): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction) => {
        const token = extractToken(req);
        if (!token) {
            if (req.authOptional) return next();
            return res.status(401).json({errcode: "M_UNAUTHENTICATED", error: "missing bearer token"});
        }
        const secret = process.env.MEMZ_AUTH_SECRET || (config.auth && config.auth.betterSecret) || "";
        if (!secret) {
            LogService.error("Auth", "MEMZ_AUTH_SECRET not configured; rejecting all auth");
            return res.status(503).json({errcode: "M_NOT_YET_UPLOADED", error: "auth not configured"});
        }
        const payload = verifyBetterToken(token, secret);
        if (!payload) {
            if (req.authOptional) return next();
            return res.status(401).json({errcode: "M_UNAUTHENTICATED", error: "invalid or expired token"});
        }
        const user = await resolveDimensionUser(String(payload.sub));
        if (!user) {
            return res.status(401).json({errcode: "M_UNAUTHENTICATED", error: "user not found or disabled"});
        }
        req.authUser = {
            userId: (user as any).userId,
            username: (user as any).username || (user as any).userId,
            role: (user as any).role === "admin" ? "admin" : "user",
        };
        req.authClaims = claimsFromBetter(payload);
        next();
    };
}

export function requireAdmin(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
        if (!req.authUser) {
            return res.status(401).json({errcode: "M_UNAUTHENTICATED", error: "login required"});
        }
        if (req.authUser.role !== "admin") {
            return res.status(403).json({errcode: "M_FORBIDDEN", error: "admin only"});
        }
        next();
    };
}

/**
 * Optional auth: sets req.authUser if a valid token is present, otherwise
 * continues. Used for endpoints that have a richer response when logged in
 * (e.g. /me returns 200 with the user, or 200 with {authenticated:false}).
 */
export function optionalAuth(): RequestHandler {
    return (req: Request, _res: Response, next: NextFunction) => {
        req.authOptional = true;
        return requireAuth()(req, _res, next);
    };
}
