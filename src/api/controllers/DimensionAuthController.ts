/**
 * Native + OIDC auth endpoints.
 *
 * Public routes (mounted at /api/v1/dimension/auth/*):
 *
 *   GET  /status                 bridge health, no secrets leaked
 *   GET  /me                     current user (200 anonymous OK)
 *   POST /login                  native username + password to JWT
 *   POST /register               public registration (gated by config)
 *   POST /oidc/callback          OIDC code exchange to JWT + auto-provision
 *
 * Admin routes (mounted at /api/v1/dimension/auth/admin/*):
 *
 *   GET    /users                list users (admin only)
 *   POST   /users                create user (admin only)
 *   PATCH  /users/:userId        update role / disable (admin only)
 *   DELETE /users/:userId        hard delete (admin only)
 *
 * Tokens are HS256 better-auth JWTs (memzchat/auth/jwt.ts). Verification
 * is in memzchat/api/security/dimensionAuth.ts.
 */

import { Context, DELETE, GET, PATCH, POST, Path, PathParam, Security, ServiceContext } from "typescript-rest";
import { LogService } from "matrix-bot-sdk";
import { Op } from "sequelize";
import config from "../../config";
import DimensionUser, { DimensionUserRole } from "../../db/models/DimensionUser";
import { hashPassword, verifyPassword, needsRehash } from "../../auth/passwords";
import {
    signBetterToken,
    exchangeOidcCode,
    verifyOidcIdToken,
    AuthClaims,
} from "../../auth/jwt";

export interface LoginRequest {
    username?: string;
    password?: string;
}

export interface RegisterRequest {
    username?: string;
    password?: string;
    email?: string;
}

export interface OidcCallbackRequest {
    code?: string;
    redirect_uri?: string;
}

export interface CreateUserRequest {
    username?: string;
    password?: string;
    role?: string;
    email?: string;
}

export interface UpdateUserRequest {
    role?: string;
    isActive?: boolean;
    password?: string;
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

function getSecret(): string {
    return process.env.MEMZ_AUTH_SECRET || (config.auth && config.auth.betterSecret) || "";
}

function getTtl(): number {
    return (config.auth && config.auth.tokenTtlSec) || 3600;
}

function oidcAdminWhitelist(): Set<string> {
    const raw = process.env.MEMZ_OIDC_ADMINS || "";
    return new Set(raw.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean));
}

function shouldOidcBeAdmin(claims: Record<string, any>, adminCount: number): boolean {
    // 1. Config-level auto-admin: first user becomes admin
    if (config.auth && config.auth.oidcAutoAdmin && adminCount === 0) return true;
    // 2. Explicit whitelist via env
    const whitelist = oidcAdminWhitelist();
    if (whitelist.size === 0) return false;
    const sub = String(claims.sub || "").toLowerCase();
    const email = String(claims.email || "").toLowerCase();
    const preferred = String(claims.preferred_username || "").toLowerCase();
    return whitelist.has(sub) || whitelist.has(email) || whitelist.has(preferred);
}

function deriveUsernameFromOidc(claims: Record<string, any>): string {
    const pref = claims.preferred_username;
    if (typeof pref === "string" && pref.trim()) return pref.trim().slice(0, 128);
    const email = claims.email;
    if (typeof email === "string" && email.includes("@")) {
        const local = email.split("@", 1)[0].trim().slice(0, 128);
        if (local) return local;
        return email.slice(0, 128);
    }
    return "oidc-" + String(claims.sub || "unknown").slice(0, 64);
}

async function mintTokenForUser(user: DimensionUser, source: "better-auth" | "oidc"): Promise<{token: string; claims: AuthClaims}> {
    const secret = getSecret();
    if (!secret) throw new Error("auth not configured");
    const ttl = getTtl();
    const now = Math.floor(Date.now() / 1000);
    const role = ((user as any).role === "admin") ? "admin" : "user";
    const username = (user as any).username || (user as any).userId;
    const claims: AuthClaims = {
        sub: (user as any).userId,
        username,
        role,
        iss: "dimension",
        aud: "dimension-web",
        iat: now,
        exp: now + ttl,
        scope: role === "admin" ? "admin" : "user",
        source,
    };
    const token = signBetterToken(claims, secret);
    return {token, claims};
}

async function ensureBootstrapAdmin(): Promise<DimensionUser | null> {
    const adminPw = process.env.MEMZ_ADMIN_PASSWORD || (config.auth && config.auth.defaultAdminPassword) || "";
    if (!adminPw) return null;
    const userId = "@admin:localhost";
    let row = await DimensionUser.findOne({where: {userId}});
    if (!row) {
        row = await DimensionUser.create({
            userId,
            isSelfBot: false,
            username: "admin",
            passwordHash: await hashPassword(adminPw),
            role: "admin" as DimensionUserRole,
            isActive: true,
        } as any);
        LogService.info("Auth", `bootstrap admin row created (userId=${userId})`);
    } else if ((row as any).role !== "admin") {
        await row.update({role: "admin" as DimensionUserRole});
    }
    return row;
}

// -----------------------------------------------------------------------
// Public endpoints
// -----------------------------------------------------------------------

export interface AuthPublicStatusResponse {
    better_auth_enabled: boolean;
    oidc_enabled: boolean;
    oidc_issuer: string | null;
    oidc_audience: string | null;
    allow_public_registration: boolean;
    has_admin: boolean;
    bootstrap_admin_configured: boolean;
}

@Path("/api/v1/dimension/auth")
export class DimensionAuthController {

    @Context
    public context: ServiceContext;

    @GET
    @Path("/status")
    public async status(): Promise<AuthPublicStatusResponse> {
        const secret = getSecret();
        const oidcIssuer = process.env.MEMZ_OIDC_ISSUER || (config.auth && config.auth.oidcIssuer) || "";
        const oidcAud = (config.auth && config.auth.oidcAudience) || "dimension-web";
        const adminCount = await DimensionUser.count({where: {role: "admin"}});
        const adminPw = process.env.MEMZ_ADMIN_PASSWORD || (config.auth && config.auth.defaultAdminPassword) || "";
        return {
            better_auth_enabled: secret.length >= 16,
            oidc_enabled: oidcIssuer.length > 0,
            oidc_issuer: oidcIssuer || null,
            oidc_audience: oidcAud,
            allow_public_registration: !!(config.auth && config.auth.allowPublicRegistration),
            has_admin: adminCount > 0,
            bootstrap_admin_configured: adminPw.length > 0,
        };
    }

    @GET
    @Path("/me")
    public async me(): Promise<any> {
        const req = this.context.request as any;
        if (!req.authUser) return {authenticated: false};
        return {
            authenticated: true,
            user: {
                userId: req.authUser.userId,
                username: req.authUser.username,
                role: req.authUser.role,
            },
            source: req.authClaims ? req.authClaims.source : "unknown",
        };
    }

    @POST
    @Path("/login")
    public async login(body: LoginRequest): Promise<any> {
        const username = (body && typeof body.username === "string") ? body.username.trim() : "";
        const password = (body && typeof body.password === "string") ? body.password : "";
        if (!username || !password) {
            return {statusCode: 400, errcode: "M_BAD_REQUEST", error: "username and password required"};
        }
        if (username === "admin") {
            const adminPw = process.env.MEMZ_ADMIN_PASSWORD || (config.auth && config.auth.defaultAdminPassword) || "";
            if (adminPw && password === adminPw) {
                const row = await ensureBootstrapAdmin();
                if (row) {
                    const {token, claims} = await mintTokenForUser(row, "better-auth");
                    return {
                        access_token: token,
                        token_type: "bearer",
                        expires_in: claims.exp - claims.iat,
                        user: {userId: (row as any).userId, username: "admin", role: "admin"},
                        source: "bootstrap",
                    };
                }
            }
        }
        const user = await DimensionUser.findOne({where: {username}});
        if (!user || !(user as any).isActive || !(user as any).passwordHash) {
            // constant-time-ish: still hash a dummy password
            await verifyPassword(password, "scrypt$N=32768,r=8,p=1$AAAA$AAAA").catch(() => false);
            return {statusCode: 401, errcode: "M_UNAUTHENTICATED", error: "invalid credentials"};
        }
        const ok = await verifyPassword(password, (user as any).passwordHash);
        if (!ok) {
            return {statusCode: 401, errcode: "M_UNAUTHENTICATED", error: "invalid credentials"};
        }
        if (needsRehash((user as any).passwordHash)) {
            await user.update({passwordHash: await hashPassword(password)});
        }
        const {token, claims} = await mintTokenForUser(user, "better-auth");
        return {
            access_token: token,
            token_type: "bearer",
            expires_in: claims.exp - claims.iat,
            user: {userId: (user as any).userId, username: (user as any).username, role: (user as any).role},
            source: "native",
        };
    }

    @POST
    @Path("/register")
    public async register(body: RegisterRequest): Promise<any> {
        if (!(config.auth && config.auth.allowPublicRegistration)) {
            return {statusCode: 403, errcode: "M_FORBIDDEN", error: "registration disabled"};
        }
        const username = (body && typeof body.username === "string") ? body.username.trim() : "";
        const password = (body && typeof body.password === "string") ? body.password : "";
        const email = (body && typeof body.email === "string") ? body.email : null;
        if (!username || username.length < 3 || username.length > 128) {
            return {statusCode: 400, errcode: "M_BAD_REQUEST", error: "username must be 3..128 chars"};
        }
        if (!password || password.length < 8 || password.length > 4096) {
            return {statusCode: 400, errcode: "M_BAD_REQUEST", error: "password must be 8..4096 chars"};
        }
        const userId = "@" + username + ":self";
        const existing = await DimensionUser.findOne({where: {[Op.or as any]: [{username}, {userId}]}});
        if (existing) {
            return {statusCode: 409, errcode: "M_USER_IN_USE", error: "username taken"};
        }
        const user = await DimensionUser.create({
            userId,
            isSelfBot: false,
            username,
            passwordHash: await hashPassword(password),
            email,
            role: "user" as DimensionUserRole,
            isActive: true,
        } as any);
        return {userId: (user as any).userId, username, role: "user", created: true};
    }

    @POST
    @Path("/oidc/callback")
    public async oidcCallback(body: OidcCallbackRequest): Promise<any> {
        const issuer = process.env.MEMZ_OIDC_ISSUER || (config.auth && config.auth.oidcIssuer) || "";
        const clientId = process.env.MEMZ_OIDC_CLIENT_ID || (config.auth && config.auth.oidcClientId) || "";
        const clientSecret = process.env.MEMZ_OIDC_CLIENT_SECRET || (config.auth && config.auth.oidcClientSecret) || "";
        const audience = (config.auth && config.auth.oidcAudience) || "dimension-web";
        if (!issuer || !clientId || !clientSecret) {
            return {statusCode: 503, errcode: "M_NOT_YET_UPLOADED", error: "oidc not configured"};
        }
        const code = body && typeof body.code === "string" ? body.code : "";
        const redirectUri = body && typeof body.redirect_uri === "string" ? body.redirect_uri : "";
        if (!code) {
            return {statusCode: 400, errcode: "M_BAD_REQUEST", error: "code required"};
        }
        let tokens: any;
        try {
            tokens = await exchangeOidcCode(code, redirectUri, {issuer, audience, clientId, clientSecret});
        } catch (e) {
            LogService.warn("Auth", "oidc token exchange failed:", e);
            return {statusCode: 401, errcode: "M_UNAUTHENTICATED", error: "oidc token exchange failed"};
        }
        if (!tokens.id_token) {
            return {statusCode: 401, errcode: "M_UNAUTHENTICATED", error: "no id_token in OIDC response"};
        }
        const idClaims = await verifyOidcIdToken(tokens.id_token, {issuer, audience, clientId, clientSecret});
        if (!idClaims || typeof idClaims.sub !== "string") {
            return {statusCode: 401, errcode: "M_UNAUTHENTICATED", error: "id_token verification failed"};
        }
        let user = await DimensionUser.findOne({where: {oidcSub: idClaims.sub, oidcProvider: issuer}});
        const username = deriveUsernameFromOidc(idClaims);
        if (!user) {
            const adminCount = await DimensionUser.count({where: {role: "admin"}});
            const role: DimensionUserRole = shouldOidcBeAdmin(idClaims, adminCount) ? "admin" : "user";
            user = await DimensionUser.create({
                userId: "@oidc-" + idClaims.sub.slice(0, 32) + ":self",
                isSelfBot: false,
                username,
                oidcSub: idClaims.sub,
                oidcProvider: issuer,
                email: typeof idClaims.email === "string" ? idClaims.email : null,
                role,
                isActive: true,
            } as any);
            LogService.info("Auth", `OIDC user auto-provisioned sub=${idClaims.sub} role=${role}`);
        } else if (!(user as any).isActive) {
            return {statusCode: 403, errcode: "M_FORBIDDEN", error: "user disabled"};
        }
        const {token, claims} = await mintTokenForUser(user, "oidc");
        return {
            access_token: token,
            token_type: "bearer",
            expires_in: claims.exp - claims.iat,
            user: {userId: (user as any).userId, username: (user as any).username, role: (user as any).role},
            source: "oidc",
        };
    }
}

// -----------------------------------------------------------------------
// Admin endpoints
// -----------------------------------------------------------------------

@Path("/api/v1/dimension/auth/admin")
@Security("ROLE_ADMIN")
export class DimensionAuthAdminController {

    @Context
    public context: ServiceContext;

    @GET
    @Path("/users")
    public async listUsers(): Promise<any[]> {
        const rows = await DimensionUser.findAll({order: [["createdAt", "DESC"]]});
        return rows.map((u) => ({
            userId: (u as any).userId,
            username: (u as any).username,
            email: (u as any).email,
            role: (u as any).role,
            isActive: (u as any).isActive,
            oidcSub: (u as any).oidcSub ? "[set]" : null,
            oidcProvider: (u as any).oidcProvider,
            createdAt: (u as any).createdAt,
        }));
    }

    @POST
    @Path("/users")
    public async createUser(body: CreateUserRequest): Promise<any> {
        const username = (body && typeof body.username === "string") ? body.username.trim() : "";
        const password = (body && typeof body.password === "string") ? body.password : "";
        const role: DimensionUserRole = (body && body.role === "admin") ? "admin" : "user";
        const email = (body && typeof body.email === "string") ? body.email : null;
        if (!username || username.length < 3) {
            return {statusCode: 400, errcode: "M_BAD_REQUEST", error: "username required"};
        }
        if (!password || password.length < 8) {
            return {statusCode: 400, errcode: "M_BAD_REQUEST", error: "password must be >= 8 chars"};
        }
        const existing = await DimensionUser.findOne({where: {username}});
        if (existing) return {statusCode: 409, errcode: "M_USER_IN_USE", error: "username taken"};
        const userId = "@" + username + ":self";
        const u = await DimensionUser.create({
            userId, isSelfBot: false, username,
            passwordHash: await hashPassword(password),
            email, role, isActive: true,
        } as any);
        return {userId, username, role, created: true};
    }

    @PATCH
    @Path("/users/:userId")
    public async updateUser(@PathParam("userId") userId: string, body: UpdateUserRequest): Promise<any> {
        const u = await DimensionUser.findOne({where: {userId: decodeURIComponent(userId)}});
        if (!u) return {statusCode: 404, errcode: "M_NOT_FOUND", error: "user not found"};
        const patch: any = {};
        if (typeof body.role === "string" && (body.role === "admin" || body.role === "user")) patch.role = body.role;
        if (typeof body.isActive === "boolean") patch.isActive = body.isActive;
        if (typeof body.password === "string" && body.password.length >= 8) patch.passwordHash = await hashPassword(body.password);
        await u.update(patch);
        return {updated: true, userId: (u as any).userId, role: (u as any).role, isActive: (u as any).isActive};
    }

    @DELETE
    @Path("/users/:userId")
    public async deleteUser(@PathParam("userId") userId: string): Promise<any> {
        const u = await DimensionUser.findOne({where: {userId: decodeURIComponent(userId)}});
        if (!u) return {statusCode: 404, errcode: "M_NOT_FOUND", error: "user not found"};
        await u.destroy();
        return {deleted: true, userId};
    }
}
