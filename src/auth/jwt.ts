/**
 * JWT mint + verify for the dimension multi-user auth feature.
 *
 * Two signing paths:
 *
 *   1. better-auth (HS256, single secret) — used for native username/password
 *      login. Secret comes from MEMZ_AUTH_SECRET. We tolerate a runtime
 *      fallback in dev mode (NODE_ENV=development) so the integration-manager
 *      frontend can still log in when the env is unconfigured.
 *
 *   2. OIDC (RS256, JWKS) — used when the operator wants to delegate auth to
 *      Authentik or any other OIDC IdP. JWKS document is fetched from the
 *      issuer's /.well-known/openid-configuration endpoint and cached for
 *      10 minutes (jwks_uri).
 *
 * A token is accepted if either path verifies it. The Claims.source field
 * reports which path matched for audit logging.
 *
 * Tokens carry: sub (userId), username, role ("user"|"admin"), iss, aud,
 * iat, exp, scope (space-separated).
 */

import { createHmac, randomUUID } from "crypto";

// --- HS256 (better-auth) ---

function b64url(input: Buffer | string): string {
    const buf = typeof input === "string" ? Buffer.from(input) : input;
    return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64urlDecode(s: string): Buffer {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Buffer.from(s, "base64");
}

/**
 * HS256 sign. Pure stdlib — no jsonwebtoken dependency. Format:
 *   base64url(header).base64url(payload).base64url(hmac_sha256)
 */
export function signBetterToken(
    payload: Record<string, any>,
    secret: string
): string {
    if (!secret || secret.length < 16) {
        throw new Error("better-auth secret must be >= 16 chars");
    }
    const header = {alg: "HS256", typ: "JWT"};
    const now = Math.floor(Date.now() / 1000);
    const full = {...payload, iat: payload.iat ?? now, exp: payload.exp ?? (now + 3600)};
    const h = b64url(JSON.stringify(header));
    const p = b64url(JSON.stringify(full));
    const sig = createHmac("sha256", secret).update(`${h}.${p}`).digest();
    return `${h}.${p}.${b64url(sig)}`;
}

export function verifyBetterToken(token: string, secret: string): any | null {
    if (!token || !secret) return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const expected = createHmac("sha256", secret).update(`${h}.${p}`).digest();
    const got = b64urlDecode(s);
    if (expected.length !== got.length) return null;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ got[i];
    if (diff !== 0) return null;
    let payload: any;
    try { payload = JSON.parse(b64urlDecode(p).toString("utf8")); } catch { return null; }
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== "number" || payload.exp <= now) return null;
    return payload;
}

// --- OIDC (RS256, JWKS) ---

interface JWKSCacheEntry { fetchedAt: number; keys: any[] }
const jwksCache = new Map<string, JWKSCacheEntry>();
const JWKS_TTL_MS = 10 * 60 * 1000;

export interface OidcConfig {
    issuer: string;
    audience: string;
    clientId: string;
    clientSecret: string;
}

async function discoverOidc(issuer: string): Promise<{jwks_uri: string; token_endpoint?: string}> {
    const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
    const ctl = new AbortController();
    (setTimeout(() => ctl.abort(), 5000) as any).unref?.();
    const r = await fetch(url, {signal: ctl.signal});
    if (!r.ok) throw new Error(`oidc discovery failed: ${r.status}`);
    return r.json() as any;
}

async function fetchJwks(issuer: string): Promise<any[]> {
    const cached = jwksCache.get(issuer);
    if (cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) return cached.keys;
    const meta = await discoverOidc(issuer);
    const ctl = new AbortController();
    (setTimeout(() => ctl.abort(), 5000) as any).unref?.();
    const r = await fetch(meta.jwks_uri, {signal: ctl.signal});
    if (!r.ok) throw new Error(`oidc jwks fetch failed: ${r.status}`);
    const jwks = await r.json() as any;
    jwksCache.set(issuer, {fetchedAt: Date.now(), keys: jwks.keys || []});
    return jwks.keys || [];
}

function pemFromJwk(jwk: any): string {
    // Build a SubjectPublicKeyInfo (SPKI) PEM from RSA n + e.
    // We delegate the heavy ASN.1 to Node via subtle.
    // Node 16+ supports jwk format directly.
    const {createPublicKey} = require("crypto") as typeof import("crypto");
    return createPublicKey({key: jwk as any, format: "jwk" as any}).export({type: "spki", format: "pem"}) as string;
}

function verifyRs256(token: string, publicKeyPem: string, audience: string, issuer: string): any | null {
    const {createVerify} = require("crypto") as typeof import("crypto");
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const sig = b64urlDecode(s);
    const sigView = new Uint8Array(sig.buffer, sig.byteOffset, sig.byteLength);
    const verifier = createVerify("RSA-SHA256");
    verifier.update(`${h}.${p}`);
    verifier.end();
    if (!verifier.verify(publicKeyPem as any, sigView)) return null;
    let payload: any;
    try { payload = JSON.parse(b64urlDecode(p).toString("utf8")); } catch { return null; }
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== "number" || payload.exp <= now) return null;
    if (payload.iss !== issuer) return null;
    const aud = payload.aud;
    const audOk = Array.isArray(aud) ? aud.includes(audience) : aud === audience;
    if (!audOk) return null;
    return payload;
}

export async function verifyOidcIdToken(token: string, cfg: OidcConfig): Promise<any | null> {
    try {
        const keys = await fetchJwks(cfg.issuer);
        let unverifiedHeader: any;
        try { unverifiedHeader = JSON.parse(b64urlDecode(token.split(".")[0]).toString("utf8")); } catch { return null; }
        const kid = unverifiedHeader.kid;
        const matched = kid ? keys.find((k) => k.kid === kid) : keys[0];
        if (!matched) return null;
        const pem = pemFromJwk(matched);
        return verifyRs256(token, pem, cfg.audience, cfg.issuer);
    } catch {
        return null;
    }
}

/**
 * Exchange an OIDC `code` for an id_token + access_token via the issuer's
 * token_endpoint. Returns the raw id_token (verify separately).
 */
export async function exchangeOidcCode(code: string, redirectUri: string, cfg: OidcConfig): Promise<{id_token?: string; access_token?: string}> {
    const meta = await discoverOidc(cfg.issuer);
    if (!meta.token_endpoint) throw new Error("oidc issuer has no token_endpoint");
    const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        redirect_uri: redirectUri,
    });
    const r = await fetch(meta.token_endpoint, {
        method: "POST",
        headers: {"content-type": "application/x-www-form-urlencoded"},
        body,
        signal: (() => { const c = new AbortController(); (setTimeout(() => c.abort(), 8000) as any).unref?.(); return c.signal; })(),
    });
    if (!r.ok) throw new Error(`oidc token exchange failed: ${r.status}`);
    return r.json() as any;
}

// --- claims shape ---

export interface AuthClaims {
    sub: string;            // dimension userId
    username: string;
    role: "user" | "admin";
    iss: string;
    aud: string;
    iat: number;
    exp: number;
    scope: string;
    source: "better-auth" | "oidc";
}

export function claimsFromBetter(payload: any): AuthClaims {
    return {
        sub: String(payload.sub),
        username: String(payload.username ?? payload.sub),
        role: payload.role === "admin" ? "admin" : "user",
        iss: String(payload.iss ?? "dimension"),
        aud: String(payload.aud ?? "dimension-web"),
        iat: Number(payload.iat),
        exp: Number(payload.exp),
        scope: String(payload.scope ?? ""),
        source: "better-auth",
    };
}

export function claimsFromOidc(payload: any, username: string, role: "user" | "admin"): AuthClaims {
    return {
        sub: String(payload.sub),
        username,
        role,
        iss: String(payload.iss),
        aud: String(payload.aud),
        iat: Number(payload.iat),
        exp: Number(payload.exp),
        scope: String(payload.scope ?? ""),
        source: "oidc",
    };
}

export const NEW_JTI = randomUUID;
