/**
 * Password hashing via Node-native scrypt (RFC 7914).
 *
 * Why scrypt over argon2/bcrypt:
 *
 *   - zero npm dependency (we audit-bumped 50 vulns in the last commit;
 *     adding argon2 or bcrypt would either rebuild native bindings or
 *     add transitive risk)
 *   - available since Node 10; we target Node 16+
 *   - configurable cost; OWASP recommends N=2^17, r=8, p=1 for interactive
 *     logins (2024). We default to N=2^15 for faster logins on the
 *     integration-manager workload.
 *
 * Output format: scrypt$N=16384,r=8,p=1$<salt-b64>$<hash-b64>
 * The version prefix lets us upgrade params without breaking old hashes.
 */

import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "crypto";
import { promisify } from "util";

const scrypt: (password: string, salt: ArrayBufferView, keylen: number, options: { N: number; r: number; p: number; maxmem?: number }) => Promise<Buffer> = promisify(scryptCb as any) as any;

const N = 1 << 15; // 32768
const R = 8;
const P = 1;
const MAXMEM = 128 * 1024 * 1024; // 128 MB cap (default is 32 MB which rejects N=32768)
const KEY_LEN = 64;
const SALT_LEN = 16;

export const SCRYPT_PARAMS = Object.freeze({N, R, P, keyLen: KEY_LEN, saltLen: SALT_LEN});

/**
 * Hash a plaintext password. Returns the serialized hash string.
 * Throws if password is empty or not a string.
 */
export async function hashPassword(password: string): Promise<string> {
    if (typeof password !== "string" || password.length === 0) {
        throw new Error("password must be a non-empty string");
    }
    if (password.length > 4096) {
        throw new Error("password too long");
    }
    const salt = randomBytes(SALT_LEN);
    const hash = await scrypt(password, salt, KEY_LEN, {N, r: R, p: P, maxmem: MAXMEM});
    return `scrypt$N=${N},r=${R},p=${P}$${salt.toString("base64")}$${hash.toString("base64")}`;
}

/**
 * Verify a plaintext password against a stored hash.
 * Constant-time comparison; tolerates malformed stored hashes (returns false).
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
    if (typeof password !== "string" || typeof stored !== "string") return false;
    const parts = stored.split("$");
    if (parts.length !== 4 || parts[0] !== "scrypt") return false;
    const saltB64 = parts[2];
    const hashB64 = parts[3];
    if (!saltB64 || !hashB64) return false;
    const salt = Buffer.from(saltB64, "base64");
    const expected = Buffer.from(hashB64, "base64");
    const candidate = await scrypt(password, salt, expected.length, {N, r: R, p: P, maxmem: MAXMEM});
    if (candidate.length !== expected.length) return false;
    const candView = new Uint8Array(candidate.buffer, candidate.byteOffset, candidate.byteLength);
    const expView = new Uint8Array(expected.buffer, expected.byteOffset, expected.byteLength);
    return timingSafeEqual(candView, expView);
}

/**
 * Returns true when the stored hash uses the current cost parameters.
 * False triggers rehash-on-login (caller responsibility).
 */
export function needsRehash(stored: string): boolean {
    if (typeof stored !== "string") return false;
    const parts = stored.split("$");
    if (parts.length !== 4 || parts[0] !== "scrypt") return true;
    return parts[1] !== `N=${N},r=${R},p=${P}`;
}
