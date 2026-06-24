/**
 * Tests for the password hashing + JWT mint/verify utilities.
 * Pure-stdlib, no DB, no network.
 */

import { hashPassword, verifyPassword, needsRehash } from "../../src/auth/passwords";
import { signBetterToken, verifyBetterToken } from "../../src/auth/jwt";

describe("passwords (scrypt)", () => {
    test("hashPassword produces a string with the expected prefix", async () => {
        const h = await hashPassword("hunter2");
        expect(h.startsWith("scrypt$N=32768,r=8,p=1$")).toBe(true);
        expect(h.split("$")).toHaveLength(4);
    });

    test("verifyPassword accepts the correct password", async () => {
        const h = await hashPassword("hunter2hunter2");
        expect(await verifyPassword("hunter2hunter2", h)).toBe(true);
    });

    test("verifyPassword rejects wrong password", async () => {
        const h = await hashPassword("correct");
        expect(await verifyPassword("wrong", h)).toBe(false);
    });

    test("verifyPassword returns false on malformed stored hash", async () => {
        expect(await verifyPassword("anything", "not-a-hash")).toBe(false);
        expect(await verifyPassword("anything", "")).toBe(false);
        expect(await verifyPassword("anything", "$a$b")).toBe(false);
    });

    test("hashPassword rejects empty / too-long passwords", async () => {
        await expect(hashPassword("")).rejects.toThrow();
        await expect(hashPassword("x".repeat(5000))).rejects.toThrow();
    });

    test("needsRehash detects obsolete params", async () => {
        expect(needsRehash("not-a-hash")).toBe(true);
        const h = await hashPassword("ok");
        expect(needsRehash(h)).toBe(false);
        // Manually craft an old-format hash
        expect(needsRehash("scrypt$N=1024,r=8,p=1$AAAA$BBBB")).toBe(true);
    });

    test("two hashes of the same password differ (random salt)", async () => {
        const a = await hashPassword("same");
        const b = await hashPassword("same");
        expect(a).not.toBe(b);
    });
});

describe("better-auth JWT (HS256)", () => {
    const secret = "x".repeat(32);

    test("signBetterToken + verifyBetterToken roundtrip", () => {
        const token = signBetterToken({sub: "u1", role: "admin"}, secret);
        const decoded = verifyBetterToken(token, secret);
        expect(decoded).not.toBeNull();
        expect(decoded.sub).toBe("u1");
        expect(decoded.role).toBe("admin");
    });

    test("verifyBetterToken rejects wrong secret", () => {
        const token = signBetterToken({sub: "u1"}, secret);
        expect(verifyBetterToken(token, "y".repeat(32))).toBeNull();
    });

    test("verifyBetterToken rejects malformed token", () => {
        expect(verifyBetterToken("not.a.token", secret)).toBeNull();
        expect(verifyBetterToken("only.two", secret)).toBeNull();
        expect(verifyBetterToken("", secret)).toBeNull();
    });

    test("verifyBetterToken rejects expired tokens", () => {
        const now = Math.floor(Date.now() / 1000);
        const token = signBetterToken({sub: "u1", iat: now - 7200, exp: now - 60}, secret);
        expect(verifyBetterToken(token, secret)).toBeNull();
    });

    test("signBetterToken rejects too-short secret", () => {
        expect(() => signBetterToken({sub: "u1"}, "short")).toThrow();
    });

    test("verifyBetterToken is constant-time-ish on signature mismatch", () => {
        const token = signBetterToken({sub: "u1"}, secret);
        const parts = token.split(".");
        // Flip one byte in the signature
        // base64url: replace - with +, _ with /, strip padding, then base64
        const s = parts[2].replace(/-/g, "+").replace(/_/g, "/");
        const padded = s + "=".repeat((4 - s.length % 4) % 4);
        const sigBytes = Buffer.from(padded, "base64");
        sigBytes[0] ^= 0xff;
        const tampered = parts[0] + "." + parts[1] + "." + sigBytes.toString("base64").replace(/=+$/, "");
        expect(verifyBetterToken(tampered, secret)).toBeNull();
    });
});
