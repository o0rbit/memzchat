/**
 * Jest config for the dimension backend tests.
 *
 * ts-jest compiles test files. We disable strict type-checking for deps
 * with minor TS lib version skews (helmet, `@types/supertest`, sharp
 * that need newer `buffer`/lib types the test CP has). The source code
 * is type-checked separately via `npx tsc --noEmit -p tsconfig.backend.json`.
 */
module.exports = {
    preset: "ts-jest",
    testEnvironment: "node",
    rootDir: "..",
    roots: ["<rootDir>/test"],
    testMatch: ["**/test/**/*.test.ts"],
    transform: {
        "^.+\\.ts$": [
            "ts-jest",
            {
                tsconfig: "tsconfig.test.json",
                diagnostics: {
                    // Skip type errors from third-party declarations that are
                    // technically broken against this project's TS-lib but
                    // don't affect runtime behaviour.
                    ignoreCodes: [2305, 2307, 2315, 2344, 2503],
                },
            },
        ],
    },
    moduleFileExtensions: ["ts", "js", "json"],
    setupFiles: ["<rootDir>/test/setup.ts"],
    testTimeout: 15000,
    detectOpenHandles: false,
    forceExit: true,
    // Colours make it easier to scan CI output.
    verbose: true,
};