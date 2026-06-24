/**
 * Jest setup — runs before each test file.
 *
 * Intentionally minimal. Per-file mocks are declared inline in each test
 * (jest.mock(...) at the top of the file) so the setup contract is
 * visible to the reader. This file exists so jest.config.js can point
 * at it without throwing.
 */
export {};