import { defineConfig } from 'vitest/config';

// Keep the complete suite usable alongside the local API, broker and sandbox.
// This changes test-process concurrency only, never audit execution budgets.
export default defineConfig({ test: { maxWorkers: 1 } });
