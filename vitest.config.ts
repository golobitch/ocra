import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      // Type-only module: erased at build time, so it has no runtime lines.
      exclude: ["src/types.ts"],
      reporter: ["text", "lcov"],
      thresholds: {
        statements: 100,
        functions: 100,
        lines: 100,
        // The one gap is a defensive length check in timingSafeEqual that the
        // public API's own validation makes unreachable.
        branches: 99,
      },
    },
  },
});
