import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      exclude: ["dist/**", "**/*.test.ts", "vitest.config.ts", "tsup.config.ts"],
    },
  },
});
