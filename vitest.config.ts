import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Patch tests run against built packages via scripts/build-patch.mjs, not here.
    include: ["test/**/*.test.ts"],
  },
});
