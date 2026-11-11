import { defineConfig } from "vitest/config";
import { SHARED_DEPS } from "./build/shared";

export default defineConfig({
  resolve: { dedupe: SHARED_DEPS },
  test: {
    include: ["test/**/*.test.ts", "test/**/*.test.tsx", "tauri/test/**/*.test.ts"],
    environment: "node",
    testTimeout: 60_000,
  },
});
