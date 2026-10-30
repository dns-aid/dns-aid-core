import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: process.env.DNS_AID_LIVE ? [] : ["test/live.test.ts"],
  },
});
