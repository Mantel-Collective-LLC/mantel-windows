import { describe, expect, it } from "vitest";
import packageJson from "../package.json";
import { USER_AGENT } from "../src/main/api/client";

describe("app version", () => {
  it("is YEAR.MINOR.PATCH", () => {
    expect(packageJson.version).toMatch(/^\d{4}\.\d{1,2}\.\d{1,3}$/);
  });

  it("is sent in the User-Agent", () => {
    expect(USER_AGENT).toBe(`MantelDesktop/${packageJson.version} (${process.platform === "darwin" ? "macOS" : "Windows"})`);
  });
});
