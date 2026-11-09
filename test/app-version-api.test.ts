import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApiClient } from "../src/main/api/client";
import type { AppVersionInfo } from "../shared/core/app-version";

const INFO: AppVersionInfo = {
  platform: "windows",
  latest: "2026.1.0",
  minimum: "2026.0.1",
  downloadUrl: "/download",
  notes: { de: "Schneller verbinden.", en: "Faster connecting." },
  sha256: "a".repeat(64),
};

describe("ApiClient.appVersion (Windows shell)", () => {
  let server: Server;
  let port = 0;
  const seen: { url?: string; headers?: IncomingHttpHeaders }[] = [];
  let answer: unknown = { ...INFO };
  beforeAll(async () => {
    server = createServer((request, response) => {
      seen.push({ url: request.url, headers: request.headers });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(answer));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("asks anonymously, only with the platform", async () => {
    const api = new ApiClient(() => `http://127.0.0.1:${port}`, () => "secret-session-token-123456");
    expect(await api.appVersion("windows")).toEqual(INFO);
    const request = seen.at(-1)!;
    expect(request.url).toBe("/api/v1/app-version?platform=windows");
    expect(request.headers?.authorization).toBeUndefined();
    expect(request.headers?.cookie).toBeUndefined();
  });

  it("Mac app: asks with platform=macos and accepts only a macos answer", async () => {
    const api = new ApiClient(() => `http://127.0.0.1:${port}`, () => null);
    answer = { ...INFO, platform: "macos" };
    expect(await api.appVersion("macos")).toEqual({ ...INFO, platform: "macos" });
    expect(seen.at(-1)!.url).toBe("/api/v1/app-version?platform=macos");
    answer = { ...INFO };
    await expect(api.appVersion("macos")).rejects.toMatchObject({ code: "server" });
  });

  it("rejects a malformed answer", async () => {
    answer = { platform: "android", latest: "2026.1.0" };
    const api = new ApiClient(() => `http://127.0.0.1:${port}`, () => null);
    await expect(api.appVersion("windows")).rejects.toMatchObject({ code: "server" });
    answer = { ...INFO };
  });
});
