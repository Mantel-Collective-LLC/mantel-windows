import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApiClient, ApiError, routeTemplate, type ApiRequestRecord } from "../src/main/api/client";
import { buildTunnelConfig, parseEndpoint } from "../src/main/wireguard/config";
import { generateKeyPair, publicKeyFromPrivate } from "../src/main/wireguard/keys";

const CODE = "1234567890123456";

function startMock(port: number, env: Record<string, string> = {}): Promise<ChildProcess> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(__dirname, "..", "dev", "mock-api.mjs")], {
      env: { ...process.env, MOCK_PORT: String(port), ...env },
      stdio: ["ignore", "pipe", "inherit"],
    });
    child.stdout?.on("data", (chunk: Buffer) => {
      if (chunk.toString().includes("Mock-API")) resolve(child);
    });
    child.on("error", reject);
  });
}

function client(port: number) {
  let token: string | null = null;
  const api = new ApiClient(() => `http://127.0.0.1:${port}`, () => token);
  return { api, setToken: (next: string | null) => (token = next) };
}

const mocks: ChildProcess[] = [];
beforeAll(async () => {
  mocks.push(
    await startMock(3911),
    await startMock(3912, { MOCK_SERVER_KEYS: "1" }),
    await startMock(3913, { MOCK_REGISTER_LIMIT: "2" }),
    await startMock(3914),
    await startMock(3915, { MOCK_TOTP: "123456" }),
  );
});
afterAll(() => mocks.forEach((mock) => mock.kill()));

describe("API contract against the mock", () => {
  it("two-factor login: totp is always sent, totp_required without a code, totp_invalid for a wrong one", async () => {
    const { api } = client(3915);
    const required = await api.login(CODE).catch((error: ApiError) => error);
    expect(required).toBeInstanceOf(ApiError);
    expect(required).toMatchObject({ code: "totp_required", apiCode: "totp_required", status: 401 });
    const wrong = await api.login(CODE, "000000").catch((error: ApiError) => error);
    expect(wrong).toMatchObject({ code: "invalid", apiCode: "totp_invalid" });
    expect((await api.login(CODE, "123456")).token).toBeTruthy();
  });

  it("logs in, lists nodes, registers and deletes a device with a client key", async () => {
    const { api, setToken } = client(3911);
    const login = await api.login(CODE);
    setToken(login.token);
    expect(login.account.id).toMatch(/^acc_/);

    const nodes = await api.nodes();
    expect(nodes.find((node) => node.id === "is-rkv")?.online).toBe(false);
    expect(nodes.find((node) => node.id === "ch-gva")?.status).toBe("full");
    expect(nodes.find((node) => node.id === "ch-zrh")?.status).toBeUndefined();
    const node = nodes.find((entry) => entry.online && !entry.status)!;

    const keys = generateKeyPair();
    const registered = await api.registerDevice({ name: "Windows TEST", nodeId: node.id, publicKey: keys.publicKey });
    expect(registered.privateKey).toBeUndefined();
    expect(registered.device.nodeId).toBe(node.id);
    expect(registered.device.obfsToken).toMatch(/^[0-9a-f]{64}$/);
    expect(nodes.find((entry) => entry.id === "de-fra")?.obfuscation).toMatchObject({ version: 1, port: 443 });
    expect(nodes.find((entry) => entry.id === "ch-zrh")?.obfuscation).toBeUndefined();

    const endpoint = parseEndpoint(registered.config.endpoint)!;
    const config = buildTunnelConfig({
      privateKey: keys.privateKey,
      server: registered.config,
      endpoint,
      settings: { killSwitch: true, lanAccess: false, ipv6: true },
    });
    expect(config.text).toContain(`PrivateKey = ${keys.privateKey}`);
    expect(config.text).toContain("AllowedIPs = 0.0.0.0/0, ::/0");

    const account = await api.account();
    expect(account.devices.map((device) => device.id)).toContain(registered.device.id);
    expect(account.devices.find((device) => device.id === registered.device.id)?.obfsToken).toBe(registered.device.obfsToken);

    await api.deleteDevice(registered.device.id);
    const after = await api.account();
    expect(after.devices.map((device) => device.id)).not.toContain(registered.device.id);

    await api.logout();
    await expect(api.account()).rejects.toMatchObject({ code: "unauthorized", status: 401 });
  });

  it("patches settings partially and returns the full object", async () => {
    const { api, setToken } = client(3911);
    setToken((await api.login(CODE)).token);
    const next = await api.updateSettings({ dns: { social: true }, lanAccess: true });
    expect(next.dns.social).toBe(true);
    expect(next.dns.ads).toBe(true);
    expect(next.lanAccess).toBe(true);
    const reverted = await api.updateSettings({ dns: { social: false }, lanAccess: false });
    expect(reverted.lanAccess).toBe(false);
  });

  it("maps wrong codes to 401 and repeated failures to 429", async () => {
    const { api } = client(3911);
    const errors: ApiError[] = [];
    for (let attempt = 0; attempt < 6; attempt += 1) {
      errors.push(await api.login("9999999999999999").catch((error: ApiError) => error) as ApiError);
    }
    expect(errors[0]?.code).toBe("unauthorized");
    expect(errors[0]?.message).toBe("Diese Kontonummer kennen wir nicht.");
    expect(errors.at(-1)?.code).toBe("rate_limited");
  });

  it("supports the server-generated private key fallback", async () => {
    const { api, setToken } = client(3912);
    setToken((await api.login(CODE)).token);
    const registered = await api.registerDevice({ name: "Windows TEST", nodeId: "ch-zrh", publicKey: generateKeyPair().publicKey });
    expect(registered.privateKey).toBeDefined();
    expect(publicKeyFromPrivate(registered.privateKey!)).toMatch(/=$/);
  });

  it("answers a full, paused or migrating location with its error code", async () => {
    const { api, setToken } = client(3912);
    setToken((await api.login(CODE)).token);
    const register = (nodeId: string) => api.registerDevice({ name: "Windows TEST", nodeId, publicKey: generateKeyPair().publicKey });
    await expect(register("ch-gva")).rejects.toMatchObject({ status: 503, apiCode: "location_full" });
    await expect(register("at-vie")).rejects.toMatchObject({ status: 503, apiCode: "location_paused" });
    await expect(register("fr-par")).rejects.toMatchObject({ status: 503, apiCode: "location_upgrading" });
  });

  it("registers a new account: 16-digit code + session, the code logs in to the same account", async () => {
    const { api, setToken } = client(3914);
    const created = await api.register();
    expect(created.code).toMatch(/^\d{16}$/);
    expect(created.account.id).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
    expect(Date.parse(created.account.paidUntil)).toBeGreaterThan(Date.now());
    setToken(created.token);
    expect((await api.account()).id).toBe(created.account.id);
    const again = await api.login(created.code);
    expect(again.account.id).toBe(created.account.id);
  });

  it("maps the register rate limit to rate_limited", async () => {
    const { api } = client(3913);
    await api.register();
    await api.register();
    await expect(api.register()).rejects.toMatchObject({ code: "rate_limited", status: 429 });
  });

  it("reports finished requests to the debug observer without ids", async () => {
    const { api, setToken } = client(3914);
    const records: ApiRequestRecord[] = [];
    api.onRequest = (record) => records.push(record);
    setToken((await api.login(CODE)).token);
    await api.deleteDevice("dev_secret123");
    await api.login("9999999999999999").catch(() => undefined);
    expect(records.map((record) => [record.method, record.route, record.status])).toEqual([
      ["POST", "/api/v1/auth/login", 200],
      ["DELETE", "/api/v1/devices/:id", 404],
      ["POST", "/api/v1/auth/login", 401],
    ]);
    expect(records[2]?.code).toBe("unauthorized");
    expect(JSON.stringify(records)).not.toContain("dev_secret123");
    expect(routeTemplate("/api/v1/devices/abc/x")).toBe("/api/v1/devices/:id/x");
  });

  it("reports an unreachable server as a network error", async () => {
    const api = new ApiClient(() => "http://127.0.0.1:1", () => null);
    await expect(api.nodes()).rejects.toMatchObject({ code: "network" });
  });
});
