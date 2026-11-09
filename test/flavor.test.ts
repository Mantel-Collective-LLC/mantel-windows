import { describe, expect, it } from "vitest";
import { flavorDefine, resolveFlavor } from "../build/flavor";
import { DEBUG_API_URL, resolveApiUrl } from "../shared/core/api-url";
import { redact, redactValue } from "../src/main/debug/redact";
import { API_BASE_URL, FLAVOR, identityOf, IS_DEBUG } from "../src/main/flavor";

describe("build flavor", () => {
  it("defaults to prod and rejects typos instead of guessing", () => {
    expect(resolveFlavor(undefined)).toBe("prod");
    expect(resolveFlavor("")).toBe("prod");
    expect(resolveFlavor("prod")).toBe("prod");
    expect(resolveFlavor(" Debug ")).toBe("debug");
    expect(() => resolveFlavor("dbg")).toThrow(/ungültig/);
    expect(flavorDefine("debug", { strict: true, apiUrl: "" })["import.meta.env.MANTEL_FLAVOR"]).toBe('"debug"');
  });

  it("is prod when nothing defines it (Vitest, like a build without MANTEL_FLAVOR)", () => {
    expect(FLAVOR).toBe("prod");
    expect(IS_DEBUG).toBe(false);
  });

  it("takes the API server only from the build: prod needs MANTEL_API_URL (HTTPS), debug defaults to the local one", () => {
    const strict = { debugDefault: DEBUG_API_URL.desktop, strict: true };
    expect(() => resolveApiUrl("prod", undefined, strict)).toThrow(/MANTEL_API_URL fehlt/);
    expect(() => resolveApiUrl("prod", "  ", strict)).toThrow(/MANTEL_API_URL fehlt/);
    expect(() => resolveApiUrl("prod", "http://api.example.org", strict)).toThrow(/nur HTTPS/);
    expect(resolveApiUrl("prod", " https://API.example.org/v1/ ", strict)).toBe("https://api.example.org");
    expect(resolveApiUrl("debug", undefined, strict)).toBe("http://localhost:3000");
    expect(resolveApiUrl("debug", "http://127.0.0.1:3101", strict)).toBe("http://127.0.0.1:3101");
    expect(() => resolveApiUrl("debug", "ftp://x", strict)).toThrow(/http/);
    expect(() => resolveApiUrl("debug", "http://user:pw@host", strict)).toThrow(/Zugangsdaten/);
    expect(() => resolveApiUrl("debug", "kein url", strict)).toThrow(/gültige/);
    expect(resolveApiUrl("prod", undefined, { ...strict, strict: false })).toBe("http://localhost:3000");
    expect(DEBUG_API_URL.android).toBe("http://10.0.2.2:3000");
  });

  it("puts the API server into the bundle as a constant and fails a prod build without one", () => {
    expect(() => flavorDefine("prod", { strict: true, apiUrl: undefined })).toThrow(/MANTEL_API_URL fehlt/);
    expect(flavorDefine("prod", { strict: true, apiUrl: "https://api.example.org" })["import.meta.env.MANTEL_API_URL"]).toBe(
      '"https://api.example.org"',
    );
    expect(flavorDefine("debug", { strict: true, apiUrl: "" })["import.meta.env.MANTEL_API_URL"]).toBe('"http://localhost:3000"');
    expect(API_BASE_URL).toBe("http://localhost:3000");
  });

  it("gives both variants their own identity so they can be installed side by side", () => {
    const prod = identityOf("prod");
    const debug = identityOf("debug");
    expect(prod.productName).toBe("Mantel");
    expect(prod.tunnelName).toBe("mantel");
    expect(prod.firewallGroup).toBe("Mantel Kill Switch");
    for (const key of Object.keys(prod) as Array<keyof typeof prod>) {
      expect(debug[key], key).not.toBe(prod[key]);
    }
    expect(debug.tunnelName).toMatch(/^[a-zA-Z0-9_=+.-]{1,32}$/);
  });
});

describe("debug redaction", () => {
  it("removes tokens, account codes and keys from text", () => {
    const text = [
      "Authorization: Bearer abcDEF123._~+/=-xyz",
      "code 1234 5678 9012 3456 and 1234567890123456 and 1234-5678-9012-3456",
      "key yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
      "token Qm9vX2Zvby1iYXJfYmF6LWJhcl9xdXV4LXF1dXg123456",
    ].join("\n");
    const result = redact(text);
    expect(result).not.toMatch(/\d{4} ?\d{4} ?\d{4} ?\d{4}/);
    expect(result).not.toContain("yAnz5TF");
    expect(result).not.toContain("abcDEF123");
    expect(result).not.toContain("Qm9vX2Zv");
    expect(result).toContain("[account code]");
    expect(result).toContain("[key]");
  });

  it("keeps ordinary diagnostics readable", () => {
    expect(redact("GET /api/v1/devices/:id → 204 12 ms")).toBe("GET /api/v1/devices/:id → 204 12 ms");
    expect(redact("10.64.0.7/32, 198.51.100.7:51820, 2026-10-22T03:00:00.000Z")).toBe(
      "10.64.0.7/32, 198.51.100.7:51820, 2026-10-22T03:00:00.000Z",
    );
  });

  it("replaces secret keys in objects, whatever their value looks like", () => {
    expect(redactValue({ token: "short", nested: { privateKey: "x", nodeId: "ch-zrh" }, code: "network" })).toEqual({
      token: "[redacted]",
      nested: { privateKey: "[redacted]", nodeId: "ch-zrh" },
      code: "network",
    });
  });
});
