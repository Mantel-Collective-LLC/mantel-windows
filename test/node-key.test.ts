import { describe, expect, it } from "vitest";
import { nodeSchema } from "../src/main/api/schemas";
import { withNodeKey } from "../src/main/vpn";

const base = { id: "hk-1", city: "Hongkong", country: "HK", endpointHost: "198.51.100.7", endpointPort: 51820, online: true };
const oldKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const newKey = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

describe("node server key", () => {
  it("is optional and invalid values count as missing", () => {
    expect(nodeSchema.parse(base).serverPublicKey).toBeUndefined();
    expect(nodeSchema.parse({ ...base, serverPublicKey: "nope" }).serverPublicKey).toBeUndefined();
    expect(nodeSchema.parse({ ...base, serverPublicKey: newKey }).serverPublicKey).toBe(newKey);
  });

  it("replaces the stored key of the device for the tunnel", () => {
    const device = { id: "d1", config: { serverPublicKey: oldKey, endpoint: "198.51.100.7:51820" } };
    expect(withNodeKey(device, { serverPublicKey: newKey }).config).toEqual({ serverPublicKey: newKey, endpoint: "198.51.100.7:51820" });
    expect(device.config.serverPublicKey).toBe(oldKey);
    expect(withNodeKey(device, {})).toBe(device);
  });
});
