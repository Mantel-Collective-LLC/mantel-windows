import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { parseScQuery, parseWgShow } from "../src/main/wireguard/parse";
import { phaseFor } from "../src/main/wireguard/phase";

const fixture = (name: string) => readFileSync(path.join(__dirname, "fixtures", name), "utf8");

describe("wg show (non-secret subcommands)", () => {
  const PEER = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
  const OTHER = "h2lcXP+HuIipSc5D9u5MMVC139EotqrfTZ6u/c++XwA=";
  const IFACE = "pLLGZN3M20E9HOfCw9BTwB1UWPNJLHZEkJS0Bi4uKxw=";

  it("combines public-key, latest-handshakes, transfer and endpoints", () => {
    const status = parseWgShow({
      publicKey: `${IFACE}\r\n`,
      latestHandshakes: `${PEER}\t1760750000\r\n${OTHER}\t0\r\n`,
      transfer: `${PEER}\t1048576\t524288\n${OTHER}\t0\t0\n`,
      endpoints: `${PEER}\t198.51.100.7:51820\n${OTHER}\t(none)\n`,
    });
    expect(status).toEqual({
      publicKey: IFACE,
      peers: [
        { publicKey: PEER, endpoint: "198.51.100.7:51820", latestHandshakeAt: 1_760_750_000_000, rxBytes: 1_048_576, txBytes: 524_288 },
        { publicKey: OTHER, endpoint: null, latestHandshakeAt: null, rxBytes: 0, txBytes: 0 },
      ],
    });
  });

  it("tolerates missing transfer/endpoints and skips bad lines", () => {
    const status = parseWgShow({ publicKey: IFACE, latestHandshakes: `garbage\n${PEER}\t5\n`, transfer: "", endpoints: "" });
    expect(status?.peers).toEqual([{ publicKey: PEER, endpoint: null, latestHandshakeAt: 5000, rxBytes: 0, txBytes: 0 }]);
  });

  it("returns null without a readable interface key", () => {
    expect(parseWgShow({ publicKey: "", latestHandshakes: "", transfer: "", endpoints: "" })).toBeNull();
    expect(parseWgShow({ publicKey: "Unable to access interface: Permission denied", latestHandshakes: "", transfer: "", endpoints: "" })).toBeNull();
  });
});

describe("sc query", () => {
  it("reads the state from recorded output", () => {
    expect(parseScQuery(fixture("sc-running.txt"))).toBe("RUNNING");
    expect(parseScQuery(fixture("sc-missing.txt"))).toBeNull();
    expect(parseScQuery("        STATUS             : 1  STOPPED \r\n")).toBe("STOPPED");
    expect(parseScQuery("        STATE              : 2  START_PENDING \r\n")).toBe("START_PENDING");
  });
});

describe("stale detection", () => {
  const now = 1_000_000_000;
  it("flags a tunnel without handshake for over three minutes", () => {
    expect(phaseFor({ now, connectedAt: now - 600_000, lastHandshakeAt: now - 181_000 })).toBe("stale");
    expect(phaseFor({ now, connectedAt: now - 600_000, lastHandshakeAt: now - 30_000 })).toBe("connected");
    expect(phaseFor({ now, connectedAt: now - 5_000, lastHandshakeAt: null })).toBe("connecting");
    expect(phaseFor({ now, connectedAt: now - 60_000, lastHandshakeAt: null })).toBe("stale");
  });
});
