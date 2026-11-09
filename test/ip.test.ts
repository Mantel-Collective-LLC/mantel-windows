import { describe, expect, it } from "vitest";
import {
  cidrRanges,
  complementRanges,
  formatAddress,
  mergeRanges,
  parseAddress,
  parseCidr,
  rangesToCidrs,
  subtractRanges,
} from "../src/main/net/ip";
import { LAN_V6, ROUTE_EXCLUDE_V4 } from "../src/main/net/ranges";

function covered(cidrs: string[], address: string): boolean {
  const parsed = parseAddress(address);
  if (!parsed) return false;
  return cidrRanges(cidrs).some(
    (range) => range.family === parsed.family && parsed.value >= range.start && parsed.value <= range.end,
  );
}

describe("ip parsing and formatting", () => {
  it("round-trips IPv4 and compresses IPv6", () => {
    expect(formatAddress(4, parseAddress("192.168.1.20")!.value)).toBe("192.168.1.20");
    expect(formatAddress(6, parseAddress("fd00:0:0:0:0:0:0:1")!.value)).toBe("fd00::1");
    expect(formatAddress(6, parseAddress("::")!.value)).toBe("::");
    expect(formatAddress(6, parseAddress("2001:db8:0:1:0:0:0:1")!.value)).toBe("2001:db8:0:1::1");
    expect(formatAddress(6, parseAddress("::ffff:10.0.0.1")!.value)).toBe("::ffff:a00:1");
  });

  it("rejects malformed CIDRs", () => {
    expect(parseCidr("10.0.0.0/33")).toBeNull();
    expect(parseCidr("10.0.0/8")).toBeNull();
    expect(parseCidr("fe80::/129")).toBeNull();
    expect(parseCidr("10.0.0.0/8")).not.toBeNull();
  });
});

describe("complement routing", () => {
  const lan = cidrRanges([...ROUTE_EXCLUDE_V4, ...LAN_V6]);
  const v4 = rangesToCidrs(complementRanges(4, lan));
  const v6 = rangesToCidrs(complementRanges(6, lan));

  it("excludes every private, link-local, multicast and broadcast address", () => {
    for (const address of ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.178.1", "169.254.10.10", "224.0.0.251", "239.255.255.250", "255.255.255.255"]) {
      expect(covered(v4, address)).toBe(false);
    }
    for (const address of ["fd12::1", "fc00::1", "fe80::1", "ff02::1"]) {
      expect(covered(v6, address)).toBe(false);
    }
  });

  it("covers every public address", () => {
    for (const address of ["0.0.0.1", "1.1.1.1", "9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0", "223.255.255.255"]) {
      expect(covered(v4, address)).toBe(true);
    }
    for (const address of ["::1", "2001:db8::1", "2a00:1450::1", "fbff:ffff::1", "fe7f::1", "fec0::1", "feff::1"]) {
      expect(covered(v6, address)).toBe(true);
    }
  });

  it("produces disjoint ranges whose union with the LAN set is the whole space", () => {
    const total = (family: 4 | 6) =>
      mergeRanges([...complementRanges(family, lan), ...lan.filter((range) => range.family === family)]);
    expect(total(4)).toEqual([{ family: 4, start: 0n, end: 2n ** 32n - 1n }]);
    expect(total(6)).toEqual([{ family: 6, start: 0n, end: 2n ** 128n - 1n }]);
    expect(v4).toMatchSnapshot();
    expect(v6).toMatchSnapshot();
  });

  it("subtracts single hosts from ranges", () => {
    const result = subtractRanges(cidrRanges(["10.0.0.0/8"]), cidrRanges(["10.10.10.114/32"]));
    expect(rangesToCidrs(result)).not.toContain("10.10.10.114/32");
    expect(result).toHaveLength(2);
  });
});
