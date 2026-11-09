import { describe, expect, it } from "vitest";
import { BLOCKLIST_IDS, DNS_FILTER_GROUPS, dnsGroupActive, dnsGroupPatch, type DnsBlocklists } from "../shared/core/contract";
import de from "../shared/core/i18n/de.json";
import en from "../shared/core/i18n/en.json";

const none = Object.fromEntries(BLOCKLIST_IDS.map((id) => [id, false])) as DnsBlocklists;

describe("DNS filter groups (one switch for ads, trackers and malware, like the website)", () => {
  it("covers every blocklist exactly once", () => {
    const lists = DNS_FILTER_GROUPS.flatMap((group) => [...group.lists]).sort();
    expect(lists).toEqual([...BLOCKLIST_IDS].sort());
  });

  it("switches the core lists together", () => {
    const core = DNS_FILTER_GROUPS[0];
    expect(dnsGroupPatch(core, true)).toEqual({ ads: true, trackers: true, malware: true });
    expect(dnsGroupActive({ ...none, trackers: true }, core)).toBe(true);
    expect(dnsGroupActive(none, core)).toBe(false);
  });

  it("has a label per group in German and English", () => {
    for (const group of DNS_FILTER_GROUPS) {
      expect(de.settings.blocklists[group.id]).toBeTruthy();
      expect(en.settings.blocklists[group.id]).toBeTruthy();
    }
  });
});
