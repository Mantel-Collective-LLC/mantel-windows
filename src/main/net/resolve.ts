import { lookup as dnsLookup } from "node:dns/promises";
import { isIP, type LookupFunction } from "node:net";
import { LocalizedError } from "../../../shared/core/i18n";
import { isIpLiteral } from "./ip";

export const MAX_CACHED_ADDRESSES = 4;
const LOOKUP_TIMEOUT_MS = 5_000;

export type AddressCache = {
  read: (host: string) => string[];
  write: (host: string, addresses: string[]) => void;
};

export type SystemLookup = (host: string) => Promise<string[]>;

export class UnresolvedHostError extends LocalizedError {
  readonly code = "ENOTFOUND";
  constructor(
    readonly host: string,
    readonly dnsBlocked: boolean,
  ) {
    super(dnsBlocked ? "dnsBlockedUnknownHost" : "hostUnresolved", { host });
  }
}

export function normalizeHost(host: string): string {
  return host.trim().replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
}

export async function systemLookup(host: string): Promise<string[]> {
  const results = await dnsLookup(host, { all: true, verbatim: false });
  return results.map((entry) => entry.address).filter(isIpLiteral);
}

export function mergeAddresses(fresh: readonly string[], previous: readonly string[], max = MAX_CACHED_ADDRESSES): string[] {
  return [...new Set([...fresh, ...previous].filter(isIpLiteral))].slice(0, max);
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new LocalizedError("dnsTimeout")), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export class HostResolver {
  private readonly lookup: SystemLookup;
  private readonly timeoutMs: number;

  constructor(
    private readonly options: {
      cache: AddressCache;
      dnsBlocked: () => boolean;
      lookup?: SystemLookup;
      timeoutMs?: number;
      onChange?: (host: string) => void;
    },
  ) {
    this.lookup = options.lookup ?? systemLookup;
    this.timeoutMs = options.timeoutMs ?? LOOKUP_TIMEOUT_MS;
  }

  dnsBlocked(): boolean {
    return this.options.dnsBlocked();
  }

  cached(host: string): string[] {
    return this.options.cache.read(normalizeHost(host)).filter(isIpLiteral);
  }

  async resolve(rawHost: string): Promise<string[]> {
    const host = normalizeHost(rawHost);
    if (isIpLiteral(host)) return [host];
    const cached = this.cached(host);
    if (cached.length > 0 && this.dnsBlocked()) return cached;
    let fresh: string[];
    try {
      fresh = await withTimeout(this.lookup(host), this.timeoutMs);
    } catch {
      fresh = [];
    }
    if (fresh.length === 0) return cached;
    const merged = mergeAddresses(fresh, cached);
    if (!sameList(merged, cached)) {
      this.options.cache.write(host, merged);
      this.options.onChange?.(host);
    }
    return merged;
  }

  async require(host: string): Promise<string[]> {
    const addresses = await this.resolve(host);
    if (addresses.length === 0) throw new UnresolvedHostError(normalizeHost(host), this.dnsBlocked());
    return addresses;
  }
}

function wantedFamily(family: unknown): 0 | 4 | 6 {
  if (family === 4 || family === "IPv4") return 4;
  if (family === 6 || family === "IPv6") return 6;
  return 0;
}

export function pinnedLookup(expectedHost: string, resolve: (host: string) => Promise<string[]>): LookupFunction {
  const expected = normalizeHost(expectedHost);
  return (hostname, options, callback) => {
    if (normalizeHost(hostname) !== expected) {
      dnsLookupCallback(hostname, options, callback);
      return;
    }
    resolve(expected).then(
      (addresses) => {
        const family = wantedFamily(options.family);
        const entries = addresses
          .map((address) => ({ address, family: isIP(address) }))
          .filter((entry) => entry.family !== 0 && (family === 0 || entry.family === family));
        const first = entries[0];
        if (!first) {
          callback(new UnresolvedHostError(expected, false), "", 0);
          return;
        }
        if (options.all) callback(null, entries);
        else callback(null, first.address, first.family);
      },
      (error: unknown) => callback(error instanceof Error ? error : new Error(String(error)), "", 0),
    );
  };
}

function dnsLookupCallback(...args: Parameters<LookupFunction>): void {
  const [hostname, options, callback] = args;
  dnsLookup(hostname, options).then(
    (result) => {
      if (Array.isArray(result)) callback(null, result);
      else callback(null, result.address, result.family);
    },
    (error: NodeJS.ErrnoException) => callback(error, "", 0),
  );
}
