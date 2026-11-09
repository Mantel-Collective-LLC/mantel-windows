import { DEBUG_API_URL, resolveApiUrl } from "../shared/core/api-url";

export const FLAVORS = ["prod", "debug"] as const;
export type Flavor = (typeof FLAVORS)[number];

export function resolveFlavor(value: string | undefined): Flavor {
  const normalized = (value ?? "").trim().toLowerCase();
  if (normalized === "") return "prod";
  if ((FLAVORS as readonly string[]).includes(normalized)) return normalized as Flavor;
  throw new Error(`MANTEL_FLAVOR="${value}" ist ungültig. Erlaubt: ${FLAVORS.join(", ")}.`);
}

export function flavorDefine(
  flavor: Flavor,
  options: { strict: boolean; apiUrl?: string } = { strict: true },
): Record<string, string> {
  const apiUrl = resolveApiUrl(flavor, "apiUrl" in options ? options.apiUrl : process.env.MANTEL_API_URL, {
    debugDefault: DEBUG_API_URL.desktop,
    strict: options.strict,
  });
  return {
    "import.meta.env.MANTEL_FLAVOR": JSON.stringify(flavor),
    "import.meta.env.MANTEL_API_URL": JSON.stringify(apiUrl),
    "import.meta.env.MANTEL_BUILD_TIME": JSON.stringify(new Date().toISOString()),
  };
}
