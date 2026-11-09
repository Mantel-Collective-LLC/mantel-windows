const RULES: Array<[RegExp, string]> = [
  [/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [token]"],
  [/[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=/g, "[key]"],
  [/(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)/g, "[account code]"],
  [/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])/g, "[token]"],
];

export function redact(text: string): string {
  return RULES.reduce((current, [pattern, replacement]) => current.replace(pattern, replacement), text);
}

const SECRET_KEYS = /^(token|accountCode|privateKey|presharedKey|publicKey|authorization|password|secret|accountId)$/i;

export function redactValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[…]";
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map((entry) => redactValue(entry, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        SECRET_KEYS.test(key) && entry !== null && entry !== undefined ? "[redacted]" : redactValue(entry, depth + 1),
      ]),
    );
  }
  return value;
}
