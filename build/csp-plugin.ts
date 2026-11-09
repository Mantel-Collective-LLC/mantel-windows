import type { Plugin } from "vite";

const PRODUCTION = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");

const DEVELOPMENT = [
  "default-src 'none'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  `connect-src 'self' ws: ${[...new Set(["3101", process.env.MOCK_PORT ?? "3101"])]
    .filter((port) => /^\d{2,5}$/.test(port))
    .map((port) => `http://localhost:${port} http://127.0.0.1:${port}`)
    .join(" ")}`,
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");

export function cspPlugin(): Plugin {
  let isBuild = false;
  return {
    name: "mantel-csp",
    configResolved(config) {
      isBuild = config.command === "build";
    },
    transformIndexHtml(html) {
      const policy = isBuild ? PRODUCTION : DEVELOPMENT;
      return html.replace("%MANTEL_CSP%", policy);
    },
  };
}
