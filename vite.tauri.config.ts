import { relative, resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";
import { flavorDefine, resolveFlavor } from "./build/flavor";
import { rendererRoot, sharedDepAliases, sharedDir } from "./build/shared";

const IPC = "ipc: http://ipc.localhost";
const PRODUCTION = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  `connect-src ${IPC}`,
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");
const DEVELOPMENT = PRODUCTION.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")
  .replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")
  .replace(`connect-src ${IPC}`, `connect-src 'self' ws: ${IPC}`);

const ENTRY = resolve(__dirname, "tauri/src/entry.ts");

function tauriEntry(): Plugin {
  let isBuild = false;
  return {
    name: "mantel-tauri-entry",
    configResolved(config) {
      isBuild = config.command === "build";
    },
    transformIndexHtml: {
      order: "pre",
      handler(html) {
        const withCsp = html.replace("%MANTEL_CSP%", isBuild ? PRODUCTION : DEVELOPMENT);
        const entry = (isBuild ? relative(rendererRoot, ENTRY) : `/@fs/${ENTRY}`).replace(/\\/g, "/");
        const replaced = withCsp.replace('src="./src/main.tsx"', `src="${entry}"`);
        if (replaced === withCsp) throw new Error("shared/ui/index.html: Einstiegspunkt ./src/main.tsx nicht gefunden");
        return replaced;
      },
    },
  };
}

export default defineConfig(({ command }) => ({
  root: rendererRoot,
  define: flavorDefine(resolveFlavor(process.env.MANTEL_FLAVOR), { strict: command === "build" }),
  plugins: [react(), tailwindcss(), tauriEntry()],
  resolve: {
    alias: [
      ...sharedDepAliases,
      { find: /^node:net$/, replacement: resolve(__dirname, "tauri/src/node-net.ts") },
    ],
  },
  clearScreen: false,
  server: { port: 5175, strictPort: true, fs: { allow: [sharedDir, __dirname] } },
  build: {
    outDir: resolve(__dirname, "out/tauri"),
    emptyOutDir: true,
    sourcemap: false,
    assetsInlineLimit: 0,
    target: "es2022",
  },
}));
