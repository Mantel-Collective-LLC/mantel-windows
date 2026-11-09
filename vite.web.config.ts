import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { cspPlugin } from "./build/csp-plugin";
import { flavorDefine, resolveFlavor } from "./build/flavor";
import { rendererRoot, sharedDepAliases, sharedDir } from "./build/shared";

export default defineConfig({
  root: rendererRoot,
  define: flavorDefine(resolveFlavor(process.env.MANTEL_FLAVOR), { strict: false }),
  plugins: [react(), tailwindcss(), cspPlugin()],
  resolve: { alias: sharedDepAliases },
  server: { port: 5174, strictPort: true, fs: { allow: [sharedDir, __dirname] } },
});
