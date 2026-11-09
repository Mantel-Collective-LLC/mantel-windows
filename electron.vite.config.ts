import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "electron-vite";
import { cspPlugin } from "./build/csp-plugin";
import { flavorDefine, resolveFlavor } from "./build/flavor";
import { rendererRoot, sharedDepAliases, sharedDir } from "./build/shared";

export default defineConfig(({ command }) => {
  const define = flavorDefine(resolveFlavor(process.env.MANTEL_FLAVOR), { strict: command === "build" });
  return {
    main: {
      define,
      build: {
        externalizeDeps: false,
        sourcemap: false,
      },
    },
    preload: {
      define,
      build: {
        externalizeDeps: false,
        sourcemap: false,
      },
    },
    renderer: {
      root: rendererRoot,
      define,
      plugins: [react(), tailwindcss(), cspPlugin()],
      resolve: { alias: sharedDepAliases },
      server: { fs: { allow: [sharedDir, __dirname] } },
      build: {
        outDir: resolve(__dirname, "out/renderer"),
        emptyOutDir: true,
        sourcemap: false,
        assetsInlineLimit: 0,
        rolldownOptions: {
          input: resolve(rendererRoot, "index.html"),
        },
      },
    },
  };
});
