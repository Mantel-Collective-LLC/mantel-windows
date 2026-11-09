import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mock = spawn(process.execPath, [path.join(root, "dev", "mock-api.mjs")], { cwd: root, stdio: "inherit" });
const viteCli = path.join(root, "node_modules", "electron-vite", "bin", "electron-vite.js");
const app = spawn(process.execPath, [viteCli, "dev"], {
  cwd: root,
  stdio: "inherit",
  env: { ...process.env, MANTEL_FLAVOR: "debug", MANTEL_API_URL: "http://127.0.0.1:3101" },
});

const stop = () => {
  mock.kill();
  app.kill();
};
app.on("exit", (code) => {
  mock.kill();
  process.exit(code ?? 0);
});
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
