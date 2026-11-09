import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const [flavor, command, ...args] = process.argv.slice(2);

if (!["prod", "debug"].includes(flavor ?? "") || !command) {
  console.error("Aufruf: node scripts/flavor.mjs <prod|debug> <paket> [argumente…]");
  process.exit(2);
}

const packageDir = path.join(root, "node_modules", command);
const manifest = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8"));
const bin = typeof manifest.bin === "string" ? manifest.bin : manifest.bin?.[command];
if (!bin) {
  console.error(`${command}: kein ausführbares Programm gefunden.`);
  process.exit(2);
}

const child = spawn(process.execPath, [path.join(packageDir, bin), ...args], {
  cwd: root,
  stdio: "inherit",
  env: { ...process.env, MANTEL_FLAVOR: flavor },
});
child.on("exit", (code, signal) => process.exit(signal ? 1 : (code ?? 0)));
process.on("SIGINT", () => child.kill("SIGINT"));
process.on("SIGTERM", () => child.kill("SIGTERM"));
