import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const [mode, flavor, ...rest] = process.argv.slice(2);
if (!["dev", "dist"].includes(mode ?? "") || !["prod", "debug"].includes(flavor ?? "")) {
  console.error("Aufruf: node scripts/tauri.mjs <dev|dist> <prod|debug> [--out <ordner>]");
  process.exit(2);
}
const outIndex = rest.indexOf("--out");
const outDir = path.resolve(root, outIndex >= 0 ? (rest[outIndex + 1] ?? "") : flavor === "debug" ? "dist-tauri-debug" : "dist-tauri");
const version = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")).version;
const env = { ...process.env, MANTEL_FLAVOR: flavor };
const tauriDir = path.join(root, "tauri");
const flavorConfig = flavor === "debug" ? ["--config", path.join(tauriDir, "src-tauri", "tauri.debug.conf.json")] : [];

function run(label, args, cwd = root) {
  console.log(`\n=== ${label}`);
  const result = spawnSync(process.execPath, args, { cwd, env, stdio: "inherit" });
  if (result.status !== 0) {
    console.error(`${label} fehlgeschlagen (Exit-Code ${result.status}).`);
    process.exit(result.status ?? 1);
  }
}

const vite = path.join(root, "node_modules", "vite", "bin", "vite.js");
const tauri = path.join(root, "node_modules", "@tauri-apps", "cli", "tauri.js");

const engineExe = path.join(root, "build", "service", "mantel.exe");

if (mode === "dev") {
  if (fs.existsSync(engineExe)) env.MANTEL_ENGINE_EXE = engineExe;
  else console.warn(`Hinweis: ${engineExe} fehlt (node scripts/build-service.mjs debug), Verbinden geht dann nicht.`);
  run(`tauri dev (${flavor})`, [tauri, "dev", ...flavorConfig], tauriDir);
  process.exit(0);
}

run(`Tunnel-Engine (${flavor})`, [path.join(root, "scripts", "build-service.mjs"), flavor]);
run(`Webview-Bundle (${flavor})`, [vite, "build", "--config", "vite.tauri.config.ts"]);
const resources = JSON.stringify({ bundle: { resources: { "../../build/service/mantel.exe": "service/mantel.exe" } } });
run(`Rust-App + NSIS-Installer (${flavor})`, [tauri, "build", "--bundles", "nsis", ...flavorConfig, "--config", resources], tauriDir);

const bundleDir = path.join(tauriDir, "src-tauri", "target", "release", "bundle", "nsis");
const built = fs
  .readdirSync(bundleDir)
  .filter((name) => name.endsWith("-setup.exe") && name.includes(version))
  .map((name) => path.join(bundleDir, name))
  .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
if (!built) {
  console.error(`Kein NSIS-Installer für ${version} in ${bundleDir}.`);
  process.exit(1);
}
fs.mkdirSync(outDir, { recursive: true });
const target = path.join(outDir, `Mantel-${flavor === "debug" ? "Debug-" : ""}Setup-${version}-x64.exe`);
fs.copyFileSync(built, target);
console.log(`\n=== Installer: ${target} (${(fs.statSync(target).size / 1024 / 1024).toFixed(1)} MB)`);
