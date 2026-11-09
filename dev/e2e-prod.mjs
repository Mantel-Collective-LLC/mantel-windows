import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { _electron as electron } from "playwright-core";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const shots = process.argv[2] ?? path.join(os.tmpdir(), "mantel-e2e-prod");
const FIXED = "https://api.mantel.invalid";
mkdirSync(shots, { recursive: true });

const results = [];
function check(name, condition, detail = "") {
  results.push({ name, ok: Boolean(condition), detail });
  process.stdout.write(`${condition ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}\n`);
}

const build = spawnSync(process.execPath, [path.join(root, "scripts", "flavor.mjs"), "prod", "electron-vite", "build"], {
  cwd: root,
  stdio: "inherit",
  env: { ...process.env, MANTEL_API_URL: FIXED },
});
if (build.status !== 0) process.exit(build.status ?? 1);

const electronPath = (await import("electron")).default;
const env = { ...process.env };
delete env.ELECTRON_RENDERER_URL;
const app = await electron.launch({ executablePath: electronPath, args: [root], cwd: root, env });

try {
  const page = await app.firstWindow();
  await page.setViewportSize({ width: 420, height: 720 }).catch(() => undefined);
  await page.waitForFunction(() => Boolean(window.mantel), null, { timeout: 20_000 });
  await page.waitForSelector("#account-code", { timeout: 20_000 });

  const keys = await page.evaluate(() => Object.keys(window.mantel).sort());
  check("Keine Debug-Bridge", !keys.includes("debug"), keys.join(","));
  check("Konto erstellen verfügbar", keys.includes("register") && keys.includes("confirmRegistration"));
  const preferences = await page.evaluate(() => window.mantel.preferences());
  check("Server aus dem Build (MANTEL_API_URL)", preferences.baseUrl === FIXED, preferences.baseUrl);
  check("Keine setBaseUrl-Brücke", !keys.includes("setBaseUrl"), keys.join(","));
  const debugChannel = await app.evaluate(({ ipcMain }) => {
    try {
      ipcMain.handle("mantel:debug-info", () => null);
      ipcMain.removeHandler("mantel:debug-info");
      return "free";
    } catch {
      return "registered";
    }
  });
  check("Kein Debug-IPC-Handler registriert", debugChannel === "free", debugChannel);
  check("Kein Server-Feld im Login", (await page.locator("input:not(#account-code)").count()) === 0);
  check("Kein DEBUG-Badge", (await page.locator("[data-testid=debug-badge]").count()) === 0);
  check("Button „Konto erstellen“", (await page.locator("role=button[name=/Konto erstellen|Create account/]").count()) === 1);
  const title = await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.getTitle());
  check("Fenstertitel ohne Debug", title === "Mantel", title);
  await page.screenshot({ path: path.join(shots, "prod-login.png") });
} catch (error) {
  check("Unerwarteter Fehler", false, String(error));
} finally {
  await app.evaluate(({ app: electronApp }) => electronApp.exit(0)).catch(() => undefined);
}

const failed = results.filter((result) => !result.ok);
process.stdout.write(`\n${results.length - failed.length}/${results.length} bestanden · Screenshots: ${shots}\n`);
process.exit(failed.length === 0 ? 0 : 1);
