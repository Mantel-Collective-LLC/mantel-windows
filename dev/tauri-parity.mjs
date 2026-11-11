import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { startFakeService } from "./fake-service.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const shots = path.resolve(process.argv[2] ?? path.join(os.tmpdir(), "mantel-tauri-parity"));
const tauriExe = path.join(root, "tauri", "src-tauri", "target", "release", "mantel-desktop.exe");
const electronExe = path.join(root, "dist-debug", "win-unpacked", "MantelDebug.exe");
const CDP_PORT = 9339;
mkdirSync(shots, { recursive: true });

async function visibleText(page) {
  const text = await page.evaluate(() => document.body.innerText);
  return text
    .replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, "<code>")
    .replace(/\b[A-Za-z0-9_-]{20,}\b/g, "<id>")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

async function settle(page) {
  await page.waitForTimeout(1200);
}

async function flow(name, page) {
  const screens = {};
  const capture = async (screen) => {
    await settle(page);
    await page.screenshot({ path: path.join(shots, `${screen}-${name}.png`) });
    screens[screen] = await visibleText(page);
  };
  await page.waitForSelector("text=Create account", { timeout: 60_000 });
  await capture("01-login");
  await page.click("button:has-text('Create account')");
  await page.waitForSelector("text=Write it down.", { timeout: 30_000 });
  await capture("02-register");
  await page.click("input[type=checkbox]");
  await page.click("button:has-text('Continue')");
  await page.locator("nav:visible").first().waitFor({ timeout: 30_000 });
  await capture("03-home");
  await page.locator("nav button:visible", { hasText: "Settings" }).first().click();
  await capture("04-settings");
  return screens;
}

async function cdpRun(name, exe, args, env, port) {
  const child = spawn(exe, args, { env: { ...process.env, ...env }, stdio: "ignore" });
  try {
    let browser = null;
    for (let attempt = 0; attempt < 60 && !browser; attempt++) {
      browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`).catch(() => null);
      if (!browser) await new Promise((resolve) => setTimeout(resolve, 500));
    }
    if (!browser) throw new Error(`${name}: Debug-Port ${port} nicht erreichbar`);
    const context = browser.contexts()[0];
    const page = context.pages().find((entry) => !entry.url().startsWith("devtools:")) ?? (await context.waitForEvent("page"));
    return await flow(name, page);
  } finally {
    child.kill();
  }
}

const service = await startFakeService();
const results = {};
try {
  results.electron = await cdpRun("electron", electronExe, [`--remote-debugging-port=${CDP_PORT}`], {}, CDP_PORT);
  results.tauri = await cdpRun("tauri", tauriExe, [], { WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${CDP_PORT + 1}` }, CDP_PORT + 1);
} finally {
  service.close();
}

let differences = 0;
for (const screen of Object.keys(results.electron)) {
  const electronLines = results.electron[screen] ?? [];
  const tauriLines = results.tauri[screen] ?? [];
  const onlyElectron = electronLines.filter((line) => !tauriLines.includes(line));
  const onlyTauri = tauriLines.filter((line) => !electronLines.includes(line));
  const same = onlyElectron.length === 0 && onlyTauri.length === 0;
  if (!same) differences += 1;
  console.log(`${same ? "GLEICH " : "ANDERS "} ${screen}${same ? "" : `\n  nur Electron: ${JSON.stringify(onlyElectron)}\n  nur Tauri:    ${JSON.stringify(onlyTauri)}`}`);
}
writeFileSync(path.join(shots, "texts.json"), JSON.stringify(results, null, 2));
console.log(`Screenshots und Texte: ${shots}`);
process.exit(differences === 0 ? 0 : 1);
