import { spawn, spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { _electron as electron } from "playwright-core";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const shots = process.argv[2] ?? path.join(os.tmpdir(), "mantel-e2e");
const PORT = 3921;
const API = `http://127.0.0.1:${PORT}`;
mkdirSync(shots, { recursive: true });

const results = [];
function check(name, condition, detail = "") {
  results.push({ name, ok: Boolean(condition), detail });
  process.stdout.write(`${condition ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}\n`);
}

function startMock() {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(root, "dev", "mock-api.mjs")], {
      env: { ...process.env, MOCK_PORT: String(PORT) },
      stdio: ["ignore", "pipe", "inherit"],
    });
    child.stdout.on("data", (chunk) => {
      if (chunk.toString().includes("Mock-API")) resolve(child);
    });
  });
}

const tab = (page, name) => page.locator("nav button:visible", { hasText: name }).first();

async function api(method, route, token, body) {
  const response = await fetch(`${API}${route}`, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: response.status, body: response.status === 204 ? null : await response.json() };
}

const build = spawnSync(process.execPath, [path.join(root, "scripts", "flavor.mjs"), "debug", "electron-vite", "build"], {
  cwd: root,
  stdio: "inherit",
  env: { ...process.env, MANTEL_API_URL: API },
});
if (build.status !== 0) process.exit(build.status ?? 1);

const mock = await startMock();
const electronPath = (await import("electron")).default;
const env = { ...process.env };
delete env.ELECTRON_RENDERER_URL;
const app = await electron.launch({ executablePath: electronPath, args: [root], cwd: root, env });
let previousLanguage = null;

try {
  const page = await app.firstWindow();
  await page.setViewportSize({ width: 420, height: 720 }).catch(() => undefined);
  await page.waitForFunction(() => Boolean(window.mantel), null, { timeout: 20_000 });
  previousLanguage = (await page.evaluate(() => window.mantel.preferences())).language ?? "system";
  await page.evaluate(() => window.mantel.setLanguage("de"));
  await page.reload();
  await page.waitForSelector("text=Gib deine 16-stellige Kontonummer ein.", { timeout: 20_000 });
  check("Login-Ansicht erscheint", true);
  check("Renderer läuft über app://", page.url().startsWith("app://mantel/"), page.url());

  const isolation = await page.evaluate(() => ({
    require: typeof globalThis.require,
    process: typeof globalThis.process,
    bridgeKeys: Object.keys(window.mantel ?? {}).sort().join(","),
    frozen: Object.isFrozen(window.mantel),
    csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute("content") ?? "",
  }));
  check("Kein require/process im Renderer", isolation.require === "undefined" && isolation.process === "undefined");
  check("Bridge eingefroren", isolation.frozen);
  check("Keine generische invoke-Methode", !isolation.bridgeKeys.includes("invoke"), isolation.bridgeKeys);
  check("Strikte CSP ohne unsafe-inline/eval", !/unsafe/.test(isolation.csp) && isolation.csp.includes("script-src 'self'"), isolation.csp);

  const evalBlocked = await page.evaluate(async () => {
    const violations = [];
    document.addEventListener("securitypolicyviolation", (event) => violations.push(event.violatedDirective));
    window.setTimeout("window.__mantelEvalRan = true", 0);
    await new Promise((resolve) => window.setTimeout(resolve, 200));
    return { ran: window.__mantelEvalRan === true, violations };
  });
  check("String-Code (eval) durch CSP blockiert", !evalBlocked.ran, evalBlocked.violations.join(","));

  const openBlocked = await page.evaluate(() => window.open("https://example.com") === null);
  check("window.open verweigert", openBlocked);

  const invalidLogin = await page.evaluate(() => window.mantel.login("12ab"));
  check("IPC lehnt ungültigen Code ab", invalidLogin.ok === false && invalidLogin.code === "invalid", JSON.stringify(invalidLogin));
  const invalidPatch = await page.evaluate(() => window.mantel.updateSettings({ killSwitch: "yes", evil: 1 }));
  check("IPC lehnt ungültigen Settings-Patch ab", invalidPatch.ok === false && invalidPatch.code === "invalid");
  const invalidNode = await page.evaluate(() => window.mantel.connect("../../etc"));
  check("IPC lehnt ungültige Node-ID ab", invalidNode.ok === false && invalidNode.code === "invalid");

  await page.screenshot({ path: path.join(shots, "01-login.png") });

  await page.fill("#account-code", "9999999999999999");
  await page.click("button[type=submit]");
  await page.waitForSelector("text=Diese Kontonummer kennen wir nicht.", { timeout: 10_000 });
  check("Falscher Code zeigt Server-Fehler", true);
  await page.screenshot({ path: path.join(shots, "02-login-error.png") });

  await page.fill("#account-code", "1234567890123456");
  await page.click("button[type=submit]");
  await page.waitForSelector("role=button[name=/Standort ändern/]", { timeout: 15_000 });
  await page.waitForSelector("text=Zürich >> visible=true", { timeout: 10_000 });
  check("Login und Standortauswahl", true);
  await page.waitForTimeout(600);
  await page.screenshot({ path: path.join(shots, "03-home.png") });

  const navButtons = await page.locator("nav button:visible").allTextContents();
  check("Tab-Leiste mit drei Tabs", navButtons.join("|") === "Verbindung|Standorte|Einstellungen", navButtons.join("|"));
  check("Verbindung ist der aktuelle Tab", (await tab(page, "Verbindung").getAttribute("aria-current")) === "page");
  const stopLight = await page.evaluate(() => window.getComputedStyle(document.documentElement).getPropertyValue("--color-stop").trim().toLowerCase());
  check("Trennen-Rot im CSS (#dc2626)", stopLight === "#dc2626", stopLight);
  const mapLabel = await page.locator("[role=img][aria-label^=Weltkarte]:visible").first().getAttribute("aria-label");
  check("Weltkarte auf dem Verbindungsbildschirm", /Weltkarte mit \d+ Standorten/.test(mapLabel ?? ""), mapLabel ?? "");
  const external = await page.evaluate(() =>
    window.performance.getEntriesByType("resource").map((entry) => entry.name).filter((name) => !name.startsWith("app://") && !name.startsWith("data:")),
  );
  check("Keine Anfragen der Oberfläche nach außen (Karte offline)", external.every((name) => name.startsWith("http://127.0.0.1:")), external.join(","));

  await page.click("role=button[name=/Standort ändern/]");
  await page.waitForSelector("main >> role=radiogroup[name=Standorte]", { timeout: 5_000 });
  check("Standort ändern öffnet den Standorte-Tab", (await tab(page, "Standorte").getAttribute("aria-current")) === "page");
  check("Standorte als Liste im Tab, kein Dialog", (await page.locator("role=dialog").count()) === 0);
  await page.fill("main >> input[type=search]", "frankfurt");
  check("Suche filtert die Standorte", (await page.locator("main >> role=radio").count()) === 1);
  await page.fill("main >> input[type=search]", "");
  await page.waitForTimeout(300);
  await page.screenshot({ path: path.join(shots, "03b-locations-tab.png") });
  await page.click("main >> role=radio[name=/Frankfurt/]");
  await page.waitForTimeout(800);
  const prefs = await page.evaluate(() => window.mantel.preferences());
  check("Standortwahl gespeichert", prefs.lastNodeId === "de-fra", prefs.lastNodeId);
  check("Nach der Wahl zurück auf Verbindung", (await tab(page, "Verbindung").getAttribute("aria-current")) === "page");
  check("Gewählter Standort auf der Karte", (await page.locator("[role=img][aria-label^=Weltkarte]:visible").first().textContent())?.includes("Frankfurt") === true);

  const environment = await page.evaluate(() => window.mantel.environment());
  check("WireGuard erkannt", environment.wireguardInstalled, environment.wireguardPath ?? "");
  if (!environment.elevated) {
    const connect = await page.evaluate(() => window.mantel.connect("de-fra"));
    check("Verbinden ohne Admin wird sauber verweigert", connect.ok === false && connect.code === "elevation", connect.error);
  }

  await tab(page, "Einstellungen").click();
  await page.waitForSelector("text=DNS-Inhaltsblocker", { timeout: 10_000 });
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(shots, "04-settings.png"), fullPage: true });
  check("Konto-Karte mit Laufzeit", (await page.locator("text=Noch 23 Tage").count()) + (await page.locator("text=Noch 22 Tage").count()) >= 1);

  await page.click('main button:has-text("DNS-Inhaltsblocker")');
  await page.waitForSelector('role=switch[name="Soziale Medien blockieren"]', { timeout: 5_000 });
  await page.click('role=switch[name="Soziale Medien blockieren"]');
  await page.waitForSelector("text=Gespeichert", { timeout: 10_000 });
  const login = await api("POST", "/api/v1/auth/login", null, { code: "1234567890123456" });
  const account = await api("GET", "/api/v1/account", login.body.token);
  check("DNS-Einstellung per PATCH synchronisiert", account.body.settings.dns.social === true);

  await page.keyboard.press("Escape");
  await page.waitForSelector('main button:has-text("Verbindung")', { timeout: 5_000 });
  await page.waitForTimeout(600);
  await page.click('main button:has-text("Verbindung")');
  await page.click('role=switch[name="Lokales Netzwerk erlauben"]');
  await page.waitForTimeout(800);
  const afterLan = await api("GET", "/api/v1/account", login.body.token);
  check("LAN-Einstellung synchronisiert", afterLan.body.settings.lanAccess === true);
  const forwarding = page.locator('[data-testid="port-forwarding"]');
  await forwarding.waitFor({ timeout: 5_000 });
  const forwardingText = (await forwarding.textContent()) ?? "";
  check("Portweiterleitung unter Verbindung", forwardingText.includes("Portweiterleitung"), forwardingText.slice(0, 80));
  check("Portweiterleitung ohne Gerät: Hinweis + Warnung", forwardingText.includes("Verbinde dich einmal") && forwardingText.includes("aus dem Internet erreichbar"));
  check("Portweiterleitung ohne Gerät nicht schaltbar", await page.locator('role=switch[name="Portweiterleitung"]').isDisabled());
  await page.screenshot({ path: path.join(shots, "04b-settings-connection.png"), fullPage: true });

  await page.keyboard.press("Escape");
  await page.waitForTimeout(600);
  const settingsScroll = await page.$("main");
  await settingsScroll?.evaluate((element) => element.scrollTo(0, element.scrollHeight));
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(shots, "05-settings-bottom.png") });

  await page.click('main button:has-text("Bald verfügbar")');
  await page.waitForSelector('main >> role=heading[name="Bald verfügbar"]', { timeout: 5_000 }).catch(() => undefined);
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(shots, "05a-upcoming.png") });
  const upcomingDisabled = await page.locator("text=Bald verfügbar").count();
  check("Nicht umgesetzte Features als „Bald verfügbar“", upcomingDisabled >= 4, String(upcomingDisabled));
  await page.keyboard.press("Escape");
  await page.waitForTimeout(600);

  await page.click('main button:has-text("Design")');
  await page.click('role=radio[name*="Dunkel"]');
  await page.waitForTimeout(600);
  const dark = await page.evaluate(() => document.documentElement.dataset.theme);
  const darkPrefs = await page.evaluate(() => window.mantel.preferences());
  const darkBackground = await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].getBackgroundColor());
  check("Design Dunkel wirkt sofort und wird gespeichert", dark === "dark" && darkPrefs.theme === "dark", `${dark} ${darkPrefs.theme}`);
  check("Fenster/Titelleiste folgen dem Design", darkBackground.toLowerCase() === "#0c0c0e", darkBackground);
  await page.screenshot({ path: path.join(shots, "05b-settings-dark.png") });
  const stopDark = await page.evaluate(() => window.getComputedStyle(document.documentElement).getPropertyValue("--color-stop").trim().toLowerCase());
  check("Trennen-Rot im Dunkelmodus unverändert (#dc2626)", stopDark === "#dc2626", stopDark);
  await page.evaluate(() => window.mantel.setTheme("system"));

  await page.click('main button:has-text("DNS-Inhaltsblocker")');
  await page.waitForSelector('role=switch[name="Soziale Medien blockieren"]', { timeout: 5_000 });
  await tab(page, "Einstellungen").click();
  await page.waitForSelector('main button:has-text("DNS-Inhaltsblocker")', { timeout: 5_000 });
  check("Tab Einstellungen führt aus der Unterseite zurück", (await page.locator('role=switch[name="Soziale Medien blockieren"]').count()) === 0);

  await tab(page, "Verbindung").click();
  await page.setViewportSize({ width: 1280, height: 820 }).catch(() => undefined);
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(1280, 860));
  await page.waitForTimeout(900);
  const rail = await page.locator("nav:visible").first().evaluate((element) => element.getBoundingClientRect());
  check("Breites Fenster: Navigation links", rail.left < 10 && rail.height > rail.width, JSON.stringify(rail));
  const wideMap = await page.locator("[role=img][aria-label^=Weltkarte]:visible").first().evaluate((element) => element.getBoundingClientRect().width);
  check("Breites Fenster: große Karte neben dem Panel", wideMap > 600, String(Math.round(wideMap)));
  await page.screenshot({ path: path.join(shots, "05c-wide.png") });
  await page.evaluate(() => window.mantel.setLanguage("en"));
  await page.reload();
  await page.waitForSelector("nav button:visible >> text=Locations", { timeout: 10_000 });
  check("Englisch: Navigation übersetzt", (await page.locator("nav button:visible").allTextContents()).join("|") === "Connection|Locations|Settings");
  await page.screenshot({ path: path.join(shots, "05d-wide-en.png") });
  await page.evaluate(() => window.mantel.setLanguage("de"));
  await page.reload();
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(420, 720));
  await page.setViewportSize({ width: 420, height: 720 }).catch(() => undefined);
  await page.waitForSelector("nav button:visible >> text=Verbindung", { timeout: 10_000 });
  await page.waitForTimeout(400);

  await api("POST", "/api/v1/auth/logout", login.body.token);
  const session = await page.evaluate(() => window.mantel.session());
  check("Sitzung aktiv vor Logout", session.loggedIn === true);

  await tab(page, "Einstellungen").click();
  await page.click("main >> role=button[name=Abmelden]");
  await page.waitForSelector("text=Trennt den Tunnel", { timeout: 5_000 });
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(shots, "06-logout-confirm.png") });
  await page.click("role=dialog >> role=button[name=Abmelden]");
  await page.waitForSelector("text=Gib deine 16-stellige Kontonummer ein.", { timeout: 15_000 });
  const afterLogout = await page.evaluate(() => window.mantel.session());
  check("Logout löscht Sitzung", afterLogout.loggedIn === false);

  check("DEBUG-Badge sichtbar", (await page.locator("[data-testid=debug-badge]").count()) === 1);
  const debugInfo = await page.evaluate(() => window.mantel.debug?.info());
  check("Debug-Bridge vorhanden", debugInfo?.flavor === "debug" && debugInfo.baseUrl === API, JSON.stringify(debugInfo ?? null));
  check("Debug: eigener Tunnel-Dienst", debugInfo?.serviceName === "WireGuardTunnel$mantel-debug", debugInfo?.serviceName);
  check("Kein Server-Feld (Server beim Bauen festgelegt)", (await page.locator("input:not(#account-code)").count()) === 0);
  check("Keine setBaseUrl-Brücke", (await page.evaluate(() => typeof window.mantel.setBaseUrl)) === "undefined");

  await page.click('role=button[name="Konto erstellen"]');
  await page.waitForSelector("[data-testid=new-account-code]", { timeout: 10_000 });
  const shownCode = (await page.textContent("[data-testid=new-account-code]"))?.replace(/\s/g, "") ?? "";
  check("Neue Kontonummer wird angezeigt", /^\d{16}$/.test(shownCode), shownCode.replace(/\d/g, "#"));
  const pendingSession = await page.evaluate(() => window.mantel.session());
  check("Vor der Bestätigung keine Sitzung gespeichert", pendingSession.loggedIn === false);
  check("Weiter ist gesperrt bis zur Bestätigung", await page.locator("role=button[name=Weiter]").isDisabled());
  await page.screenshot({ path: path.join(shots, "07-register-reveal.png") });
  await page.click("text=Ich habe meine Kontonummer gespeichert");
  await page.click("role=button[name=Weiter]");
  await page.waitForSelector("role=button[name=/Standort ändern/]", { timeout: 15_000 });
  const registered = await page.evaluate(() => window.mantel.session());
  const viaCode = await api("POST", "/api/v1/auth/login", null, { code: shownCode });
  check("Konto erstellt und eingeloggt", registered.loggedIn && viaCode.body.account?.id === registered.accountId, registered.accountId ?? "");

  const requestLog = await page.evaluate(() => window.mantel.debug?.requestLog());
  const logText = JSON.stringify(requestLog ?? []);
  check("API-Log enthält register", logText.includes("/api/v1/auth/register"));
  check("API-Log ohne Kontonummer/Token", !logText.includes(shownCode) && !logText.includes(viaCode.body.token));
  const diagnostics = await page.evaluate(() => window.mantel.debug?.copyDiagnostics());
  check("Diagnose ohne Kontonummer/Token", diagnostics?.ok === true && !diagnostics.value.includes(shownCode), String(diagnostics?.value?.length ?? 0));
  const health = await page.evaluate(() => window.mantel.debug?.healthCheck());
  check("API-Healthcheck", health?.ok === true && health.nodes > 0, JSON.stringify(health ?? null));

  const reset = await page.evaluate(() => window.mantel.debug?.resetLocalData());
  const afterReset = await page.evaluate(() => window.mantel.session());
  check("Lokale Daten zurücksetzen meldet ab", reset?.ok === true && afterReset.loggedIn === false, JSON.stringify(reset ?? null));
} catch (error) {
  check("Unerwarteter Fehler", false, String(error));
  const page = await app.firstWindow();
  await page.screenshot({ path: path.join(shots, "error.png") }).catch(() => undefined);
} finally {
  if (previousLanguage && previousLanguage !== "de") {
    const page = await app.firstWindow().catch(() => null);
    await page?.evaluate((language) => window.mantel.setLanguage(language), previousLanguage).catch(() => undefined);
  }
  await app.evaluate(({ app: electronApp }) => electronApp.exit(0)).catch(() => undefined);
  mock.kill();
}

const failed = results.filter((result) => !result.ok);
process.stdout.write(`\n${results.length - failed.length}/${results.length} bestanden · Screenshots: ${shots}\n`);
process.exit(failed.length === 0 ? 0 : 1);
