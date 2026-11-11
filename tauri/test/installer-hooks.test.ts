import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = path.resolve(__dirname, "..", "..");
const hooks = readFileSync(path.join(root, "tauri", "src-tauri", "installer-hooks.nsh"), "utf8").replace(/\r\n/g, "\n");

function macro(name: string): string {
  const start = hooks.indexOf(`!macro ${name}\n`);
  expect(start, name).toBeGreaterThanOrEqual(0);
  return hooks.slice(start, hooks.indexOf("!macroend", start));
}



describe("Tauri installer hooks", () => {
  it("runs the Electron uninstaller from a copy outside the install folder", () => {
    const pre = macro("NSIS_HOOK_PREINSTALL");
    expect(pre).not.toMatch(/ExecWait '"\$INSTDIR\\Uninstall/);
    expect(pre).toContain('CopyFiles /SILENT "$INSTDIR\\Uninstall ${PRODUCTNAME}.exe" "$PLUGINSDIR\\electron-uninstaller.exe"');
    expect(pre).toMatch(/ExecWait '"\$PLUGINSDIR\\electron-uninstaller\.exe" \/S \/allusers \/KEEP_APP_DATA --updated _\?=\$INSTDIR'/);
  });

  it("always removes the Electron leftovers, also after an earlier switch-over", () => {
    const pre = macro("NSIS_HOOK_PREINSTALL");
    const endIf = pre.lastIndexOf("${EndIf}");
    expect(pre.indexOf("!insertmacro MANTEL_REMOVE_ELECTRON_FILES")).toBeGreaterThan(endIf);

    const remove = macro("MANTEL_REMOVE_ELECTRON_FILES");
    for (const file of [
      "LICENSE.electron.txt", "LICENSES.chromium.html", "chrome_100_percent.pak", "chrome_200_percent.pak",
      "d3dcompiler_47.dll", "dxcompiler.dll", "dxil.dll", "ffmpeg.dll", "icudtl.dat", "resources.pak",
      "snapshot_blob.bin", "uninstallerIcon.ico", "v8_context_snapshot.bin", "vk_swiftshader.dll",
      "vk_swiftshader_icd.json", "vulkan-1.dll", "libEGL.dll", "libGLESv2.dll", "Uninstall ${PRODUCTNAME}.exe",
    ]) {
      expect(remove).toContain(`Delete /REBOOTOK "$INSTDIR\\${file}"`);
    }
    expect(remove).toContain('RMDir /r /REBOOTOK "$INSTDIR\\resources"');
    expect(remove).toContain('RMDir /r /REBOOTOK "$INSTDIR\\locales"');
    expect(remove).toContain('DeleteRegKey HKLM64 "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${MANTEL_ELECTRON_GUID}"');
  });

  it("never deletes the install folder, the Tauri files or user data", () => {
    const targets = [...hooks.matchAll(/^\s*(?:Delete|RMDir)\b[^"\n]*"([^"]+)"/gm)].map((m) => m[1]);
    expect(targets.length).toBeGreaterThan(10);
    for (const target of targets) {
      expect(target).not.toMatch(/^\$INSTDIR\\?$/);
      expect(target).not.toMatch(/\$APPDATA|\$INSTDIR\\service|\$INSTDIR\\uninstall\.exe|\$\{MAINBINARYNAME\}\.exe/i);
    }
    expect(hooks).not.toMatch(/RMDir \/r[^\n]*\$INSTDIR\s*$/m);
  });

  it("picks the flavor names inside the hooks (PRODUCTNAME is defined after the include)", () => {
    expect(hooks.indexOf('!if "${PRODUCTNAME}"')).toBeGreaterThan(hooks.indexOf("!macro MANTEL_FLAVOR_DEFINES"));
    for (const hook of ["NSIS_HOOK_PREINSTALL", "NSIS_HOOK_POSTINSTALL", "NSIS_HOOK_PREUNINSTALL"]) {
      expect(macro(hook).split("\n")[1]?.trim()).toBe("!insertmacro MANTEL_FLAVOR_DEFINES");
    }
  });
});
