import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { createTranslator, DICTIONARIES, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { OpenWifiNotice } from "../shared/ui/src/screens/home";

function render(language: Language, autoConnect: boolean | null): string {
  return renderToStaticMarkup(
    <I18nProvider translator={createTranslator(language)}>
      <OpenWifiNotice canConnect busy={false} autoConnect={autoConnect} onConnect={() => undefined} onAlwaysConnect={() => undefined} />
    </I18nProvider>,
  );
}

describe("OpenWifiNotice", () => {
  it.each(["de", "en"] as const)("%s: title, text and both actions", (language) => {
    const home = DICTIONARIES[language].home;
    const html = render(language, false);
    for (const text of [home.openWifiTitle, home.openWifiConnect, home.openWifiAlways]) expect(html).toContain(text);
    expect(html).toContain('aria-labelledby="open-wifi-title"');
  });

  it("hides the auto-connect shortcut when it is on or the shell has no such setting", () => {
    expect(render("en", true)).not.toContain(DICTIONARIES.en.home.openWifiAlways);
    expect(render("en", null)).not.toContain(DICTIONARIES.en.home.openWifiAlways);
  });
});
