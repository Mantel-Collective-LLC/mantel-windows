import {
  createTranslator,
  DEFAULT_LANGUAGE_PREFERENCE,
  errorMessage,
  languageOfLocale,
  resolveLanguage,
  type Language,
  type LanguagePreference,
  type Translator,
} from "../../shared/core/i18n";

let preference: LanguagePreference = DEFAULT_LANGUAGE_PREFERENCE;
let systemLocales: readonly string[] = [];
let translator: Translator = createTranslator(resolveLanguage(preference));

function update(): void {
  translator = createTranslator(resolveLanguage(preference), systemLocales[0]);
}

export function setSystemLocales(locales: readonly string[]): void {
  systemLocales = locales.filter((entry) => typeof entry === "string" && entry.length > 0);
  update();
}

export function setLanguagePreference(next: LanguagePreference | undefined): void {
  preference = next ?? DEFAULT_LANGUAGE_PREFERENCE;
  update();
}

export function systemLocale(): string | undefined {
  return systemLocales[0];
}

export function systemLanguage(): Language {
  return languageOfLocale(systemLocales[0]);
}

export function activeLanguage(): Language {
  return translator.language;
}

export function i18n(): Translator {
  return translator;
}

export function localizeError(error: unknown): string {
  return errorMessage(error, translator.language);
}
