import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

/**
 * Locales are loaded ON DEMAND, not bundled.
 *
 * All eighteen used to be static imports, which put every translation of every
 * language into the main chunk: ~305 kB of the 3 124 kB bundle, of which a given
 * user reads exactly one. Static imports also meant the figure grew by
 * 18 x (new keys) at every milestone — M7-M9 alone added 312 keys per locale.
 *
 * `import.meta.glob` with `import: 'default'` gives Vite one lazy chunk per
 * locale file. English stays EAGER and stays in the main chunk: it is the
 * fallback, so it must be present before the first render or the very first
 * paint shows raw key paths.
 */
const LOCALE_LOADERS = import.meta.glob<Record<string, unknown>>(
  './locales/*/translation.json',
  { import: 'default' },
);

// The fallback is the one locale we cannot afford to wait for.
import en from './locales/en/translation.json';

export const SUPPORTED_LANGUAGES: Array<{ code: string; name: string; nativeName: string; dir?: 'rtl' }> = [
  { code: 'en',    name: 'English',            nativeName: 'English' },
  { code: 'fr',    name: 'French',             nativeName: 'Français' },
  { code: 'es',    name: 'Spanish',            nativeName: 'Español' },
  { code: 'de',    name: 'German',             nativeName: 'Deutsch' },
  { code: 'pt-BR', name: 'Portuguese (Brazil)', nativeName: 'Português (Brasil)' },
  { code: 'zh-CN', name: 'Chinese (Simplified)', nativeName: '简体中文' },
  { code: 'ja',    name: 'Japanese',           nativeName: '日本語' },
  { code: 'ko',    name: 'Korean',             nativeName: '한국어' },
  { code: 'ru',    name: 'Russian',            nativeName: 'Русский' },
  { code: 'ar',    name: 'Arabic',             nativeName: 'العربية', dir: 'rtl' },
  { code: 'it',    name: 'Italian',            nativeName: 'Italiano' },
  { code: 'nl',    name: 'Dutch',              nativeName: 'Nederlands' },
  { code: 'pl',    name: 'Polish',             nativeName: 'Polski' },
  { code: 'tr',    name: 'Turkish',            nativeName: 'Türkçe' },
  { code: 'sv',    name: 'Swedish',            nativeName: 'Svenska' },
  { code: 'da',    name: 'Danish',             nativeName: 'Dansk' },
  { code: 'cs',    name: 'Czech',              nativeName: 'Čeština' },
  { code: 'uk',    name: 'Ukrainian',          nativeName: 'Українська' },
];

const savedLang = localStorage.getItem('i18n_language') || navigator.language.split('-')[0] || 'en';
const initialLang = SUPPORTED_LANGUAGES.find(l => l.code === savedLang || l.code.startsWith(savedLang))?.code ?? 'en';

i18n
  .use(initReactI18next)
  .init({
    // English only. Every other locale is added by `loadLocale` below, and until
    // it lands i18next falls back to English — which is the SAME string the
    // sixteen untranslated locales carry today anyway (milestone M13).
    resources: { en: { translation: en } },
    lng: 'en',
    fallbackLng: 'en',
    interpolation: { escapeValue: false },
  });

const loaded = new Set<string>(['en']);

/**
 * Fetch a locale's chunk and register it. Idempotent, and safe to call for a
 * language that has no file: the caller keeps running in English rather than
 * getting an exception in its render path.
 */
export async function loadLocale(code: string): Promise<boolean> {
  if (loaded.has(code)) return true;
  const loader = LOCALE_LOADERS[`./locales/${code}/translation.json`];
  if (!loader) return false;
  try {
    const bundle = await loader();
    i18n.addResourceBundle(code, 'translation', bundle, true, true);
    loaded.add(code);
    return true;
  } catch {
    // A chunk that fails to load (offline, stale deploy) must not blank the UI.
    return false;
  }
}

/** Change the active language, persist the choice, update <html dir> for RTL. */
export async function setLanguage(code: string): Promise<void> {
  await loadLocale(code);
  await i18n.changeLanguage(code);
  localStorage.setItem('i18n_language', code);
  const lang = SUPPORTED_LANGUAGES.find(l => l.code === code);
  document.documentElement.setAttribute('lang', code);
  document.documentElement.setAttribute('dir', lang?.dir ?? 'ltr');
}

// Apply the stored preference. Deliberately NOT awaited at module scope: the app
// renders immediately in English and swaps when the chunk arrives, rather than
// holding the first paint hostage to a network round-trip.
if (initialLang !== 'en') void setLanguage(initialLang);
else {
  document.documentElement.setAttribute('lang', 'en');
  document.documentElement.setAttribute('dir', 'ltr');
}

export default i18n;
