import { ref } from 'vue'
import en from './en.js'
import ptBR from './pt-BR.js'

const STORAGE_KEY = 'kasumi_lang'
const catalogs = { en, 'pt-BR': ptBR }

function detectInitialLocale() {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY)
    if (saved && catalogs[saved]) return saved
  } catch {
    // ignore storage errors
  }
  const nav = typeof navigator !== 'undefined' ? navigator.language || '' : ''
  return nav.toLowerCase().startsWith('pt') ? 'pt-BR' : 'en'
}

export const locale = ref(detectInitialLocale())

export function setLocale(code) {
  if (!catalogs[code]) return
  locale.value = code
  try {
    window.localStorage.setItem(STORAGE_KEY, code)
  } catch {
    // ignore
  }
}

export function t(key, vars = {}) {
  const dict = catalogs[locale.value] || en
  const raw = dict[key] ?? en[key] ?? key
  return raw.replace(/\{(\w+)\}/g, (_, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : `{${name}}`
  )
}
