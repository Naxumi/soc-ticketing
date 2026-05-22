export type ThemeMode = "light" | "dark"

const THEME_STORAGE_KEY = "defendersoc-theme"

function getStoredTheme(): ThemeMode | null {
  if (typeof window === "undefined") return null
  const value = window.localStorage.getItem(THEME_STORAGE_KEY)
  return value === "dark" || value === "light" ? value : null
}

function getPreferredTheme(): ThemeMode {
  if (typeof window === "undefined") return "light"
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
}

export function getTheme(): ThemeMode {
  return getStoredTheme() ?? getPreferredTheme()
}

export function setTheme(theme: ThemeMode) {
  if (typeof window === "undefined") return
  document.documentElement.classList.toggle("dark", theme === "dark")
  window.localStorage.setItem(THEME_STORAGE_KEY, theme)
}

export function toggleTheme(current: ThemeMode): ThemeMode {
  return current === "dark" ? "light" : "dark"
}

export function initSystemThemeClass() {
  if (typeof window === "undefined") return
  setTheme(getTheme())
}
