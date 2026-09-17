import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

type Theme = 'dark' | 'light'
type Language = 'zh-CN' | 'en'

interface AppSettings {
  theme: Theme
  language: Language
  backendUrl: string
  graphitiEnabled: boolean
  observabilityEnabled: boolean
  autoRemediation: boolean
}

interface SettingsContextType {
  settings: AppSettings
  updateSettings: (partial: Partial<AppSettings>) => void
  saveSettings: () => void
}

const defaultSettings: AppSettings = {
  theme: 'dark',
  language: 'zh-CN',
  backendUrl: 'http://localhost:8080',
  graphitiEnabled: true,
  observabilityEnabled: false,
  autoRemediation: true,
}

const STORAGE_KEY = 'bee-settings'

function loadSettings(): AppSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) return { ...defaultSettings, ...JSON.parse(raw) }
  } catch {}
  return defaultSettings
}

const SettingsContext = createContext<SettingsContextType | null>(null)

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(loadSettings)

  // 应用主题
  useEffect(() => {
    const root = document.documentElement
    if (settings.theme === 'light') {
      root.classList.add('light')
      root.classList.remove('dark')
    } else {
      root.classList.add('dark')
      root.classList.remove('light')
    }
  }, [settings.theme])

  const updateSettings = (partial: Partial<AppSettings>) => {
    setSettings(prev => ({ ...prev, ...partial }))
  }

  const saveSettings = () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
  }

  return (
    <SettingsContext.Provider value={{ settings, updateSettings, saveSettings }}>
      {children}
    </SettingsContext.Provider>
  )
}

export function useSettings() {
  const ctx = useContext(SettingsContext)
  if (!ctx) throw new Error('useSettings must be used within SettingsProvider')
  return ctx
}