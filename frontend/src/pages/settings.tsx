import { useSettings } from '@/lib/settings'
import { useT } from '@/lib/i18n'
import { Hexagon, Moon, Sun, Globe, Server } from 'lucide-react'
import { toast } from 'sonner'

export default function SettingsPage() {
  const { settings, updateSettings, saveSettings } = useSettings()
  const t = useT()

  const handleChange = (partial: Partial<typeof settings>) => {
    updateSettings(partial)
    saveSettings()
  }

  const handleToggle = (key: 'graphitiEnabled' | 'observabilityEnabled' | 'autoRemediation') => {
    handleChange({ [key]: !settings[key] })
  }

  const handleThemeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const theme = e.target.value as 'dark' | 'light'
    handleChange({ theme })
    const label = theme === 'dark' ? t('settings.dark') : t('settings.light')
    toast.success(`${t('settings.themeChanged')}${label}`)
  }

  const handleLanguageChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const lang = e.target.value as 'zh-CN' | 'en'
    handleChange({ language: lang })
    const label = lang === 'zh-CN' ? t('settings.chinese') : t('settings.english')
    toast.success(`${t('settings.langChanged')}${label}`)
  }

  const toggles = [
    { key: 'graphitiEnabled' as const, label: t('settings.graphiti'), desc: t('settings.graphitiDesc') },
    { key: 'observabilityEnabled' as const, label: t('settings.observability'), desc: t('settings.observabilityDesc') },
    { key: 'autoRemediation' as const, label: t('settings.autoRemediation'), desc: t('settings.autoRemediationDesc') },
  ]

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
          <Hexagon className="w-6 h-6 text-honey-500" />
          {t('settings.title')}
        </h1>
        <p className="text-hive-400 text-sm mt-1.5">{t('settings.subtitle')}</p>
      </div>

      {/* {t('settings.appearance')} */}
      <div className="card p-5 space-y-4">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Sun className="w-4 h-4 text-honey-400" />
          {t('settings.appearance')}
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="flex items-center justify-between px-4 py-3 rounded-lg bg-hive-950/50 border border-hive-700/20">
            <div className="flex items-center gap-2">
              {settings.theme === 'dark' ? <Moon className="w-4 h-4 text-hive-400" /> : <Sun className="w-4 h-4 text-honey-400" />}
              <span className="text-sm text-hive-300">{t('settings.theme')}</span>
            </div>
            <select
              value={settings.theme}
              onChange={handleThemeChange}
              className="bg-hive-800 border border-hive-600 rounded-lg px-3 py-1.5 text-sm text-hive-200 focus:outline-none focus:border-honey-500 cursor-pointer"
            >
              <option value="dark">{t('settings.dark')}</option>
              <option value="light">{t('settings.light')}</option>
            </select>
          </div>
          <div className="flex items-center justify-between px-4 py-3 rounded-lg bg-hive-950/50 border border-hive-700/20">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-hive-400" />
              <span className="text-sm text-hive-300">{t('settings.language')}</span>
            </div>
            <select
              value={settings.language}
              onChange={handleLanguageChange}
              className="bg-hive-800 border border-hive-600 rounded-lg px-3 py-1.5 text-sm text-hive-200 focus:outline-none focus:border-honey-500 cursor-pointer"
            >
              <option value="zh-CN">{t('settings.chinese')}</option>
              <option value="en">{t('settings.english')}</option>
            </select>
          </div>
        </div>
      </div>

      {/* 后端连接 */}
      <div className="card p-5 space-y-4">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Server className="w-4 h-4 text-honey-400" />
          {t('settings.backend')}
        </h3>
        <div>
          <label className="text-sm text-hive-400 mb-1.5 block">{t('settings.backendLabel')}</label>
          <input
            type="text"
            value={settings.backendUrl}
            onChange={e => handleChange({ backendUrl: e.target.value })}
            className="input-field"
            style={{ paddingLeft: '1rem' }}
            placeholder="http://localhost:8080"
          />
        </div>
      </div>

      {/* 功能开关 */}
      <div className="card p-5 space-y-4">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Globe className="w-4 h-4 text-honey-400" />
          {t('settings.features')}
        </h3>
        <div className="space-y-3">
          {toggles.map(({ key, label, desc }) => (
            <div key={key} className="flex items-center justify-between px-4 py-3 rounded-lg bg-hive-950/50 border border-hive-700/20">
              <div className="flex-1 mr-4">
                <span className="text-sm text-hive-300">{label}</span>
                <p className="text-xs text-hive-500 mt-0.5">{desc}</p>
              </div>
              <button
                onClick={() => handleToggle(key)}
                className="w-11 h-6 rounded-full flex-shrink-0 cursor-pointer relative"
                style={{ backgroundColor: settings[key] ? '#f59e0b' : '#475569', transition: 'background-color 0.2s' }}
              >
                <span
                  className="absolute w-5 h-5 rounded-full bg-white shadow-sm"
                  style={{
                    top: 2,
                    left: settings[key] ? 22 : 2,
                    transition: 'left 0.2s',
                  }}
                />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}