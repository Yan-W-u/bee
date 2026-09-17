import { useState, useEffect } from 'react'
import { Cpu, Plus, CheckCircle, XCircle, Hexagon, Key, Link, Box, Loader2, Trash2, Edit2, Database } from 'lucide-react'
import { toast } from 'sonner'
import { useT } from '@/lib/i18n'
import { useQuery } from '@/lib/hooks'
import { providersService, type ProviderInfo } from '@/services/providers'
import { providerPresetService, type ProviderPreset, type ProviderPresetPayload } from '@/services/providerPresets'

const providerColors: Record<string, string> = {
  openai: 'bg-emerald-600',
  deepseek: 'bg-indigo-600',
  anthropic: 'bg-amber-600',
  gemini: 'bg-blue-600',
  ollama: 'bg-slate-700',
}

const providerOptions = [
  { value: 'openai', label: 'OpenAI', models: ['gpt-4o', 'gpt-4-turbo', 'gpt-3.5-turbo'] },
  { value: 'deepseek', label: 'DeepSeek', models: ['deepseek-chat', 'deepseek-coder'] },
  { value: 'anthropic', label: 'Anthropic', models: ['claude-3-5-sonnet', 'claude-3-opus'] },
  { value: 'gemini', label: 'Google AI', models: ['gemini-2.0-flash', 'gemini-1.5-pro'] },
  { value: 'ollama', label: 'Ollama', models: ['qwen3', 'llama3', 'deepseek-r1'] },
  { value: 'custom', label: 'Custom', models: ['custom-model'] },
]

interface PresetForm {
  name: string
  type: string
  apiKey: string
  endpoint: string
  model: string
}

const emptyPresetForm: PresetForm = {
  name: '',
  type: 'openai',
  apiKey: '',
  endpoint: '',
  model: '',
}

export default function Providers() {
  const t = useT()
  const { data: apiProviders, loading, error } = useQuery(() => providersService.list(), [])
  const [presets, setPresets] = useState<ProviderPreset[]>([])
  const [loadingPresets, setLoadingPresets] = useState(true)
  const [showPresetModal, setShowPresetModal] = useState(false)
  const [editingPreset, setEditingPreset] = useState<ProviderPreset | null>(null)
  const [presetForm, setPresetForm] = useState<PresetForm>(emptyPresetForm)

  const providers = !apiProviders ? [] : apiProviders.map((p: ProviderInfo) => ({
    id: p.name,
    name: p.name,
    type: p.type,
    defaultModel: p.default_model,
    models: p.models.map(m => m.name).join(', '),
    status: 'connected' as const,
  }))

  useEffect(() => {
    loadPresets()
  }, [])

  const loadPresets = () => {
    setLoadingPresets(true)
    providerPresetService.list()
      .then(data => setPresets(data || []))
      .catch(err => toast.error(t('providers.presetsLoadError') || `加载预设失败: ${err.message || err}`))
      .finally(() => setLoadingPresets(false))
  }

  const resetPresetForm = () => {
    setPresetForm(emptyPresetForm)
    setEditingPreset(null)
  }

  const openAddPreset = () => {
    resetPresetForm()
    setShowPresetModal(true)
  }

  const openEditPreset = (preset: ProviderPreset) => {
    setEditingPreset(preset)
    setPresetForm({
      name: preset.name,
      type: preset.api_provider,
      apiKey: preset.api_key,
      endpoint: preset.api_endpoint,
      model: preset.model,
    })
    setShowPresetModal(true)
  }

  const handleSavePreset = async () => {
    if (!presetForm.name.trim()) {
      toast.error(t('providers.nameRequired') || '请输入预设名称')
      return
    }
    if (!presetForm.apiKey.trim()) {
      toast.error(t('providers.apiKeyRequired') || '请输入 API Key')
      return
    }
    if (!presetForm.endpoint.trim()) {
      toast.error(t('providers.endpointRequired') || '请输入 API Endpoint')
      return
    }
    if (!presetForm.model.trim()) {
      toast.error(t('providers.modelRequired') || '请输入模型名称')
      return
    }

    const payload: ProviderPresetPayload = {
      name: presetForm.name.trim(),
      api_provider: presetForm.type,
      api_key: presetForm.apiKey.trim(),
      api_endpoint: presetForm.endpoint.trim(),
      model: presetForm.model.trim(),
    }

    try {
      if (editingPreset?.id) {
        await providerPresetService.update(editingPreset.id, payload)
        toast.success(t('providers.presetUpdated') || '预设已更新')
      } else {
        await providerPresetService.create(payload)
        toast.success(t('providers.presetAdded') || '预设已添加')
      }
      setShowPresetModal(false)
      resetPresetForm()
      loadPresets()
    } catch (err: any) {
      toast.error(t('providers.presetSaveError') || `保存预设失败: ${err.message || err}`)
    }
  }

  const handleDeletePreset = async (preset: ProviderPreset) => {
    if (!preset.id) return
    if (!confirm(t('providers.presetDeleteConfirm') || `确定删除预设「${preset.name}」吗？`)) return
    try {
      await providerPresetService.delete(preset.id)
      toast.success(t('providers.presetDeleted') || '预设已删除')
      loadPresets()
    } catch (err: any) {
      toast.error(t('providers.presetDeleteError') || `删除预设失败: ${err.message || err}`)
    }
  }

  const handleTest = (id: string) => {
    toast.success(t('providers.testSuccess'))
  }

  const selectedProvider = providerOptions.find(p => p.value === presetForm.type)
  const availableModels = selectedProvider?.models || []

  return (
    <div className="p-6 space-y-8">
      {/* Providers section */}
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
              <Hexagon className="w-6 h-6 text-honey-500" />
              {t('providers.title')}
            </h1>
            <p className="text-hive-400 text-sm mt-1.5">{t('providers.subtitle')}</p>
          </div>
        </div>

        {error && (
          <div className="card p-4 border border-danger/30 bg-danger/5 text-sm text-danger flex items-center gap-2">
            <XCircle className="w-4 h-4" />
            {t('common.apiError') || 'Backend connection failed'}
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-8 h-8 text-honey-500 animate-spin" />
          </div>
        ) : providers.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-hive-500">
            <Box className="w-12 h-12 mb-3 opacity-30" />
            <span className="text-sm">{t('providers.empty')}</span>
            <span className="text-xs mt-1 opacity-60">{t('providers.emptyHint')}</span>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {providers.map(p => (
              <div key={p.id} className="card p-5 space-y-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`w-9 h-9 rounded-xl ${providerColors[p.id] || 'bg-hive-700'} flex items-center justify-center text-white text-sm font-bold flex-shrink-0`}>
                      {p.name.charAt(0)}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-semibold text-white">{p.name}</h3>
                        <span className={`badge ${p.status === 'connected' ? 'badge-success' : 'badge-warning'}`}>
                          {p.status === 'connected' ? t('providers.connected') : t('providers.disconnected')}
                        </span>
                      </div>
                      <p className="text-xs text-hive-400 mt-0.5">{p.models}</p>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => handleTest(p.id)} className="btn-secondary text-xs flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5" />
                    {t('providers.test')}
                  </button>
                  <span className="flex items-center gap-1 text-xs text-hive-500">
                    {p.status === 'connected' ? <CheckCircle className="w-3 h-3 text-success" /> : <XCircle className="w-3 h-3 text-hive-500" />}
                    {p.defaultModel}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Presets section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Database className="w-5 h-5 text-honey-500" />
              {t('providers.presetsTitle') || 'API 模型预设'}
            </h2>
            <p className="text-hive-400 text-sm mt-1">{t('providers.presetsSubtitle') || '提前填写常用 API 配置，配置蜂群时直接选择，无需重复输入 API Key。'}</p>
          </div>
          <button onClick={openAddPreset} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            {t('providers.addPreset') || '添加预设'}
          </button>
        </div>

        {loadingPresets ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-7 h-7 text-honey-500 animate-spin" />
          </div>
        ) : presets.length === 0 ? (
          <div className="card p-6 text-center text-hive-500">
            <Database className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">{t('providers.presetsEmpty') || '还没有 API 模型预设'}</p>
            <p className="text-xs mt-1 opacity-60">{t('providers.presetsEmptyHint') || '点击右上角添加预设，之后在「蜂群」页面直接选用。'}</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {presets.map(preset => (
              <div key={preset.id} className="card p-4 space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`w-9 h-9 rounded-xl ${providerColors[preset.api_provider] || 'bg-hive-700'} flex items-center justify-center text-white text-sm font-bold flex-shrink-0`}>
                      {preset.name.charAt(0).toUpperCase()}
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-sm font-semibold text-white truncate">{preset.name}</h3>
                      <p className="text-xs text-hive-400 truncate">{preset.model}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <button
                      onClick={() => openEditPreset(preset)}
                      className="p-1.5 text-hive-500 hover:text-hive-300 hover:bg-hive-700/30 rounded-lg transition-colors"
                      title={t('common.edit') || '编辑'}
                    >
                      <Edit2 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleDeletePreset(preset)}
                      className="p-1.5 text-hive-500 hover:text-danger hover:bg-danger/10 rounded-lg transition-colors"
                      title={t('common.delete') || '删除'}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                <div className="space-y-1 text-xs text-hive-500">
                  <div className="flex items-center gap-2">
                    <Key className="w-3 h-3" />
                    <span className="font-mono">{preset.api_key ? '••••••••' + preset.api_key.slice(-4) : '-'}</span>
                  </div>
                  <div className="flex items-center gap-2 truncate">
                    <Link className="w-3 h-3 flex-shrink-0" />
                    <span className="truncate">{preset.api_endpoint}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showPresetModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={() => setShowPresetModal(false)}>
          <div className="card p-6 w-full max-w-md space-y-4" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              {editingPreset ? <Edit2 className="w-5 h-5 text-honey-400" /> : <Plus className="w-5 h-5 text-honey-400" />}
              {editingPreset ? (t('providers.editPreset') || '编辑预设') : (t('providers.addPreset') || '添加预设')}
            </h2>

            <div className="space-y-3">
              <div>
                <label className="text-sm text-hive-400 mb-1.5 block">{t('providers.presetName') || '预设名称'}</label>
                <input
                  type="text"
                  value={presetForm.name}
                  onChange={e => setPresetForm(prev => ({ ...prev, name: e.target.value }))}
                  placeholder={t('providers.presetNamePlaceholder') || '例如：公司 DeepSeek'}
                  className="input-field"
                />
              </div>

              <div>
                <label className="text-sm text-hive-400 mb-1.5 block">{t('providers.type') || '提供商'}</label>
                <select
                  value={presetForm.type}
                  onChange={e => setPresetForm(prev => ({ ...prev, type: e.target.value, model: '' }))}
                  className="input-field"
                  style={{ paddingLeft: '0.75rem' }}
                >
                  {providerOptions.map(p => (
                    <option key={p.value} value={p.value}>{p.label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-sm text-hive-400 mb-1.5 block">{t('providers.model') || '模型'}</label>
                <input
                  type="text"
                  list={`models-${presetForm.type}`}
                  value={presetForm.model}
                  onChange={e => setPresetForm(prev => ({ ...prev, model: e.target.value }))}
                  placeholder={t('providers.modelPlaceholder') || 'deepseek-chat'}
                  className="input-field"
                />
                <datalist id={`models-${presetForm.type}`}>
                  {availableModels.map(m => (
                    <option key={m} value={m} />
                  ))}
                </datalist>
              </div>

              <div>
                <label className="text-sm text-hive-400 mb-1.5 block">{t('providers.apiKey')}</label>
                <div className="relative">
                  <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-hive-500" />
                  <input
                    type="password"
                    value={presetForm.apiKey}
                    onChange={e => setPresetForm(prev => ({ ...prev, apiKey: e.target.value }))}
                    placeholder="sk-..."
                    className="input-field"
                    style={{ paddingLeft: '2.5rem' }}
                  />
                </div>
              </div>

              <div>
                <label className="text-sm text-hive-400 mb-1.5 block">{t('providers.apiEndpoint')}</label>
                <div className="relative">
                  <Link className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-hive-500" />
                  <input
                    type="text"
                    value={presetForm.endpoint}
                    onChange={e => setPresetForm(prev => ({ ...prev, endpoint: e.target.value }))}
                    placeholder="https://api.deepseek.com"
                    className="input-field"
                    style={{ paddingLeft: '2.5rem' }}
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3 pt-2">
              <button onClick={() => setShowPresetModal(false)} className="btn-secondary flex-1">
                {t('common.cancel')}
              </button>
              <button onClick={handleSavePreset} className="btn-primary flex-1">
                {t('common.save')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
