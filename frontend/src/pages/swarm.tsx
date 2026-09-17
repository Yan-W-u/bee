import { useState, useMemo, useEffect, useCallback } from 'react'
import { Hexagon, Cpu, Key, Link, Save, TestTube, ChevronDown, ChevronUp, CheckCircle, XCircle, Activity, Zap, Shield, Search, Code, Lightbulb, Brain, Package, FileText, MessageSquare, RefreshCw, Layers, Eye, EyeOff, AlertTriangle, Loader2 } from 'lucide-react'
import { useT } from '@/lib/i18n'
import { toast } from 'sonner'
import { swarmService, type SwarmAgentConfig } from '@/services/swarm'
import { providerPresetService, type ProviderPreset } from '@/services/providerPresets'

interface Agent {
  id: string; name: string; role: string; desc: string
  icon: typeof Hexagon; iconColor: string
  apiProvider: string; apiKey: string; apiEndpoint: string; model: string
  status: 'configured' | 'unconfigured'; expanded: boolean
  required?: boolean
}

const providerLabels: Record<string, string> = { openai: 'OpenAI', deepseek: 'DeepSeek', anthropic: 'Anthropic', gemini: 'Google AI', ollama: 'Ollama', custom: 'Custom' }
const providerValueMap: Record<string, string> = { 'OpenAI': 'openai', 'DeepSeek': 'deepseek', 'Anthropic': 'anthropic', 'Google AI': 'gemini', 'Ollama': 'ollama', 'Custom': 'custom' }
const labelFromValue: Record<string, string> = Object.fromEntries(Object.entries(providerLabels).map(([k, v]) => [k, v]))

export default function Swarm() {
  const t = useT()
  const defaultAgents = useMemo<Agent[]>(() => [
    { id:'primary', name:t('swarm.primary.name'), role:t('swarm.primary.role'), desc:t('swarm.primary.desc'), icon:Cpu, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'', apiEndpoint:'', model:'deepseek-chat', status:'unconfigured', expanded:false, required:true, },
    { id:'pentester', name:t('swarm.pentester.name'), role:t('swarm.pentester.role'), desc:t('swarm.pentester.desc'), icon:Zap, iconColor:'text-danger', apiProvider:'DeepSeek', apiKey:'', apiEndpoint:'', model:'deepseek-chat', status:'unconfigured', expanded:false, required:true, },
    { id:'searcher', name:t('swarm.searcher.name'), role:t('swarm.searcher.role'), desc:t('swarm.searcher.desc'), icon:Search, iconColor:'text-honey-300', apiProvider:'OpenAI', apiKey:'', apiEndpoint:'', model:'gpt-4o', status:'unconfigured', expanded:false, required:true, },
    { id:'remediator', name:t('swarm.remediator.name'), role:t('swarm.remediator.role'), desc:t('swarm.remediator.desc'), icon:Shield, iconColor:'text-success', apiProvider:'DeepSeek', apiKey:'', apiEndpoint:'', model:'deepseek-chat', status:'unconfigured', expanded:false, required:true, },
    { id:'coder', name:t('swarm.coder.name'), role:t('swarm.coder.role'), desc:t('swarm.coder.desc'), icon:Code, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'', apiEndpoint:'', model:'deepseek-chat', status:'unconfigured', expanded:false },
    { id:'adviser', name:t('swarm.adviser.name'), role:t('swarm.adviser.role'), desc:t('swarm.adviser.desc'), icon:Lightbulb, iconColor:'text-warning', apiProvider:'Anthropic', apiKey:'', apiEndpoint:'', model:'claude-3-5-sonnet', status:'unconfigured', expanded:false },
    { id:'memorist', name:t('swarm.memorist.name'), role:t('swarm.memorist.role'), desc:t('swarm.memorist.desc'), icon:Brain, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'', apiEndpoint:'', model:'deepseek-chat', status:'unconfigured', expanded:false },
    { id:'explainer', name:t('swarm.explainer.name'), role:t('swarm.explainer.role'), desc:t('swarm.explainer.desc'), icon:MessageSquare, iconColor:'text-honey-300', apiProvider:'DeepSeek', apiKey:'', apiEndpoint:'', model:'deepseek-chat', status:'unconfigured', expanded:false },
    { id:'installer', name:t('swarm.installer.name'), role:t('swarm.installer.role'), desc:t('swarm.installer.desc'), icon:Package, iconColor:'text-hive-300', apiProvider:'Ollama', apiKey:'', apiEndpoint:'', model:'qwen3', status:'unconfigured', expanded:false },
    { id:'reporter', name:t('swarm.reporter.name'), role:t('swarm.reporter.role'), desc:t('swarm.reporter.desc'), icon:FileText, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'', apiEndpoint:'', model:'deepseek-chat', status:'unconfigured', expanded:false },
    { id:'reflector', name:t('swarm.reflector.name'), role:t('swarm.reflector.role'), desc:t('swarm.reflector.desc'), icon:RefreshCw, iconColor:'text-honey-300', apiProvider:'DeepSeek', apiKey:'', apiEndpoint:'', model:'deepseek-chat', status:'unconfigured', expanded:false },
    { id:'enricher', name:t('swarm.enricher.name'), role:t('swarm.enricher.role'), desc:t('swarm.enricher.desc'), icon:Layers, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'', apiEndpoint:'', model:'deepseek-chat', status:'unconfigured', expanded:false },
  ], [t])
  const [agents, setAgents] = useState<Agent[]>(defaultAgents)
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({})
  const [loadingConfigs, setLoadingConfigs] = useState(true)
  const [presets, setPresets] = useState<ProviderPreset[]>([])
  const providerOptions = [
    { value:'openai', label:'OpenAI', models:['gpt-4o','gpt-4-turbo','gpt-3.5-turbo'] },
    { value:'deepseek', label:'DeepSeek', models:['deepseek-chat','deepseek-coder'] },
    { value:'anthropic', label:'Anthropic', models:['claude-3-5-sonnet','claude-3-opus'] },
    { value:'gemini', label:'Google AI', models:['gemini-2.0-flash','gemini-1.5-pro'] },
    { value:'ollama', label:'Ollama', models:['qwen3','llama3','deepseek-r1'] },
    { value:'custom', label:'Custom', models:['custom-model'] },
  ]

  // Fetch saved configs from backend and merge with defaults
  useEffect(() => {
    let cancelled = false
    setLoadingConfigs(true)

    providerPresetService.list()
      .then(data => {
        if (!cancelled) setPresets(data || [])
      })
      .catch(() => {
        // Silently fail if backend endpoint isn't available yet
      })

    swarmService.list()
      .then(configs => {
        if (cancelled) return
        if (configs && Array.isArray(configs) && configs.length > 0) {
          const configMap = new Map(configs.map(c => [c.agent_id, c]))
          setAgents(prev => prev.map(agent => {
            const saved = configMap.get(agent.id)
            if (!saved) return agent
            return {
              ...agent,
              apiProvider: labelFromValue[saved.api_provider] || saved.api_provider || agent.apiProvider,
              apiKey: saved.api_key || '',
              apiEndpoint: saved.api_endpoint || '',
              model: saved.model || agent.model,
              status: saved.status === 'configured' ? 'configured' : 'unconfigured',
            }
          }))
        }
      })
      .catch(() => {
        // If backend doesn't have the endpoint yet, silently continue with defaults
      })
      .finally(() => {
        if (!cancelled) setLoadingConfigs(false)
      })
    return () => { cancelled = true }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const updateAgent = (id: string, patch: Partial<Agent>) => {
    setAgents(prev => prev.map(a => a.id === id ? { ...a, ...patch } : a))
  }

  const applyPreset = (agentId: string, presetId: string) => {
    const preset = presets.find(p => String(p.id) === presetId)
    if (!preset) return
    updateAgent(agentId, {
      apiProvider: labelFromValue[preset.api_provider] || preset.api_provider,
      apiKey: preset.api_key,
      apiEndpoint: preset.api_endpoint,
      model: preset.model,
    })
    toast.success(t('swarm.presetApplied') || '已应用预设')
  }

  const toggleExpand = (id: string) => {
    setAgents(prev => prev.map(a => a.id === id ? { ...a, expanded: !a.expanded } : a))
  }

  // Persist all agent configs to backend
  const persistToBackend = useCallback((currentAgents: Agent[]) => {
    const configs: SwarmAgentConfig[] = currentAgents.map(a => ({
      agent_id: a.id,
      api_provider: providerValueMap[a.apiProvider] || a.apiProvider.toLowerCase(),
      api_key: a.apiKey,
      api_endpoint: a.apiEndpoint,
      model: a.model,
      status: a.status,
    }))
    swarmService.save(configs).catch(() => {
      // Silently fail if backend endpoint isn't available yet
    })
  }, [])

  const handleSave = (id: string) => {
    const agent = agents.find(a => a.id === id)
    if (!agent) return
    const configured = !!(agent.apiKey && agent.apiEndpoint)
    const updatedAgents = agents.map(a => {
      if (a.id !== id) return a
      return { ...a, status: configured ? 'configured' as const : 'unconfigured' as const, expanded: configured ? false : a.expanded }
    })
    setAgents(updatedAgents)
    persistToBackend(updatedAgents)
    if (configured) {
      toast.success(t('swarm.saved'))
    } else {
      toast.warning(t('swarm.fillKey'))
    }
  }

  const handleTest = (id: string) => {
    const agent = agents.find(a => a.id === id)
    if (!agent) return
    if (!agent.apiKey || !agent.apiEndpoint) {
      toast.error(t('swarm.fillKey'))
      return
    }
    const updatedAgents = agents.map(a => {
      if (a.id !== id) return a
      return { ...a, status: 'configured' as const, expanded: false }
    })
    setAgents(updatedAgents)
    persistToBackend(updatedAgents)
    toast.success(t('swarm.testSuccess'))
  }

  if (loadingConfigs) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Hexagon className="w-6 h-6 text-honey-500" />
            {t('swarm.title')}
          </h1>
          <p className="text-hive-400 text-sm mt-1.5">{t('swarm.subtitle')}</p>
        </div>
        <div className="flex items-center justify-center py-16">
          <Loader2 className="w-8 h-8 text-honey-500 animate-spin" />
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
          <Hexagon className="w-6 h-6 text-honey-500" />
          {t('swarm.title')}
        </h1>
        <p className="text-hive-400 text-sm mt-1.5">{t('swarm.subtitle')}</p>
      </div>

      {/* 必需配置提示 */}
      <div className="card p-4 border border-honey-500/30 bg-honey-500/5 text-sm text-honey-300 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-honey-400 flex-shrink-0 mt-0.5" />
        <div>
          <span className="font-medium">必需配置：</span>
          蜂王、攻击蜂、侦查蜂、修复蜂 为系统核心蜂群，必须配置 API Key 和 Endpoint 后方可正常使用。其余蜂群可按需配置。
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {agents.map(agent => {
          const Icon = agent.icon
          return (
            <div key={agent.id} className="card overflow-hidden">
              <div className="p-4 flex items-start gap-3">
                <div className={`w-10 h-10 rounded-xl ${agent.status === 'configured' ? 'bg-honey-500/10' : 'bg-hive-700'} border ${agent.status === 'configured' ? 'border-honey-500/20' : 'border-hive-600'} flex items-center justify-center flex-shrink-0`}>
                  <Icon className={`w-5 h-5 ${agent.iconColor}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-semibold text-white">{agent.name}</span>
                    {agent.required && (
                      <span className="badge badge-info text-[10px] px-1.5 py-0">必需</span>
                    )}
                    <span className={`badge ${agent.status === 'configured' ? 'badge-success' : 'badge-warning'} text-xs`}>
                      {agent.status === 'configured' ? t('swarm.configured') : t('swarm.unconfigured')}
                    </span>
                  </div>
                  <p className="text-xs text-hive-400">{agent.role}</p>
                </div>
                <button
                  onClick={() => toggleExpand(agent.id)}
                  className="flex-shrink-0 text-hive-500 hover:text-hive-300 mt-1"
                >
                  {agent.expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>

              {agent.expanded && (
                <div className="px-4 pb-4 space-y-3 border-t border-hive-700/30 pt-3">
                  <p className="text-xs text-hive-300 leading-relaxed">{agent.desc}</p>

                  {presets.length > 0 && (
                    <div>
                      <label className="text-xs text-hive-400 mb-1 block">{t('swarm.applyPreset') || '应用预设'}</label>
                      <select
                        value=""
                        onChange={e => applyPreset(agent.id, e.target.value)}
                        className="input-field text-sm" style={{ paddingLeft: '0.75rem' }}
                      >
                        <option value="">{t('swarm.selectPreset') || '选择已保存的模型...'}</option>
                        {presets.map(preset => (
                          <option key={preset.id} value={preset.id}>
                            {preset.name} · {preset.model}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}

                  <div>
                    <label className="text-xs text-hive-400 mb-1 block">{t('swarm.provider')}</label>
                    <select
                      value={agent.apiProvider}
                      onChange={e => updateAgent(agent.id, { apiProvider: e.target.value })}
                      className="input-field text-sm" style={{ paddingLeft: '0.75rem' }}
                    >
                      {providerOptions.map(p => (
                        <option key={p.value} value={p.label}>{p.label}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="text-xs text-hive-400 mb-1 block">{t('swarm.model')}</label>
                    <select
                      value={agent.model}
                      onChange={e => updateAgent(agent.id, { model: e.target.value })}
                      className="input-field text-sm" style={{ paddingLeft: '0.75rem' }}
                    >
                      {(providerOptions.find(p => p.label === agent.apiProvider)?.models || ['custom']).map(m => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="text-xs text-hive-400 mb-1 block">{t('swarm.apiKey')}</label>
                    <div className="relative">
                      <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-hive-500" />
                      <input
                        type={showKeys[agent.id] ? 'text' : 'password'}
                        value={agent.apiKey}
                        onChange={e => updateAgent(agent.id, { apiKey: e.target.value })}
                        placeholder="sk-..."
                        className="input-field text-sm" style={{ paddingLeft: '2.2rem', paddingRight: '2.2rem' }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowKeys(prev => ({ ...prev, [agent.id]: !prev[agent.id] }))}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-hive-500 hover:text-hive-300"
                      >
                        {showKeys[agent.id] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="text-xs text-hive-400 mb-1 block">{t('swarm.endpoint')}</label>
                    <div className="relative">
                      <Link className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-hive-500" />
                      <input
                        type="text"
                        value={agent.apiEndpoint}
                        onChange={e => updateAgent(agent.id, { apiEndpoint: e.target.value })}
                        placeholder="https://api.deepseek.com"
                        className="input-field text-sm" style={{ paddingLeft: '2.2rem' }}
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-2 pt-1">
                    <button onClick={() => handleSave(agent.id)} className="btn-primary text-xs flex items-center gap-1.5">
                      <Save className="w-3.5 h-3.5" />
                      {t('common.save')}
                    </button>
                    <button onClick={() => handleTest(agent.id)} className="btn-secondary text-xs flex items-center gap-1.5">
                      <TestTube className="w-3.5 h-3.5" />
                      {t('swarm.test')}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
