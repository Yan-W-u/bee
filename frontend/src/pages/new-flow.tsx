import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Target, ArrowLeft, Plus, Shield, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { useT } from '@/lib/i18n'
import { useMutation } from '@/lib/hooks'
import { flowsService, type CreateFlowInput } from '@/services/flows'
import { extractApiError } from '@/lib/api'

const targetTypeKeys = ['web', 'api', 'network', 'db', 'cloud', 'mobile'] as const

export default function NewFlow() {
  const t = useT()
  const navigate = useNavigate()
  const [selectedType, setSelectedType] = useState('')
  const [target, setTarget] = useState('')
  const [scope, setScope] = useState('')

  const targetTypes = [
    { value: 'web', label: t('taskType.web'), desc: t('taskType.webDesc'), icon: '🌐' },
    { value: 'api', label: t('taskType.api'), desc: t('taskType.apiDesc'), icon: '🔌' },
    { value: 'network', label: t('taskType.network'), desc: t('taskType.networkDesc'), icon: '🔍' },
    { value: 'db', label: t('taskType.db'), desc: t('taskType.dbDesc'), icon: '🗄️' },
    { value: 'cloud', label: t('taskType.cloud'), desc: t('taskType.cloudDesc'), icon: '☁️' },
    { value: 'mobile', label: t('taskType.mobile'), desc: t('taskType.mobileDesc'), icon: '📱' },
  ]

  const { execute: createFlow, loading } = useMutation((v: CreateFlowInput) => flowsService.create(v))

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!target || !selectedType) {
      toast.error(t('newFlow.fillRequired'))
      return
    }
    try {
      await createFlow({ input: scope || target, provider: 'deepseek' })
      toast.success(t('newFlow.created'))
      navigate('/flows')
    } catch (err: unknown) {
      toast.error(extractApiError(err) || t('newFlow.error'))
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-2xl">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate('/flows')}
          className="w-9 h-9 rounded-lg bg-hive-800 border border-hive-700 flex items-center justify-center hover:bg-hive-700 transition-colors"
        >
          <ArrowLeft className="w-4 h-4 text-hive-400" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-white">{t('newFlow.title')}</h1>
          <p className="text-hive-400 text-sm mt-1">{t('newFlow.subtitle')}</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target Input */}
        <div className="card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Target className="w-4 h-4 text-honey-400" />
            {t('newFlow.target')}
          </h3>
          <div>
            <label className="text-sm text-hive-400 mb-1.5 block">{t('newFlow.targetAddr')}</label>
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder={t('newFlow.targetPlaceholder')}
              className="input-field"
            />
          </div>
          <div>
            <label className="text-sm text-hive-400 mb-1.5 block">{t('newFlow.scope')}</label>
            <textarea
              value={scope}
              onChange={e => setScope(e.target.value)}
              placeholder={t('newFlow.scopePlaceholder')}
              rows={3}
              className="input-field resize-none"
            />
          </div>
        </div>

        {/* Task Type */}
        <div className="card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-honey-400" />
            {t('newFlow.type')}
          </h3>
          <div className="grid grid-cols-2 gap-3">
            {targetTypes.map(t => (
              <button
                key={t.value}
                type="button"
                onClick={() => setSelectedType(t.value)}
                className={`text-left p-4 rounded-xl border transition-all duration-200 ${
                  selectedType === t.value
                    ? 'border-honey-500/50 bg-honey-500/5'
                    : 'border-hive-700/50 bg-hive-800/40 hover:border-hive-600'
                }`}
              >
                <span className="text-xl">{t.icon}</span>
                <p className="text-sm font-medium text-white mt-2">{t.label}</p>
                <p className="text-xs text-hive-400 mt-1">{t.desc}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Submit */}
        <button type="submit" className="btn-primary flex items-center gap-2" disabled={loading}>
          {loading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Plus className="w-4 h-4" />
          )}
          {loading ? t('common.loading') : t('newFlow.submit')}
        </button>
      </form>
    </div>
  )
}