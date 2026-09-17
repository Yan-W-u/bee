import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Target,
  Search,
  Plus,
  ArrowRight,
  Activity,
  CheckCircle,
  AlertTriangle,
  Clock,
  Hexagon,
} from 'lucide-react'
import { useT } from '@/lib/i18n'
import { useQuery } from '@/lib/hooks'
import { flowsService, type FlowItem } from '@/services/flows'



export default function Flows() {
  const navigate = useNavigate()
  const t = useT()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  const { data: apiData, loading, error } = useQuery(
    () => flowsService.list(),
    []
  )

  const flows = useMemo(() => {
    if (!apiData?.flows) return []
    return apiData.flows.map((item: FlowItem) => ({
      id: String(item.id),
      type: item.model || item.title,
      agent: item.model_provider_name,
      target: item.title,
      status: item.status,
      progress: item.status === 'completed' ? 100 : item.status === 'running' ? 50 : 0,
      vulns: '—',
      date: item.created_at,
    }))
  }, [apiData])

  const statusConfig: Record<string, { label: string; className: string; icon: typeof Activity }> = {
    running: { label: t('flows.running'), className: 'badge-info', icon: Activity },
    completed: { label: t('flows.completed'), className: 'badge-success', icon: CheckCircle },
    failed: { label: t('flows.failed'), className: 'badge-danger', icon: AlertTriangle },
    pending: { label: t('dashboard.pending'), className: 'badge-warning', icon: Clock },
  }

  const filtered = flows.filter(f => {
    if (statusFilter !== 'all' && f.status !== statusFilter) return false
    if (search && !f.target.toLowerCase().includes(search.toLowerCase()) && !f.type.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Hexagon className="w-6 h-6 text-honey-500" />
            {t('flows.title')}
          </h1>
          <p className="text-hive-400 text-sm mt-1.5">{t('flows.subtitle')}</p>
        </div>
        <button onClick={() => navigate('/flows/new')} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          {t('flows.new')}
        </button>
      </div>

      {error && (
        <div className="card p-4 border border-danger/30 bg-danger/5 text-sm text-danger flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          {t('common.apiError') || 'Backend connection failed'}
        </div>
      )}

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-hive-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={t('flows.search')}
            className="input-field" style={{ paddingLeft: '2.5rem' }}
          />
        </div>
        <div className="flex items-center gap-1.5 bg-hive-800 rounded-lg border border-hive-700 p-1">
          {[
            { key: 'all', label: t('flows.all') },
            { key: 'running', label: t('flows.running') },
            { key: 'completed', label: t('flows.completed') },
            { key: 'failed', label: t('flows.failed') },
          ].map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setStatusFilter(key)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                statusFilter === key
                  ? 'bg-honey-500/15 text-honey-400'
                  : 'text-hive-400 hover:text-hive-200'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="flex items-center gap-2 text-hive-400 text-sm">
              <Activity className="w-4 h-4 animate-spin" />
              {t('flows.loading')}
            </div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-hive-500">
            <Hexagon className="w-12 h-12 mb-3 opacity-30" />
            <span className="text-sm">{t('flows.empty')}</span>
            <span className="text-xs mt-1 opacity-60">{t('flows.emptyHint')}</span>
          </div>
        ) : (
          filtered.map(flow => {
          const status = statusConfig[flow.status] || statusConfig.pending
          const StatusIcon = status.icon
          return (
            <div
              key={flow.id}
              onClick={() => navigate(`/flows/${flow.id}`)}
              className="card-hover flex items-center gap-4 px-5 py-4 cursor-pointer group"
            >
              <div className="flex-shrink-0 w-10 h-10 rounded-xl bg-hive-800 border border-hive-700/50 flex items-center justify-center text-xs font-mono text-hive-400">
                {flow.id.slice(-3)}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-white">{flow.target}</span>
                  <span className={`badge ${status.className}`}>
                    <StatusIcon className="w-3 h-3" />
                    {status.label}
                  </span>
                </div>
                <div className="flex items-center gap-4 mt-1.5">
                  <span className="text-xs text-hive-500">{flow.type}</span>
                  <span className="text-xs text-hive-600">|</span>
                  <span className="text-xs text-hive-500">{t('flows.agent')}: {flow.agent}</span>
                  <span className="text-xs text-hive-600">|</span>
                  <span className="text-xs text-hive-500">{flow.date}</span>
                </div>
              </div>

              <div className="flex items-center gap-3 flex-shrink-0">
                <div className="text-right">
                  <span className="text-sm font-medium text-hive-300">{flow.progress}%</span>
                  <p className="text-xs text-hive-500">{t('flows.vulns')}: {flow.vulns}</p>
                </div>
                <div className="w-24 h-2 bg-hive-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      flow.status === 'failed' ? 'bg-danger' :
                      flow.status === 'completed' ? 'bg-success' : 'bg-honey-500'
                    }`}
                    style={{ width: `${flow.progress}%` }}
                  />
                </div>
                <ArrowRight className="w-4 h-4 text-hive-600 group-hover:text-honey-400 transition-colors" />
              </div>
            </div>
          )
        })
        )}
      </div>
    </div>
  )
}
