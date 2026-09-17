import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Bug,
  Search,
  Shield,
  AlertTriangle,
  Info,
  ChevronRight,
  Hexagon,
} from 'lucide-react'
import { useT } from '@/lib/i18n'
import { useQuery } from '@/lib/hooks'
import { apiGet } from '@/lib/api'

const severityConfig: Record<string, { label: string; className: string; bg: string; border: string; text: string }> = {
  critical: { label: 'Critical', className: 'badge-danger', bg: 'bg-danger/10', border: 'border-danger/30', text: 'text-danger' },
  high: { label: 'High', className: 'badge-danger', bg: 'bg-danger/10', border: 'border-danger/30', text: 'text-danger' },
  medium: { label: 'Medium', className: 'badge-warning', bg: 'bg-warning/10', border: 'border-warning/30', text: 'text-warning' },
  low: { label: 'Low', className: 'badge-info', bg: 'bg-honey-500/10', border: 'border-honey-500/30', text: 'text-honey-400' },
}

export default function Vulns() {
  const t = useT()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')

  const sevLabelMap: Record<string, string> = {
    critical: t('vulns.critical'),
    high: t('vulns.high'),
    medium: t('vulns.medium'),
    low: t('vulns.low'),
  }

  const { data: vulns, loading, error } = useQuery(async () => {
    const flowsRes = await apiGet<any>('/v1/flows', { page: 1, pageSize: 100, type: 'init' })
    const flows = flowsRes?.flows || flowsRes || []
    const allVulns: any[] = []
    for (const flow of flows) {
      const tasksRes = await apiGet<any>(`/v1/flows/${flow.id}/tasks`, { page: 1, pageSize: 100, type: 'init' })
      const tasks = tasksRes?.tasks || tasksRes || []
      for (const task of tasks) {
        // Parse task.result field which may contain JSON with vulnerability data
        if (task.result) {
          try {
            const parsed = JSON.parse(task.result)
            // Extract vulnerabilities from various possible structures
            const vulnArray = parsed.vulnerabilities || parsed.vulns || parsed.findings || []
            if (Array.isArray(vulnArray)) {
              for (const vuln of vulnArray) {
                allVulns.push({
                  ...vuln,
                  id: vuln.id || `${task.id}-${allVulns.length}`,
                  flowId: flow.id,
                  taskId: task.id,
                })
              }
            } else if (parsed.title && parsed.severity) {
              // Single vulnerability object
              allVulns.push({
                ...parsed,
                id: parsed.id || `${task.id}-0`,
                flowId: flow.id,
                taskId: task.id,
              })
            }
          } catch {
            // result is not valid JSON, skip
          }
        }
      }
    }
    return allVulns
  }, [])

  const filtered = (vulns || []).filter((v: any) => {
    if (severityFilter !== 'all' && v.severity !== severityFilter) return false
    if (search && !v.title?.toLowerCase().includes(search.toLowerCase()) && !v.target?.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
          <Hexagon className="w-6 h-6 text-honey-500" />
          {t('vulns.title')}
        </h1>
        <p className="text-hive-400 text-sm mt-1.5">{t('vulns.subtitle')}</p>
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
            placeholder={t('vulns.search')}
            className="input-field" style={{ paddingLeft: '2.5rem' }}
          />
        </div>
        <div className="flex items-center gap-1.5 bg-hive-800 rounded-lg border border-hive-700 p-1">
          {['all', 'critical', 'high', 'medium', 'low'].map(s => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                severityFilter === s
                  ? 'bg-honey-500/15 text-honey-400'
                  : 'text-hive-400 hover:text-hive-200'
              }`}
            >
              {s === 'all' ? t('vulns.all') : (sevLabelMap[s] || s)}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-3">
        {loading ? (
          <div className="flex items-center justify-center py-12 text-hive-400 text-sm gap-2">
            <Shield className="w-4 h-4 animate-spin" />
            {t('flows.loading')}
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-hive-500">
            <Bug className="w-12 h-12 mb-3 opacity-30" />
            <span className="text-sm">{t('flows.empty')}</span>
            <span className="text-xs mt-1 opacity-60">{t('flows.emptyHint')}</span>
          </div>
        ) : filtered.map((vuln: any) => {
          const sev = severityConfig[vuln.severity] || severityConfig.low
          return (
            <div
              key={vuln.id}
              onClick={() => navigate(`/vulns/${vuln.id}`)}
              className="card-hover p-5 cursor-pointer group"
            >
              <div className="flex items-start gap-4">
                <div className={`w-10 h-10 rounded-xl ${sev.bg} ${sev.border} border flex items-center justify-center flex-shrink-0`}>
                  <Bug className={`w-5 h-5 ${sev.text}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-semibold text-white">{vuln.title}</span>
                    <span className={`badge ${sev.className}`}>{sevLabelMap[vuln.severity] || sev.label}</span>
                  </div>
                  <p className="text-xs text-hive-400 mt-1.5 line-clamp-2">{vuln.description}</p>
                  <div className="flex items-center gap-3 mt-2">
                    <span className="text-xs text-hive-500 flex items-center gap-1">
                      <Info className="w-3 h-3" /> {vuln.target}
                    </span>
                    <span className="text-xs text-hive-500">{vuln.date}</span>
                    {vuln.cve && (
                      <span className="text-xs text-honey-500/70 font-mono">{vuln.cve}</span>
                    )}
                  </div>
                </div>
                <ChevronRight className="w-4 h-4 text-hive-600 group-hover:text-honey-400 flex-shrink-0 mt-1" />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
