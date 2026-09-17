import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Target,
  Bug,
  Wrench,
  TrendingUp,
  Plus,
  ArrowRight,
  Activity,
  Hexagon,
  ShieldCheck,
  Clock,
  CheckCircle,
  AlertTriangle,
  Zap,
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { useT } from '@/lib/i18n'
import { useQuery } from '@/lib/hooks'
import { flowsService } from '@/services'
import type { FlowItem } from '@/services/flows'

const COLORS = ['#22c55e', '#eab308', '#6b7280', '#ef4444', '#8b5cf6']

export default function Dashboard() {
  const navigate = useNavigate()
  const t = useT()

  const { data: flowsData, loading: flowsLoading, error } = useQuery(
    () => flowsService.list(),
    [],
  )

  const flows = (flowsData?.flows || []) as FlowItem[]

  const stats = useMemo(() => {
    const total = flows.length
    const active = flows.filter(f => f.status === 'running').length
    const completed = flows.filter(f => f.status === 'completed' || f.status === 'finished').length
    const failed = flows.filter(f => f.status === 'failed').length
    return {
      totalTasks: total,
      activeTasks: active,
      completedTasks: completed,
      failedTasks: failed,
      successRate: total > 0 ? Math.round((completed / total) * 100) : 0,
    }
  }, [flows])

  const recentTasks = useMemo(() => {
    return flows.slice(0, 10).map(flow => ({
      id: `T-${flow.id}`,
      target: flow.title || `Flow #${flow.id}`,
      type: flow.model_provider_name || flow.model || '',
      status: flow.status || 'pending',
      vulns: 0,
      date: flow.created_at
        ? new Date(flow.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : '',
    }))
  }, [flows])

  const pieData = useMemo(() => {
    const completed = flows.filter(f => f.status === 'completed' || f.status === 'finished').length
    const running = flows.filter(f => f.status === 'running').length
    const pending = flows.filter(f => !f.status || f.status === 'created' || f.status === 'pending').length
    const failed = flows.filter(f => f.status === 'failed').length
    const all = [
      { name: t('dashboard.completed'), value: completed, color: '#22c55e' },
      { name: t('dashboard.running'), value: running, color: '#eab308' },
      { name: t('dashboard.pending'), value: pending, color: '#6b7280' },
      { name: t('dashboard.failed'), value: failed, color: '#ef4444' },
    ]
    return all.filter(d => d.value > 0).length > 0 ? all : [{ name: t('dashboard.none'), value: 1, color: '#334155' }]
  }, [flows, t])

  const severityData = useMemo(() => [
    { name: t('dashboard.totalTasks'), value: flows.length || 0, color: '#f59e0b' },
    { name: t('dashboard.running'), value: stats.activeTasks, color: '#3b82f6' },
    { name: t('dashboard.completed'), value: stats.completedTasks, color: '#22c55e' },
    { name: t('dashboard.failed'), value: stats.failedTasks, color: '#ef4444' },
  ], [flows.length, stats, t])

  const statusConfig: Record<string, { label: string; className: string; icon: typeof Activity }> = {
    running: { label: t('dashboard.running'), className: 'badge-info', icon: Activity },
    completed: { label: t('dashboard.completed'), className: 'badge-success', icon: CheckCircle },
    finished: { label: t('dashboard.completed'), className: 'badge-success', icon: CheckCircle },
    failed: { label: t('dashboard.failed'), className: 'badge-danger', icon: AlertTriangle },
    pending: { label: t('dashboard.pending'), className: 'badge-warning', icon: Clock },
    created: { label: t('dashboard.pending'), className: 'badge-warning', icon: Clock },
  }

  return (
    <div className="p-6 space-y-6">
      {flowsLoading && (
        <div className="flex items-center justify-center py-12">
          <div className="flex items-center gap-2 text-hive-400 text-sm">
            <Activity className="w-4 h-4 animate-spin" />
            Loading...
          </div>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Hexagon className="w-6 h-6 text-honey-500" />
            {t('dashboard.title')}
          </h1>
          <p className="text-hive-400 text-sm mt-1.5">{t('dashboard.subtitle')}</p>
        </div>
        <button onClick={() => navigate('/flows/new')} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          {t('dashboard.newFlow')}
        </button>
      </div>

      {error && (
        <div className="card p-4 border border-danger/30 bg-danger/5 text-sm text-danger flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          {t('common.apiError') || 'Backend connection failed'}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { icon: Target, label: t('dashboard.totalTasks'), value: stats.totalTasks, colorClass: 'text-hive-300' },
          { icon: Activity, label: t('dashboard.running'), value: stats.activeTasks, colorClass: 'text-blue-400' },
          { icon: CheckCircle, label: t('dashboard.completed'), value: stats.completedTasks, colorClass: 'text-success' },
          { icon: TrendingUp, label: t('dashboard.successRate'), value: `${stats.successRate}%`, colorClass: 'text-warning' },
        ].map(({ icon: Icon, label, value, colorClass }, i) => (
          <div key={i} className="card-hover p-5 group">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-sm text-hive-400 mb-1">{label}</p>
                <p className={`text-2xl font-bold ${colorClass}`}>{value}</p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-honey-500/5 border border-honey-500/10 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Icon className={`w-5 h-5 ${colorClass}`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card p-5 lg:col-span-1">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-honey-400" />
            {t('dashboard.taskDist')}
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={3}
                dataKey="value"
              >
                {pieData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} stroke="transparent" />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '12px',
                  color: '#e2e8f0',
                  fontSize: '13px',
                }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap gap-3 justify-center mt-2">
            {pieData.map((d, i) => (
              <div key={i} className="flex items-center gap-1.5 text-xs text-hive-400">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                {d.name} ({d.value})
              </div>
            ))}
          </div>
        </div>

        <div className="card p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-honey-400" />
              {t('dashboard.recentTasks')}
            </h3>
            <button
              onClick={() => navigate('/flows')}
              className="text-xs text-honey-400 hover:text-honey-300 flex items-center gap-1 transition-colors"
            >
              {t('dashboard.viewAll')} <ArrowRight className="w-3 h-3" />
            </button>
          </div>
          {recentTasks.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-hive-500">
              <Hexagon className="w-10 h-10 mb-3 opacity-30" />
              <span className="text-sm">{t('flows.empty')}</span>
            </div>
          ) : (
            <div className="space-y-2">
              {recentTasks.map(task => {
                const status = statusConfig[task.status] || statusConfig.pending
                const StatusIcon = status.icon
                return (
                  <div
                    key={task.id}
                    onClick={() => navigate(`/flows/${task.id}`)}
                    className="flex items-center gap-4 px-4 py-3 rounded-lg bg-hive-950/50 border border-hive-700/20 hover:border-honey-600/20 cursor-pointer transition-all duration-200"
                  >
                    <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-hive-800 border border-hive-700/50 flex items-center justify-center text-xs font-mono text-hive-400">
                      {task.id.slice(-3)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-white font-medium truncate">{task.target}</p>
                      <p className="text-xs text-hive-500">{task.type} / {task.date}</p>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <span className={`badge ${status.className}`}>
                        <StatusIcon className="w-3 h-3" />
                        {status.label}
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      <div className="card p-5">
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Zap className="w-4 h-4 text-honey-400" />
          {t('dashboard.severity')}
        </h3>
        <div className="grid grid-cols-4 gap-4">
          {severityData.map((item, i) => (
            <div key={i} className="text-center">
              <div className="relative h-2 bg-hive-700 rounded-full overflow-hidden mb-2">
                <div
                  className="absolute inset-y-0 left-0 rounded-full transition-all duration-500"
                  style={{
                    width: `${flows.length > 0 ? (item.value / flows.length) * 100 : 0}%`,
                    backgroundColor: ['#f59e0b', '#3b82f6', '#22c55e', '#ef4444'][i],
                  }}
                />
              </div>
              <p className="text-lg font-bold text-white">{item.value}</p>
              <p className="text-xs text-hive-400">{item.name}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
