import { useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  Activity,
  Hexagon,
  CheckCircle,
  AlertTriangle,
  Clock,
  Bug,
  Loader2,
  Play,
} from 'lucide-react'
import { toast } from 'sonner'
import { useT } from '@/lib/i18n'
import { useQuery, useMutation } from '@/lib/hooks'
import { flowsService } from '@/services/flows'
import { extractApiError } from '@/lib/api'

const statusConfig: Record<string, { label: string; className: string; icon: typeof Activity }> = {
  running: { label: 'Running', className: 'badge-info', icon: Activity },
  completed: { label: 'Completed', className: 'badge-success', icon: CheckCircle },
  finished: { label: 'Completed', className: 'badge-success', icon: CheckCircle },
  failed: { label: 'Failed', className: 'badge-danger', icon: AlertTriangle },
  pending: { label: 'Pending', className: 'badge-warning', icon: Clock },
  created: { label: 'Created', className: 'badge-warning', icon: Clock },
}

export default function FlowDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const t = useT()
  const flowId = Number(id)
  const [runningFlow, setRunningFlow] = useState(false)

  const { data: flowData, loading, error, refresh: refreshFlow } = useQuery(() => flowsService.get(flowId), [flowId])
  const { data: tasksData, refresh: refreshTasks } = useQuery(() => flowsService.getTasks(flowId), [flowId])

  const logEntries = useMemo(() => {
    if (!tasksData?.tasks) return []
    return tasksData.tasks.map(task => {
      // Parse result field if it contains JSON
      let resultPreview = ''
      if (task.result) {
        try {
          const parsed = JSON.parse(task.result)
          // Extract key info from vulnerability results
          if (parsed.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
            resultPreview = `Found ${parsed.vulnerabilities.length} vulnerabilities`
          } else if (parsed.summary) {
            resultPreview = parsed.summary
          } else if (typeof parsed === 'string') {
            resultPreview = parsed
          } else {
            resultPreview = JSON.stringify(parsed).slice(0, 100)
          }
        } catch {
          resultPreview = task.result.slice(0, 100)
        }
      }

      return {
        time: task.created_at?.slice(11, 19) || '',
        agent: task.status || '',
        message: task.title || task.input || '',
        result: resultPreview,
      }
    })
  }, [tasksData])

  const handleRunFlow = async () => {
    if (!flowData || runningFlow) return
    setRunningFlow(true)
    try {
      // Send input action to trigger flow execution
      await flowsService.update(flowId, {
        action: 'input',
        input: flowData.title || 'Start flow execution',
      } as any)
      toast.success(t('flows.runStarted') || 'Flow execution started')
      refreshFlow()
      refreshTasks()
    } catch (err: unknown) {
      toast.error(extractApiError(err) || t('flows.runError') || 'Failed to start flow')
    } finally {
      setRunningFlow(false)
    }
  }

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-8 h-8 text-honey-500 animate-spin" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6 space-y-6">
        <button onClick={() => navigate('/flows')} className="w-9 h-9 rounded-lg bg-hive-800 border border-hive-700 flex items-center justify-center hover:bg-hive-700">
          <ArrowLeft className="w-4 h-4 text-hive-400" />
        </button>
        <div className="flex flex-col items-center justify-center py-20 gap-3">
          <AlertTriangle className="w-12 h-12 text-danger" />
          <span className="text-hive-300 text-sm">{t('common.apiError') || 'Backend connection failed'}</span>
        </div>
      </div>
    )
  }

  if (!flowData) {
    return (
      <div className="p-6 space-y-6">
        <button onClick={() => navigate('/flows')} className="w-9 h-9 rounded-lg bg-hive-800 border border-hive-700 flex items-center justify-center hover:bg-hive-700">
          <ArrowLeft className="w-4 h-4 text-hive-400" />
        </button>
        <div className="flex flex-col items-center justify-center py-20 text-hive-500">
          <Hexagon className="w-12 h-12 mb-3 opacity-30" />
          <span className="text-sm">{t('flows.notFound') || 'Flow not found'}</span>
        </div>
      </div>
    )
  }

  const status = statusConfig[flowData.status] || statusConfig.pending
  const StatusIcon = status.icon

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <div className="flex items-center gap-4">
        <button onClick={() => navigate('/flows')} className="w-9 h-9 rounded-lg bg-hive-800 border border-hive-700 flex items-center justify-center hover:bg-hive-700">
          <ArrowLeft className="w-4 h-4 text-hive-400" />
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-white">{flowData.title || `Flow #${flowData.id}`}</h1>
            <span className={`badge ${status.className}`}>
              <StatusIcon className="w-3 h-3" />
              {status.label}
            </span>
          </div>
          <div className="flex items-center gap-4 mt-1.5 text-xs text-hive-500">
            <span>{flowData.model_provider_name} / {flowData.model}</span>
            <span>{flowData.created_at ? new Date(flowData.created_at).toLocaleString() : ''}</span>
          </div>
        </div>
        {/* Run Flow button - only show for created or pending status */}
        {(flowData.status === 'created' || flowData.status === 'pending') && (
          <button
            onClick={handleRunFlow}
            disabled={runningFlow}
            className="btn-primary flex items-center gap-2"
          >
            {runningFlow ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            {runningFlow ? t('common.loading') : t('flows.runFlow') || 'Run Flow'}
          </button>
        )}
      </div>

      <div className="card p-5">
        <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-honey-400" />
          {t('flows.taskLog') || 'Task History'}
        </h3>
        {logEntries.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-hive-500">
            <Activity className="w-10 h-10 mb-3 opacity-30" />
            <span className="text-sm">{t('flows.noTasks') || 'No tasks yet'}</span>
          </div>
        ) : (
          <div className="space-y-3">
            {logEntries.map((log, i) => (
              <div key={i} className="flex items-start gap-3 px-3 py-2.5 rounded-lg bg-hive-950/50 border border-hive-700/20">
                <span className="text-xs font-mono text-hive-500 flex-shrink-0 w-16">{log.time}</span>
                <span className={`badge text-xs ${
                  log.agent === 'finished' ? 'badge-success' :
                  log.agent === 'failed' ? 'badge-danger' :
                  log.agent === 'running' ? 'badge-info' : 'badge-warning'
                } flex-shrink-0 w-20 justify-center`}>
                  {log.agent}
                </span>
                <div className="flex-1 min-w-0">
                  <span className="text-xs text-hive-300 leading-relaxed block">{log.message}</span>
                  {log.result && (
                    <span className="text-xs text-honey-400/70 mt-1 block truncate">{log.result}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
