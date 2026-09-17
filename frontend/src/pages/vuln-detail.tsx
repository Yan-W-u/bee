import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  Bug,
  Shield,
  AlertTriangle,
  Code,
  ExternalLink,
  Copy,
  Check,
  Wrench,
  FileText,
  Clock,
} from 'lucide-react'
import { toast } from 'sonner'
import { useT } from '@/lib/i18n'
import { useQuery } from '@/lib/hooks'
import { apiGet } from '@/lib/api'

const severityConfig: Record<string, { className: string; bg: string; border: string; text: string }> = {
  critical: { className: 'badge-danger', bg: 'bg-danger/10', border: 'border-danger/30', text: 'text-danger' },
  high: { className: 'badge-danger', bg: 'bg-danger/10', border: 'border-danger/30', text: 'text-danger' },
  medium: { className: 'badge-warning', bg: 'bg-warning/10', border: 'border-warning/30', text: 'text-warning' },
  low: { className: 'badge-info', bg: 'bg-honey-500/10', border: 'border-honey-500/30', text: 'text-honey-400' },
}

export default function VulnDetail() {
  const t = useT()
  const { id } = useParams()
  const navigate = useNavigate()
  const [copied, setCopied] = useState('')

  const { data: vulnData, loading, error } = useQuery(() => apiGet(`/v1/knowledge/${id}`), [id])

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center min-h-[400px]">
        <Bug className="w-8 h-8 text-honey-500 animate-spin" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6 flex flex-col items-center justify-center py-20 gap-3">
        <AlertTriangle className="w-12 h-12 text-danger" />
        <span className="text-hive-300 text-sm">{t('common.apiError') || 'Backend connection failed'}</span>
      </div>
    )
  }

  if (!vulnData) {
    return (
      <div className="p-6 flex items-center justify-center py-20">
        <span className="text-hive-500 text-sm">{t('vulns.notFound') || 'Vulnerability not found'}</span>
      </div>
    )
  }

  const sev = severityConfig[vulnData.severity] || severityConfig.low

  const sevLabelMap: Record<string, string> = {
    critical: t('vulns.critical'),
    high: t('vulns.high'),
    medium: t('vulns.medium'),
    low: t('vulns.low'),
  }

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopied(key)
    toast.success(t('common.copied'))
    setTimeout(() => setCopied(''), 2000)
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate('/vulns')}
          className="w-9 h-9 rounded-lg bg-hive-800 border border-hive-700 flex items-center justify-center hover:bg-hive-700 transition-colors"
        >
          <ArrowLeft className="w-4 h-4 text-hive-400" />
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-2.5">
            <div className={`w-9 h-9 rounded-xl ${sev.bg} ${sev.border} border flex items-center justify-center`}>
              <Bug className={`w-5 h-5 ${sev.text}`} />
            </div>
            <h1 className="text-xl font-bold text-white">{vulnData.title}</h1>
            <span className={`badge ${sev.className}`}>{sevLabelMap[vulnData.severity] || ''}</span>
          </div>
          <p className="text-hive-400 text-sm mt-1.5">
            {vulnData.target} · {vulnData.cve} · {vulnData.date}
          </p>
        </div>
      </div>

      {vulnData.description && (
        <div className="card p-5 space-y-3">
          <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide flex items-center gap-2">
            <FileText className="w-4 h-4 text-honey-400" />
            {t('vulnDetail.description')}
          </h3>
          <p className="text-sm text-hive-200 leading-relaxed">{vulnData.description}</p>
        </div>
      )}

      {vulnData.rootCause && (
        <div className="card p-5 space-y-3">
          <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide flex items-center gap-2">
            <Bug className="w-4 h-4 text-danger" />
            {t('vulnDetail.rootCause')}
          </h3>
          <div className="px-4 py-3 bg-danger/5 border border-danger/10 rounded-lg">
            <p className="text-sm text-hive-200 leading-relaxed">{vulnData.rootCause}</p>
          </div>
        </div>
      )}

      {vulnData.impact && (
        <div className="card p-5 space-y-3">
          <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-warning" />
            {t('vulnDetail.impact')}
          </h3>
          <div className="px-4 py-3 bg-warning/5 border border-warning/10 rounded-lg">
            <p className="text-sm text-hive-200 leading-relaxed">{vulnData.impact}</p>
          </div>
        </div>
      )}

      {vulnData.poc && (
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide flex items-center gap-2">
              <Code className="w-4 h-4 text-honey-400" />
              {t('vulnDetail.poc')}
            </h3>
            <button
              onClick={() => handleCopy(vulnData.poc, 'poc')}
              className="flex items-center gap-1 text-xs text-hive-500 hover:text-honey-400 transition-colors"
            >
              {copied === 'poc' ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
              {copied === 'poc' ? t('remediation.copied') : t('remediation.copy')}
            </button>
          </div>
          <pre className="bg-hive-950 border border-hive-700 rounded-lg p-4 text-xs text-hive-200 font-mono overflow-x-auto whitespace-pre-wrap">
            {vulnData.poc}
          </pre>
        </div>
      )}

      {vulnData.remediation && (
        <div className="card p-5 space-y-5">
          <div className="flex items-center gap-2">
            <Wrench className="w-5 h-5 text-success" />
            <h2 className="text-lg font-bold text-white">{t('vulnDetail.remediation')}</h2>
          </div>

          <div className="flex items-center gap-4 text-xs text-hive-400">
            {vulnData.remediation.estimatedTime && (
              <span className="flex items-center gap-1">
                <Clock className="w-3.5 h-3.5" /> {t('remediation.estTime')}: {vulnData.remediation.estimatedTime}
              </span>
            )}
            {vulnData.remediation.difficulty && (
              <span className="flex items-center gap-1">
                <Shield className="w-3.5 h-3.5" /> {t('remediation.difficulty')}: {vulnData.remediation.difficulty}
              </span>
            )}
          </div>

          {vulnData.remediation.steps && vulnData.remediation.steps.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide mb-3">{t('remediation.fixSteps')}</h3>
              <div className="space-y-2">
                {vulnData.remediation.steps.map((s: any) => (
                  <div key={s.step || s.title} className="flex items-start gap-3 px-4 py-3 rounded-lg bg-hive-950/50 border border-hive-700/20">
                    <span className="w-6 h-6 rounded-full bg-honey-500/10 text-honey-400 flex items-center justify-center text-xs flex-shrink-0 mt-0.5">
                      {s.step}
                    </span>
                    <div>
                      <p className="text-sm font-medium text-white">{s.title}</p>
                      {s.detail && <p className="text-xs text-hive-400 mt-0.5">{s.detail}</p>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {(vulnData.remediation.codeBefore || vulnData.remediation.codeAfter) && (
            <div>
              <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide mb-3">{t('vulnDetail.codeCompare')}</h3>
              <div className="grid grid-cols-1 gap-3">
                {vulnData.remediation.codeBefore && (
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs text-danger font-medium">{t('vulnDetail.before')}</span>
                      <button
                        onClick={() => handleCopy(vulnData.remediation.codeBefore, 'before')}
                        className="flex items-center gap-1 text-xs text-hive-500 hover:text-honey-400 transition-colors"
                      >
                        {copied === 'before' ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <pre className="bg-hive-950 border border-danger/20 rounded-lg p-4 text-xs text-hive-200 font-mono overflow-x-auto">
                      {vulnData.remediation.codeBefore}
                    </pre>
                  </div>
                )}
                {vulnData.remediation.codeAfter && (
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs text-success font-medium">{t('vulnDetail.after')}</span>
                      <button
                        onClick={() => handleCopy(vulnData.remediation.codeAfter, 'after')}
                        className="flex items-center gap-1 text-xs text-hive-500 hover:text-honey-400 transition-colors"
                      >
                        {copied === 'after' ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <pre className="bg-hive-950 border border-success/20 rounded-lg p-4 text-xs text-hive-200 font-mono overflow-x-auto">
                      {vulnData.remediation.codeAfter}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}

          {vulnData.remediation.verifySteps && vulnData.remediation.verifySteps.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4 text-success" />
                {t('vulnDetail.verifySteps')}
              </h3>
              <div className="space-y-1.5">
                {vulnData.remediation.verifySteps.map((step: string, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-sm text-hive-300">
                    <Check className="w-3.5 h-3.5 text-success flex-shrink-0" />
                    {step}
                  </div>
                ))}
              </div>
            </div>
          )}

          {vulnData.remediation.riskReassessment && (
            <div>
              <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide mb-2">{t('vulnDetail.riskReassess')}</h3>
              <div className="px-4 py-3 bg-success/5 border border-success/10 rounded-lg">
                <p className="text-sm text-hive-200">{vulnData.remediation.riskReassessment}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {vulnData.references && vulnData.references.length > 0 && (
        <div className="card p-5 space-y-3">
          <h3 className="text-sm font-semibold text-hive-300 uppercase tracking-wide">{t('vulnDetail.references')}</h3>
          <div className="space-y-1.5">
            {vulnData.references.map((ref: string, i: number) => (
              <a
                key={i}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-sm text-honey-400 hover:text-honey-300 transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                {ref}
              </a>
            ))}
          </div>
        </div>
      )}

      {vulnData.tags && vulnData.tags.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          {vulnData.tags.map((tag: string, i: number) => (
            <span key={i} className="px-2.5 py-1 rounded-md bg-hive-800 text-xs text-hive-400 border border-hive-700/50">
              {tag}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
