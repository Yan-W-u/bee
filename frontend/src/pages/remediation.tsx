import { useState } from 'react'
import { Hexagon, Copy, Check, ChevronDown, ChevronUp, Clock, Shield, Wrench, Code, FileText, Search } from 'lucide-react'
import { toast } from 'sonner'
import { useT } from '@/lib/i18n'
import { useQuery } from '@/lib/hooks'
import { apiGet } from '@/lib/api'

export default function Remediation() {
  const t = useT()
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  const { data: apiFixes, loading, error } = useQuery(
    () => apiGet('/v1/knowledge', { page: 1, pageSize: 100, answer_type: 'vulnerability' }),
    [],
  )

  const fixes = (apiFixes?.items || apiFixes || [])

  const filtered = fixes.filter((f: any) => {
    if (!search) return true
    const s = search.toLowerCase()
    const q = (f.question || f.title || '').toLowerCase()
    const c = (f.content || f.description || '').toLowerCase()
    return q.includes(s) || c.includes(s)
  })

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id)
  }

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    toast.success(t('common.copied'))
    setTimeout(() => setCopiedId(null), 2000)
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
          <Hexagon className="w-6 h-6 text-honey-500" />
          {t('remediation.title')}
        </h1>
        <p className="text-hive-400 text-sm mt-1.5">{t('remediation.subtitle')}</p>
      </div>

      {error && (
        <div className="card p-4 border border-danger/30 bg-danger/5 text-sm text-danger flex items-center gap-2">
          <Shield className="w-4 h-4" />
          {t('common.apiError') || 'Backend connection failed'}
        </div>
      )}

      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-hive-500" />
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder={t('remediation.search')}
          className="input-field" style={{ paddingLeft: '2.5rem' }}
        />
      </div>

      <div className="space-y-3">
        {loading ? (
          <div className="flex items-center justify-center py-12 text-hive-400 text-sm gap-2">
            <Wrench className="w-4 h-4 animate-spin" />
            {t('flows.loading')}
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-hive-500">
            <Wrench className="w-12 h-12 mb-3 opacity-30" />
            <span className="text-sm">{t('remediation.empty')}</span>
          </div>
        ) : filtered.map((fix: any, idx: number) => {
          const id = fix.id || String(idx)
          const expanded = expandedId === id
          const isCopied = copiedId === id
          const question = fix.question || fix.title || t('remediation.untitled')
          const content = fix.content || fix.summary || ''
          const steps = fix.steps || []
          const code = fix.code || ''
          const language = fix.codeLang || fix.language || ''
          const difficulty = fix.difficulty || ''
          const estimatedTime = fix.estimatedTime || ''
          const explainWhy = fix.explainWhy || fix.principle || ''

          return (
            <div key={id} className="card overflow-hidden">
              <div
                onClick={() => toggleExpand(id)}
                className="p-5 flex items-start gap-4 cursor-pointer hover:bg-hive-900/20 transition-colors"
              >
                <div className="w-10 h-10 rounded-xl bg-success/10 border border-success/20 flex items-center justify-center flex-shrink-0">
                  <Wrench className="w-5 h-5 text-success" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-white">{question}</span>
                    {difficulty && <span className="badge badge-info text-xs">{difficulty}</span>}
                  </div>
                  <p className="text-xs text-hive-400 mt-1 line-clamp-2">{content}</p>
                  <div className="flex items-center gap-3 mt-2">
                    {estimatedTime && (
                      <span className="text-xs text-hive-500 flex items-center gap-1">
                        <Clock className="w-3 h-3" /> {estimatedTime}
                      </span>
                    )}
                    <span className="text-xs text-hive-600">{fix.question ? 'Knowledge' : 'Remediation'}</span>
                  </div>
                </div>
                <button className="flex-shrink-0 text-hive-500 hover:text-hive-300 mt-1">
                  {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>

              {expanded && (
                <div className="px-5 pb-5 space-y-4 border-t border-hive-700/30 pt-4">
                  {explainWhy && (
                    <div>
                      <h4 className="text-xs font-semibold text-hive-400 uppercase tracking-wide mb-2 flex items-center gap-1.5">
                        <FileText className="w-3.5 h-3.5" />
                        {t('remediation.principle')}
                      </h4>
                      <p className="text-sm text-hive-200 leading-relaxed">{explainWhy}</p>
                    </div>
                  )}

                  {steps.length > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold text-hive-400 uppercase tracking-wide mb-2">
                        {t('remediation.fixSteps')}
                      </h4>
                      <div className="space-y-2">
                        {steps.map((step: string, i: number) => (
                          <div key={i} className="flex items-start gap-2 text-sm text-hive-300">
                            <span className="w-5 h-5 rounded-full bg-honey-500/10 text-honey-400 flex items-center justify-center text-xs flex-shrink-0 mt-0.5">
                              {i + 1}
                            </span>
                            {step}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {code && (
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="text-xs font-semibold text-hive-400 uppercase tracking-wide flex items-center gap-1.5">
                          <Code className="w-3.5 h-3.5" />
                          {t('vulnDetail.code')} {language && `(${language})`}
                        </h4>
                        <button
                          onClick={(e) => { e.stopPropagation(); handleCopy(id, code) }}
                          className="flex items-center gap-1 text-xs text-hive-500 hover:text-honey-400 transition-colors"
                        >
                          {isCopied ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                          {isCopied ? t('remediation.copied') : t('remediation.copy')}
                        </button>
                      </div>
                      <pre className="bg-hive-950 border border-hive-700 rounded-lg p-4 text-xs text-hive-200 font-mono overflow-x-auto">
                        {code}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
