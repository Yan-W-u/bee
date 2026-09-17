$path = "d:\智盾\bee\frontend\src\pages\swarm.tsx"
$c1 = 'import { useState, useMemo } from ' + "'react'"
$c2 = 'import { Hexagon, Cpu, Key, Link, Save, TestTube, ChevronDown, ChevronUp, CheckCircle, XCircle, Activity, Zap, Shield, Search, Code, Lightbulb, Brain, Package, FileText, MessageSquare, RefreshCw, Layers, Eye, EyeOff } from ' + "'lucide-react'"
$c3 = 'import { useT } from ' + "'@/lib/i18n'"
$c4 = 'import { toast } from ' + "'sonner'"
$s = @"
interface Agent {
  id: string; name: string; role: string; desc: string
  icon: typeof Hexagon; iconColor: string
  apiProvider: string; apiKey: string; apiEndpoint: string; model: string
  status: 'configured' | 'unconfigured'; expanded: boolean
}
const providerLabels: Record<string, string> = { openai: 'OpenAI', deepseek: 'DeepSeek', anthropic: 'Anthropic', gemini: 'Google AI', ollama: 'Ollama', custom: 'custom' }
export default function Swarm() {
  const t = useT()
  const defaultAgents = useMemo<Agent[]>(() => [
    { id:'primary', name:t('swarm.primary.name'), role:t('swarm.primary.role'), desc:t('swarm.primary.desc'), icon:Cpu, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'sk-••••••••••••••••', apiEndpoint:'https://api.deepseek.com', model:'deepseek-chat', status:'configured', expanded:false },
    { id:'pentester', name:t('swarm.pentester.name'), role:t('swarm.pentester.role'), desc:t('swarm.pentester.desc'), icon:Zap, iconColor:'text-danger', apiProvider:'DeepSeek', apiKey:'sk-••••••••••••••••', apiEndpoint:'https://api.deepseek.com', model:'deepseek-chat', status:'configured', expanded:false },
    { id:'searcher', name:t('swarm.searcher.name'), role:t('swarm.searcher.role'), desc:t('swarm.searcher.desc'), icon:Search, iconColor:'text-honey-300', apiProvider:'OpenAI', apiKey:'', apiEndpoint:'', model:'gpt-4o', status:'unconfigured', expanded:false },
    { id:'remediator', name:t('swarm.remediator.name'), role:t('swarm.remediator.role'), desc:t('swarm.remediator.desc'), icon:Shield, iconColor:'text-success', apiProvider:'DeepSeek', apiKey:'sk-••••••••••••••••', apiEndpoint:'https://api.deepseek.com', model:'deepseek-chat', status:'configured', expanded:false },
    { id:'coder', name:t('swarm.coder.name'), role:t('swarm.coder.role'), desc:t('swarm.coder.desc'), icon:Code, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'sk-••••••••••••••••', apiEndpoint:'https://api.deepseek.com', model:'deepseek-chat', status:'configured', expanded:false },
    { id:'adviser', name:t('swarm.adviser.name'), role:t('swarm.adviser.role'), desc:t('swarm.adviser.desc'), icon:Lightbulb, iconColor:'text-warning', apiProvider:'Anthropic', apiKey:'', apiEndpoint:'', model:'claude-3-5-sonnet', status:'unconfigured', expanded:false },
    { id:'memorist', name:t('swarm.memorist.name'), role:t('swarm.memorist.role'), desc:t('swarm.memorist.desc'), icon:Brain, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'sk-••••••••••••••••', apiEndpoint:'https://api.deepseek.com', model:'deepseek-chat', status:'configured', expanded:false },
    { id:'explainer', name:t('swarm.explainer.name'), role:t('swarm.explainer.role'), desc:t('swarm.explainer.desc'), icon:MessageSquare, iconColor:'text-honey-300', apiProvider:'DeepSeek', apiKey:'sk-••••••••••••••••', apiEndpoint:'https://api.deepseek.com', model:'deepseek-chat', status:'configured', expanded:false },
    { id:'installer', name:t('swarm.installer.name'), role:t('swarm.installer.role'), desc:t('swarm.installer.desc'), icon:Package, iconColor:'text-hive-300', apiProvider:'Ollama', apiKey:'', apiEndpoint:'http://localhost:11434', model:'qwen3', status:'unconfigured', expanded:false },
    { id:'reporter', name:t('swarm.reporter.name'), role:t('swarm.reporter.role'), desc:t('swarm.reporter.desc'), icon:FileText, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'sk-••••••••••••••••', apiEndpoint:'https://api.deepseek.com', model:'deepseek-chat', status:'configured', expanded:false },
    { id:'reflector', name:t('swarm.reflector.name'), role:t('swarm.reflector.role'), desc:t('swarm.reflector.desc'), icon:RefreshCw, iconColor:'text-honey-300', apiProvider:'DeepSeek', apiKey:'sk-••••••••••••••••', apiEndpoint:'https://api.deepseek.com', model:'deepseek-chat', status:'configured', expanded:false },
    { id:'enricher', name:t('swarm.enricher.name'), role:t('swarm.enricher.role'), desc:t('swarm.enricher.desc'), icon:Layers, iconColor:'text-honey-400', apiProvider:'DeepSeek', apiKey:'sk-••••••••••••••••', apiEndpoint:'https://api.deepseek.com', model:'deepseek-chat', status:'configured', expanded:false },
  ], [t])
  const [agents, setAgents] = useState<Agent[]>(defaultAgents)
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({})
  const providerOptions = [
    { value:'openai', label:'OpenAI', models:['gpt-4o','gpt-4-turbo','gpt-3.5-turbo'] },
    { value:'deepseek', label:'DeepSeek', models:['deepseek-chat','deepseek-coder'] },
    { value:'anthropic', label:'Anthropic', models:['claude-3-5-sonnet','claude-3-opus'] },
    { value:'gemini', label:'Google AI', models:['gemini-2.0-flash','gemini-1.5-pro'] },
    { value:'ollama', label:'Ollama ('+t('swarm.local')+')', models:['qwen3','llama3','deepseek-r1'] },
    { value:'custom', label:t('swarm.custom'), models:['custom-model'] },
  ]
  const toggleExpand = (id) => setAgents(p=>p.map(a=>a.id===id?{...a,expanded:!a.expanded}:a))
  const toggleKey = (id) => setShowKeys(p=>({...p,[id]:!p[id]}))
  const updateAgent = (id,field,value) => setAgents(p=>p.map(a=>a.id===id?{...a,[field]:value}:a))
  const handleProviderChange = (id,pv) => {
    const pr=providerOptions.find(p=>p.value===pv); const m=pr?.models[0]||''
    setAgents(p=>p.map(a=>a.id!==id?a:{...a,apiProvider:pr?.label||pv,model:m,apiKey:'',apiEndpoint:pv==='ollama'?'http://localhost:11434':'',status:'unconfigured'}))
  }
  const handleTest = (a) => { if(!a.apiKey){toast.error(t('swarm.fillKey'));return} toast.success(a.name+' '+t('swarm.testSuccess')) }
  const handleSave = (a) => { if(!a.apiKey){toast.error(t('swarm.fillKey'));return} setAgents(p=>p.map(x=>x.id===a.id?{...x,expanded:false,status:'configured'}:x)); toast.success(a.name+' '+t('swarm.saved')) }
  const cc = agents.filter(a=>a.status==='configured').length
  return (<div className="p-6 space-y-6">
    <div><h1 className="text-2xl font-bold text-white flex items-center gap-2.5"><Hexagon className="w-6 h-6 text-honey-500" />{t('swarm.title')}</h1><p className="text-hive-400 text-sm mt-1.5">{t('swarm.subtitle')}</p></div>
    <div className="flex items-center gap-4">
      <div className="card px-4 py-3 flex items-center gap-3"><Activity className="w-4 h-4 text-honey-400" /><span className="text-sm text-hive-300">{t('swarm.configCount')} <span className="text-honey-400 font-semibold">{cc}</span> / {agents.length} {t('swarm.configStatus')}</span></div>
      <div className="card px-4 py-3 flex items-center gap-3"><Zap className="w-4 h-4 text-honey-400" /><span className="text-sm text-hive-300">{t('swarm.manageProviders')} <a href="/providers" className="text-honey-400 hover:underline">{t('nav.providers')}</a> {t('swarm.pageManage')}</span></div>
    </div>
    <div className="space-y-2">{agents.map(a=>{const I=a.icon;return(<div key={a.id} className="card overflow-hidden transition-all duration-200">
      <div onClick={()=>toggleExpand(a.id)} className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-hive-800/60 transition-colors">
        <div className="w-10 h-10 rounded-xl bg-hive-800 border border-hive-700/50 flex items-center justify-center flex-shrink-0"><I className={"w-5 h-5 "+a.iconColor} /></div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2"><span className="text-sm font-semibold text-white">{a.name}</span><span className="text-xs text-hive-500">{a.role}</span><span className={"badge "+(a.status==='configured'?'badge-success':'badge-neutral')}>{a.status==='configured'?<CheckCircle className="w-3 h-3"/>:<XCircle className="w-3 h-3"/>}{a.status==='configured'?t('swarm.configured'):t('swarm.unconfigured')}</span></div>
          <p className="text-xs text-hive-400 mt-0.5 line-clamp-1">{a.desc}</p>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0"><span className="text-xs text-hive-500">{a.model}</span>{a.expanded?<ChevronUp className="w-5 h-5 text-hive-500"/>:<ChevronDown className="w-5 h-5 text-hive-500"/>}</div>
      </div>
      {a.expanded&&(<div className="border-t border-hive-700/50 px-5 py-5 bg-hive-950/30 space-y-4">
        <p className="text-sm text-hive-300">{a.desc}</p>
        <div className="grid grid-cols-2 gap-4">
          <div><label className="text-xs text-hive-400 mb-1.5 block">{t('swarm.provider')}</label><select value={providerOptions.find(p=>p.label===a.apiProvider)?.value||'custom'} onChange={e=>handleProviderChange(a.id,e.target.value)} className="input-field text-sm" style={{paddingLeft:'0.75rem'}}>{providerOptions.map(p=><option key={p.value} value={p.value}>{p.label}</option>)}</select></div>
          <div><label className="text-xs text-hive-400 mb-1.5 block">{t('swarm.model')}</label><select value={a.model} onChange={e=>updateAgent(a.id,'model',e.target.value)} className="input-field text-sm" style={{paddingLeft:'0.75rem'}}>{(providerOptions.find(p=>p.label===a.apiProvider)?.models||[a.model]).map(m=><option key={m} value={m}>{m}</option>)}</select></div>
          <div><label className="text-xs text-hive-400 mb-1.5 block">{t('swarm.apiKey')}</label><div className="relative"><Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-hive-500"/><input type={showKeys[a.id]?'text':'password'} value={a.apiKey} onChange={e=>updateAgent(a.id,'apiKey',e.target.value)} placeholder="sk-..." className="input-field text-sm" style={{paddingLeft:'2.5rem',paddingRight:'2.5rem'}}/><button type="button" onClick={()=>toggleKey(a.id)} className="absolute right-3 top-1/2 -translate-y-1/2 text-hive-500 hover:text-hive-300 transition-colors">{showKeys[a.id]?<EyeOff className="w-4 h-4"/>:<Eye className="w-4 h-4"/>}</button></div></div>
          <div><label className="text-xs text-hive-400 mb-1.5 block">{t('swarm.endpoint')}</label><div className="relative"><Link className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-hive-500"/><input type="text" value={a.apiEndpoint} onChange={e=>updateAgent(a.id,'apiEndpoint',e.target.value)} placeholder="https://api.openai.com" className="input-field text-sm" style={{paddingLeft:'2.5rem'}}/></div></div>
        </div>
        <div className="flex items-center gap-3 pt-1"><button onClick={()=>handleTest(a)} className="btn-secondary flex items-center gap-2 text-sm"><TestTube className="w-4 h-4"/>{t('swarm.test')}</button><button onClick={()=>handleSave(a)} className="btn-primary flex items-center gap-2 text-sm"><Save className="w-4 h-4"/>{t('swarm.save')}</button></div>
      </div>)}
    </div>)})}</div>
  </div>)
}
"@
$c1 | Out-File -FilePath $path -Encoding UTF8
$c2 | Out-File -FilePath $path -Encoding UTF8 -Append
$c3 | Out-File -FilePath $path -Encoding UTF8 -Append
$c4 | Out-File -FilePath $path -Encoding UTF8 -Append
"" | Out-File -FilePath $path -Encoding UTF8 -Append
$s | Out-File -FilePath $path -Encoding UTF8 -Append
Write-Host "Done:" (Get-Item $path).Length "bytes"