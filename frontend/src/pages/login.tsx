import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { BeeLogo } from '@/components/bee-logo'
import { Key, User, Eye, EyeOff, Hexagon } from 'lucide-react'
import { toast } from 'sonner'
import { useT } from '@/lib/i18n'
import { useAuth } from '@/lib/auth'
import { extractApiError } from '@/lib/api'

export default function Login() {
  const navigate = useNavigate()
  const t = useT()
  const { login } = useAuth()
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [form, setForm] = useState({ mail: '', password: '' })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.mail || !form.password) {
      toast.error(t('login.error'))
      return
    }
    setLoading(true)
    try {
      await login(form.mail, form.password)
      toast.success(t('login.welcome'))
      navigate('/dashboard')
    } catch (err) {
      toast.error(extractApiError(err) || t('login.invalid'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-hive-950 relative overflow-hidden">
      {/* 蜂巢六边形背景 */}
      <div className="hex-bg absolute inset-0" />

      {/* 装饰性发光蜂巢 */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] opacity-[0.03]">
        <svg viewBox="0 0 600 600" fill="none">
          {Array.from({ length: 7 }).map((_, row) =>
            Array.from({ length: 7 }).map((_, col) => (
              <path
                key={`${row}-${col}`}
                d={`M${150 + col * 50 + (row % 2) * 25} ${row * 43} l25 14.4 v28.8 l-25 14.4 l-25 -14.4 v-28.8 z`}
                fill="none"
                stroke="#f59e0b"
                strokeWidth="0.5"
              />
            ))
          )}
        </svg>
      </div>

      {/* 登录卡片 */}
      <div className="relative z-10 w-full max-w-md mx-4">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-20 h-20 rounded-2xl bg-honey-500/10 border border-honey-500/20 flex items-center justify-center mb-4 shadow-[0_0_40px_rgba(245,158,11,0.15)]">
            <BeeLogo size={48} className="text-honey-400" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight glow-honey">Bee</h1>
          <p className="text-sm text-hive-400 mt-1.5">{t('login.subtitle')}</p>
        </div>

        {/* 表单卡片 */}
        <div className="card p-8 space-y-5">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-sm text-hive-400 mb-1.5 block">{t('login.username')}</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-hive-500" />
                <input
                  type="text"
                  value={form.mail}
                  onChange={e => setForm({ ...form, mail: e.target.value })}
                  placeholder="admin@bee.com"
                  className="input-field"
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>
            </div>

            <div>
              <label className="text-sm text-hive-400 mb-1.5 block">{t('login.password')}</label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-hive-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={form.password}
                  onChange={e => setForm({ ...form, password: e.target.value })}
                  placeholder="••••••••"
                  className="input-field"
                  style={{ paddingLeft: '2.5rem', paddingRight: '2.5rem' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-hive-500 hover:text-hive-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full flex items-center justify-center gap-2 h-11"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  {t('login.loading')}
                </>
              ) : (
                <>
                  <Hexagon className="w-4 h-4" />
                  {t('login.enter')}
                </>
              )}
            </button>
          </form>
        </div>

        {/* 底部 */}
        <p className="text-center text-xs text-hive-600 mt-6">
          {t('login.footer')}
        </p>
      </div>
    </div>
  )
}