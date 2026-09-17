import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Network,
  Target,
  Bug,
  Wrench,
  Cpu,
  Settings,
  Hexagon,
} from 'lucide-react'
import { BeeLogo } from '@/components/bee-logo'
import { useT } from '@/lib/i18n'

export function Sidebar() {
  const location = useLocation()
  const t = useT()

  const navItems = [
    { to: '/dashboard', icon: LayoutDashboard, label: t('nav.dashboard') },
    { to: '/swarm', icon: Network, label: t('nav.swarm') },
    { to: '/flows', icon: Target, label: t('nav.flows') },
    { to: '/vulns', icon: Bug, label: t('nav.vulns') },
    { to: '/remediation', icon: Wrench, label: t('nav.remediation') },
    { to: '/providers', icon: Cpu, label: t('nav.providers') },
    { to: '/settings', icon: Settings, label: t('nav.settings') },
  ]

  return (
    <aside className="w-[230px] min-w-[230px] h-screen flex flex-col bg-hive-950 border-r border-hive-700/30 select-none">
      <div className="px-5 py-5 border-b border-hive-700/20">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-honey-500/10 border border-honey-500/20 flex items-center justify-center relative overflow-hidden">
            <BeeLogo size={28} className="text-honey-400" />
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-lg font-bold text-white tracking-tight glow-honey">
              Bee
            </span>
            <span className="text-[10px] font-medium text-honey-500/60 tracking-[0.25em] uppercase">
              {t('nav.brand')}
            </span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
        {navItems.map(({ to, icon: Icon, label }) => {
          const isActive = location.pathname.startsWith(to)
          return (
            <NavLink
              key={to}
              to={to}
              className={`
                group relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
                transition-all duration-200
                ${isActive
                  ? 'text-honey-400 bg-honey-500/8'
                  : 'text-hive-400 hover:text-hive-200 hover:bg-hive-800/50'
                }
              `}
            >
              {isActive && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-6 bg-honey-500 rounded-full shadow-[0_0_8px_rgba(245,158,11,0.5)]" />
              )}
              <Icon
                className={`w-5 h-5 transition-colors duration-200 ${
                  isActive
                    ? 'text-honey-400 drop-shadow-[0_0_6px_rgba(245,158,11,0.4)]'
                    : 'text-hive-500 group-hover:text-hive-300'
                }`}
              />
              <span className={isActive ? 'glow-honey' : ''}>{label}</span>
            </NavLink>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-hive-700/20">
        <div className="flex items-center gap-2.5 text-xs text-hive-500">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-honey-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-honey-500" />
          </span>
          <span>Bee v0.1.0</span>
          <span className="ml-auto flex items-center gap-1">
            <Hexagon className="w-3 h-3" />
          </span>
        </div>
      </div>
    </aside>
  )
}