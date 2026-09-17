import { Outlet } from 'react-router-dom'
import { Sidebar } from './sidebar'

export function AppLayout() {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto relative">
        {/* 蜂巢六边形背景装饰 */}
        <div className="hex-bg fixed inset-0 pointer-events-none" style={{ left: 230 }} />
        <div className="relative z-10">
          <Outlet />
        </div>
      </main>
    </div>
  )
}