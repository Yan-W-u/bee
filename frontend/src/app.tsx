import { lazy, Suspense } from 'react'
import {
  createBrowserRouter,
  createRoutesFromElements,
  Navigate,
  Route,
  RouterProvider,
} from 'react-router-dom'
import { AppLayout } from '@/components/layouts/app-layout'
import { SettingsProvider } from '@/lib/settings'
import { I18nProvider } from '@/lib/i18n'
import { AuthProvider } from '@/lib/auth'
import { Toaster } from 'sonner'

// 懒加载页面
const Login = lazy(() => import('@/pages/login'))
const Dashboard = lazy(() => import('@/pages/dashboard'))
const Swarm = lazy(() => import('@/pages/swarm'))
const Flows = lazy(() => import('@/pages/flows'))
const FlowDetail = lazy(() => import('@/pages/flow-detail'))
const NewFlow = lazy(() => import('@/pages/new-flow'))
const Vulns = lazy(() => import('@/pages/vulns'))
const VulnDetail = lazy(() => import('@/pages/vuln-detail'))
const Remediation = lazy(() => import('@/pages/remediation'))
const Providers = lazy(() => import('@/pages/providers'))
const Settings = lazy(() => import('@/pages/settings'))

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-full min-h-[400px]">
      <div className="flex flex-col items-center gap-3">
        {/* 蜂巢加载动画 */}
        <svg className="animate-spin h-10 w-10 text-honey-500" viewBox="0 0 64 64" fill="none">
          <path
            d="M32 4L56 18V46L32 60L8 46V18L32 4Z"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            opacity="0.3"
          />
          <path
            d="M32 10L50 20.5V41.5L32 52L14 41.5V20.5L32 10Z"
            fill="none"
            stroke="currentColor"
            strokeWidth="1"
            opacity="0.6"
          />
        </svg>
        <span className="text-sm text-hive-500">蜂群集结中...</span>
      </div>
    </div>
  )
}

const router = createBrowserRouter(
  createRoutesFromElements(
    <Route>
      {/* 登录页 — 无侧边栏 */}
      <Route
        path="login"
        element={
          <Suspense fallback={<PageLoader />}>
            <Login />
          </Suspense>
        }
      />

      {/* 认证后的页面 — 带侧边栏 */}
      <Route element={<AppLayout />}>
        <Route
          path="dashboard"
          element={
            <Suspense fallback={<PageLoader />}>
              <Dashboard />
            </Suspense>
          }
        />
        <Route
          path="swarm"
          element={
            <Suspense fallback={<PageLoader />}>
              <Swarm />
            </Suspense>
          }
        />
        <Route
          path="flows"
          element={
            <Suspense fallback={<PageLoader />}>
              <Flows />
            </Suspense>
          }
        />
        <Route
          path="flows/new"
          element={
            <Suspense fallback={<PageLoader />}>
              <NewFlow />
            </Suspense>
          }
        />
        <Route
          path="flows/:id"
          element={
            <Suspense fallback={<PageLoader />}>
              <FlowDetail />
            </Suspense>
          }
        />
        <Route
          path="vulns"
          element={
            <Suspense fallback={<PageLoader />}>
              <Vulns />
            </Suspense>
          }
        />
        <Route
          path="vulns/:id"
          element={
            <Suspense fallback={<PageLoader />}>
              <VulnDetail />
            </Suspense>
          }
        />
        <Route
          path="remediation"
          element={
            <Suspense fallback={<PageLoader />}>
              <Remediation />
            </Suspense>
          }
        />
        <Route
          path="providers"
          element={
            <Suspense fallback={<PageLoader />}>
              <Providers />
            </Suspense>
          }
        />
        <Route
          path="settings"
          element={
            <Suspense fallback={<PageLoader />}>
              <Settings />
            </Suspense>
          }
        />
      </Route>

      {/* 默认重定向到登录页 */}
      <Route path="/" element={<Navigate to="/login" replace />} />
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Route>,
  ),
)

export function App() {
  return (
    <SettingsProvider>
      <AuthProvider>
        <I18nProvider>
          <Toaster
            position="top-right"
            toastOptions={{
              style: {
                background: '#1e293b',
                border: '1px solid #334155',
                color: '#e2e8f0',
              },
            }}
          />
          <RouterProvider router={router} />
        </I18nProvider>
      </AuthProvider>
    </SettingsProvider>
  )
}