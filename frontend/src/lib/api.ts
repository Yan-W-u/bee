import axios from 'axios'
import { useSettings } from './settings'

const getBaseURL = (): string => {
  const raw = localStorage.getItem('bee-settings')
  if (raw) {
    try {
      const s = JSON.parse(raw)
      if (s.backendUrl) return s.backendUrl.replace(/\/+$/, '') + '/api'
    } catch { /* ignore */ }
  }
  return '/api'
}

export const apiClient = axios.create({
  baseURL: getBaseURL(),
  withCredentials: true,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

apiClient.interceptors.request.use(config => {
  config.baseURL = getBaseURL()
  return config
})

apiClient.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      const raw = localStorage.getItem('bee-settings')
      if (raw) {
        try {
          const s = JSON.parse(raw)
          s.auth = undefined
          localStorage.setItem('bee-settings', JSON.stringify(s))
        } catch { /* ignore */ }
      }
    }
    return Promise.reject(err)
  },
)

export async function apiGet<T = any>(url: string, params?: Record<string, any>): Promise<T> {
  const res = await apiClient.get(url, { params })
  const d = res.data
  if (d && d.status === 'success') return d.data as T
  return d as T
}

export async function apiPost<T = any>(url: string, body?: any): Promise<T> {
  const res = await apiClient.post(url, body)
  const d = res.data
  if (d && d.status === 'success') return d.data as T
  return d as T
}

export async function apiPut<T = any>(url: string, body?: any): Promise<T> {
  const res = await apiClient.put(url, body)
  const d = res.data
  if (d && d.status === 'success') return d.data as T
  return d as T
}

export async function apiDel<T = any>(url: string): Promise<T> {
  const res = await apiClient.delete(url)
  const d = res.data
  if (d && d.status === 'success') return d.data as T
  return d as T
}

export interface ApiError {
  status: string
  code: string
  msg: string
  error?: string
}

export function extractApiError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const d = err.response?.data as ApiError | undefined
    return d?.msg || d?.error || err.message
  }
  if (err instanceof Error) return err.message
  return String(err)
}
