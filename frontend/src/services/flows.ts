import { apiGet, apiPost, apiPut, apiDel } from '@/lib/api'

export interface FlowItem {
  id: number
  status: string
  title: string
  model: string
  model_provider_name: string
  model_provider_type: string
  language: string
  user_id: number
  created_at: string
  updated_at: string
}

export interface TaskItem {
  id: number
  status: string
  title: string
  input: string
  result: string
  flow_id: number
  created_at: string
  updated_at: string
}

export interface FlowsResponse {
  flows: FlowItem[]
  total: number
}

export interface TasksResponse {
  tasks: TaskItem[]
  total: number
}

export interface CreateFlowInput {
  input: string
  provider: string
  functions?: { disabled: string[]; functions: string[] }
}

export const flowsService = {
  list: (params?: Record<string, any>) => apiGet<FlowsResponse>('/v1/flows', { page: 1, pageSize: 100, type: 'init', ...params }),
  get: (id: number) => apiGet<FlowItem>(`/v1/flows/${id}`),
  create: (data: CreateFlowInput) => apiPost<FlowItem>('/v1/flows', data),
  update: (id: number, data: Partial<FlowItem>) => apiPut<FlowItem>(`/v1/flows/${id}`, data),
  delete: (id: number) => apiDel<void>(`/v1/flows/${id}`),
  getTasks: (flowId: number, params?: Record<string, any>) => apiGet<TasksResponse>(`/v1/flows/${flowId}/tasks`, { page: 1, pageSize: 100, type: 'init', ...params }),
  getTask: (flowId: number, taskId: number) => apiGet<TaskItem>(`/v1/flows/${flowId}/tasks/${taskId}`),
}
