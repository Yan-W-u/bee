import { apiGet, apiPost } from '@/lib/api'

export interface ModelInfo {
  name: string
  agent_types: string[]
  price_info?: { input: number; output: number; cache_read: number; cache_write: number }
}

export interface ProviderInfo {
  name: string
  type: string
  default_model: string
  models: ModelInfo[]
}

export interface SettingsInfo {
  debug: boolean
  ask_user: boolean
  version: string
  docker_inside: boolean
  is_develop_mode: boolean
  assistant_use_agents: boolean
}

export interface InfoResponse {
  type: string
  develop: boolean
  user?: { id: number; name: string; mail: string }
  role?: { id: number; name: string }
  providers: string[]
  privileges: string[]
  oauth: boolean
}

export const providersService = {
  list: () => apiGet<ProviderInfo[]>('/v1/providers'),
  settings: () => apiGet<SettingsInfo>('/v1/settings'),
  info: () => apiGet<InfoResponse>('/v1/info'),
}
