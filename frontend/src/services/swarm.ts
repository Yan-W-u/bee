import { apiGet, apiPost } from '@/lib/api'

export interface SwarmAgentConfig {
  id?: number
  user_id?: number
  agent_id: string
  api_provider: string
  api_key: string
  api_endpoint: string
  model: string
  status: string
  created_at?: string
  updated_at?: string
}

export const swarmService = {
  list: () => apiGet<SwarmAgentConfig[]>('/v1/swarm'),
  save: (agents: SwarmAgentConfig[]) => apiPost<SwarmAgentConfig[]>('/v1/swarm', { agents }),
}
