import { apiGet, apiPost, apiPut, apiDel } from '@/lib/api'

export interface ProviderPreset {
  id?: number
  user_id?: number
  name: string
  api_provider: string
  api_key: string
  api_endpoint: string
  model: string
  created_at?: string
  updated_at?: string
}

export interface ProviderPresetPayload {
  name: string
  api_provider: string
  api_key: string
  api_endpoint: string
  model: string
}

export const providerPresetService = {
  list: () => apiGet<ProviderPreset[]>('/v1/provider-presets'),
  create: (payload: ProviderPresetPayload) =>
    apiPost<ProviderPreset>('/v1/provider-presets', payload),
  update: (id: number, payload: ProviderPresetPayload) =>
    apiPut<ProviderPreset>(`/v1/provider-presets/${id}`, payload),
  delete: (id: number) => apiDel<{ id: number }>(`/v1/provider-presets/${id}`),
}
