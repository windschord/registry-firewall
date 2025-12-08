// API client for registry-firewall backend

const API_BASE = '/api'

async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  })

  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`)
  }

  // Handle 204 No Content responses
  if (response.status === 204) {
    return undefined as T
  }

  return response.json()
}

// Types
export interface DashboardStats {
  total_requests: number
  blocked_requests: number
  cache_hit_rate: number
  security_sources_count: number
  blocked_packages_count: number
  security_sources: SecuritySourceSummary[]
}

export interface SecuritySourceSummary {
  name: string
  ecosystems: string[]
  last_sync: string | null
  status: string
  records_count: number
}

export interface BlockLogEntry {
  id: number | null
  ecosystem: string
  package: string
  version: string
  source: string
  reason: string | null
  client_ip: string | null
  timestamp: string
}

export interface BlockLogsResponse {
  logs: BlockLogEntry[]
  total: number
}

export interface SecuritySourceInfo {
  name: string
  ecosystems: string[]
  last_sync: string | null
  status: string
  records_count: number
}

export interface SecuritySourcesResponse {
  sources: SecuritySourceInfo[]
}

export interface CacheStats {
  plugin: string
  hits: number
  misses: number
  total_size_bytes: number
  entries: number
}

export interface CustomRule {
  id?: number
  ecosystem: string
  package_pattern: string
  version_constraint: string
  reason?: string
}

export interface RulesResponse {
  rules: CustomRule[]
}

export interface TokenInfo {
  id: string
  name: string
  token_prefix: string
  created_at: string
  expires_at: string | null
  last_used_at: string | null
  allowed_ecosystems: string[]
}

export interface TokensResponse {
  tokens: TokenInfo[]
}

// API functions
export async function getDashboard(): Promise<DashboardStats> {
  return fetchApi<DashboardStats>('/dashboard')
}

export async function getBlockLogs(limit = 50, offset = 0): Promise<BlockLogsResponse> {
  return fetchApi<BlockLogsResponse>(`/blocks?limit=${limit}&offset=${offset}`)
}

export async function getSecuritySources(): Promise<SecuritySourcesResponse> {
  return fetchApi<SecuritySourcesResponse>('/security-sources')
}

export async function triggerSync(sourceName: string): Promise<{ message: string }> {
  return fetchApi<{ message: string }>(`/security-sources/${sourceName}/sync`, {
    method: 'POST',
  })
}

export async function getCacheStats(): Promise<CacheStats> {
  return fetchApi<CacheStats>('/cache/stats')
}

export async function clearCache(): Promise<{ message: string }> {
  return fetchApi<{ message: string }>('/cache', {
    method: 'DELETE',
  })
}

export async function getRules(): Promise<RulesResponse> {
  return fetchApi<RulesResponse>('/rules')
}

export async function createRule(rule: Omit<CustomRule, 'id'>): Promise<{ id: number }> {
  return fetchApi<{ id: number }>('/rules', {
    method: 'POST',
    body: JSON.stringify(rule),
  })
}

export async function deleteRule(id: number): Promise<void> {
  await fetchApi<void>(`/rules/${id}`, {
    method: 'DELETE',
  })
}

export async function getTokens(): Promise<TokensResponse> {
  return fetchApi<TokensResponse>('/tokens')
}

export async function createToken(name: string, ecosystems?: string[]): Promise<{ id: string; token: string }> {
  return fetchApi<{ id: string; token: string }>('/tokens', {
    method: 'POST',
    body: JSON.stringify({ name, allowed_ecosystems: ecosystems }),
  })
}

export async function revokeToken(id: string): Promise<void> {
  await fetchApi<void>(`/tokens/${id}`, {
    method: 'DELETE',
  })
}
