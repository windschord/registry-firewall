import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  getDashboard,
  getBlockLogs,
  getSecuritySources,
  triggerSync,
  getCacheStats,
  clearCache,
  getRules,
  createRule,
  deleteRule,
  getTokens,
  createToken,
  revokeToken,
} from './client'

const mockFetch = vi.fn()
global.fetch = mockFetch

describe('API Client', () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('getDashboard', () => {
    it('fetches dashboard stats', async () => {
      const mockData = {
        total_requests: 1000,
        blocked_requests: 50,
        cache_hit_rate: 0.85,
        security_sources_count: 3,
        blocked_packages_count: 100,
        security_sources: [],
      }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await getDashboard()

      expect(mockFetch).toHaveBeenCalledWith('/api/dashboard', expect.any(Object))
      expect(result).toEqual(mockData)
    })

    it('throws error on API failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      })

      await expect(getDashboard()).rejects.toThrow('API error: 500 Internal Server Error')
    })
  })

  describe('getBlockLogs', () => {
    it('fetches block logs with default params', async () => {
      const mockData = { logs: [], total: 0 }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await getBlockLogs()

      expect(mockFetch).toHaveBeenCalledWith('/api/blocks?limit=50&offset=0', expect.any(Object))
      expect(result).toEqual(mockData)
    })

    it('fetches block logs with custom params', async () => {
      const mockData = { logs: [], total: 0 }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      await getBlockLogs(20, 40)

      expect(mockFetch).toHaveBeenCalledWith('/api/blocks?limit=20&offset=40', expect.any(Object))
    })
  })

  describe('getSecuritySources', () => {
    it('fetches security sources', async () => {
      const mockData = { sources: [] }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await getSecuritySources()

      expect(mockFetch).toHaveBeenCalledWith('/api/security-sources', expect.any(Object))
      expect(result).toEqual(mockData)
    })
  })

  describe('triggerSync', () => {
    it('triggers sync for a source', async () => {
      const mockData = { message: 'Sync triggered' }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await triggerSync('osv')

      expect(mockFetch).toHaveBeenCalledWith('/api/security-sources/osv/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      expect(result).toEqual(mockData)
    })
  })

  describe('getCacheStats', () => {
    it('fetches cache stats', async () => {
      const mockData = {
        plugin: 'filesystem',
        hits: 100,
        misses: 20,
        total_size_bytes: 1024,
        entries: 50,
      }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await getCacheStats()

      expect(mockFetch).toHaveBeenCalledWith('/api/cache/stats', expect.any(Object))
      expect(result).toEqual(mockData)
    })
  })

  describe('clearCache', () => {
    it('clears the cache', async () => {
      const mockData = { message: 'Cache cleared' }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await clearCache()

      expect(mockFetch).toHaveBeenCalledWith('/api/cache', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
      })
      expect(result).toEqual(mockData)
    })
  })

  describe('getRules', () => {
    it('fetches rules', async () => {
      const mockData = { rules: [] }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await getRules()

      expect(mockFetch).toHaveBeenCalledWith('/api/rules', expect.any(Object))
      expect(result).toEqual(mockData)
    })
  })

  describe('createRule', () => {
    it('creates a new rule', async () => {
      const mockData = { id: 1 }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const rule = {
        ecosystem: 'pypi',
        package_pattern: 'malicious-*',
        version_constraint: '*',
      }
      const result = await createRule(rule)

      expect(mockFetch).toHaveBeenCalledWith('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rule),
      })
      expect(result).toEqual(mockData)
    })
  })

  describe('deleteRule', () => {
    it('deletes a rule', async () => {
      const mockData = { message: 'Rule deleted' }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await deleteRule(1)

      expect(mockFetch).toHaveBeenCalledWith('/api/rules/1', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
      })
      expect(result).toEqual(mockData)
    })
  })

  describe('getTokens', () => {
    it('fetches tokens', async () => {
      const mockData = { tokens: [] }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await getTokens()

      expect(mockFetch).toHaveBeenCalledWith('/api/tokens', expect.any(Object))
      expect(result).toEqual(mockData)
    })
  })

  describe('createToken', () => {
    it('creates a token without ecosystems', async () => {
      const mockData = { id: 'token-id', token: 'rf_xxx' }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await createToken('CI Token')

      expect(mockFetch).toHaveBeenCalledWith('/api/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'CI Token', allowed_ecosystems: undefined }),
      })
      expect(result).toEqual(mockData)
    })

    it('creates a token with ecosystems', async () => {
      const mockData = { id: 'token-id', token: 'rf_xxx' }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await createToken('CI Token', ['pypi', 'cargo'])

      expect(mockFetch).toHaveBeenCalledWith('/api/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'CI Token', allowed_ecosystems: ['pypi', 'cargo'] }),
      })
      expect(result).toEqual(mockData)
    })
  })

  describe('revokeToken', () => {
    it('revokes a token', async () => {
      const mockData = { message: 'Token revoked' }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockData),
      })

      const result = await revokeToken('token-id')

      expect(mockFetch).toHaveBeenCalledWith('/api/tokens/token-id', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
      })
      expect(result).toEqual(mockData)
    })
  })
})
