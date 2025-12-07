import { useState, useEffect } from 'react'
import {
  getCacheStats,
  clearCache,
  getRules,
  createRule,
  deleteRule,
  getTokens,
  createToken,
  revokeToken,
  CacheStats,
  CustomRule,
  TokenInfo,
} from '../api/client'

function CacheSection() {
  const [stats, setStats] = useState<CacheStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [clearing, setClearing] = useState(false)

  const fetchStats = async () => {
    try {
      const data = await getCacheStats()
      setStats(data)
    } catch (err) {
      console.error('Failed to load cache stats:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStats()
  }, [])

  const handleClear = async () => {
    if (!confirm('Are you sure you want to clear the cache?')) return
    setClearing(true)
    try {
      await clearCache()
      fetchStats()
    } catch (err) {
      alert(`Failed to clear cache: ${err instanceof Error ? err.message : 'Unknown error'}`)
    } finally {
      setClearing(false)
    }
  }

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-medium text-gray-900 mb-4">Cache</h3>
      {loading ? (
        <div className="animate-pulse h-20 bg-gray-200 rounded"></div>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Plugin:</span>
              <p className="font-medium">{stats?.plugin || 'none'}</p>
            </div>
            <div>
              <span className="text-gray-500">Entries:</span>
              <p className="font-medium">{stats?.entries.toLocaleString() || 0}</p>
            </div>
            <div>
              <span className="text-gray-500">Size:</span>
              <p className="font-medium">{formatBytes(stats?.total_size_bytes || 0)}</p>
            </div>
            <div>
              <span className="text-gray-500">Hit Rate:</span>
              <p className="font-medium">
                {stats && (stats.hits + stats.misses) > 0
                  ? `${((stats.hits / (stats.hits + stats.misses)) * 100).toFixed(1)}%`
                  : '0%'}
              </p>
            </div>
          </div>
          <button
            onClick={handleClear}
            disabled={clearing}
            className="px-4 py-2 text-sm bg-red-50 text-red-600 rounded hover:bg-red-100 disabled:opacity-50"
          >
            {clearing ? 'Clearing...' : 'Clear Cache'}
          </button>
        </div>
      )}
    </div>
  )
}

function RulesSection() {
  const [rules, setRules] = useState<CustomRule[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [newRule, setNewRule] = useState({
    ecosystem: 'pypi',
    package_pattern: '',
    version_pattern: '*',
    reason: '',
  })

  const fetchRules = async () => {
    try {
      const data = await getRules()
      setRules(data.rules)
    } catch (err) {
      console.error('Failed to load rules:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRules()
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await createRule({
        ecosystem: newRule.ecosystem,
        package_pattern: newRule.package_pattern,
        version_pattern: newRule.version_pattern,
        reason: newRule.reason || undefined,
        enabled: true,
      })
      setShowForm(false)
      setNewRule({ ecosystem: 'pypi', package_pattern: '', version_pattern: '*', reason: '' })
      fetchRules()
    } catch (err) {
      alert(`Failed to create rule: ${err instanceof Error ? err.message : 'Unknown error'}`)
    }
  }

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this rule?')) return
    try {
      await deleteRule(id)
      fetchRules()
    } catch (err) {
      alert(`Failed to delete rule: ${err instanceof Error ? err.message : 'Unknown error'}`)
    }
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-medium text-gray-900">Custom Block Rules</h3>
        <button
          onClick={() => setShowForm(!showForm)}
          className="px-4 py-2 text-sm bg-blue-50 text-blue-600 rounded hover:bg-blue-100"
        >
          {showForm ? 'Cancel' : 'Add Rule'}
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="mb-6 p-4 bg-gray-50 rounded space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-600 mb-1">Ecosystem</label>
              <select
                value={newRule.ecosystem}
                onChange={e => setNewRule({ ...newRule, ecosystem: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded"
              >
                <option value="pypi">PyPI</option>
                <option value="cargo">Cargo</option>
                <option value="go">Go</option>
                <option value="docker">Docker</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-gray-600 mb-1">Package Pattern</label>
              <input
                type="text"
                value={newRule.package_pattern}
                onChange={e => setNewRule({ ...newRule, package_pattern: e.target.value })}
                placeholder="e.g., malicious-*"
                required
                className="w-full px-3 py-2 border border-gray-300 rounded"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-600 mb-1">Version Pattern</label>
              <input
                type="text"
                value={newRule.version_pattern}
                onChange={e => setNewRule({ ...newRule, version_pattern: e.target.value })}
                placeholder="e.g., * or >=1.0.0"
                className="w-full px-3 py-2 border border-gray-300 rounded"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-600 mb-1">Reason</label>
              <input
                type="text"
                value={newRule.reason}
                onChange={e => setNewRule({ ...newRule, reason: e.target.value })}
                placeholder="Optional reason"
                className="w-full px-3 py-2 border border-gray-300 rounded"
              />
            </div>
          </div>
          <button
            type="submit"
            className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Create Rule
          </button>
        </form>
      )}

      {loading ? (
        <div className="animate-pulse h-20 bg-gray-200 rounded"></div>
      ) : rules.length === 0 ? (
        <p className="text-gray-500 text-center py-8">No custom rules defined</p>
      ) : (
        <table className="min-w-full divide-y divide-gray-200">
          <thead>
            <tr>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Ecosystem</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Package</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Version</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Reason</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {rules.map(rule => (
              <tr key={rule.id}>
                <td className="px-4 py-2 text-sm">{rule.ecosystem}</td>
                <td className="px-4 py-2 text-sm font-mono">{rule.package_pattern}</td>
                <td className="px-4 py-2 text-sm font-mono">{rule.version_pattern}</td>
                <td className="px-4 py-2 text-sm text-gray-500">{rule.reason || '-'}</td>
                <td className="px-4 py-2">
                  <button
                    onClick={() => rule.id && handleDelete(rule.id)}
                    className="text-red-600 hover:text-red-800"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function TokensSection() {
  const [tokens, setTokens] = useState<TokenInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [newToken, setNewToken] = useState({ name: '', ecosystems: '' })
  const [createdToken, setCreatedToken] = useState<string | null>(null)

  const fetchTokens = async () => {
    try {
      const data = await getTokens()
      setTokens(data.tokens)
    } catch (err) {
      console.error('Failed to load tokens:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchTokens()
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const ecosystems = newToken.ecosystems
        ? newToken.ecosystems.split(',').map(e => e.trim())
        : undefined
      const result = await createToken(newToken.name, ecosystems)
      setCreatedToken(result.token)
      setShowForm(false)
      setNewToken({ name: '', ecosystems: '' })
      fetchTokens()
    } catch (err) {
      alert(`Failed to create token: ${err instanceof Error ? err.message : 'Unknown error'}`)
    }
  }

  const handleRevoke = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this token?')) return
    try {
      await revokeToken(id)
      fetchTokens()
    } catch (err) {
      alert(`Failed to revoke token: ${err instanceof Error ? err.message : 'Unknown error'}`)
    }
  }

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-medium text-gray-900">API Tokens</h3>
        <button
          onClick={() => setShowForm(!showForm)}
          className="px-4 py-2 text-sm bg-blue-50 text-blue-600 rounded hover:bg-blue-100"
        >
          {showForm ? 'Cancel' : 'Create Token'}
        </button>
      </div>

      {createdToken && (
        <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded">
          <p className="text-sm font-medium text-green-800">Token created! Copy it now - it won't be shown again:</p>
          <code className="block mt-2 p-2 bg-white rounded border text-sm font-mono break-all">
            {createdToken}
          </code>
          <button
            onClick={() => {
              navigator.clipboard.writeText(createdToken)
              setCreatedToken(null)
            }}
            className="mt-2 text-sm text-green-600 hover:text-green-800"
          >
            Copy and dismiss
          </button>
        </div>
      )}

      {showForm && (
        <form onSubmit={handleCreate} className="mb-6 p-4 bg-gray-50 rounded space-y-4">
          <div>
            <label className="block text-sm text-gray-600 mb-1">Token Name</label>
            <input
              type="text"
              value={newToken.name}
              onChange={e => setNewToken({ ...newToken, name: e.target.value })}
              placeholder="e.g., CI Pipeline Token"
              required
              className="w-full px-3 py-2 border border-gray-300 rounded"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-600 mb-1">
              Allowed Ecosystems (comma-separated, leave empty for all)
            </label>
            <input
              type="text"
              value={newToken.ecosystems}
              onChange={e => setNewToken({ ...newToken, ecosystems: e.target.value })}
              placeholder="e.g., pypi, cargo"
              className="w-full px-3 py-2 border border-gray-300 rounded"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Create Token
          </button>
        </form>
      )}

      {loading ? (
        <div className="animate-pulse h-20 bg-gray-200 rounded"></div>
      ) : tokens.length === 0 ? (
        <p className="text-gray-500 text-center py-8">No tokens created</p>
      ) : (
        <table className="min-w-full divide-y divide-gray-200">
          <thead>
            <tr>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Expires</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Ecosystems</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {tokens.map(token => (
              <tr key={token.id}>
                <td className="px-4 py-2 text-sm font-medium">{token.name}</td>
                <td className="px-4 py-2 text-sm text-gray-500">
                  {new Date(token.created_at).toLocaleDateString()}
                </td>
                <td className="px-4 py-2 text-sm text-gray-500">
                  {token.expires_at ? new Date(token.expires_at).toLocaleDateString() : 'Never'}
                </td>
                <td className="px-4 py-2 text-sm text-gray-500">
                  {token.allowed_ecosystems.length > 0
                    ? token.allowed_ecosystems.join(', ')
                    : 'All'}
                </td>
                <td className="px-4 py-2">
                  <button
                    onClick={() => handleRevoke(token.id)}
                    className="text-red-600 hover:text-red-800"
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export default function Settings() {
  return (
    <div className="p-8">
      <h2 className="text-2xl font-bold text-gray-900 mb-8">Settings</h2>
      <div className="space-y-8">
        <CacheSection />
        <RulesSection />
        <TokensSection />
      </div>
    </div>
  )
}
