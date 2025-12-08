import { useState, useEffect } from 'react'
import { getDashboard, DashboardStats, triggerSync } from '../api/client'

function StatCard({ title, value, subtitle }: { title: string; value: string | number; subtitle?: string }) {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-sm font-medium text-gray-500">{title}</h3>
      <p className="mt-2 text-3xl font-bold text-gray-900">{value}</p>
      {subtitle && <p className="mt-1 text-sm text-gray-500">{subtitle}</p>}
    </div>
  )
}

function SecuritySourceCard({
  name,
  ecosystems,
  lastSync,
  status,
  recordsCount,
  onSync,
}: {
  name: string
  ecosystems: string[]
  lastSync: string | null
  status: string
  recordsCount: number
  onSync: () => void
}) {
  const statusColors: Record<string, string> = {
    success: 'bg-green-100 text-green-800',
    pending: 'bg-yellow-100 text-yellow-800',
    failed: 'bg-red-100 text-red-800',
    syncing: 'bg-blue-100 text-blue-800',
  }

  return (
    <div className="bg-white rounded-lg shadow p-4">
      <div className="flex justify-between items-start">
        <div>
          <h4 className="font-medium text-gray-900">{name}</h4>
          <p className="text-sm text-gray-500">{ecosystems.join(', ')}</p>
        </div>
        <span className={`px-2 py-1 text-xs font-medium rounded ${statusColors[status] || 'bg-gray-100 text-gray-800'}`}>
          {status}
        </span>
      </div>
      <div className="mt-4 flex justify-between items-center">
        <div className="text-sm text-gray-600">
          <p>{recordsCount.toLocaleString()} records</p>
          {lastSync && (
            <p className="text-gray-400">
              Last sync: {new Date(lastSync).toLocaleString()}
            </p>
          )}
        </div>
        <button
          onClick={onSync}
          className="px-3 py-1 text-sm bg-blue-50 text-blue-600 rounded hover:bg-blue-100 transition-colors"
        >
          Sync Now
        </button>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchData = async () => {
    try {
      const data = await getDashboard()
      setStats(data)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 30000) // Refresh every 30 seconds
    return () => clearInterval(interval)
  }, [])

  const handleSync = async (sourceName: string) => {
    try {
      await triggerSync(sourceName)
      fetchData() // Refresh after sync
    } catch (err) {
      alert(`Failed to trigger sync: ${err instanceof Error ? err.message : 'Unknown error'}`)
    }
  }

  if (loading) {
    return (
      <div className="p-8">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-8"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-32 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-8">
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
          {error}
        </div>
      </div>
    )
  }

  return (
    <div className="p-8">
      <h2 className="text-2xl font-bold text-gray-900 mb-8">Dashboard</h2>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard
          title="Total Requests"
          value={stats?.total_requests.toLocaleString() || 0}
        />
        <StatCard
          title="Blocked Requests"
          value={stats?.blocked_requests.toLocaleString() || 0}
          subtitle="Malicious packages blocked"
        />
        <StatCard
          title="Cache Hit Rate"
          value={`${((stats?.cache_hit_rate || 0) * 100).toFixed(1)}%`}
        />
        <StatCard
          title="Blocked Packages"
          value={stats?.blocked_packages_count.toLocaleString() || 0}
          subtitle="Total known threats"
        />
      </div>

      {/* Security Sources */}
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Sources</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {stats?.security_sources.map((source) => (
          <SecuritySourceCard
            key={source.name}
            name={source.name}
            ecosystems={source.ecosystems}
            lastSync={source.last_sync}
            status={source.status}
            recordsCount={source.records_count}
            onSync={() => handleSync(source.name)}
          />
        ))}
        {stats?.security_sources.length === 0 && (
          <div className="col-span-full text-center py-8 text-gray-500">
            No security sources configured
          </div>
        )}
      </div>
    </div>
  )
}
