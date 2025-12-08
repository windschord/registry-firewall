import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react'
import Dashboard from './Dashboard'
import * as api from '../api/client'

vi.mock('../api/client')

const mockDashboardData: api.DashboardStats = {
  total_requests: 1000,
  blocked_requests: 50,
  cache_hit_rate: 0.85,
  security_sources_count: 2,
  blocked_packages_count: 100,
  security_sources: [
    {
      name: 'OSV',
      ecosystems: ['pypi', 'cargo'],
      last_sync: '2024-01-15T10:00:00Z',
      status: 'success',
      records_count: 500,
    },
    {
      name: 'OpenSSF',
      ecosystems: ['pypi'],
      last_sync: null,
      status: 'pending',
      records_count: 0,
    },
  ],
}

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('shows loading state initially', () => {
    vi.mocked(api.getDashboard).mockReturnValue(new Promise(() => {}))

    render(<Dashboard />)

    expect(screen.getByText((_, element) => {
      return element?.className?.includes('animate-pulse') ?? false
    })).toBeInTheDocument()
  })

  it('renders dashboard stats after loading', async () => {
    vi.mocked(api.getDashboard).mockResolvedValue(mockDashboardData)

    render(<Dashboard />)

    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })

    expect(screen.getByText('Total Requests')).toBeInTheDocument()
    expect(screen.getByText('1,000')).toBeInTheDocument()
    expect(screen.getByText('Blocked Requests')).toBeInTheDocument()
    expect(screen.getByText('50')).toBeInTheDocument()
    expect(screen.getByText('Cache Hit Rate')).toBeInTheDocument()
    expect(screen.getByText('85.0%')).toBeInTheDocument()
    expect(screen.getByText('Blocked Packages')).toBeInTheDocument()
    expect(screen.getByText('100')).toBeInTheDocument()
  })

  it('renders security sources', async () => {
    vi.mocked(api.getDashboard).mockResolvedValue(mockDashboardData)

    render(<Dashboard />)

    await waitFor(() => {
      expect(screen.getByText('OSV')).toBeInTheDocument()
    })

    expect(screen.getByText('pypi, cargo')).toBeInTheDocument()
    expect(screen.getByText('500 records')).toBeInTheDocument()
    expect(screen.getByText('OpenSSF')).toBeInTheDocument()
  })

  it('shows error state on API failure', async () => {
    vi.mocked(api.getDashboard).mockRejectedValue(new Error('Network error'))

    render(<Dashboard />)

    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument()
    })
  })

  it('triggers sync when clicking Sync Now button', async () => {
    vi.mocked(api.getDashboard).mockResolvedValue(mockDashboardData)
    vi.mocked(api.triggerSync).mockResolvedValue({ message: 'Sync started' })

    render(<Dashboard />)

    await waitFor(() => {
      expect(screen.getByText('OSV')).toBeInTheDocument()
    })

    const syncButtons = screen.getAllByText('Sync Now')
    fireEvent.click(syncButtons[0])

    await waitFor(() => {
      expect(api.triggerSync).toHaveBeenCalledWith('OSV')
    })
  })

  it('shows empty state when no security sources', async () => {
    vi.mocked(api.getDashboard).mockResolvedValue({
      ...mockDashboardData,
      security_sources: [],
    })

    render(<Dashboard />)

    await waitFor(() => {
      expect(screen.getByText('No security sources configured')).toBeInTheDocument()
    })
  })

  it('handles sync failure gracefully', async () => {
    vi.mocked(api.getDashboard).mockResolvedValue(mockDashboardData)
    vi.mocked(api.triggerSync).mockRejectedValue(new Error('Sync failed'))
    const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => {})

    render(<Dashboard />)

    await waitFor(() => {
      expect(screen.getByText('OSV')).toBeInTheDocument()
    })

    const syncButtons = screen.getAllByText('Sync Now')
    fireEvent.click(syncButtons[0])

    await waitFor(() => {
      expect(alertMock).toHaveBeenCalledWith('Failed to trigger sync: Sync failed')
    })

    alertMock.mockRestore()
  })

  it('refreshes data periodically', async () => {
    vi.useFakeTimers()
    vi.mocked(api.getDashboard).mockResolvedValue(mockDashboardData)

    await act(async () => {
      render(<Dashboard />)
    })

    await act(async () => {
      await vi.runOnlyPendingTimersAsync()
    })

    const initialCalls = vi.mocked(api.getDashboard).mock.calls.length

    await act(async () => {
      vi.advanceTimersByTime(30000)
      await vi.runOnlyPendingTimersAsync()
    })

    // Should have been called at least once more after advancing timers
    expect(vi.mocked(api.getDashboard).mock.calls.length).toBeGreaterThan(initialCalls)
  })
})
