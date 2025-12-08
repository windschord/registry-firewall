import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import BlockLogs from './BlockLogs'
import * as api from '../api/client'

vi.mock('../api/client')

const mockBlockLogs: api.BlockLogsResponse = {
  logs: [
    {
      id: 1,
      ecosystem: 'pypi',
      package: 'malicious-package',
      version: '1.0.0',
      source: 'osv',
      reason: 'Known malware',
      client_ip: '192.168.1.1',
      timestamp: '2024-01-15T10:00:00Z',
    },
    {
      id: 2,
      ecosystem: 'cargo',
      package: 'bad-crate',
      version: '2.0.0',
      source: 'custom',
      reason: null,
      client_ip: null,
      timestamp: '2024-01-15T11:00:00Z',
    },
  ],
  total: 45,
}

describe('BlockLogs', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows loading state initially', () => {
    vi.mocked(api.getBlockLogs).mockReturnValue(new Promise(() => {}))

    render(<BlockLogs />)

    expect(screen.getByText((_, element) => {
      return element?.className?.includes('animate-pulse') ?? false
    })).toBeInTheDocument()
  })

  it('renders block logs after loading', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue(mockBlockLogs)

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('Block Logs')).toBeInTheDocument()
    })

    expect(screen.getByText('malicious-package')).toBeInTheDocument()
    expect(screen.getByText('1.0.0')).toBeInTheDocument()
    expect(screen.getByText('Known malware')).toBeInTheDocument()
    expect(screen.getByText('bad-crate')).toBeInTheDocument()
  })

  it('shows total count', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue(mockBlockLogs)

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('45 total entries')).toBeInTheDocument()
    })
  })

  it('shows error state on API failure', async () => {
    vi.mocked(api.getBlockLogs).mockRejectedValue(new Error('Failed to fetch'))

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('Failed to fetch')).toBeInTheDocument()
    })
  })

  it('shows empty state when no logs', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue({ logs: [], total: 0 })

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('No blocked packages yet')).toBeInTheDocument()
    })
  })

  it('renders pagination when there are multiple pages', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue(mockBlockLogs)

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
    })

    expect(screen.getByText('Previous')).toBeInTheDocument()
    expect(screen.getByText('Next')).toBeInTheDocument()
  })

  it('navigates to next page', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue(mockBlockLogs)

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Next'))

    await waitFor(() => {
      expect(api.getBlockLogs).toHaveBeenCalledWith(20, 20)
    })
  })

  it('navigates to previous page', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue(mockBlockLogs)

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
    })

    // First go to page 2
    fireEvent.click(screen.getByText('Next'))

    await waitFor(() => {
      expect(screen.getByText('Page 2 of 3')).toBeInTheDocument()
    })

    // Then go back to page 1
    fireEvent.click(screen.getByText('Previous'))

    await waitFor(() => {
      expect(api.getBlockLogs).toHaveBeenCalledWith(20, 0)
    })
  })

  it('disables previous button on first page', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue(mockBlockLogs)

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
    })

    expect(screen.getByText('Previous')).toBeDisabled()
  })

  it('applies correct ecosystem badge colors', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue(mockBlockLogs)

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('pypi')).toBeInTheDocument()
    })

    const pypiBadge = screen.getByText('pypi')
    expect(pypiBadge).toHaveClass('bg-blue-100')

    const cargoBadge = screen.getByText('cargo')
    expect(cargoBadge).toHaveClass('bg-orange-100')
  })

  it('shows dash when reason is null', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue(mockBlockLogs)

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('-')).toBeInTheDocument()
    })
  })

  it('does not show pagination when only one page', async () => {
    vi.mocked(api.getBlockLogs).mockResolvedValue({
      logs: mockBlockLogs.logs,
      total: 10,
    })

    render(<BlockLogs />)

    await waitFor(() => {
      expect(screen.getByText('Block Logs')).toBeInTheDocument()
    })

    expect(screen.queryByText('Previous')).not.toBeInTheDocument()
    expect(screen.queryByText('Next')).not.toBeInTheDocument()
  })
})
