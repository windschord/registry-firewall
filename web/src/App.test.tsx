import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import App from './App'

// Mock the page components
vi.mock('./pages/Dashboard', () => ({
  default: () => <div data-testid="dashboard-page">Dashboard Page</div>,
}))

vi.mock('./pages/BlockLogs', () => ({
  default: () => <div data-testid="blocklogs-page">Block Logs Page</div>,
}))

vi.mock('./pages/Settings', () => ({
  default: () => <div data-testid="settings-page">Settings Page</div>,
}))

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the sidebar with title', () => {
    render(
      <MemoryRouter>
        <App />
      </MemoryRouter>
    )

    expect(screen.getByText('Registry Firewall')).toBeInTheDocument()
    expect(screen.getByText('Security Dashboard')).toBeInTheDocument()
  })

  it('renders navigation items', () => {
    render(
      <MemoryRouter>
        <App />
      </MemoryRouter>
    )

    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Block Logs')).toBeInTheDocument()
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('renders Dashboard page on root path', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    )

    expect(screen.getByTestId('dashboard-page')).toBeInTheDocument()
  })

  it('renders Block Logs page on /blocks path', () => {
    render(
      <MemoryRouter initialEntries={['/blocks']}>
        <App />
      </MemoryRouter>
    )

    expect(screen.getByTestId('blocklogs-page')).toBeInTheDocument()
  })

  it('renders Settings page on /settings path', () => {
    render(
      <MemoryRouter initialEntries={['/settings']}>
        <App />
      </MemoryRouter>
    )

    expect(screen.getByTestId('settings-page')).toBeInTheDocument()
  })

  it('highlights active navigation link', () => {
    render(
      <MemoryRouter initialEntries={['/blocks']}>
        <App />
      </MemoryRouter>
    )

    const blockLogsLink = screen.getByRole('link', { name: /Block Logs/i })
    expect(blockLogsLink).toHaveClass('bg-gray-900')
  })
})
