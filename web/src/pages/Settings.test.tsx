import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import Settings from './Settings'
import * as api from '../api/client'

vi.mock('../api/client')

const mockCacheStats: api.CacheStats = {
  plugin: 'filesystem',
  hits: 800,
  misses: 200,
  total_size_bytes: 1048576, // 1 MB
  entries: 150,
}

const mockRules: api.RulesResponse = {
  rules: [
    {
      id: 1,
      ecosystem: 'pypi',
      package_pattern: 'malicious-*',
      version_constraint: '*',
      reason: 'Known malware pattern',
    },
  ],
}

const mockTokens: api.TokensResponse = {
  tokens: [
    {
      id: 'token-1',
      name: 'CI Pipeline',
      token_prefix: 'rf_token-1***',
      created_at: '2024-01-15T10:00:00Z',
      expires_at: '2025-01-15T10:00:00Z',
      last_used_at: null,
      allowed_ecosystems: ['pypi', 'cargo'],
    },
    {
      id: 'token-2',
      name: 'Dev Token',
      token_prefix: 'rf_token-2***',
      created_at: '2024-01-10T10:00:00Z',
      expires_at: null,
      last_used_at: '2024-01-14T10:00:00Z',
      allowed_ecosystems: [],
    },
  ],
}

describe('Settings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.getCacheStats).mockResolvedValue(mockCacheStats)
    vi.mocked(api.getRules).mockResolvedValue(mockRules)
    vi.mocked(api.getTokens).mockResolvedValue(mockTokens)
  })

  it('renders all sections', async () => {
    render(<Settings />)

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })

    expect(screen.getByText('Cache')).toBeInTheDocument()
    expect(screen.getByText('Custom Block Rules')).toBeInTheDocument()
    expect(screen.getByText('API Tokens')).toBeInTheDocument()
  })

  describe('Cache Section', () => {
    it('displays cache stats', async () => {
      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('filesystem')).toBeInTheDocument()
      })

      expect(screen.getByText('150')).toBeInTheDocument() // entries
      expect(screen.getByText('1 MB')).toBeInTheDocument() // size
      expect(screen.getByText('80.0%')).toBeInTheDocument() // hit rate
    })

    it('clears cache when clicking Clear Cache', async () => {
      vi.mocked(api.clearCache).mockResolvedValue({ message: 'Cache cleared' })
      const confirmMock = vi.spyOn(window, 'confirm').mockReturnValue(true)

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Clear Cache')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Clear Cache'))

      await waitFor(() => {
        expect(api.clearCache).toHaveBeenCalled()
      })

      confirmMock.mockRestore()
    })

    it('does not clear cache when confirm is cancelled', async () => {
      const confirmMock = vi.spyOn(window, 'confirm').mockReturnValue(false)

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Clear Cache')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Clear Cache'))

      expect(api.clearCache).not.toHaveBeenCalled()

      confirmMock.mockRestore()
    })

    it('shows 0 B for zero bytes', async () => {
      vi.mocked(api.getCacheStats).mockResolvedValue({
        ...mockCacheStats,
        total_size_bytes: 0,
      })

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('0 B')).toBeInTheDocument()
      })
    })

    it('shows 0% hit rate when no requests', async () => {
      vi.mocked(api.getCacheStats).mockResolvedValue({
        ...mockCacheStats,
        hits: 0,
        misses: 0,
      })

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('0%')).toBeInTheDocument()
      })
    })

    it('shows alert on clear cache failure', async () => {
      vi.mocked(api.clearCache).mockRejectedValue(new Error('Clear failed'))
      const confirmMock = vi.spyOn(window, 'confirm').mockReturnValue(true)
      const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => {})

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Clear Cache')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Clear Cache'))

      await waitFor(() => {
        expect(alertMock).toHaveBeenCalledWith('Failed to clear cache: Clear failed')
      })

      confirmMock.mockRestore()
      alertMock.mockRestore()
    })

    it('shows none when no cache plugin', async () => {
      vi.mocked(api.getCacheStats).mockResolvedValue({
        ...mockCacheStats,
        plugin: '',
      })

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('none')).toBeInTheDocument()
      })
    })
  })

  describe('Rules Section', () => {
    it('displays existing rules', async () => {
      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('malicious-*')).toBeInTheDocument()
      })

      expect(screen.getByText('Known malware pattern')).toBeInTheDocument()
    })

    it('shows empty state when no rules', async () => {
      vi.mocked(api.getRules).mockResolvedValue({ rules: [] })

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('No custom rules defined')).toBeInTheDocument()
      })
    })

    it('shows form when clicking Add Rule', async () => {
      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Add Rule')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Add Rule'))

      expect(screen.getByText('Create Rule')).toBeInTheDocument()
      expect(screen.getByPlaceholderText('e.g., malicious-*')).toBeInTheDocument()
    })

    it('creates a new rule', async () => {
      vi.mocked(api.createRule).mockResolvedValue({ id: 2 })

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Add Rule')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Add Rule'))

      fireEvent.change(screen.getByPlaceholderText('e.g., malicious-*'), {
        target: { value: 'evil-package' },
      })

      fireEvent.click(screen.getByText('Create Rule'))

      await waitFor(() => {
        expect(api.createRule).toHaveBeenCalledWith(
          expect.objectContaining({
            package_pattern: 'evil-package',
          })
        )
      })
    })

    it('deletes a rule', async () => {
      vi.mocked(api.deleteRule).mockResolvedValue({ message: 'Deleted' })
      const confirmMock = vi.spyOn(window, 'confirm').mockReturnValue(true)

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('malicious-*')).toBeInTheDocument()
      })

      const deleteButtons = screen.getAllByText('Delete')
      fireEvent.click(deleteButtons[0])

      await waitFor(() => {
        expect(api.deleteRule).toHaveBeenCalledWith(1)
      })

      confirmMock.mockRestore()
    })

    it('does not delete rule when confirm is cancelled', async () => {
      const confirmMock = vi.spyOn(window, 'confirm').mockReturnValue(false)

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('malicious-*')).toBeInTheDocument()
      })

      const deleteButtons = screen.getAllByText('Delete')
      fireEvent.click(deleteButtons[0])

      expect(api.deleteRule).not.toHaveBeenCalled()

      confirmMock.mockRestore()
    })

    it('shows alert on create rule failure', async () => {
      vi.mocked(api.createRule).mockRejectedValue(new Error('Create failed'))
      const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => {})

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Add Rule')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Add Rule'))

      fireEvent.change(screen.getByPlaceholderText('e.g., malicious-*'), {
        target: { value: 'evil-package' },
      })

      fireEvent.click(screen.getByText('Create Rule'))

      await waitFor(() => {
        expect(alertMock).toHaveBeenCalledWith('Failed to create rule: Create failed')
      })

      alertMock.mockRestore()
    })

    it('shows alert on delete rule failure', async () => {
      vi.mocked(api.deleteRule).mockRejectedValue(new Error('Delete failed'))
      const confirmMock = vi.spyOn(window, 'confirm').mockReturnValue(true)
      const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => {})

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('malicious-*')).toBeInTheDocument()
      })

      const deleteButtons = screen.getAllByText('Delete')
      fireEvent.click(deleteButtons[0])

      await waitFor(() => {
        expect(alertMock).toHaveBeenCalledWith('Failed to delete rule: Delete failed')
      })

      confirmMock.mockRestore()
      alertMock.mockRestore()
    })

    it('displays rule without reason', async () => {
      vi.mocked(api.getRules).mockResolvedValue({
        rules: [
          {
            id: 1,
            ecosystem: 'pypi',
            package_pattern: 'test-*',
            version_constraint: '*',
          },
        ],
      })

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('test-*')).toBeInTheDocument()
      })

      // Should show dash for missing reason
      const cells = screen.getAllByRole('cell')
      const reasonCell = cells.find(cell => cell.textContent === '-')
      expect(reasonCell).toBeInTheDocument()
    })

    it('hides form when clicking Cancel', async () => {
      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Add Rule')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Add Rule'))
      expect(screen.getByText('Create Rule')).toBeInTheDocument()

      fireEvent.click(screen.getByText('Cancel'))

      await waitFor(() => {
        expect(screen.getByText('Add Rule')).toBeInTheDocument()
      })
    })
  })

  describe('Tokens Section', () => {
    it('displays existing tokens', async () => {
      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('CI Pipeline')).toBeInTheDocument()
      })

      expect(screen.getByText('Dev Token')).toBeInTheDocument()
      expect(screen.getByText('pypi, cargo')).toBeInTheDocument()
      expect(screen.getByText('All')).toBeInTheDocument() // Dev Token has no restrictions
    })

    it('shows empty state when no tokens', async () => {
      vi.mocked(api.getTokens).mockResolvedValue({ tokens: [] })

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('No tokens created')).toBeInTheDocument()
      })
    })

    it('shows form when clicking Create Token', async () => {
      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('Create Token')).toBeInTheDocument()
      })

      const createButtons = screen.getAllByText('Create Token')
      fireEvent.click(createButtons[0])

      expect(screen.getByPlaceholderText('e.g., CI Pipeline Token')).toBeInTheDocument()
    })

    it('creates a new token and shows it', async () => {
      vi.mocked(api.createToken).mockResolvedValue({
        id: 'new-token',
        token: 'rf_secret_token_value',
      })

      render(<Settings />)

      await waitFor(() => {
        const createButtons = screen.getAllByText('Create Token')
        fireEvent.click(createButtons[0])
      })

      fireEvent.change(screen.getByPlaceholderText('e.g., CI Pipeline Token'), {
        target: { value: 'New API Token' },
      })

      const submitButton = screen.getByRole('button', { name: 'Create Token' })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText('rf_secret_token_value')).toBeInTheDocument()
      })

      expect(screen.getByText(/Token created!/)).toBeInTheDocument()
    })

    it('revokes a token', async () => {
      vi.mocked(api.revokeToken).mockResolvedValue({ message: 'Revoked' })
      const confirmMock = vi.spyOn(window, 'confirm').mockReturnValue(true)

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('CI Pipeline')).toBeInTheDocument()
      })

      const revokeButtons = screen.getAllByText('Revoke')
      fireEvent.click(revokeButtons[0])

      await waitFor(() => {
        expect(api.revokeToken).toHaveBeenCalledWith('token-1')
      })

      confirmMock.mockRestore()
    })

    it('copies token and dismisses', async () => {
      vi.mocked(api.createToken).mockResolvedValue({
        id: 'new-token',
        token: 'rf_secret_token_value',
      })

      const writeTextMock = vi.fn().mockResolvedValue(undefined)
      Object.assign(navigator, {
        clipboard: { writeText: writeTextMock },
      })

      render(<Settings />)

      await waitFor(() => {
        const createButtons = screen.getAllByText('Create Token')
        fireEvent.click(createButtons[0])
      })

      fireEvent.change(screen.getByPlaceholderText('e.g., CI Pipeline Token'), {
        target: { value: 'New API Token' },
      })

      const submitButton = screen.getByRole('button', { name: 'Create Token' })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(screen.getByText('Copy and dismiss')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Copy and dismiss'))

      expect(writeTextMock).toHaveBeenCalledWith('rf_secret_token_value')
    })

    it('does not revoke token when confirm is cancelled', async () => {
      const confirmMock = vi.spyOn(window, 'confirm').mockReturnValue(false)

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('CI Pipeline')).toBeInTheDocument()
      })

      const revokeButtons = screen.getAllByText('Revoke')
      fireEvent.click(revokeButtons[0])

      expect(api.revokeToken).not.toHaveBeenCalled()

      confirmMock.mockRestore()
    })

    it('shows alert on create token failure', async () => {
      vi.mocked(api.createToken).mockRejectedValue(new Error('Token creation failed'))
      const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => {})

      render(<Settings />)

      await waitFor(() => {
        const createButtons = screen.getAllByText('Create Token')
        fireEvent.click(createButtons[0])
      })

      fireEvent.change(screen.getByPlaceholderText('e.g., CI Pipeline Token'), {
        target: { value: 'New API Token' },
      })

      const submitButton = screen.getByRole('button', { name: 'Create Token' })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(alertMock).toHaveBeenCalledWith('Failed to create token: Token creation failed')
      })

      alertMock.mockRestore()
    })

    it('shows alert on revoke token failure', async () => {
      vi.mocked(api.revokeToken).mockRejectedValue(new Error('Revoke failed'))
      const confirmMock = vi.spyOn(window, 'confirm').mockReturnValue(true)
      const alertMock = vi.spyOn(window, 'alert').mockImplementation(() => {})

      render(<Settings />)

      await waitFor(() => {
        expect(screen.getByText('CI Pipeline')).toBeInTheDocument()
      })

      const revokeButtons = screen.getAllByText('Revoke')
      fireEvent.click(revokeButtons[0])

      await waitFor(() => {
        expect(alertMock).toHaveBeenCalledWith('Failed to revoke token: Revoke failed')
      })

      confirmMock.mockRestore()
      alertMock.mockRestore()
    })

    it('creates token with ecosystems', async () => {
      vi.mocked(api.createToken).mockResolvedValue({
        id: 'new-token',
        token: 'rf_secret_token_value',
      })

      render(<Settings />)

      await waitFor(() => {
        const createButtons = screen.getAllByText('Create Token')
        fireEvent.click(createButtons[0])
      })

      fireEvent.change(screen.getByPlaceholderText('e.g., CI Pipeline Token'), {
        target: { value: 'Limited Token' },
      })

      fireEvent.change(screen.getByPlaceholderText('e.g., pypi, cargo'), {
        target: { value: 'pypi, cargo' },
      })

      const submitButton = screen.getByRole('button', { name: 'Create Token' })
      fireEvent.click(submitButton)

      await waitFor(() => {
        expect(api.createToken).toHaveBeenCalledWith('Limited Token', ['pypi', 'cargo'])
      })
    })

    it('hides token form when clicking Cancel', async () => {
      render(<Settings />)

      await waitFor(() => {
        const createButtons = screen.getAllByText('Create Token')
        fireEvent.click(createButtons[0])
      })

      expect(screen.getByPlaceholderText('e.g., CI Pipeline Token')).toBeInTheDocument()

      // Find and click Cancel button in tokens section
      const cancelButton = screen.getByRole('button', { name: 'Cancel' })
      fireEvent.click(cancelButton)

      await waitFor(() => {
        expect(screen.queryByPlaceholderText('e.g., CI Pipeline Token')).not.toBeInTheDocument()
      })
    })
  })
})
