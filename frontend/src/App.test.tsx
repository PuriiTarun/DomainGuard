import { afterEach, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from './App';

const response = {
  domain: 'example.com', scanned_at: '2026-11-03T08:00:00+00:00',
  network: { safe: true, addresses: ['8.8.8.8'], message: 'public' },
  https: { success: true, status_code: 200, message: 'connected', headers: {} },
  tls: { valid: true, expires: '2026-12-03', days_remaining: 30, message: 'verified' },
  dns: { records: { A: { status: 'found', values: ['8.8.8.8'] } }, spf: { status: 'missing', values: [] }, dmarc: { status: 'error', values: [] } },
  headers: { status: 'checked', checks: {}, message: 'checked' },
  redirects: { status: 'unknown', http_status: null, location: null, message: 'Not checked' }
};

afterEach(() => { vi.unstubAllGlobals(); localStorage.clear(); });

it('renders an empty state rather than invented results', () => {
  render(<App />);
  expect(screen.getByText('Ready for your first scan')).toBeInTheDocument();
  expect(screen.queryByText('Connected')).not.toBeInTheDocument();
});

it('submits a domain and renders the API response', async () => {
  const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => response });
  vi.stubGlobal('fetch', fetchMock);
  render(<App />);
  fireEvent.change(screen.getByLabelText('Domain name'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Run scan' }));
  await waitFor(() => expect(screen.getByText('Connected')).toBeInTheDocument());
  expect(fetchMock).toHaveBeenCalledWith('/api/v1/scans', expect.objectContaining({
    method: 'POST', body: JSON.stringify({ domain: 'example.com' })
  }));
});

it('displays API failures without a fabricated scan', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 429, json: async () => ({ detail: 'Too many scans' }) }));
  render(<App />);
  fireEvent.change(screen.getByLabelText('Domain name'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Run scan' }));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Too many scans'));
  expect(screen.queryByText('Connected')).not.toBeInTheDocument();
});
