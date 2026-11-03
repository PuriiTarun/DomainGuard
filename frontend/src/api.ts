import type { ScanResult } from './types';

export async function requestScan(domain: string): Promise<ScanResult> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 60000);
  try {
    const response = await fetch('/api/v1/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
      signal: controller.signal
    });
    if (!response.ok) {
      const body: unknown = await response.json().catch(() => null);
      const detail = body && typeof body === 'object' && 'detail' in body
        ? (body as { detail: unknown }).detail : null;
      throw new Error(typeof detail === 'string' ? detail : 'Scan failed. Check the domain and try again.');
    }
    return (await response.json()) as ScanResult;
  } finally {
    window.clearTimeout(timer);
  }
}
