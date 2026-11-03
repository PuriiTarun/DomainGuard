export type DnsLookup = { status: string; values: string[] };
export type ScanResult = {
  domain: string;
  scanned_at: string;
  network: { safe: boolean; addresses: string[]; message: string };
  https: { success: boolean; status_code: number | null; message: string; headers: Record<string, string> };
  tls: { valid: boolean; expires: string | null; days_remaining: number | null; message: string };
  dns: { records: Record<string, DnsLookup>; spf: DnsLookup; dmarc: DnsLookup };
  headers: { status: string; message: string; checks: Record<string, { status: string; value: string | null; message: string }> };
  redirects: { status: string; http_status: number | null; location: string | null; message: string };
};
