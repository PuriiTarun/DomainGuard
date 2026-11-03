import type { ScanResult } from './types';

export function exportReport(scan: ScanResult, format: 'json' | 'md') {
  const content = format === 'json'
    ? JSON.stringify(scan, null, 2)
    : [
      '# DomainGuard: ' + scan.domain,
      'Scanned: ' + scan.scanned_at,
      '',
      '## HTTPS',
      scan.https.message,
      '',
      '## TLS',
      scan.tls.message + '. Expires: ' + (scan.tls.expires ?? 'unknown'),
      '',
      '## DNS',
      ...Object.entries(scan.dns.records).map(([name, record]) =>
        name + ': ' + record.status + ' | ' + record.values.join(', ')
      ),
      '',
      '## SPF / DMARC',
      'SPF: ' + scan.dns.spf.status,
      'DMARC: ' + scan.dns.dmarc.status,
      '',
      '## Security headers',
      ...Object.entries(scan.headers.checks).map(([name, finding]) =>
        name + ': ' + finding.status + ' | ' + finding.message
      ),
      '',
      '## HTTP redirect',
      scan.redirects.status + ': ' + scan.redirects.message,
      '',
      'Configuration observations are not proof that a site is secure.'
    ].join('\n');
  const url = URL.createObjectURL(new Blob([content], {
    type: format === 'json' ? 'application/json' : 'text/markdown'
  }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'domainguard-' + scan.domain + '-' + scan.scanned_at.slice(0, 10) + '.' + format;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
