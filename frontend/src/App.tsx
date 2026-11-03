import { useState, type FormEvent, type ReactNode } from 'react';
import { requestScan } from './api';
import { exportReport } from './report';
import type { ScanResult } from './types';

type Tab = 'summary' | 'dns' | 'headers';
const HISTORY_KEY = 'domainguard-local-history';

function storedScans(): ScanResult[] {
  try {
    const data: unknown = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]');
    return Array.isArray(data) ? (data as ScanResult[]).slice(0, 10) : [];
  } catch {
    return [];
  }
}

function Pill({ value, tone = 'neutral' }: { value: string; tone?: 'good' | 'review' | 'neutral' }) {
  const color = tone === 'good'
    ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
    : tone === 'review'
      ? 'bg-amber-500/10 text-amber-700 dark:text-amber-300'
      : 'bg-slate-500/10 text-slate-600 dark:text-slate-300';
  return <span className={'rounded-md px-2.5 py-1 text-xs font-semibold ' + color}>{value}</span>;
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-white/10 dark:bg-slate-900/80">
    <h2 className="mb-4 text-base font-semibold tracking-tight">{title}</h2>{children}
  </section>;
}

function Detail({ name, value, detail, tone }: { name: string; value: string; detail?: string; tone?: 'good' | 'review' | 'neutral' }) {
  return <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 py-3 last:border-0 dark:border-white/10">
    <div className="min-w-0 flex-1"><p className="text-sm font-medium">{name}</p>
      {detail && <p className="mt-1 break-words text-xs text-slate-500 dark:text-slate-400">{detail}</p>}
    </div><Pill value={value} tone={tone} />
  </div>;
}

export default function App() {
  const [domain, setDomain] = useState('');
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>(storedScans);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<Tab>('summary');
  const [dark, setDark] = useState(() => localStorage.getItem('domainguard-theme') !== 'light');

  function changeTheme() {
    const next = !dark;
    setDark(next);
    localStorage.setItem('domainguard-theme', next ? 'dark' : 'light');
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = domain.trim().toLowerCase();
    if (!name || loading) return;
    setLoading(true);
    setError('');
    setScan(null);
    try {
      const result = await requestScan(name);
      setScan(result);
      setTab('summary');
      setHistory(previous => {
        const updated = [result, ...previous.filter(item => item.domain !== result.domain)].slice(0, 10);
        try { localStorage.setItem(HISTORY_KEY, JSON.stringify(updated)); } catch { /* storage not available */ }
        return updated;
      });
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Scan unavailable');
    } finally {
      setLoading(false);
    }
  }

  return <div className={dark ? 'dark' : ''}>
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-[#0b1120] dark:text-slate-100">
      <header className="border-b border-slate-200 bg-white dark:border-white/10 dark:bg-[#101b2c]">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-5 sm:px-8">
          <div className="flex items-center gap-3">
            <span className="grid h-10 w-10 place-items-center rounded-xl bg-sky-600 text-xl font-bold text-white" aria-hidden="true">D</span>
            <div><p className="text-lg font-bold tracking-tight">DomainGuard<span className="text-sky-500">.</span></p>
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">Website security diagnostics</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden text-xs text-emerald-600 dark:text-emerald-400 sm:block">● Local development</span>
            <button type="button" onClick={changeTheme} aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'} className="rounded-lg border border-slate-300 px-3 py-2 text-xs font-semibold dark:border-white/20">{dark ? 'Light mode' : 'Dark mode'}</button>
          </div>
        </div>
      </header>
      <div className="mx-auto grid max-w-7xl gap-7 px-5 py-9 sm:px-8 lg:grid-cols-[minmax(0,1fr)_280px]">
        <main className="min-w-0 space-y-6">
          <div>
            <p className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-sky-600 dark:text-sky-400">Website intelligence</p>
            <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Know what's behind your domain.</h1>
            <p className="mt-3 max-w-2xl text-sm leading-7 text-slate-600 dark:text-slate-400">Inspect HTTPS, TLS, DNS, mail authentication, security headers and redirects. Every result comes from a real diagnostic request.</p>
          </div>
          <Card title="Scan a domain">
            <form onSubmit={onSubmit}>
              <label htmlFor="domain" className="mb-2 block text-sm font-medium">Domain name</label>
              <div className="flex flex-col gap-3 sm:flex-row">
                <input id="domain" value={domain} onChange={event => setDomain(event.target.value)}
                  required maxLength={253} autoComplete="off" spellCheck={false} placeholder="example.com"
                  className="min-w-0 flex-1 rounded-xl border border-slate-300 bg-slate-50 px-4 py-3 text-sm outline-none focus:border-sky-500 dark:border-white/10 dark:bg-slate-950" />
                <button disabled={loading} type="submit" className="rounded-xl bg-sky-600 px-7 py-3 text-sm font-semibold text-white hover:bg-sky-500 disabled:opacity-60">{loading ? 'Scanning…' : 'Run scan'}</button>
              </div>
              <p className="mt-3 text-xs text-slate-500">Enter a domain only. Scan websites you own or are authorized to assess.</p>
              <p role="status" aria-live="polite" className="mt-2 text-sm text-sky-500">{loading ? 'Running diagnostics. Results will appear when complete.' : ''}</p>
              {error && <p role="alert" className="mt-3 rounded-lg bg-rose-500/10 p-3 text-sm text-rose-500">{error}</p>}
            </form>
          </Card>
          {!scan && !loading && !error && <div className="rounded-2xl border border-dashed border-slate-300 p-12 text-center dark:border-white/15">
            <h2 className="text-lg font-semibold">Ready for your first scan</h2>
            <p className="mt-2 text-sm text-slate-500">Enter a domain above. This dashboard does not display fabricated scan results.</p>
          </div>}
          {scan && <>
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div><p className="text-xs uppercase tracking-widest text-slate-500">Latest scan</p><h2 className="mt-1 break-all text-2xl font-bold">{scan.domain}</h2>
                <p className="mt-1 text-xs text-slate-500">{new Date(scan.scanned_at).toLocaleString()}</p></div>
              <div className="flex gap-2">
                <button onClick={() => exportReport(scan, 'json')} className="rounded-lg border border-slate-300 px-3 py-2 text-xs font-semibold dark:border-white/15">JSON</button>
                <button onClick={() => exportReport(scan, 'md')} className="rounded-lg border border-slate-300 px-3 py-2 text-xs font-semibold dark:border-white/15">Download report</button>
              </div>
            </div>
            <div className="grid gap-4 sm:grid-cols-3">
              <Card title="HTTPS"><p className="text-xl font-bold">{scan.https.success ? 'Connected' : 'Unavailable'}</p>
                <p className="mt-2 text-xs text-slate-500">{scan.https.status_code === null ? scan.https.message : 'HTTP ' + scan.https.status_code}</p></Card>
              <Card title="TLS certificate"><p className="text-xl font-bold">{scan.tls.valid ? 'Verified' : 'Not verified'}</p>
                <p className="mt-2 text-xs text-slate-500">{scan.tls.days_remaining === null ? scan.tls.message : String(scan.tls.days_remaining) + ' days remaining'}</p></Card>
              <Card title="HTTP redirect"><p className="text-xl font-bold">{scan.redirects.status === 'pass' ? 'HTTPS redirect' : scan.redirects.status === 'review' ? 'Review' : 'Unknown'}</p>
                <p className="mt-2 text-xs text-slate-500">{scan.redirects.message}</p></Card>
            </div>
            <div role="tablist" aria-label="Diagnostic sections" className="flex flex-wrap gap-2 border-b border-slate-200 pb-3 dark:border-white/10">
              {(['summary', 'dns', 'headers'] as Tab[]).map(item =>
                <button key={item} type="button" role="tab" aria-selected={tab === item} onClick={() => setTab(item)}
                  className={'rounded-lg px-4 py-2 text-sm font-semibold ' + (tab === item ? 'bg-sky-600 text-white' : 'text-slate-500 hover:bg-slate-200 dark:hover:bg-white/10')}>
                  {item === 'headers' ? 'Security headers' : item.toUpperCase()}</button>)}
            </div>
            {tab === 'summary' && <div className="grid gap-5 md:grid-cols-2">
              <Card title="Connection & TLS">
                <Detail name="Approved IP addresses" value={scan.network.safe ? 'PUBLIC' : 'UNKNOWN'} tone={scan.network.safe ? 'good' : 'neutral'} detail={scan.network.addresses.join(', ')} />
                <Detail name="TLS certificate" value={scan.tls.valid ? 'VERIFIED' : 'UNKNOWN'} tone={scan.tls.valid ? 'good' : 'neutral'} detail={scan.tls.expires ?? scan.tls.message} />
              </Card>
              <Card title="Email authentication">
                <p className="mb-2 text-xs text-slate-500">Record detection only, not policy validation</p>
                <Detail name="SPF" value={scan.dns.spf.status.toUpperCase()} tone={scan.dns.spf.status === 'found' ? 'good' : 'review'} detail={scan.dns.spf.values.join(', ') || 'No record returned'} />
                <Detail name="DMARC" value={scan.dns.dmarc.status.toUpperCase()} tone={scan.dns.dmarc.status === 'found' ? 'good' : 'review'} detail={scan.dns.dmarc.values.join(', ') || 'No record returned'} />
              </Card>
            </div>}
            {tab === 'dns' && <Card title="DNS records">
              <div className="overflow-x-auto"><table className="w-full text-left text-sm">
                <thead className="border-b border-slate-200 text-xs uppercase text-slate-500 dark:border-white/10"><tr><th className="py-3">Type</th><th className="py-3">Status</th><th className="py-3">Values</th></tr></thead>
                <tbody>{Object.entries(scan.dns.records).map(([name, record]) =>
                  <tr key={name} className="border-b border-slate-100 last:border-0 dark:border-white/10">
                    <th scope="row" className="py-3 pr-4 font-semibold">{name}</th>
                    <td className="py-3 pr-4"><Pill value={record.status.toUpperCase()} tone={record.status === 'found' ? 'good' : record.status === 'error' ? 'neutral' : 'review'} /></td>
                    <td className="break-all py-3 text-slate-500">{record.values.join(', ') || 'No data'}</td>
                  </tr>)}</tbody>
              </table></div>
            </Card>}
            {tab === 'headers' && <Card title="Security response headers">
              {scan.headers.status !== 'checked' ? <p className="text-sm text-slate-500">{scan.headers.message}</p> :
                Object.entries(scan.headers.checks).map(([name, item]) =>
                  <Detail key={name} name={name} detail={item.message} value={item.status.toUpperCase()}
                    tone={item.status === 'present' || item.status === 'alternative' ? 'good' : 'review'} />)}
            </Card>}
            <p className="text-xs leading-6 text-slate-500">These are configuration observations, not confirmed vulnerabilities. Unavailable checks are never interpreted as passing.</p>
          </>}
        </main>
        <aside className="space-y-5">
          <Card title="Recent scans">
            <p className="mb-3 text-xs text-slate-500">Stored locally in this browser, maximum 10.</p>
            {history.length === 0 ? <p className="text-sm text-slate-500">No history yet.</p> : history.map(item =>
              <button type="button" key={item.domain + item.scanned_at}
                onClick={() => { setScan(item); setDomain(item.domain); setError(''); setTab('summary'); }}
                className="mb-2 w-full rounded-lg border border-slate-200 p-3 text-left hover:border-sky-500 dark:border-white/10">
                <p className="truncate text-sm font-semibold">{item.domain}</p>
                <p className="mt-1 text-xs text-slate-500">{new Date(item.scanned_at).toLocaleString()}</p>
              </button>)}
            {history.length > 0 && <button type="button" onClick={() => { setHistory([]); localStorage.removeItem(HISTORY_KEY); }} className="mt-3 text-xs font-semibold text-slate-500 underline">Clear history</button>}
          </Card>
          <div className="rounded-2xl border border-sky-500/20 bg-sky-500/5 p-5">
            <p className="text-xs font-semibold uppercase tracking-widest text-sky-500">Responsible use</p>
            <p className="mt-3 text-sm leading-6 text-slate-500 dark:text-slate-300">Non-invasive, authorized website checks only. DomainGuard is not a vulnerability scanner.</p>
          </div>
        </aside>
      </div>
      <footer className="border-t border-slate-200 px-5 py-5 text-center text-xs text-slate-500 dark:border-white/10">DomainGuard · Local diagnostics · Results depend on current network conditions</footer>
    </div>
  </div>;
}
