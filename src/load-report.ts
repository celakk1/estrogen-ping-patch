import { escapeHtml } from './report';
import { formatProbeMs } from './measurement';
import type { LoadPhase, LoadRun } from './load-types';

export const phaseNames: Record<LoadPhase, string> = {
  idle: 'Idle baseline',
  download: 'Download',
  upload: 'Upload',
  recovery: 'Recovery',
};
export const formatMbps = (value: number | null | undefined): string =>
  value == null || !Number.isFinite(value) ? 'Unavailable' : `${value.toFixed(2)} Mbps`;
export const loadNotes =
  'Application payload goodput includes connection setup, TLS, and server time; it is not a link-capacity estimate or the provider website score. Concurrent latency summaries include probes overlapping in-flight requests or observed payload progress. Fast or limited transfers may provide too few concurrent samples. Saturation is not guaranteed. Upload bytes queued to the HTTP client are separate from accepted payload. Headers, TLS overhead, retransmissions, and latency probes are outside the payload budget. No optimization or statistical improvement is inferred from this session.';

export function loadReportHtml(run: LoadRun): string {
  const rows = run.transfers
    .map(
      ({ providerIndex, phase, result, error }) =>
        `<tr><td>${providerIndex + 1}</td><td>${phaseNames[phase]}</td><td>${escapeHtml(result?.provider.origin ?? '')}</td><td>${escapeHtml(result?.status ?? error ?? 'Unavailable')}</td><td>${formatMbps(result?.applicationGoodputMbps)}</td><td>${result?.acceptedPayloadBytes ?? 0}</td></tr>`,
    )
    .join('');
  const latency = run.latencySummaries
    .map(
      ({ providerIndex, phase, results }) =>
        `<h3>Provider ${providerIndex + 1}: ${phaseNames[phase]}</h3><ul>${results.map(({ endpoint, summary }) => `<li>${escapeHtml(endpoint.id)} (${escapeHtml(endpoint.address)}): median ${escapeHtml(formatProbeMs(summary.medianMs, endpoint.protocol ?? 'tcpConnect'))}; p95 ${escapeHtml(formatProbeMs(summary.p95Ms, endpoint.protocol ?? 'tcpConnect'))}; ${summary.successful}/${summary.attempted} successful probes</li>`).join('')}</ul>`,
    )
    .join('');
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>estrogen ping patch load report</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px;color:#172035}table{border-collapse:collapse;width:100%}th,td{padding:10px;border:1px solid #ddd;text-align:left;overflow-wrap:anywhere}</style><h1>Transfer and concurrent latency report</h1><p>${escapeHtml(run.startedAt)} | ${escapeHtml(run.status)} | version ${escapeHtml(run.appVersion)}</p><p>${loadNotes}</p><table><thead><tr><th>Provider</th><th>Direction</th><th>Server origin</th><th>Status</th><th>Payload goodput</th><th>Accepted bytes</th></tr></thead><tbody>${rows}</tbody></table>${latency}<p>Raw per-stream outcomes, peer addresses, byte counters, and latency samples are available in JSON. Windows network settings were unchanged.</p></html>`;
}

export function downloadLoadReport(run: LoadRun, format: 'json' | 'html'): void {
  const content = format === 'json' ? JSON.stringify(run, null, 2) : loadReportHtml(run);
  const url = URL.createObjectURL(
    new Blob([content], { type: format === 'json' ? 'application/json' : 'text/html' }),
  );
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `epp-load-${run.id}.${format}`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
