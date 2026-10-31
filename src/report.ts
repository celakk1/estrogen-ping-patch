import type { BenchmarkRun } from './types';

export const formatMs = (value: number | null | undefined): string =>
  value == null || !Number.isFinite(value) ? 'Unavailable' : `${value.toFixed(2)} ms`;

export const escapeHtml = (value: unknown): string =>
  String(value).replace(
    /[&<>"']/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!,
  );

export function reportHtml(run: BenchmarkRun): string {
  const rows = run.results
    .map(
      ({ endpoint, summary }) =>
        `<tr><td>${escapeHtml(endpoint.id)}</td><td>${escapeHtml(endpoint.address)}</td><td>${formatMs(summary.medianMs)}</td><td>${formatMs(summary.p95Ms)}</td><td>${summary.connectionFailurePercent.toFixed(1)}%</td></tr>`,
    )
    .join('');
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>estrogen ping patch report</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:24px;color:#172035}table{border-collapse:collapse;width:100%}th,td{padding:12px;border:1px solid #ddd;text-align:left}h1{font-size:28px}</style><h1>Network baseline report</h1><p>${escapeHtml(run.startedAt)} | ${escapeHtml(run.status)} | version ${escapeHtml(run.appVersion)}</p><p>Protocol: TCP connection establishment. Connection failures are not a measurement of application packet loss. This run does not measure throughput or loaded latency.</p><table><thead><tr><th>Endpoint</th><th>Address</th><th>Median</th><th>p95</th><th>Connection failures</th></tr></thead><tbody>${rows}</tbody></table><p>No system configuration was changed. No improvement or statistical confidence is inferred from one baseline run.</p></html>`;
}

export function downloadReport(run: BenchmarkRun, format: 'json' | 'html'): void {
  const content = format === 'json' ? JSON.stringify(run, null, 2) : reportHtml(run);
  const url = URL.createObjectURL(
    new Blob([content], { type: format === 'json' ? 'application/json' : 'text/html' }),
  );
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `epp-baseline-${run.id}.${format}`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
