import type { BackupExport, BenchmarkRun } from './types';
import {
  dnsAnswerText,
  dnsCountsText,
  failureNames,
  failurePercent,
  formatProbeMs,
  protocolNames,
  protocolNotes,
} from './measurement';
export { formatMs } from './measurement';

export const escapeHtml = (value: unknown): string =>
  String(value).replace(
    /[&<>"']/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!,
  );

export function reportHtml(run: BenchmarkRun): string {
  const metricName = failureNames[run.protocol];
  const protocolName = protocolNames[run.protocol];
  const rows = run.results
    .map(({ endpoint, summary, echoCounts, dnsCounts }) => {
      const errors = dnsCounts
        ? dnsCountsText(dnsCounts)
        : echoCounts
          ? `Timeouts ${echoCounts.timeouts}; IP errors ${echoCounts.ipErrors}; system errors ${echoCounts.osErrors}; invalid replies ${echoCounts.invalidReplies}; unsupported ${echoCounts.unsupported}`
          : '--';
      const dns = run.samples
        .filter((sample) => sample.endpointId === endpoint.id && sample.dns)
        .at(-1)?.dns;
      return `<tr><td>${escapeHtml(endpoint.id)}</td><td>${escapeHtml(endpoint.address)}</td><td>${escapeHtml(formatProbeMs(summary.medianMs, run.protocol))}</td><td>${escapeHtml(formatProbeMs(summary.p95Ms, run.protocol))}</td><td>${failurePercent(summary, run.protocol)}</td><td>${escapeHtml(errors)}${dns ? `<br>Last response: ${escapeHtml(dnsAnswerText(dns))}` : ''}</td></tr>`;
    })
    .join('');
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>estrogen ping patch report</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:24px;color:#172035}table{border-collapse:collapse;width:100%}th,td{padding:12px;border:1px solid #ddd;text-align:left}h1{font-size:28px}</style><h1>Network baseline report</h1><p>${escapeHtml(run.startedAt)} | ${escapeHtml(run.status)} | version ${escapeHtml(run.appVersion)}</p><p>Protocol: ${protocolName}. ${escapeHtml(protocolNotes[run.protocol])}</p><table><thead><tr><th>Endpoint</th><th>Address</th><th>Median</th><th>p95</th><th>${metricName}</th><th>Probe outcomes</th></tr></thead><tbody>${rows}</tbody></table><p>No system configuration was changed. No improvement or statistical confidence is inferred from one baseline run.</p></html>`;
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

export function downloadBackup(backup: BackupExport): void {
  const url = URL.createObjectURL(new Blob([backup.payloadJson], { type: 'application/json' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `epp-network-backup-${backup.summary.id}-${backup.summary.sha256}.json`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
