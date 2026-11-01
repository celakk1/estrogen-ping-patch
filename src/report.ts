import type { BackupExport, BenchmarkRun } from './types';
import { runExplanation, testGuide } from './benchmark-guide';
import {
  dnsAnswerText,
  dnsCountsText,
  failureNames,
  failurePercent,
  formatProbeMs,
  protocolNames,
  protocolNotes,
  routingNote,
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
  const explanation = runExplanation(run);
  const rows = run.results
    .map(
      ({ endpoint, summary }) =>
        `<tr><td>${escapeHtml(endpoint.id)}<br>${escapeHtml(endpoint.address)}</td><td>${escapeHtml(formatProbeMs(summary.medianMs, run.protocol))}</td><td>${summary.successful} of ${summary.attempted}</td></tr>`,
    )
    .join('');
  const technicalRows = run.results
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
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>estrogen ping patch report</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:24px;color:#172035}table{border-collapse:collapse;width:100%}th,td{padding:12px;border:1px solid #ddd;text-align:left;overflow-wrap:anywhere}h1{font-size:28px}details{margin-top:24px}summary{cursor:pointer}</style><h1>Connection test report</h1><p>${escapeHtml(testGuide[run.protocol].title)} | ${escapeHtml(run.startedAt)} | version ${escapeHtml(run.appVersion)}</p><h2>${escapeHtml(explanation.title)}</h2><p>${escapeHtml(explanation.detail)}</p>${run.routing ? `<p>${escapeHtml(routingNote(run.routing))}</p>` : ''}<p>${escapeHtml(testGuide[run.protocol].measures)}</p><p>Times are shown in ms (milliseconds). Lower times mean faster replies, connections, or lookups. Typical time is the middle result of the successful checks.</p><table><thead><tr><th>Test server</th><th>Typical time</th><th>Successful checks</th></tr></thead><tbody>${rows}</tbody></table><details><summary>Technical details</summary><p>Measurement: ${protocolName}. ${escapeHtml(protocolNotes[run.protocol])}</p><p>p95 describes the slower end of the results: about 95% of successful checks were at or below this time.</p><table><thead><tr><th>Server</th><th>Address</th><th>Typical time (median)</th><th>Slower responses (p95)</th><th>${metricName}</th><th>Check details</th></tr></thead><tbody>${technicalRows}</tbody></table><p>Recorded status: ${escapeHtml(run.status)}</p></details><p>This test did not change network settings. One test cannot show whether a change would improve your connection.</p></html>`;
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
