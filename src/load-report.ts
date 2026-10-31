import { escapeHtml } from './report';
import { formatProbeMs } from './measurement';
import type { LoadPhase, LoadRun } from './load-types';

export const phaseNames: Record<LoadPhase, string> = {
  idle: 'Before traffic',
  download: 'Downloading',
  upload: 'Uploading',
  recovery: 'After traffic',
};
export const formatMbps = (value: number | null | undefined): string =>
  value == null || !Number.isFinite(value) ? 'Unavailable' : `${value.toFixed(2)} Mbps`;
export const loadNotes =
  'Application payload goodput includes connection setup, TLS, and server time; it is not a link-capacity estimate or the provider website score. Concurrent latency summaries include probes overlapping in-flight requests or observed payload progress. Fast or limited transfers may provide too few concurrent samples. Saturation is not guaranteed. Upload bytes queued to the HTTP client are separate from accepted payload. Headers, TLS overhead, retransmissions, and latency probes are outside the payload budget. No optimization or statistical improvement is inferred from this session.';

export function loadReportHtml(run: LoadRun): string {
  const rows = run.transfers
    .map(
      ({ providerIndex, phase, result, error }) =>
        `<tr><td>${providerIndex + 1}</td><td>${phaseNames[phase]}</td><td>${escapeHtml(result?.provider.origin ?? '')}</td><td>${escapeHtml(result?.status === 'completed' ? 'Finished' : result?.status === 'cancelled' ? 'Stopped early' : (error ?? 'Incomplete'))}</td><td>${formatMbps(result?.applicationGoodputMbps)}</td><td>${result?.acceptedPayloadBytes ?? 0}</td></tr>`,
    )
    .join('');
  const latency = run.latencySummaries
    .map(
      ({ providerIndex, phase, results }) =>
        `<h3>Test server ${providerIndex + 1}: ${phaseNames[phase]}</h3><ul>${results.map(({ endpoint, summary }) => `<li>${escapeHtml(endpoint.id)} (${escapeHtml(endpoint.address)}): typical time ${escapeHtml(formatProbeMs(summary.medianMs, endpoint.protocol ?? 'tcpConnect'))}; slower responses (p95) ${escapeHtml(formatProbeMs(summary.p95Ms, endpoint.protocol ?? 'tcpConnect'))}; ${summary.successful} of ${summary.attempted} checks answered</li>`).join('')}</ul>`,
    )
    .join('');
  const status = run.status === 'completed' ? 'Test finished' : 'This test did not finish';
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>estrogen ping patch speed test report</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px;color:#172035}table{border-collapse:collapse;width:100%}th,td{padding:10px;border:1px solid #ddd;text-align:left;overflow-wrap:anywhere}details{margin-top:24px}summary{cursor:pointer}</style><h1>Speed test report</h1><p>${escapeHtml(run.startedAt)} | version ${escapeHtml(run.appVersion)}</p><h2>${status}</h2><p>${run.status === 'completed' ? 'Compare reply times before, during, and after downloading or uploading. Repeat the test to see whether results are consistent.' : 'Some results may be missing. Check the transfer status and Technical details before comparing this test.'}</p><p>Higher Mbps means faster transfers. Lower ms (milliseconds) means faster replies. Higher response times during a transfer mean slower replies while data is moving.</p><table><thead><tr><th>Test server</th><th>Stage</th><th>Server URL</th><th>Transfer status</th><th>Measured speed</th><th>Bytes transferred</th></tr></thead><tbody>${rows}</tbody></table><h2>Response times before, during, and after</h2><p>Typical time is the middle successful result. p95 describes the slower end: about 95% of successful checks were at or below this time.</p>${latency}<details><summary>Technical details</summary><p>Recorded status: ${escapeHtml(run.status)}</p><p>${loadNotes}</p><p>Raw transfer details and individual response checks are available in the JSON export.</p></details><p>This test did not change Windows network settings.</p></html>`;
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
