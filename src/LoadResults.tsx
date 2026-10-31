import type { LoadPhase, LoadRun } from './load-types';
import { downloadLoadReport, formatMbps, loadNotes } from './load-report';
import { formatProbeMs } from './measurement';

export const loadStages: { phase: LoadPhase; title: string; description: string }[] = [
  { phase: 'idle', title: 'Before traffic', description: 'Check response times first.' },
  { phase: 'download', title: 'Downloading', description: 'Receive test data and check replies.' },
  { phase: 'upload', title: 'Uploading', description: 'Send test data and check replies.' },
  { phase: 'recovery', title: 'After traffic', description: 'Check response times again.' },
];

export function dataAmount(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return 'Set a valid data size';
  return `${(bytes / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 1 })} MB`;
}

export default function LoadResults({ run }: { run: LoadRun }) {
  return (
    <>
      <div className="result-explanation">
        <h3>
          {run.status === 'completed'
            ? 'Test finished'
            : run.status === 'cancelled'
              ? 'Test stopped early'
              : 'This test was incomplete'}
        </h3>
        <p>
          {run.status === 'completed'
            ? 'Compare replies before, during, and after downloading or uploading. Repeat the test to see whether the results are consistent.'
            : 'Some results may be missing. Open Technical details to see which transfers did not finish.'}
        </p>
      </div>
      <p className="measurement-key">
        <strong>Mbps</strong> measures transfer speed; higher is faster. <strong>ms</strong>{' '}
        measures delay; lower means faster replies.
      </p>
      <div className="transfer-cards">
        {run.transfers.map(({ providerIndex, phase, result, error }, index) => (
          <article className="server-result" key={index}>
            <div className="server-result-heading">
              <h3>{phase === 'download' ? 'Download' : 'Upload'}</h3>
              <span className="result-timing">{formatMbps(result?.applicationGoodputMbps)}</span>
            </div>
            <p>{result?.provider.origin ?? `Test server ${providerIndex + 1}`}</p>
            <span>
              {result?.status === 'completed'
                ? `${dataAmount(result.acceptedPayloadBytes)} transferred`
                : result?.status === 'cancelled'
                  ? 'Transfer stopped'
                  : 'Transfer incomplete'}
            </span>
            {error && <p className="transfer-error">{error}</p>}
          </article>
        ))}
      </div>
      <p className="form-note">
        The speed includes time spent connecting and waiting for the server. A short test may end
        before your connection reaches full speed or enough response checks finish.
      </p>
      <div className="button-row report-actions">
        <button onClick={() => downloadLoadReport(run, 'html')}>Save report</button>
        <button onClick={() => downloadLoadReport(run, 'json')}>Export raw data (JSON)</button>
      </div>
      <details className="advanced-settings">
        <summary>
          Technical details<span>Raw outcomes, streams, and measurement limits</span>
        </summary>
        <div className="advanced-body">
          <p className="form-note">{loadNotes}</p>
          <div className="result-list">
            {run.transfers.map(({ providerIndex, phase, result, error }, index) => (
              <div key={index}>
                <strong>
                  Provider {providerIndex + 1}: {phase}
                </strong>
                <span>Status: {result?.status ?? error}</span>
                <span>{result?.acceptedPayloadBytes.toLocaleString() ?? 0} accepted bytes</span>
                {result?.streams
                  .filter((stream) => stream.error)
                  .map((stream) => (
                    <span key={stream.ordinal}>
                      Stream {stream.ordinal + 1}: {stream.error}
                      {stream.retryAfter ? `; retry-after ${stream.retryAfter}` : ''}
                    </span>
                  ))}
              </div>
            ))}
          </div>
        </div>
      </details>
    </>
  );
}

export function LoadLatencyComparison({ run }: { run: LoadRun }) {
  return (
    <div className="form-body">
      {run.plan.providers.map((provider, providerIndex) => (
        <section key={providerIndex} className="phase-results">
          <h3>{provider.kind === 'cloudflare' ? 'Cloudflare test' : 'Your test server'}</h3>
          <p className="form-note">
            Each number is the typical response time for that stage: the middle result of the
            successful checks. Compare the same row across all four stages.
          </p>
          <div className="table-scroll">
            <table
              className="phase-table"
              aria-label={`Response times by stage for test server ${providerIndex + 1}`}
            >
              <thead>
                <tr>
                  <th>Response test server</th>
                  {loadStages.map((stage) => (
                    <th key={stage.phase}>{stage.title}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {run.plan.latencyEndpoints.map((endpoint) => (
                  <tr key={endpoint.id}>
                    <th scope="row">
                      {endpoint.id}
                      <small>{endpoint.address}</small>
                    </th>
                    {loadStages.map(({ phase }) => {
                      const result = run.latencySummaries
                        .find(
                          (summary) =>
                            summary.providerIndex === providerIndex && summary.phase === phase,
                        )
                        ?.results.find(
                          (result) =>
                            result.endpoint.id === endpoint.id &&
                            result.endpoint.address === endpoint.address,
                        );
                      return (
                        <td key={phase}>
                          {result?.summary.medianMs != null
                            ? formatProbeMs(
                                result.summary.medianMs,
                                endpoint.protocol ?? 'tcpConnect',
                              )
                            : 'No response time measured'}
                          <small>
                            {result
                              ? `${result.summary.successful}/${result.summary.attempted} checks answered`
                              : 'No checks recorded'}
                          </small>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </div>
  );
}
