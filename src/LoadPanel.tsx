import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { Config, ProbeProtocol } from './types';
import type { LoadPlan, LoadProgress, LoadRun, TransferProvider } from './load-types';
import { downloadLoadReport, formatMbps, loadNotes, phaseNames } from './load-report';
import { formatProbeMs, sampleLatency } from './measurement';

const mib = 1024 * 1024;

export default function LoadPanel({
  config,
  blocked,
  onRunningChange,
}: {
  config: Config | null;
  blocked: boolean;
  onRunningChange: (running: boolean) => void;
}) {
  const [cloudflare, setCloudflare] = useState(true);
  const [origin, setOrigin] = useState('');
  const [downloadMib, setDownloadMib] = useState(16);
  const [uploadMib, setUploadMib] = useState(4);
  const [streams, setStreams] = useState(1);
  const [latencyProtocol, setLatencyProtocol] =
    useState<Exclude<ProbeProtocol, 'dnsLookup'>>('icmpEcho');
  const [addresses, setAddresses] = useState(['1.1.1.1', '8.8.8.8']);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<LoadProgress | null>(null);
  const [selected, setSelected] = useState<LoadRun | null>(null);
  const [history, setHistory] = useState<LoadRun[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let disposed = false;
    const subscription = listen<LoadProgress>('load-progress', (event) => {
      if (!disposed) setProgress(event.payload);
    });
    invoke<LoadRun[]>('getLoadHistory')
      .then((runs) => {
        if (!disposed) setHistory(runs);
      })
      .catch((error) => {
        if (!disposed) setError(String(error));
      });
    return () => {
      disposed = true;
      void subscription.then((unlisten) => unlisten());
    };
  }, []);

  async function start() {
    if (!config || running || blocked) return;
    const providers: TransferProvider[] = [
      ...(cloudflare ? [{ kind: 'cloudflare' as const }] : []),
      ...(origin.trim() ? [{ kind: 'userOwnedHttp' as const, origin: origin.trim() }] : []),
    ];
    const plan: LoadPlan = {
      providers,
      downloadBytesPerProvider: Math.round(downloadMib * mib),
      uploadBytesPerProvider: Math.round(uploadMib * mib),
      streams,
      phaseTimeoutMs: 30_000,
      idleRounds: 3,
      intervalMs: 250,
      probeTimeoutMs: 500,
      latencyEndpoints: addresses.map((address, index) => ({
        id: `Latency destination ${index + 1}`,
        address,
        protocol: latencyProtocol,
      })),
    };
    setError('');
    setProgress(null);
    setSelected(null);
    setRunning(true);
    onRunningChange(true);
    try {
      const run = await invoke<LoadRun>('runLoadSession', { config, plan });
      setSelected(run);
      setHistory(await invoke<LoadRun[]>('getLoadHistory'));
    } catch (error) {
      setError(String(error));
    } finally {
      setRunning(false);
      onRunningChange(false);
    }
  }

  const providerCount = Number(cloudflare) + Number(Boolean(origin.trim()));
  const disabled = running || blocked;
  return (
    <>
      {error && (
        <div role="alert" className="error">
          <strong>Load session failed</strong>
          <p>{error}</p>
          <button onClick={() => setError('')}>Dismiss</button>
        </div>
      )}
      <div className="two-columns">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Transfer controls</h2>
              <p>Idle baseline, download, upload, then recovery.</p>
            </div>
          </div>
          <div className="form-body">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={cloudflare}
                disabled={disabled}
                onChange={(event) => setCloudflare(event.target.checked)}
              />{' '}
              Use Cloudflare transfer endpoints
            </label>
            <label>
              User-owned benchmark origin (optional)
              <input
                disabled={disabled}
                value={origin}
                placeholder="https://your-benchmark-server.example/"
                onChange={(event) => setOrigin(event.target.value)}
              />
            </label>
            <p className="form-note">
              The owned server must implement the EPP transfer protocol. Public origins require
              HTTPS; plain HTTP is available for literal loopback test servers. Cloudflare uses an
              anycast-selected edge. Selected providers receive your IP address and synthetic test
              traffic.
            </p>
            <div className="input-grid">
              <label>
                Download payload per provider (MiB)
                <input
                  disabled={disabled}
                  type="number"
                  min="0.001"
                  max="512"
                  step="any"
                  value={downloadMib}
                  onChange={(event) => setDownloadMib(Number(event.target.value))}
                />
              </label>
              <label>
                Upload payload per provider (MiB)
                <input
                  disabled={disabled}
                  type="number"
                  min="0.001"
                  max="512"
                  step="any"
                  value={uploadMib}
                  onChange={(event) => setUploadMib(Number(event.target.value))}
                />
              </label>
            </div>
            <label>
              Parallel transfer streams
              <select
                disabled={disabled}
                value={streams}
                onChange={(event) => setStreams(Number(event.target.value))}
              >
                {[1, 2, 3, 4].map((count) => (
                  <option key={count} value={count}>
                    {count}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Concurrent latency protocol
              <select
                disabled={disabled}
                value={latencyProtocol}
                onChange={(event) => {
                  const protocol = event.target.value as Exclude<ProbeProtocol, 'dnsLookup'>;
                  setLatencyProtocol(protocol);
                  setAddresses(
                    protocol === 'icmpEcho' ? ['1.1.1.1', '8.8.8.8'] : ['1.1.1.1:53', '8.8.8.8:53'],
                  );
                }}
              >
                <option value="icmpEcho">ICMP echo RTT</option>
                <option value="tcpConnect">TCP connection establishment</option>
              </select>
            </label>
            {addresses.map((address, index) => (
              <label key={index}>
                Load latency destination {index + 1} (
                {latencyProtocol === 'icmpEcho' ? 'IP' : 'IP:port'})
                <input
                  disabled={disabled}
                  value={address}
                  onChange={(event) =>
                    setAddresses((previous) =>
                      previous.map((value, position) =>
                        position === index ? event.target.value : value,
                      ),
                    )
                  }
                />
              </label>
            ))}
            <p className="form-note">
              Starting can temporarily compete with other traffic. Payload limit:{' '}
              {(downloadMib * providerCount).toFixed(2)} MiB down,{' '}
              {(uploadMib * providerCount).toFixed(2)} MiB up; each direction has a 30-second
              timeout. The total must fit your configured budgets.{' '}
              {providerCount === 1
                ? 'One provider is a baseline only; it is insufficient for provider diversity.'
                : ''}{' '}
              No background tests or settings changes run.
            </p>
            <div className="button-row">
              <button
                className="primary"
                disabled={!config || disabled || providerCount === 0}
                onClick={start}
              >
                Start load session
              </button>
              {running && (
                <button
                  onClick={() => invoke('cancelBaseline').catch((error) => setError(String(error)))}
                >
                  Cancel load session
                </button>
              )}
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>{running ? 'Load session in progress' : 'Transfer report'}</h2>
              <p>
                {running && progress
                  ? `Provider ${progress.providerIndex + 1}/${progress.providerCount}: ${phaseNames[progress.phase]}`
                  : (selected?.status ?? 'Awaiting measurements')}
              </p>
            </div>
          </div>
          <div className="form-body">
            {running && progress && (
              <>
                <p>Download payload read: {progress.downloadBytesRead.toLocaleString()} bytes</p>
                <p>
                  Upload payload queued: {progress.uploadBodyBytesProvided.toLocaleString()} bytes
                </p>
                {progress.sample && (
                  <p>
                    {progress.sample.sample.endpointId}:{' '}
                    {formatProbeMs(sampleLatency(progress.sample.sample), latencyProtocol)}
                  </p>
                )}
              </>
            )}
            <p className="form-note">{loadNotes}</p>
            {selected && (
              <>
                <div className="result-list">
                  {selected.transfers.map(({ providerIndex, phase, result, error }, index) => (
                    <div key={index}>
                      <strong>
                        Provider {providerIndex + 1}: {phaseNames[phase]}
                      </strong>
                      <span>{result?.provider.origin}</span>
                      <span>{result?.status ?? error}</span>
                      <span>Payload goodput {formatMbps(result?.applicationGoodputMbps)}</span>
                      <span>
                        {result?.acceptedPayloadBytes.toLocaleString() ?? 0} accepted bytes
                      </span>
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
                <div className="button-row">
                  <button onClick={() => downloadLoadReport(selected, 'json')}>
                    Export load JSON
                  </button>
                  <button onClick={() => downloadLoadReport(selected, 'html')}>
                    Export load HTML
                  </button>
                </div>
                <div className="result-list">
                  {selected.latencySummaries.map(({ providerIndex, phase, results }) => (
                    <div key={`${providerIndex}-${phase}`}>
                      <strong>
                        Provider {providerIndex + 1}: {phaseNames[phase]} latency
                      </strong>
                      {results.map(({ endpoint, summary }) => (
                        <span key={endpoint.id}>
                          {endpoint.id}: median{' '}
                          {formatProbeMs(summary.medianMs, endpoint.protocol ?? 'tcpConnect')}; p95{' '}
                          {formatProbeMs(summary.p95Ms, endpoint.protocol ?? 'tcpConnect')};{' '}
                          {summary.successful}/{summary.attempted} probes succeeded
                        </span>
                      ))}
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </section>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Saved load sessions</h2>
            <p>Separate from unloaded protocol baselines.</p>
          </div>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>Status</th>
                <th>Providers</th>
                <th>Report</th>
              </tr>
            </thead>
            <tbody>
              {history.map((run) => (
                <tr key={run.id}>
                  <td>{new Date(run.startedAt).toLocaleString()}</td>
                  <td>{run.status}</td>
                  <td>{run.plan.providers.length}</td>
                  <td>
                    <button disabled={running} onClick={() => setSelected(run)}>
                      View load report
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
