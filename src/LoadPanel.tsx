import { useEffect, useState } from 'react';
import { Activity, Play, Square } from 'iconoir-react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { Config, ProbeProtocol } from './types';
import type { LoadPlan, LoadProgress, LoadRun, TransferProvider } from './load-types';
import LoadResults, { dataAmount, loadStages, LoadLatencyComparison } from './LoadResults';
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
  const downloadBytes = Math.round(downloadMib * mib) * providerCount;
  const uploadBytes = Math.round(uploadMib * mib) * providerCount;
  const validSize = [downloadMib, uploadMib].every(
    (value) => Number.isFinite(value) && value >= 0.001 && value <= 512,
  );
  const overBudget = Boolean(
    config && (downloadBytes > config.maxDownloadBytes || uploadBytes > config.maxUploadBytes),
  );
  const preset =
    downloadMib === 16 && uploadMib === 4
      ? 'quick'
      : downloadMib === 64 && uploadMib === 16
        ? 'longer'
        : 'custom';
  return (
    <>
      {error && (
        <div role="alert" className="error">
          <strong>Test could not finish</strong>
          <p>{error}</p>
          <button onClick={() => setError('')}>Dismiss</button>
        </div>
      )}
      <div className="load-stages" aria-label="Test stages">
        {loadStages.map((stage, index) => (
          <div
            key={stage.phase}
            className={running && progress?.phase === stage.phase ? 'active' : ''}
            aria-current={running && progress?.phase === stage.phase ? 'step' : undefined}
          >
            <span className="stage-number">{index + 1}</span>
            <div>
              <strong>{stage.title}</strong>
              <p>{stage.description}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="two-columns benchmark-layout">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Check your speed</h2>
              <p>Measure speed and delay during downloads and uploads.</p>
            </div>
          </div>
          <div className="form-body">
            <label>
              Test size
              <select
                disabled={disabled}
                value={preset}
                onChange={(event) => {
                  if (event.target.value === 'quick') {
                    setDownloadMib(16);
                    setUploadMib(4);
                  } else if (event.target.value === 'longer') {
                    setDownloadMib(64);
                    setUploadMib(16);
                  }
                }}
              >
                <option value="quick">Quick (about 21 MB per test server)</option>
                <option value="longer">More data (about 84 MB per test server)</option>
                <option value="custom" disabled>
                  Custom size (set in Advanced settings)
                </option>
              </select>
            </label>
            <div className="test-facts">
              <div>
                <span>Speed test server{providerCount === 1 ? '' : 's'}</span>
                <strong>
                  {cloudflare ? 'Cloudflare' : ''}
                  {cloudflare && origin.trim() ? ', ' : ''}
                  {origin.trim() ? 'Your server' : ''}
                  {providerCount === 0 ? 'None selected' : ''}
                </strong>
              </div>
              <div>
                <span>Maximum test data</span>
                <strong>{dataAmount(downloadBytes + uploadBytes)}</strong>
              </div>
              <div>
                <span>Time limit</span>
                <strong>30 seconds for each direction</strong>
              </div>
            </div>
            <p className="form-note">
              This test can temporarily slow other downloads, calls, or games.
            </p>
            {!validSize && (
              <p role="status" className="transfer-error">
                Enter valid download and upload sizes in Advanced settings.
              </p>
            )}
            {overBudget && (
              <p role="status" className="transfer-error">
                This size exceeds your data limits ({dataAmount(config?.maxDownloadBytes ?? 0)}{' '}
                download and {dataAmount(config?.maxUploadBytes ?? 0)} upload). Choose a smaller
                test or reduce the sizes in Advanced settings.
              </p>
            )}
            {providerCount === 0 && (
              <p role="status" className="transfer-error">
                Choose at least one test server in Advanced settings.
              </p>
            )}
            {blocked && (
              <p role="status" className="form-note">
                Wait for the current connection test, backup, or service action to finish.
              </p>
            )}
            <div className="button-row">
              <button
                className="primary"
                disabled={!config || disabled || providerCount === 0 || !validSize || overBudget}
                onClick={start}
              >
                {running ? <Activity /> : <Play />}
                {running ? 'Test running...' : 'Start speed test'}
              </button>
              {running && (
                <button
                  onClick={() => invoke('cancelBaseline').catch((error) => setError(String(error)))}
                >
                  <Square />
                  Stop speed test
                </button>
              )}
            </div>
            <p className="field-help">
              Selected servers receive your IP address. The limit counts test data. Connection
              messages add to the actual data used.
            </p>
            <details className="advanced-settings">
              <summary>
                Advanced settings<span>Test servers, data limits, and response checks</span>
              </summary>
              <div className="advanced-body">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={cloudflare}
                    disabled={disabled}
                    onChange={(event) => setCloudflare(event.target.checked)}
                  />
                  Use Cloudflare for the speed test
                </label>
                <label>
                  Your own test server URL (optional)
                  <input
                    disabled={disabled}
                    value={origin}
                    placeholder="https://your-benchmark-server.example/"
                    onChange={(event) => setOrigin(event.target.value)}
                  />
                </label>
                <p className="form-note">
                  Leave this blank to use Cloudflare. To use your own server, it must support the
                  app's transfer protocol; an ordinary website or game server will not work here.
                  Use HTTPS, except for local test servers. Results from one provider do not
                  describe every route.
                </p>
                <div className="input-grid">
                  <label>
                    Download amount per server (MiB)
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
                    Upload amount per server (MiB)
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
                <p className="field-help">
                  MiB is a data-size unit, slightly larger than MB. These settings allow up to{' '}
                  {dataAmount(downloadBytes)} downloaded and {dataAmount(uploadBytes)} uploaded
                  across your selected servers.
                </p>
                <label>
                  Transfers at the same time
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
                  <span className="field-help">
                    How many transfers run at the same time. More streams do not guarantee a better
                    connection.
                  </span>
                </label>
                <label>
                  How to check response time
                  <select
                    disabled={disabled}
                    value={latencyProtocol}
                    onChange={(event) => {
                      const protocol = event.target.value as Exclude<ProbeProtocol, 'dnsLookup'>;
                      setLatencyProtocol(protocol);
                      setAddresses(
                        protocol === 'icmpEcho'
                          ? ['1.1.1.1', '8.8.8.8']
                          : ['1.1.1.1:53', '8.8.8.8:53'],
                      );
                    }}
                  >
                    <option value="icmpEcho">Ping (ICMP)</option>
                    <option value="tcpConnect">Opening a connection (TCP)</option>
                  </select>
                </label>
                {addresses.map((address, index) => (
                  <label key={index}>
                    Response test server {index + 1} (
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
                  Response checks contact Cloudflare and Google by default, separately from the
                  speed test server. Some networks limit or block ping replies. Missing replies do
                  not directly measure lost game traffic.
                </p>
              </div>
            </details>
          </div>
        </section>
        <section className="panel" aria-live="polite">
          <div className="panel-heading">
            <div>
              <h2>{running ? 'Your speed test is running' : 'Your speed test results'}</h2>
              <p>
                {running && progress
                  ? `Test server ${progress.providerIndex + 1} of ${progress.providerCount}: ${loadStages.find((stage) => stage.phase === progress.phase)?.title}`
                  : selected
                    ? new Date(selected.startedAt).toLocaleString()
                    : 'Transfer speeds and response times appear here.'}
              </p>
            </div>
          </div>
          <div className="form-body">
            {running ? (
              <>
                <h3>
                  {progress
                    ? loadStages.find((stage) => stage.phase === progress.phase)?.title
                    : 'Preparing the test...'}
                </h3>
                <p>
                  Each stage checks response times to the same servers. Short transfers may finish
                  before enough replies arrive.
                </p>
                {progress?.sample && (
                  <p className="live-reading">
                    Latest response:{' '}
                    <strong>
                      {formatProbeMs(sampleLatency(progress.sample.sample), latencyProtocol)}
                    </strong>
                  </p>
                )}
                <details className="result-details">
                  <summary>Technical details</summary>
                  <p>Download data received: {dataAmount(progress?.downloadBytesRead ?? 0)}</p>
                  <p>
                    Upload data prepared: {dataAmount(progress?.uploadBodyBytesProvided ?? 0)}. The
                    server may not have received all of it yet.
                  </p>
                </details>
              </>
            ) : selected ? (
              <LoadResults run={selected} />
            ) : (
              <div className="results-empty">
                <div className="empty-result-mark" aria-hidden="true">
                  <span />
                  <span />
                  <span />
                </div>
                <h3>See what changes when traffic starts</h3>
                <p>
                  Select <strong>Start speed test</strong>. We check response times before the
                  transfers, during download and upload, and afterward.
                </p>
                <dl>
                  <dt>Download / upload</dt>
                  <dd>How quickly this test moves data. Higher Mbps means faster transfers.</dd>
                  <dt>Response time</dt>
                  <dd>How quickly a test server replies, shown in milliseconds.</dd>
                  <dt>Before and after</dt>
                  <dd>
                    Compare replies before and after transfers to see whether the delay settles back
                    down.
                  </dd>
                </dl>
              </div>
            )}
          </div>
        </section>
      </div>
      {selected && !running && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Response times before, during, and after</h2>
              <p>
                Compare each row from left to right. Higher times during a transfer mean slower
                replies while data is moving.
              </p>
            </div>
          </div>
          <LoadLatencyComparison run={selected} />
        </section>
      )}
      <section className="panel load-history">
        <div className="panel-heading">
          <div>
            <h2>Previous speed tests</h2>
            <p>Open a saved report to review its speeds and response times.</p>
          </div>
        </div>
        {history.length === 0 ? (
          <div className="form-body">
            <p>No speed tests saved yet. Finished or stopped tests will appear here.</p>
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Result</th>
                  <th>Test servers</th>
                  <th>Report</th>
                </tr>
              </thead>
              <tbody>
                {history.map((run) => (
                  <tr key={run.id}>
                    <td>{new Date(run.startedAt).toLocaleString()}</td>
                    <td>
                      {run.status === 'completed'
                        ? 'Finished'
                        : run.status === 'cancelled'
                          ? 'Stopped'
                          : 'Incomplete'}
                    </td>
                    <td>{run.plan.providers.length}</td>
                    <td>
                      <button disabled={running} onClick={() => setSelected(run)}>
                        View report
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
