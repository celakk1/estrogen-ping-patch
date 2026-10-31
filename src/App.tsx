import { useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type {
  AppStatus,
  BackupExport,
  BackupPayload,
  BackupSummary,
  BenchmarkRun,
  Config,
  Inventory,
  Profile,
  Progress,
  Sample,
} from './types';
import { downloadBackup, downloadReport, formatMs } from './report';

type View = 'overview' | 'inventory' | 'history' | 'backups' | 'policy';
const profiles: Profile[] = ['latency', 'balanced', 'download'];

function LatencyChart({ samples }: { samples: Sample[] }) {
  const valid = samples.filter((sample) => sample.connectMs != null);
  const maximum = Math.max(10, ...valid.map((sample) => sample.connectMs!));
  const endpoints = [...new Set(samples.map((sample) => sample.endpointId))];
  return (
    <div className="chart">
      <div className="chart-axis">
        <span>{maximum.toFixed(0)} ms</span>
        <span>0 ms</span>
      </div>
      <svg
        viewBox="0 0 900 180"
        role="img"
        aria-label="Measured TCP connection establishment times"
      >
        {[30, 90, 150].map((y) => (
          <line key={y} x1="0" x2="900" y1={y} y2={y} stroke="currentColor" opacity="0.15" />
        ))}
        {endpoints.map((endpoint, index) => {
          const matching = samples.filter((sample) => sample.endpointId === endpoint);
          const points = matching.map((sample, point) =>
            sample.connectMs == null
              ? null
              : `${20 + (point * 860) / Math.max(matching.length - 1, 1)},${165 - (sample.connectMs / maximum) * 150}`,
          );
          const segments: string[][] = [[]];
          points.forEach((point) => {
            if (point == null) segments.push([]);
            else segments[segments.length - 1].push(point);
          });
          return (
            <g
              key={endpoint}
              stroke={index === 0 ? '#db8bb6' : '#91b9e7'}
              fill="none"
              strokeWidth="2.5"
            >
              {segments
                .filter((segment) => segment.length > 1)
                .map((segment, segmentIndex) => (
                  <polyline key={segmentIndex} points={segment.join(' ')} />
                ))}
              {points
                .filter((point): point is string => point != null)
                .map((point, pointIndex) => {
                  const [x, y] = point.split(',');
                  return <circle key={pointIndex} cx={x} cy={y} r="3" />;
                })}
            </g>
          );
        })}
      </svg>
      {samples.length === 0 && (
        <div className="chart-empty">
          Your measurements will appear here after a baseline starts.
        </div>
      )}
      <div className="legend">
        {endpoints.map((endpoint, index) => (
          <span key={endpoint} className={index === 0 ? 'pink' : 'blue'}>
            {endpoint}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState<View>('overview');
  const [appStatus, setAppStatus] = useState<AppStatus | null>(null);
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [config, setConfig] = useState<Config | null>(null);
  const [history, setHistory] = useState<BenchmarkRun[]>([]);
  const [backups, setBackups] = useState<BackupSummary[]>([]);
  const [capturingBackup, setCapturingBackup] = useState(false);
  const [backupNotice, setBackupNotice] = useState('');
  const [selectedBackup, setSelectedBackup] = useState<BackupExport | null>(null);
  const [selected, setSelected] = useState<BenchmarkRun | null>(null);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [running, setRunning] = useState(false);
  const [loadingInventory, setLoadingInventory] = useState(false);
  const [error, setError] = useState('');
  const [firstAddress, setFirstAddress] = useState('1.1.1.1:53');
  const [secondAddress, setSecondAddress] = useState('8.8.8.8:53');
  const [light, setLight] = useState(false);
  const runRef = useRef(false);

  async function refreshInventory() {
    setLoadingInventory(true);
    try {
      setInventory(await invoke<Inventory>('getInventory'));
    } catch (error) {
      setError(String(error));
    } finally {
      setLoadingInventory(false);
    }
  }

  async function captureBackup() {
    if (running || capturingBackup) return;
    setCapturingBackup(true);
    setBackupNotice('');
    setError('');
    try {
      const summary = await invoke<BackupSummary>('captureBackup');
      setBackups(await invoke<BackupSummary[]>('getBackups'));
      setSelectedBackup(await invoke<BackupExport>('exportBackup', { id: summary.id }));
    } catch (error) {
      if (String(error).includes('cancelled'))
        setBackupNotice('Capture cancelled. Existing backups were preserved.');
      else setError(String(error));
    } finally {
      setCapturingBackup(false);
    }
  }

  async function openBackup(id: number, exportFile = false) {
    try {
      const backup = await invoke<BackupExport>('exportBackup', { id });
      setSelectedBackup(backup);
      if (exportFile) downloadBackup(backup);
    } catch (error) {
      setError(String(error));
    }
  }

  useEffect(() => {
    let active = true;
    invoke<AppStatus>('status')
      .then((status) => {
        if (active) {
          setAppStatus(status);
          setConfig(status.config);
        }
      })
      .catch((error) => {
        if (active) setError(String(error));
      });
    invoke<BenchmarkRun[]>('getHistory')
      .then((history) => {
        if (active) setHistory(history);
      })
      .catch((error) => {
        if (active) setError(String(error));
      });
    invoke<BackupSummary[]>('getBackups')
      .then((backups) => {
        if (active) setBackups(backups);
      })
      .catch((error) => {
        if (active) setError(String(error));
      });
    refreshInventory();
    const unlisten = listen<Progress>('benchmark-progress', (event) => {
      if (!active || !runRef.current) return;
      setProgress(event.payload);
      setSamples((previous) => [...previous, event.payload.sample]);
    });
    return () => {
      active = false;
      unlisten.then((stop) => stop()).catch(() => {});
    };
  }, []);

  async function startBaseline() {
    if (!config || running || capturingBackup) return;
    setError('');
    setSamples([]);
    setProgress(null);
    setSelected(null);
    setRunning(true);
    runRef.current = true;
    try {
      const run = await invoke<BenchmarkRun>('runBaseline', {
        config,
        endpoints: [
          {
            id: firstAddress === '1.1.1.1:53' ? 'Cloudflare DNS' : 'First destination',
            address: firstAddress,
          },
          {
            id: secondAddress === '8.8.8.8:53' ? 'Google Public DNS' : 'Second destination',
            address: secondAddress,
          },
        ],
      });
      setSelected(run);
      setSamples(run.samples);
      setHistory(await invoke<BenchmarkRun[]>('getHistory'));
    } catch (error) {
      setError(String(error));
    } finally {
      setRunning(false);
      runRef.current = false;
    }
  }

  const activeAdapters = inventory?.adapters.filter((adapter) => adapter.status === 'Up') ?? [];
  const primary = selected?.results[0]?.summary;
  const shownSamples = selected?.samples ?? samples;
  const completed = progress?.completed ?? 0;
  const percent = progress ? Math.round((completed / progress.total) * 100) : 0;
  const backupPayload = useMemo<BackupPayload | null>(
    () => (selectedBackup ? JSON.parse(selectedBackup.payloadJson) : null),
    [selectedBackup],
  );

  return (
    <div className={`app ${light ? 'light' : ''}`}>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">ep</span>
          <div>
            estrogen<span>ping patch</span>
          </div>
        </div>
        <div className="workspace-label">NETWORK WORKSPACE</div>
        <nav>
          {(
            [
              ['overview', 'Overview'],
              ['inventory', 'System inventory'],
              ['history', 'Benchmark history'],
              ['backups', 'Configuration backups'],
              ['policy', 'Safety & policy'],
            ] as const
          ).map(([key, title]) => (
            <button key={key} className={view === key ? 'active' : ''} onClick={() => setView(key)}>
              <span className={`nav-mark ${key}`} />
              {title}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="status-dot" />
          Local by default<p>AI disabled. No cloud spend.</p>
          <button className="text-button" onClick={() => setLight(!light)}>
            Switch to {light ? 'dark' : 'light'} theme
          </button>
          <small>Development preview {appStatus?.version ?? ''}</small>
        </div>
      </aside>
      <main>
        <header>
          <div className="breadcrumb">
            Workspace <span>/</span>{' '}
            {view === 'overview'
              ? 'Overview'
              : view === 'inventory'
                ? 'System inventory'
                : view === 'history'
                  ? 'Benchmark history'
                  : view === 'backups'
                    ? 'Configuration backups'
                    : 'Safety & policy'}
          </div>
          <div className="pill">
            <i /> {appStatus ? 'Local service ready' : 'Connecting to desktop'}
          </div>
        </header>
        <div className="content">
          {error && (
            <div role="alert" className="error">
              <strong>Action failed</strong>
              <p>{error}</p>
              <button onClick={() => setError('')}>Dismiss</button>
            </div>
          )}
          <section className="page-heading">
            <div>
              <div className="eyebrow">MEASURE. EXPERIMENT. VALIDATE.</div>
              <h1>
                {view === 'overview'
                  ? 'Know your connection.'
                  : view === 'inventory'
                    ? 'System inventory'
                    : view === 'history'
                      ? 'Your measurement history'
                      : view === 'backups'
                        ? 'Preserve your starting point.'
                        : 'Safety comes first.'}
              </h1>
              <p>
                {view === 'overview'
                  ? 'Build an honest baseline before changing anything.'
                  : view === 'inventory'
                    ? 'Read-only Windows discovery, captured locally.'
                    : view === 'history'
                      ? 'Raw samples and reports stay on this computer.'
                      : view === 'backups'
                        ? 'Read-only settings snapshots, stored locally and checked before export.'
                        : 'Bounded operations, explicit authorization, and reversible changes.'}
              </p>
            </div>
            <span className="badge">READ-ONLY PREVIEW</span>
          </section>
          {view === 'overview' && (
            <>
              <div className="metrics">
                <article>
                  <label>ACTIVE ADAPTERS</label>
                  <strong>{inventory ? activeAdapters.length : '--'}</strong>
                  <span>
                    {activeAdapters[0]?.name ??
                      (loadingInventory ? 'Discovering interfaces' : 'No active adapter found')}
                  </span>
                </article>
                <article>
                  <label>TCP CONNECT MEDIAN</label>
                  <strong>{formatMs(primary?.medianMs)}</strong>
                  <span>{selected?.results[0]?.endpoint.id ?? 'Run a baseline to measure'}</span>
                </article>
                <article>
                  <label>CONNECTION FAILURES</label>
                  <strong>
                    {primary ? `${primary.connectionFailurePercent.toFixed(1)}%` : '--'}
                  </strong>
                  <span>TCP attempts, protocol specific</span>
                </article>
                <article>
                  <label>RETAINED CHANGES</label>
                  <strong>0</strong>
                  <span>Original configuration preserved</span>
                </article>
              </div>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Connection timeline</h2>
                    <p>TCP establishment time across independent destinations</p>
                  </div>
                  <span className="pill">
                    {running ? 'Measuring' : (selected?.status ?? 'Awaiting baseline')}
                  </span>
                </div>
                <LatencyChart samples={shownSamples} />
                <div className="chart-note">
                  Connection time includes TCP handshake overhead. This is not a throughput, ICMP
                  loss, or loaded-latency test.
                </div>
              </section>
              <div className="two-columns">
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Baseline controls</h2>
                      <p>Small, bounded probes. No configuration changes.</p>
                    </div>
                  </div>
                  <div className="form-body">
                    <label>Optimization profile</label>
                    <div className="segmented">
                      {profiles.map((profile) => (
                        <button
                          disabled={running}
                          className={config?.profile === profile ? 'chosen' : ''}
                          key={profile}
                          onClick={() => config && setConfig({ ...config, profile })}
                        >
                          {profile}
                        </button>
                      ))}
                    </div>
                    <p className="form-note">
                      Profile is recorded for future comparisons. A baseline does not rank or change
                      settings.
                    </p>
                    <div className="input-grid">
                      <label>
                        Samples per endpoint
                        <input
                          type="number"
                          min="3"
                          max="120"
                          disabled={running}
                          value={config?.sampleCount ?? 12}
                          onChange={(event) =>
                            config &&
                            setConfig({ ...config, sampleCount: Number(event.target.value) })
                          }
                        />
                      </label>
                      <label>
                        Time budget (minutes)
                        <input
                          type="number"
                          min="1"
                          max="1440"
                          disabled={running}
                          value={config?.sessionMinutes ?? 15}
                          onChange={(event) =>
                            config &&
                            setConfig({ ...config, sessionMinutes: Number(event.target.value) })
                          }
                        />
                      </label>
                    </div>
                    <label>
                      First destination (IP:port)
                      <input
                        disabled={running}
                        value={firstAddress}
                        onChange={(event) => setFirstAddress(event.target.value)}
                      />
                    </label>
                    <label>
                      Second destination (IP:port)
                      <input
                        disabled={running}
                        value={secondAddress}
                        onChange={(event) => setSecondAddress(event.target.value)}
                      />
                    </label>
                    <p className="form-note">
                      Starting sends TCP probes to these addresses. Change them only to endpoints
                      you are permitted to test.
                    </p>
                    <div className="button-row">
                      <button
                        className="primary"
                        disabled={!config || running || capturingBackup}
                        onClick={startBaseline}
                      >
                        Start baseline
                      </button>
                      {running && (
                        <button
                          onClick={() =>
                            invoke('cancelBaseline').catch((error) => setError(String(error)))
                          }
                        >
                          Cancel measurement
                        </button>
                      )}
                    </div>
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>
                        {running
                          ? 'Baseline in progress'
                          : selected
                            ? 'Measurement report'
                            : 'A measured starting point'}
                      </h2>
                      <p>
                        {running
                          ? `${completed} of ${progress?.total ?? '--'} attempts`
                          : 'Evidence before recommendations'}
                      </p>
                    </div>
                  </div>
                  <div className="form-body">
                    {running ? (
                      <>
                        <div className="progress-bar">
                          <div style={{ width: `${percent}%` }} />
                        </div>
                        <p>
                          Estimated remaining:{' '}
                          {progress
                            ? `${progress.remainingLowSeconds}-${progress.remainingHighSeconds} seconds`
                            : 'estimating after first sample'}
                        </p>
                        <p className="form-note">
                          The range adapts to observed durations and connection timeouts.
                        </p>
                      </>
                    ) : selected ? (
                      <>
                        <div className="result-list">
                          {selected.results.map(({ endpoint, summary }) => (
                            <div key={endpoint.id}>
                              <strong>{endpoint.id}</strong>
                              <span>Median {formatMs(summary.medianMs)}</span>
                              <span>
                                p95 {formatMs(summary.p95Ms)} / p99 {formatMs(summary.p99Ms)}
                              </span>
                              <span>
                                Successive variation {formatMs(summary.successiveVariationMs)}
                              </span>
                              <span>
                                {summary.successful}/{summary.attempted} successful connections
                              </span>
                            </div>
                          ))}
                        </div>
                        <div className="button-row">
                          <button onClick={() => downloadReport(selected, 'json')}>
                            Export JSON
                          </button>
                          <button onClick={() => downloadReport(selected, 'html')}>
                            Export HTML
                          </button>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="empty-visual">
                          <span />
                          <span />
                          <span />
                          <span />
                          <span />
                        </div>
                        <h3>Your network, measured.</h3>
                        <p>
                          Collect a baseline, inspect failures, and keep the raw evidence. A single
                          run cannot establish an optimization benefit.
                        </p>
                        <div className="notice">
                          Setting changes are unavailable in this preview while the service and
                          recovery safeguards are developed.
                        </div>
                      </>
                    )}
                  </div>
                </section>
              </div>
            </>
          )}
          {view === 'inventory' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Windows network discovery</h2>
                  <p>
                    {inventory
                      ? `Windows ${inventory.os.version}, build ${inventory.os.build} | ${inventory.os.architecture}`
                      : 'Waiting for Windows inventory'}
                  </p>
                </div>
                <button disabled={loadingInventory} onClick={refreshInventory}>
                  {loadingInventory ? 'Refreshing...' : 'Refresh inventory'}
                </button>
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Interface</th>
                      <th>State</th>
                      <th>Media</th>
                      <th>Link speed</th>
                      <th>Driver</th>
                    </tr>
                  </thead>
                  <tbody>
                    {inventory?.adapters.map((adapter) => (
                      <tr key={adapter.id}>
                        <td>
                          <strong>{adapter.name}</strong>
                          <small>{adapter.description}</small>
                          <small>{adapter.id}</small>
                        </td>
                        <td>{adapter.status}</td>
                        <td>{adapter.mediaType}</td>
                        <td>{adapter.linkSpeed}</td>
                        <td>{adapter.driverVersion || 'Unavailable'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="form-body">
                <h3>Default routes</h3>
                {inventory?.routes.map((route, index) => (
                  <p key={index}>
                    Interface {route.interfaceIndex} / {route.destination} / gateway {route.nextHop}{' '}
                    / route metric {route.routeMetric}
                  </p>
                ))}
                <h3>Configured DNS resolvers</h3>
                {inventory?.dns.map((dns, index) => (
                  <p key={index}>
                    Interface {dns.interfaceIndex}: {dns.servers.join(', ')}
                  </p>
                ))}
                {inventory?.limitations.map((limitation) => (
                  <p className="form-note" key={limitation}>
                    {limitation}
                  </p>
                ))}
              </div>
            </section>
          )}
          {view === 'history' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Saved baseline runs</h2>
                  <p>Most recent 30 runs. No fabricated improvements or confidence scores.</p>
                </div>
              </div>
              {history.length === 0 ? (
                <div className="form-body">
                  <p>No baseline runs saved yet.</p>
                </div>
              ) : (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Run</th>
                        <th>Started</th>
                        <th>Profile</th>
                        <th>Attempts</th>
                        <th>Status</th>
                        <th>Report</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((run) => (
                        <tr key={run.id}>
                          <td>#{run.id}</td>
                          <td>{new Date(run.startedAt).toLocaleString()}</td>
                          <td>{run.config.profile}</td>
                          <td>{run.samples.length}</td>
                          <td>{run.status}</td>
                          <td>
                            <button
                              disabled={running}
                              onClick={() => {
                                setSelected(run);
                                setView('overview');
                              }}
                            >
                              View
                            </button>
                            <button onClick={() => downloadReport(run, 'json')}>JSON</button>
                            <button onClick={() => downloadReport(run, 'html')}>HTML</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}
          {view === 'backups' && (
            <>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Network settings snapshots</h2>
                    <p>Capture before experimentation. Existing backups are never overwritten.</p>
                  </div>
                  <div className="button-row">
                    <button
                      className="primary"
                      disabled={running || capturingBackup}
                      onClick={captureBackup}
                    >
                      {capturingBackup ? 'Capturing settings...' : 'Capture backup'}
                    </button>
                    {capturingBackup && (
                      <button
                        onClick={() =>
                          invoke('cancelBaseline').catch((error) => setError(String(error)))
                        }
                      >
                        Cancel capture
                      </button>
                    )}
                  </div>
                </div>
                <div className="form-body">
                  <div className="notice">
                    Automatic restoration is not available in this preview. These snapshots preserve
                    readable settings and explicitly record unsupported sections. They are not a
                    verified full-system restore point.
                  </div>
                </div>
                {backupNotice && <p role="status">{backupNotice}</p>}
                {backups.length === 0 ? (
                  <div className="form-body">
                    <p>No configuration snapshots saved yet.</p>
                  </div>
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Backup</th>
                          <th>Captured</th>
                          <th>Captured sections</th>
                          <th>Unavailable</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {backups.map((backup) => (
                          <tr key={backup.id}>
                            <td>#{backup.id}</td>
                            <td>{new Date(backup.capturedAt).toLocaleString()}</td>
                            <td>{backup.capturedSections}</td>
                            <td>{backup.unavailableSections}</td>
                            <td>
                              <button onClick={() => openBackup(backup.id)}>View details</button>
                              <button onClick={() => openBackup(backup.id, true)}>
                                Export backup
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
              {selectedBackup && backupPayload && (
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Backup #{selectedBackup.summary.id}</h2>
                      <p>SHA-256 integrity verified against the saved document</p>
                    </div>
                  </div>
                  <div className="form-body">
                    <label>Export SHA-256</label>
                    <code>{selectedBackup.summary.sha256}</code>
                    <p className="form-note">
                      The exported file contains the exact bytes covered by this checksum. It
                      includes local network configuration; review it before sharing.
                    </p>
                    {backupPayload.limitations.map((limitation) => (
                      <p className="form-note" key={limitation}>
                        {limitation}
                      </p>
                    ))}
                  </div>
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Settings</th>
                          <th>Adapter GUID</th>
                          <th>Records</th>
                          <th>Capture status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {backupPayload.settings.sections.map((section, index) => (
                          <tr key={index}>
                            <td>
                              {section.name}
                              {section.error && <small>{section.error}</small>}
                            </td>
                            <td>{section.adapterId || 'System / interface indexes'}</td>
                            <td>{section.values.length}</td>
                            <td>{section.status}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
            </>
          )}
          {view === 'policy' && (
            <div className="two-columns">
              <section className="panel">
                <div className="panel-heading">
                  <h2>Current safety boundary</h2>
                </div>
                <div className="form-body">
                  <dl>
                    <dt>System changes</dt>
                    <dd>Disabled in this build</dd>
                    <dt>Privileged service</dt>
                    <dd>Not installed</dd>
                    <dt>AI mode</dt>
                    <dd>Disabled</dd>
                    <dt>Cloud budget</dt>
                    <dd>0</dd>
                    <dt>MCP</dt>
                    <dd>Local stdio, read-only allowlist</dd>
                    <dt>Telemetry</dt>
                    <dd>None</dd>
                  </dl>
                  <p>
                    The desktop application runs as your normal user. No startup operation requires
                    administrator privileges.
                  </p>
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Local data</h2>
                </div>
                <div className="form-body">
                  <p>Configuration, events, and raw measurements remain local.</p>
                  <code>{appStatus?.dataDirectory ?? 'Available in the desktop application'}</code>
                  <p>
                    Reports can include network endpoint information. Review exports before sharing
                    them.
                  </p>
                  <p>
                    Network discovery does not upload inventory to an AI provider or any telemetry
                    service.
                  </p>
                </div>
              </section>
            </div>
          )}
          <footer>
            <span>Original settings preserved</span>
            <span>No paid services required</span>
            <span>Local evidence. Honest conclusions.</span>
          </footer>
        </div>
      </main>
    </div>
  );
}
