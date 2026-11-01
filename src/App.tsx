import { useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import {
  Activity,
  ClockRotateRight,
  Code,
  DatabaseBackup,
  Download,
  FloppyDisk,
  HalfMoon,
  Network,
  Page,
  Refresh,
  ShieldCheck,
  SunLight,
} from 'iconoir-react';
import type {
  AppStatus,
  BackupExport,
  BackupPayload,
  BackupSummary,
  BenchmarkRun,
  Config,
  DnsQuery,
  Inventory,
  ProbeProtocol,
  Progress,
  Sample,
  ServiceReport,
} from './types';
import { downloadBackup, downloadReport } from './report';
import BenchmarkOverview from './BenchmarkOverview';
import LoadPanel from './LoadPanel';
import { testGuide } from './benchmark-guide';

type View = 'overview' | 'load' | 'inventory' | 'history' | 'backups' | 'policy';

export default function App() {
  const [view, setView] = useState<View>('overview');
  const [appStatus, setAppStatus] = useState<AppStatus | null>(null);
  const [serviceReport, setServiceReport] = useState<ServiceReport | null>(null);
  const [managingService, setManagingService] = useState(false);
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
  const [loadRunning, setLoadRunning] = useState(false);
  const [loadingInventory, setLoadingInventory] = useState(false);
  const [error, setError] = useState('');
  const [protocol, setProtocol] = useState<ProbeProtocol>('icmpEcho');
  const [targets, setTargets] = useState<Record<ProbeProtocol, [string, string]>>({
    tcpConnect: ['1.1.1.1:53', '8.8.8.8:53'],
    icmpEcho: ['1.1.1.1', '8.8.8.8'],
    dnsLookup: ['1.1.1.1:53', '8.8.8.8:53'],
  });
  const [dnsQuery, setDnsQuery] = useState<DnsQuery>({ name: 'example.com', recordType: 'A' });
  const [firstAddress, secondAddress] = targets[protocol];
  function setAddress(index: 0 | 1, address: string) {
    setTargets((previous) => {
      const updated: [string, string] = [...previous[protocol]];
      updated[index] = address;
      return { ...previous, [protocol]: updated };
    });
  }
  const [light, setLight] = useState(false);
  const runRef = useRef(false);

  async function refreshService() {
    setServiceReport(await invoke<ServiceReport>('getPrivilegedService'));
  }

  async function changeService(action: 'install' | 'start' | 'stop' | 'uninstall') {
    if (managingService) return;
    setManagingService(true);
    setError('');
    try {
      await invoke('manageService', { action });
      await refreshService();
    } catch (error) {
      setError(String(error));
    } finally {
      setManagingService(false);
    }
  }

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
    if (running || loadRunning || capturingBackup) return;
    setCapturingBackup(true);
    setBackupNotice('');
    setError('');
    try {
      const summary = await invoke<BackupSummary>('captureBackup');
      setBackups(await invoke<BackupSummary[]>('getBackups'));
      setSelectedBackup(await invoke<BackupExport>('exportBackup', { id: summary.id }));
    } catch (error) {
      if (String(error).includes('cancelled'))
        setBackupNotice('Copy cancelled. Your earlier copies are still saved.');
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
    invoke<ServiceReport>('getPrivilegedService')
      .then((report) => {
        if (active) setServiceReport(report);
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
    if (!config || running || loadRunning || capturingBackup) return;
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
            id:
              firstAddress === (protocol === 'icmpEcho' ? '1.1.1.1' : '1.1.1.1:53')
                ? 'Cloudflare control'
                : 'First destination',
            address: firstAddress,
            protocol,
            ...(protocol === 'dnsLookup' ? { dnsQuery } : {}),
          },
          {
            id:
              secondAddress === (protocol === 'icmpEcho' ? '8.8.8.8' : '8.8.8.8:53')
                ? 'Google control'
                : 'Second destination',
            address: secondAddress,
            protocol,
            ...(protocol === 'dnsLookup' ? { dnsQuery } : {}),
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

  const backupPayload = useMemo<BackupPayload | null>(
    () => (selectedBackup ? JSON.parse(selectedBackup.payloadJson) : null),
    [selectedBackup],
  );
  const showingBenchmarks = view === 'overview' || view === 'load';

  return (
    <div className={`app ${light ? 'light' : ''}`}>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">ep</span>
          <div>
            estrogen<span>ping patch</span>
          </div>
        </div>
        <div className="workspace-label">YOUR CONNECTION</div>
        <nav>
          {(
            [
              ['overview', 'Network tests', Activity],
              ['inventory', 'Your network', Network],
              ['history', 'Test history', ClockRotateRight],
              ['backups', 'Saved settings', DatabaseBackup],
              ['policy', 'Safety & privacy', ShieldCheck],
            ] as const
          ).map(([key, title, Icon]) => (
            <button
              key={key}
              className={view === key || (key === 'overview' && showingBenchmarks) ? 'active' : ''}
              onClick={() => setView(key)}
            >
              <Icon className="nav-icon" width={20} height={20} />
              {title}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="status-dot" />
          Saved on this PC<p>AI is off. No AI charges.</p>
          <button className="text-button" onClick={() => setLight(!light)}>
            {light ? <HalfMoon /> : <SunLight />}
            Switch to {light ? 'dark' : 'light'} theme
          </button>
          <small>Development preview {appStatus?.version ?? ''}</small>
        </div>
      </aside>
      <main>
        <header>
          <div className="breadcrumb">
            Network tools <span>/</span>{' '}
            {showingBenchmarks
              ? 'Network tests'
              : view === 'inventory'
                ? 'Your network'
                : view === 'history'
                  ? 'Test history'
                  : view === 'backups'
                    ? 'Saved settings'
                    : 'Safety & privacy'}
          </div>
          <div className="pill">
            <i /> {appStatus ? 'Desktop ready' : 'Connecting to desktop'}
          </div>
        </header>
        <div className="content">
          {error && (
            <div role="alert" className="error">
              <strong>Could not complete this step</strong>
              <p>{error}</p>
              <button onClick={() => setError('')}>Dismiss</button>
            </div>
          )}
          <section className="page-heading">
            <div>
              <div className="eyebrow">NETWORK TOOLS</div>
              <h1>
                {showingBenchmarks
                  ? 'Network tests'
                  : view === 'inventory'
                    ? 'Your network'
                    : view === 'history'
                      ? 'Test history'
                      : view === 'backups'
                        ? 'Saved settings'
                        : 'Safety & privacy'}
              </h1>
              <p>
                {showingBenchmarks
                  ? 'Measure your connection. These tests do not change your network settings.'
                  : view === 'inventory'
                    ? 'See the network connections and settings reported by Windows.'
                    : view === 'history'
                      ? 'Reopen your connection test results. Speed tests have their own history on the Speed test screen.'
                      : view === 'backups'
                        ? 'Save a copy of your current settings to view or download later.'
                        : 'See what this version can do and where it saves your data.'}
              </p>
            </div>
            <span className="badge">
              {showingBenchmarks ? 'Optimization is still in development' : 'DEVELOPMENT PREVIEW'}
            </span>
          </section>
          {showingBenchmarks && (
            <div className="benchmark-tabs" role="group" aria-label="Network tests">
              <button aria-pressed={view === 'overview'} onClick={() => setView('overview')}>
                <strong>Connection test</strong>
                <span>Check how quickly servers reply. Start here.</span>
              </button>
              <button aria-pressed={view === 'load'} onClick={() => setView('load')}>
                <strong>Speed test</strong>
                <span>Check speed and delay while downloading or uploading.</span>
              </button>
            </div>
          )}
          {view === 'overview' && (
            <BenchmarkOverview
              config={config}
              onConfigChange={setConfig}
              protocol={protocol}
              onProtocolChange={setProtocol}
              firstAddress={firstAddress}
              secondAddress={secondAddress}
              onAddressChange={setAddress}
              dnsQuery={dnsQuery}
              onDnsQueryChange={setDnsQuery}
              running={running}
              blocked={loadRunning || capturingBackup || managingService}
              selected={selected}
              samples={samples}
              progress={progress}
              onStart={startBaseline}
              onCancel={() => invoke('cancelBaseline').catch((error) => setError(String(error)))}
            />
          )}
          <div hidden={view !== 'load'}>
            <LoadPanel
              config={config}
              blocked={running || capturingBackup || managingService}
              onRunningChange={setLoadRunning}
            />
          </div>
          {view === 'inventory' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Your network connections</h2>
                  <p>
                    {inventory
                      ? `Windows ${inventory.os.version}, build ${inventory.os.build} | ${inventory.os.architecture}`
                      : 'Reading network details from Windows...'}
                  </p>
                </div>
                <button disabled={loadingInventory} onClick={refreshInventory}>
                  <Refresh />
                  {loadingInventory ? 'Refreshing...' : 'Refresh details'}
                </button>
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Network adapter</th>
                      <th>Status</th>
                      <th>Connection type</th>
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
                <p className="form-note">
                  Link speed is the connection to your router or network, not your measured internet
                  speed. Use Speed test to measure transfers.
                </p>
                <h3>Internet gateways</h3>
                <p className="form-note">
                  Where Windows sends traffic to reach other networks. These are the default routes
                  reported by Windows.
                </p>
                {inventory?.routes.map((route, index) => (
                  <p key={index}>
                    Interface {route.interfaceIndex} / {route.destination} / gateway {route.nextHop}{' '}
                    / route metric {route.routeMetric}
                  </p>
                ))}
                <h3>DNS servers</h3>
                <p className="form-note">These servers find the addresses for website names.</p>
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
                  <h2>Previous connection tests</h2>
                  <p>Your 30 most recent tests. Open a result or save a readable report.</p>
                </div>
              </div>
              {history.length === 0 ? (
                <div className="form-body">
                  <p>No connection tests saved yet. Start one from Network tests.</p>
                </div>
              ) : (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Test number</th>
                        <th>Started</th>
                        <th>Test</th>
                        <th>Checks</th>
                        <th>Status</th>
                        <th>Report</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((run) => (
                        <tr key={run.id}>
                          <td>#{run.id}</td>
                          <td>{new Date(run.startedAt).toLocaleString()}</td>
                          <td>{testGuide[run.protocol].title}</td>
                          <td>{run.samples.length}</td>
                          <td>
                            {run.status === 'completed'
                              ? 'Finished'
                              : run.status === 'cancelled'
                                ? 'Stopped'
                                : 'Incomplete'}
                          </td>
                          <td>
                            <button
                              disabled={running}
                              onClick={() => {
                                setSelected(run);
                                setView('overview');
                              }}
                            >
                              View results
                            </button>
                            <button onClick={() => downloadReport(run, 'json')}>
                              <Code />
                              Export raw data (JSON)
                            </button>
                            <button onClick={() => downloadReport(run, 'html')}>
                              <Page />
                              Save report
                            </button>
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
                    <h2>Copy your current settings</h2>
                    <p>Each copy is saved separately on this PC. Earlier copies are kept.</p>
                  </div>
                  <div className="button-row">
                    <button
                      className="primary"
                      disabled={running || loadRunning || capturingBackup}
                      onClick={captureBackup}
                    >
                      <FloppyDisk />
                      {capturingBackup ? 'Copying settings...' : 'Save settings copy'}
                    </button>
                    {capturingBackup && (
                      <button
                        onClick={() =>
                          invoke('cancelBaseline').catch((error) => setError(String(error)))
                        }
                      >
                        Cancel copy
                      </button>
                    )}
                  </div>
                </div>
                <div className="form-body">
                  <div className="notice">
                    This version can save and show settings, but cannot restore them. A saved copy
                    does not guarantee you can undo a network change. Missing settings are listed in
                    the details.
                  </div>
                </div>
                {backupNotice && <p role="status">{backupNotice}</p>}
                {backups.length === 0 ? (
                  <div className="form-body">
                    <p>No settings copies saved yet.</p>
                  </div>
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Backup</th>
                          <th>Saved</th>
                          <th>Sections saved</th>
                          <th>Sections missing</th>
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
                                <Download />
                                Download settings copy
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
                      <p>File check passed: this copy matches the settings originally saved.</p>
                    </div>
                  </div>
                  <div className="form-body">
                    <label>File fingerprint (SHA-256)</label>
                    <code>{selectedBackup.summary.sha256}</code>
                    <p className="form-note">
                      This fingerprint helps check that the file has not changed. The file includes
                      your network settings; review it before sharing.
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
                          <th>Adapter ID</th>
                          <th>Records</th>
                          <th>Saved successfully?</th>
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
                            <td>{section.status === 'captured' ? 'Saved' : 'Not available'}</td>
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
                  <h2>What this version can do</h2>
                </div>
                <div className="form-body">
                  <dl>
                    <dt>System changes</dt>
                    <dd>Disabled in this build</dd>
                    <dt>Optional background service</dt>
                    <dd>
                      {serviceReport
                        ? ((
                            {
                              ready: 'Running',
                              notInstalled: 'Not installed',
                              stopped: 'Stopped',
                              recoveryRequired: 'Recovery needs attention',
                              unavailable: 'Could not check status',
                              unsupported: 'Not supported on this system',
                            } as Record<string, string>
                          )[serviceReport.state] ?? 'Not ready')
                        : 'Checking status...'}
                    </dd>
                    {serviceReport?.response && (
                      <>
                        <dt>Recovery records last checked</dt>
                        <dd>
                          {new Date(
                            serviceReport.response.checkpointStore.verifiedAtUnixMs,
                          ).toLocaleString()}
                          {' at service startup'}
                        </dd>
                        <dt>Recovery records needing attention</dt>
                        <dd>{serviceReport.response.checkpointStore.pendingRecoveryCount}</dd>
                      </>
                    )}
                    <dt>AI mode</dt>
                    <dd>Disabled</dd>
                    <dt>AI spending limit</dt>
                    <dd>0 (AI is off)</dd>
                    <dt>AI tool access (MCP)</dt>
                    <dd>Local connection only. Can read approved data; cannot change settings.</dd>
                    <dt>Usage tracking</dt>
                    <dd>Off</dd>
                  </dl>
                  <p>Opening the app and running tests do not require administrator access.</p>
                  <p>{serviceReport?.detail}</p>
                  <div className="actions">
                    <button
                      disabled={managingService}
                      onClick={() =>
                        void refreshService().catch((error) => setError(String(error)))
                      }
                    >
                      Refresh service status
                    </button>
                    {serviceReport?.state === 'notInstalled' && (
                      <button
                        disabled={managingService || running || loadRunning || capturingBackup}
                        onClick={() => void changeService('install')}
                      >
                        Install optional service
                      </button>
                    )}
                    {serviceReport?.state === 'stopped' && (
                      <button
                        disabled={managingService}
                        onClick={() => void changeService('start')}
                      >
                        Start service
                      </button>
                    )}
                    {serviceReport &&
                      ['ready', 'recoveryRequired'].includes(serviceReport.state) && (
                        <button
                          disabled={managingService}
                          onClick={() => void changeService('stop')}
                        >
                          Stop service
                        </button>
                      )}
                    {serviceReport &&
                      !['notInstalled', 'unsupported', 'unavailable'].includes(
                        serviceReport.state,
                      ) && (
                        <button
                          disabled={managingService}
                          onClick={() => void changeService('uninstall')}
                        >
                          Uninstall service
                        </button>
                      )}
                  </div>
                  <p>
                    Installing, removing, starting, or stopping the service asks for Windows
                    administrator approval. It cannot change network settings in this version. You
                    can run tests and save settings copies without it.
                  </p>
                  {managingService && (
                    <p role="status">
                      Waiting for Windows. Respond to the administrator approval prompt if shown.
                    </p>
                  )}
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Where your data is saved</h2>
                </div>
                <div className="form-body">
                  <p>Settings and test results are saved on this PC:</p>
                  <code>{appStatus?.dataDirectory ?? 'Available in the desktop application'}</code>
                  <p>
                    Reports can include server addresses and network details. Review them before
                    sharing.
                  </p>
                  <p>
                    Your network details are not sent to an AI provider or usage-tracking service.
                  </p>
                </div>
              </section>
            </div>
          )}
          <footer>
            <span>Network settings unchanged</span>
            <span>No paid services required</span>
            <span>Results saved on this PC</span>
          </footer>
        </div>
      </main>
    </div>
  );
}
