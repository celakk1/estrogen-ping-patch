import { useEffect, useRef, useState } from 'react';
import { Activity, Download, Play, Square } from 'iconoir-react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { packetExplanation, type PacketCheck, type PacketSample } from './packet-types';

export default function PacketPanel({
  blocked,
  onRunningChange,
}: {
  blocked: boolean;
  onRunningChange: (running: boolean) => void;
}) {
  const [destination, setDestination] = useState('1.1.1.1');
  const [running, setRunning] = useState(false);
  const runRef = useRef(false);
  const [progress, setProgress] = useState<PacketSample | null>(null);
  const [selected, setSelected] = useState<PacketCheck | null>(null);
  const [history, setHistory] = useState<PacketCheck[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    const subscription = listen<PacketSample>('packet-progress', (event) => {
      if (active && runRef.current) setProgress(event.payload);
    });
    invoke<PacketCheck[]>('getPacketHistory')
      .then((checks) => {
        if (active) setHistory(checks);
      })
      .catch((error) => {
        if (active) setError(String(error));
      });
    return () => {
      active = false;
      void subscription.then((unlisten) => unlisten()).catch(() => {});
    };
  }, []);

  async function start() {
    if (blocked || runRef.current) return;
    runRef.current = true;
    setRunning(true);
    onRunningChange(true);
    setSelected(null);
    setProgress(null);
    setError('');
    try {
      const check = await invoke<PacketCheck>('runPacketCheck', {
        destination: destination.trim(),
      });
      setSelected(check);
      setHistory(await invoke<PacketCheck[]>('getPacketHistory'));
    } catch (error) {
      setError(String(error));
    } finally {
      runRef.current = false;
      setRunning(false);
      onRunningChange(false);
    }
  }

  function download() {
    if (!selected) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(selected, null, 2)], { type: 'application/json' }),
    );
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `epp-packet-check-${selected.id}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const explanation = selected ? packetExplanation(selected) : null;
  return (
    <>
      {error && (
        <div role="alert" className="error">
          <strong>Packet check could not finish</strong>
          <p>{error}</p>
          <button onClick={() => setError('')}>Dismiss</button>
        </div>
      )}
      <div className="two-columns benchmark-layout">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Large packet check</h2>
              <p>Check whether larger requests can reach one server.</p>
            </div>
          </div>
          <div className="form-body">
            <label>
              Packet check destination (IPv4)
              <input
                value={destination}
                disabled={running || blocked}
                onChange={(event) => setDestination(event.target.value)}
                placeholder="1.1.1.1"
                spellCheck={false}
              />
            </label>
            <p className="field-help">
              Use 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), or another IPv4 address. The server sees
              your IP address.
            </p>
            <div className="test-facts packet-facts">
              <div>
                <span>Time limit</span>
                <strong>2 minutes</strong>
              </div>
              <div>
                <span>Data limit</span>
                <strong>Under 1.3 MB of requests</strong>
              </div>
            </div>
            <p className="field-help">Replies and connection messages add to actual usage.</p>
            {blocked && (
              <p className="form-note">
                Wait for the current network task or service action to finish.
              </p>
            )}
            <div className="button-row">
              <button
                className="primary"
                disabled={running || blocked || !destination.trim()}
                onClick={start}
              >
                {running ? <Activity /> : <Play />}
                {running ? 'Checking packets...' : 'Start packet check'}
              </button>
              {running && (
                <button
                  onClick={() => invoke('cancelBaseline').catch((error) => setError(String(error)))}
                >
                  <Square />
                  Stop packet check
                </button>
              )}
            </div>
            {running && (
              <p role="status" className="form-note">
                {progress
                  ? `${progress.sequence + 1} requests recorded. Last size: ${progress.packetBytes.toLocaleString()} bytes.`
                  : 'Reading the route and adapter selected by Windows...'}{' '}
                The check stops early when it has enough evidence.
              </p>
            )}
            <details className="result-details">
              <summary>How this check works</summary>
              <p className="form-note">
                Networks split data into packets. This check compares small requests with larger
                ones, using at most 144 requests at least 75 ms apart. It stops early when a result
                is clear. Missing replies alone cannot establish a size limit. It does not measure
                download speed.
              </p>
            </details>
          </div>
        </section>
        <section className="panel" aria-label="Packet check results">
          <div className="panel-heading">
            <div>
              <h2>What the check found</h2>
              <p>{selected ? selected.report.plan.destination : 'Your result will appear here.'}</p>
            </div>
          </div>
          <div className="form-body">
            {selected && explanation ? (
              <>
                <div className="result-explanation">
                  <h3>{explanation.title}</h3>
                  <p>{explanation.detail}</p>
                </div>
                <p className="form-note">
                  Your network settings were not changed. This checks one destination using IPv4
                  requests marked “do not fragment”; it does not establish a limit for every game or
                  internet route.
                </p>
                <button onClick={download}>
                  <Download />
                  Export packet data (JSON)
                </button>
                <p className="field-help">
                  The export includes local addresses, adapter identifiers, and route details.
                  Review it before sharing.
                </p>
                <details className="result-details">
                  <summary>Technical details</summary>
                  <dl>
                    <dt>Network adapter</dt>
                    <dd>{selected.context.interfaceBefore.alias}</dd>
                    <dt>Local source address</dt>
                    <dd>{selected.report.plan.source}</dd>
                    <dt>Current interface MTU</dt>
                    <dd>{selected.report.plan.interfaceMtu.toLocaleString()} bytes</dd>
                    <dt>Local route and adapter</dt>
                    <dd>
                      {selected.contextUnchanged
                        ? 'Matched before and after'
                        : 'Changed or unavailable'}
                    </dd>
                    <dt>Requests recorded</dt>
                    <dd>{selected.report.samples.length}</dd>
                    <dt>Requested IPv4 bytes</dt>
                    <dd>{selected.report.requestedIpv4Bytes.toLocaleString()}</dd>
                  </dl>
                  {selected.report.error && <p>{selected.report.error}</p>}
                  {selected.context.afterError && <p>{selected.context.afterError}</p>}
                </details>
              </>
            ) : (
              <div className="results-empty">
                <h3>Can larger packets get through?</h3>
                <p>
                  Start this check if you suspect packet-size problems, especially on a VPN or
                  tunnel. Ordinary timeouts will leave the result inconclusive.
                </p>
                <p>
                  A size boundary alone does not prove that reducing MTU would make your connection
                  faster. Automatic optimization is still in development.
                </p>
              </div>
            )}
          </div>
        </section>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Packet check history</h2>
            <p>Up to 50 recent checks saved on this PC.</p>
          </div>
        </div>
        {history.length === 0 ? (
          <div className="form-body">
            <p className="form-note">No packet checks saved yet.</p>
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Destination</th>
                  <th>Result</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {history.map((check) => (
                  <tr key={check.id}>
                    <td>{new Date(check.report.startedAtUnixMs).toLocaleString()}</td>
                    <td>{check.report.plan.destination}</td>
                    <td>{packetExplanation(check).title}</td>
                    <td>
                      <button disabled={running} onClick={() => setSelected(check)}>
                        Open packet check {check.id}
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
