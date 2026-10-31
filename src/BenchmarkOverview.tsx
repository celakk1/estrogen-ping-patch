import type { BenchmarkRun, Config, DnsQuery, ProbeProtocol, Progress, Sample } from './types';
import { downloadReport } from './report';
import {
  dnsAnswerText,
  dnsCountsText,
  failureNames,
  failurePercent,
  formatProbeMs,
  protocolNotes,
  sampleLatency,
} from './measurement';
import { baselineLimitSeconds, runExplanation, testGuide } from './benchmark-guide';

interface Props {
  config: Config | null;
  onConfigChange: (config: Config) => void;
  protocol: ProbeProtocol;
  onProtocolChange: (protocol: ProbeProtocol) => void;
  firstAddress: string;
  secondAddress: string;
  onAddressChange: (index: 0 | 1, address: string) => void;
  dnsQuery: DnsQuery;
  onDnsQueryChange: (query: DnsQuery) => void;
  running: boolean;
  blocked: boolean;
  selected: BenchmarkRun | null;
  samples: Sample[];
  progress: Progress | null;
  onStart: () => void;
  onCancel: () => void;
}

function LatencyChart({ samples, protocol }: { samples: Sample[]; protocol: ProbeProtocol }) {
  const valid = samples.map(sampleLatency).filter((value): value is number => value != null);
  const maximum = Math.max(10, ...valid);
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
        aria-label={
          protocol === 'dnsLookup'
            ? 'Measured successful DNS lookup times'
            : protocol === 'icmpEcho'
              ? 'Measured ICMP echo round-trip times'
              : 'Measured TCP connection establishment times'
        }
      >
        {[30, 90, 150].map((y) => (
          <line key={y} x1="0" x2="900" y1={y} y2={y} stroke="currentColor" opacity="0.15" />
        ))}
        {endpoints.map((endpoint, index) => {
          const matching = samples.filter((sample) => sample.endpointId === endpoint);
          const points = matching.map((sample, point) => {
            const value = sampleLatency(sample);
            return value == null
              ? null
              : `${20 + (point * 860) / Math.max(matching.length - 1, 1)},${165 - (value / maximum) * 150}`;
          });
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
                .map((segment, index) => (
                  <polyline key={index} points={segment.join(' ')} />
                ))}
              {points
                .filter((point): point is string => point != null)
                .map((point, index) => {
                  const [x, y] = point.split(',');
                  return <circle key={index} cx={x} cy={y} r="3" />;
                })}
            </g>
          );
        })}
      </svg>
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

export default function BenchmarkOverview(props: Props) {
  const {
    config,
    onConfigChange,
    protocol,
    onProtocolChange,
    firstAddress,
    secondAddress,
    onAddressChange,
    dnsQuery,
    onDnsQueryChange,
    running,
    blocked,
    selected,
    samples,
    progress,
    onStart,
    onCancel,
  } = props;
  const shownProtocol = selected?.protocol ?? protocol;
  const shownSamples = selected?.samples ?? samples;
  const guide = testGuide[protocol];
  const explanation = selected ? runExplanation(selected) : null;
  const limitSeconds = baselineLimitSeconds(config);
  const completed = progress?.completed ?? 0;
  const percent =
    progress && progress.total > 0
      ? Math.min(100, Math.round((completed / progress.total) * 100))
      : 0;
  return (
    <>
      <div className="test-picker" role="group" aria-label="Choose what to measure">
        {(['icmpEcho', 'tcpConnect', 'dnsLookup'] as const).map((kind) => (
          <button
            key={kind}
            aria-label={testGuide[kind].title}
            aria-pressed={protocol === kind}
            className={`test-option ${protocol === kind ? 'selected' : ''}`}
            disabled={running}
            onClick={() => onProtocolChange(kind)}
          >
            <span className="test-option-title">{testGuide[kind].title}</span>
            <span>{testGuide[kind].description}</span>
            {kind === 'icmpEcho' && <small>Suggested first test</small>}
          </button>
        ))}
      </div>
      <div className="two-columns benchmark-layout">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>
                Run a{' '}
                {protocol === 'icmpEcho'
                  ? 'response time'
                  : protocol === 'dnsLookup'
                    ? 'website lookup'
                    : 'connection setup'}{' '}
                test
              </h2>
              <p>{guide.measures}</p>
            </div>
          </div>
          <div className="form-body">
            <div className="test-facts">
              <div>
                <span>Test servers</span>
                <strong>
                  {firstAddress === (protocol === 'icmpEcho' ? '1.1.1.1' : '1.1.1.1:53')
                    ? 'Cloudflare'
                    : firstAddress}
                  <br />
                  {secondAddress === (protocol === 'icmpEcho' ? '8.8.8.8' : '8.8.8.8:53')
                    ? 'Google'
                    : secondAddress}
                </strong>
              </div>
              <div>
                <span>Test size</span>
                <strong>{config?.sampleCount ?? 12} checks per server</strong>
              </div>
              <div>
                <span>Time to allow</span>
                <strong>
                  {limitSeconds == null ? 'Waiting for settings' : `About ${limitSeconds} seconds`}
                </strong>
              </div>
            </div>
            {protocol === 'dnsLookup' && (
              <label>
                Website name to look up
                <input
                  disabled={running}
                  value={dnsQuery.name}
                  maxLength={254}
                  onChange={(event) => onDnsQueryChange({ ...dnsQuery, name: event.target.value })}
                />
                <span className="field-help">
                  Use a public name, such as example.com. Only the name is sent; no website content
                  is downloaded.
                </span>
              </label>
            )}
            <div className="button-row">
              <button
                className="primary"
                disabled={!config || running || blocked}
                onClick={onStart}
              >
                {running ? 'Test running...' : 'Start test'}
              </button>
              {running && <button onClick={onCancel}>Stop test</button>}
            </div>
            <p className="field-help">
              Starting contacts the two servers above. They receive your IP address. This test does
              not change your network settings.
            </p>
            <p className="form-note">
              For a quiet-connection result, pause other downloads or streams first. Use{' '}
              <strong>Speed & load</strong> to test how your connection behaves during traffic.
            </p>
            {running && (
              <p className="form-note" role="status">
                {progress
                  ? `${completed} of ${progress.total} checks finished.`
                  : 'Preparing the first check...'}
              </p>
            )}
            {blocked && (
              <p role="status" className="form-note">
                Wait for the current load test or backup to finish before starting another test.
              </p>
            )}
            <details className="advanced-settings">
              <summary>
                Advanced settings<span>Servers, number of checks, and technical options</span>
              </summary>
              <div className="advanced-body">
                <label>
                  Network benchmark
                  <select
                    disabled={running}
                    value={protocol}
                    onChange={(event) => onProtocolChange(event.target.value as ProbeProtocol)}
                  >
                    <option value="icmpEcho">Response time (ICMP echo)</option>
                    <option value="tcpConnect">Connection setup (TCP)</option>
                    <option value="dnsLookup">Website lookup (DNS)</option>
                  </select>
                </label>
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
                        onConfigChange({ ...config, sampleCount: Number(event.target.value) })
                      }
                    />
                    <span className="field-help">How many checks to send to each server.</span>
                  </label>
                  <label>
                    Maximum runtime (minutes)
                    <input
                      type="number"
                      min="1"
                      max="1440"
                      disabled={running}
                      value={config?.sessionMinutes ?? 15}
                      onChange={(event) =>
                        config &&
                        onConfigChange({ ...config, sessionMinutes: Number(event.target.value) })
                      }
                    />
                    <span className="field-help">
                      A safety limit, not the intended test duration.
                    </span>
                  </label>
                </div>
                <label>
                  {protocol === 'icmpEcho'
                    ? 'First destination (IP or IPv6%scopeId)'
                    : 'First destination (IP:port)'}
                  <input
                    disabled={running}
                    value={firstAddress}
                    onChange={(event) => onAddressChange(0, event.target.value)}
                  />
                </label>
                <label>
                  {protocol === 'icmpEcho'
                    ? 'Second destination (IP or IPv6%scopeId)'
                    : 'Second destination (IP:port)'}
                  <input
                    disabled={running}
                    value={secondAddress}
                    onChange={(event) => onAddressChange(1, event.target.value)}
                  />
                </label>
                <p className="form-note">
                  Default addresses belong to Cloudflare and Google. They are comparison servers,
                  not a measurement of every internet route. Custom targets must be numeric IP
                  addresses
                  {protocol === 'icmpEcho'
                    ? '; link-local IPv6 also needs a numeric interface scope ID'
                    : ' with a port, such as 1.1.1.1:53'}
                  .
                </p>
                {protocol === 'dnsLookup' && (
                  <label>
                    DNS record type
                    <select
                      disabled={running}
                      value={dnsQuery.recordType}
                      onChange={(event) =>
                        onDnsQueryChange({
                          ...dnsQuery,
                          recordType: event.target.value as DnsQuery['recordType'],
                        })
                      }
                    >
                      <option value="A">IPv4 addresses (A)</option>
                      <option value="AAAA">IPv6 addresses (AAAA)</option>
                    </select>
                  </label>
                )}
                <label>
                  Report preference
                  <select
                    disabled={running}
                    value={config?.profile ?? 'balanced'}
                    onChange={(event) =>
                      config &&
                      onConfigChange({
                        ...config,
                        profile: event.target.value as Config['profile'],
                      })
                    }
                  >
                    <option value="latency">Latency</option>
                    <option value="balanced">Balanced</option>
                    <option value="download">Download</option>
                  </select>
                  <span className="field-help">
                    This label is saved with the report. It does not change the test.
                  </span>
                </label>
                <p className="form-note">{protocolNotes[protocol]}</p>
              </div>
            </details>
          </div>
        </section>
        <section className="panel" aria-live="polite">
          <div className="panel-heading">
            <div>
              <h2>{running ? 'Your test is running' : 'Your results'}</h2>
              <p>
                {selected
                  ? `${testGuide[shownProtocol].title} · ${new Date(selected.startedAt).toLocaleString()}`
                  : 'Results are saved on this computer automatically.'}
              </p>
            </div>
          </div>
          <div className="form-body">
            {running ? (
              <>
                <div
                  className="progress-bar"
                  role="progressbar"
                  aria-label="Test progress"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={percent}
                >
                  <div style={{ width: `${percent}%` }} />
                </div>
                <h3>
                  {completed} of {progress?.total ?? (config?.sampleCount ?? 12) * 2} checks
                  finished
                </h3>
                <p>
                  {progress
                    ? `About ${progress.remainingLowSeconds}–${progress.remainingHighSeconds} seconds remaining.`
                    : 'Preparing the first check...'}
                </p>
                <p className="form-note">
                  The estimate updates as replies arrive. Timeouts can slow the test down; you can
                  stop at any time.
                </p>
              </>
            ) : selected ? (
              <>
                <div className="result-explanation">
                  <h3>{explanation?.title}</h3>
                  <p>{explanation?.detail}</p>
                </div>
                <p className="measurement-key">
                  Delay is shown in <strong>ms (milliseconds)</strong>. Lower times mean faster{' '}
                  {shownProtocol === 'dnsLookup'
                    ? 'lookups'
                    : shownProtocol === 'icmpEcho'
                      ? 'replies'
                      : 'connection setup'}{' '}
                  to that server.
                </p>
                <div className="server-results">
                  {selected.results.map(({ endpoint, summary, echoCounts, dnsCounts }) => (
                    <article key={endpoint.id} className="server-result">
                      <div className="server-result-heading">
                        <div>
                          <h3>{endpoint.id}</h3>
                          <span>{endpoint.address}</span>
                        </div>
                        <span className="result-timing">
                          {formatProbeMs(summary.medianMs, shownProtocol)}
                        </span>
                      </div>
                      <p>{testGuide[shownProtocol].typical} (median)</p>
                      <div className="result-stat-row">
                        <span>
                          {summary.successful} of {summary.attempted} checks succeeded
                        </span>
                      </div>
                      <details className="result-details">
                        <summary>Technical details</summary>
                        <dl>
                          <dt>{failureNames[shownProtocol]}</dt>
                          <dd>{failurePercent(summary, shownProtocol)}</dd>
                          <dt>Slower responses (p95)</dt>
                          <dd>{formatProbeMs(summary.p95Ms, shownProtocol)}</dd>
                          <dt>p99</dt>
                          <dd>{formatProbeMs(summary.p99Ms, shownProtocol)}</dd>
                          <dt>Variation between checks</dt>
                          <dd>{formatProbeMs(summary.successiveVariationMs, shownProtocol)}</dd>
                        </dl>
                        <p className="form-note">
                          p95 is the 95th percentile of successful timings. Variation shows how much
                          consecutive successful timings differ. A short test has limited samples.
                        </p>
                        {echoCounts && (
                          <p className="form-note">
                            Timeouts {echoCounts.timeouts}; IP errors {echoCounts.ipErrors}; system
                            errors {echoCounts.osErrors}; invalid replies{' '}
                            {echoCounts.invalidReplies}; unsupported {echoCounts.unsupported}.
                          </p>
                        )}
                        {dnsCounts && (
                          <>
                            <p className="form-note">{dnsCountsText(dnsCounts)}</p>
                            <p className="form-note">
                              {(() => {
                                const last = selected.samples
                                  .filter(
                                    (sample) => sample.endpointId === endpoint.id && sample.dns,
                                  )
                                  .at(-1)?.dns;
                                return last
                                  ? `Last response: ${dnsAnswerText(last)}`
                                  : 'No DNS response recorded';
                              })()}
                            </p>
                          </>
                        )}
                      </details>
                    </article>
                  ))}
                </div>
                <div className="button-row report-actions">
                  <button onClick={() => downloadReport(selected, 'html')}>Save report</button>
                  <button onClick={() => downloadReport(selected, 'json')}>Export JSON</button>
                </div>
              </>
            ) : (
              <div className="results-empty">
                <div className="empty-result-mark" aria-hidden="true">
                  <span />
                  <span />
                  <span />
                </div>
                <h3>Start with the defaults</h3>
                <p>
                  Choose a test, then select <strong>Start test</strong>. You do not need to enter a
                  server address to begin.
                </p>
                <dl>
                  <dt>Response time</dt>
                  <dd>How long a reply takes. Lower is faster.</dd>
                  <dt>Variation</dt>
                  <dd>How much timings change from one check to the next.</dd>
                  <dt>Unsuccessful checks</dt>
                  <dd>
                    Requests that did not return a usable result. The cause depends on the test.
                  </dd>
                </dl>
              </div>
            )}
          </div>
        </section>
      </div>
      {(shownSamples.length > 0 || running) && (
        <section className="panel timeline-panel">
          <div className="panel-heading">
            <div>
              <h2>Timings during the test</h2>
              <p>Lower points mean faster responses. Gaps mark checks without a usable timing.</p>
            </div>
            <span className="pill">{running ? 'Measuring' : testGuide[shownProtocol].title}</span>
          </div>
          <LatencyChart samples={shownSamples} protocol={shownProtocol} />
          <details className="chart-note">
            <summary>How this measurement works</summary>
            <p>{protocolNotes[shownProtocol]}</p>
          </details>
        </section>
      )}
    </>
  );
}
