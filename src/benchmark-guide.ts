import type { BenchmarkRun, Config, ProbeProtocol } from './types';

export const testGuide: Record<
  ProbeProtocol,
  { title: string; measures: string; typical: string }
> = {
  icmpEcho: {
    title: 'Ping (response time)',
    measures:
      'Sends small test messages to two servers and times their replies. Lower times mean faster replies.',
    typical: 'Typical response time',
  },
  tcpConnect: {
    title: 'Opening a connection',
    measures:
      'Times how long it takes to open a new connection to each server. This measures connection setup, which differs from ping.',
    typical: 'Typical connection time',
  },
  dnsLookup: {
    title: 'Finding a website (DNS)',
    measures:
      'Asks two DNS servers to find the address for a website name. Faster lookups can help new connections start; they do not lower an ongoing game connection’s ping.',
    typical: 'Typical lookup time',
  },
};

export function baselineLimitSeconds(config: Config | null): number | null {
  if (!config) return null;
  const { sampleCount, intervalMs, timeoutMs, sessionMinutes } = config;
  if (
    ![sampleCount, intervalMs, timeoutMs, sessionMinutes].every(
      (value) => Number.isFinite(value) && value > 0,
    )
  )
    return null;
  return Math.ceil(
    Math.min(sessionMinutes * 60, (sampleCount * 2 * (timeoutMs + intervalMs)) / 1000),
  );
}

export function runExplanation(run: BenchmarkRun): { title: string; detail: string } {
  const attempted = run.results.reduce((sum, result) => sum + result.summary.attempted, 0);
  const successful = run.results.reduce((sum, result) => sum + result.summary.successful, 0);
  if (run.status !== 'completed')
    return {
      title: 'This test did not finish',
      detail: 'Any results below are partial. Run a complete test before comparing results.',
    };
  if (attempted === 0 || successful === 0)
    return {
      title: 'No usable timing results',
      detail:
        run.protocol === 'icmpEcho'
          ? 'Some networks or servers block ping requests. Choose Opening a connection under What to check, or check the server addresses under Advanced settings.'
          : 'Check your connection and the server addresses under Advanced settings, then try again. Technical details show the recorded errors.',
    };
  if (successful !== attempted)
    return {
      title: 'Some checks were unsuccessful',
      detail:
        run.protocol === 'icmpEcho'
          ? 'Missing echo replies can reflect filtering, rate limits, or a connection problem. They do not directly measure packet loss in games.'
          : 'Review the results for each server. A failed connection or lookup does not by itself identify the cause.',
    };
  return {
    title: 'Every check returned a result',
    detail:
      'This is a snapshot of these servers at this time. Repeat the same test later to see whether the results are consistent.',
  };
}
