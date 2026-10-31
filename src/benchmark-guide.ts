import type { BenchmarkRun, Config, ProbeProtocol } from './types';

export const testGuide: Record<
  ProbeProtocol,
  { title: string; description: string; measures: string; typical: string }
> = {
  icmpEcho: {
    title: 'Response time (ping)',
    description: 'Check how quickly test servers reply and how much the delay varies.',
    measures:
      'Sends small echo requests to two servers. This is a useful starting point for responsiveness.',
    typical: 'Typical response time',
  },
  tcpConnect: {
    title: 'Connection setup',
    description: 'Check how long it takes to open a connection to each server.',
    measures:
      'Measures the time needed to establish a TCP connection. It includes connection setup work, so it differs from ping.',
    typical: 'Typical connection time',
  },
  dnsLookup: {
    title: 'Website lookup (DNS)',
    description: 'Check how quickly DNS servers find the address for a website name.',
    measures:
      'Asks two DNS servers to resolve a name. Faster lookups can help new connections start; they do not lower an ongoing game connection’s ping.',
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
          ? 'Some networks or servers block ping requests. Try Connection setup, or check the server addresses under Advanced settings.'
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
