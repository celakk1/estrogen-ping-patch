import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmdirSync,
  unlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const [directory, experimentId, adapterGuid, family, ...extra] = process.argv.slice(2);
if (
  process.platform !== 'win32' ||
  process.env.GITHUB_ACTIONS !== 'true' ||
  process.env.RUNNER_ENVIRONMENT !== 'github-hosted'
)
  throw new Error(
    'Repeated native evidence inspection requires its explicitly selected hosted Windows lab.',
  );
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
assert.ok(
  directory &&
    uuid.test(experimentId) &&
    uuid.test(adapterGuid) &&
    ['ipv4', 'ipv6'].includes(family) &&
    extra.length === 0,
);
assert.equal(
  path.resolve(directory).toLowerCase(),
  path.join(process.env.ProgramData, 'estrogen-ping-patch-mtu-lab').toLowerCase(),
);
assert.equal(lstatSync(directory).isSymbolicLink(), false);
assert.equal(realpathSync(directory).toLowerCase(), path.resolve(directory).toLowerCase());
const digest = (text) => createHash('sha256').update(text).digest('hex');
const jsonHash = (value) => digest(JSON.stringify(value));
const checkedPayload = (row, field = 'payload_json') => {
  assert.ok(row && typeof row[field] === 'string');
  assert.equal(digest(row[field]), row.sha256);
  return JSON.parse(row[field]);
};
let originReference;
function verifyPolicy(document) {
  assert.equal(document.schemaVersion, 4);
  const evidence = document.policyOriginal;
  assert.deepEqual(Object.keys(evidence).sort(), ['active', 'persistent']);
  const fields = [
    'NlMtu',
    'InterfaceMetric',
    'AutomaticMetric',
    'Dhcp',
    'RouterDiscovery',
    'Forwarding',
    'WeakHostSend',
    'WeakHostReceive',
    'Advertising',
    'ManagedAddressConfiguration',
    'OtherStatefulConfiguration',
  ].sort();
  function scalar(value) {
    assert.deepEqual(Object.keys(value).sort(), ['cimType', 'value']);
    const maximum = new Map([
      [17, 255],
      [18, 65535],
      [19, 4294967295],
    ]).get(value.cimType);
    assert.notEqual(maximum, undefined);
    if (value.value !== null)
      assert.ok(Number.isInteger(value.value) && value.value >= 0 && value.value <= maximum);
  }
  for (const [name, store] of [
    ['active', 1],
    ['persistent', 0],
  ]) {
    const row = evidence[name];
    if (name === 'persistent' && row === null) continue;
    assert.deepEqual(Object.keys(row).sort(), [
      'addressFamily',
      'compartmentId',
      'interfaceIndex',
      'store',
      'values',
    ]);
    assert.equal(row.interfaceIndex, document.nativeOriginal.interfaceIndex);
    assert.equal(row.addressFamily, document.addressFamily === 'ipv4' ? 2 : 23);
    assert.equal(row.store, store);
    scalar(row.compartmentId);
    if (store === 1 || row.compartmentId.value !== null) assert.equal(row.compartmentId.value, 1);
    assert.deepEqual(Object.keys(row.values).sort(), fields);
    for (const value of Object.values(row.values)) scalar(value);
  }
  assert.equal(evidence.active.values.NlMtu.value, document.originalMtu);
}

function verifyOrigins(native) {
  assert.equal(native.schemaVersion, 2);
  assert.equal(native.registryOrigins.status, 'captured');
  const evidence = native.registryOrigins.evidence;
  assert.equal(evidence.schemaVersion, 1);
  assert.equal(evidence.adapterGuid, adapterGuid);
  assert.deepEqual(
    evidence.stacks.map((stack) => stack.name),
    ['Tcpip', 'Tcpip6'],
  );
  let bytes = 0;
  for (const stack of evidence.stacks) {
    assert.equal(typeof stack.keyPresent, 'boolean');
    assert.deepEqual(
      stack.values.map((entry) => entry.name),
      [
        'MTU',
        'EnableDHCP',
        'IPAddress',
        'SubnetMask',
        'DefaultGateway',
        'NameServer',
        'DhcpNameServer',
        'ProfileNameServer',
        'Dhcpv6DNSServers',
      ],
    );
    for (const entry of stack.values) {
      if (!stack.keyPresent) assert.equal(entry.value, null);
      if (entry.value !== null) {
        assert.ok(
          Number.isInteger(entry.value.valueType) &&
            entry.value.valueType >= 0 &&
            entry.value.valueType <= 0xffffffff,
        );
        assert.equal(typeof entry.value.dataHex, 'string');
        assert.match(entry.value.dataHex, /^(?:[0-9a-f]{2})*$/);
        bytes += entry.value.dataHex.length / 2;
      }
    }
  }
  assert.ok(bytes <= 4096);
  if (originReference === undefined) originReference = native.registryOrigins;
  assert.deepEqual(native.registryOrigins, originReference);
}
const childId = (index) => {
  const bytes = createHash('sha256')
    .update('epp-native-repeated-checkpoint-v1')
    .update(Buffer.from(experimentId.replaceAll('-', ''), 'hex'))
    .update(Buffer.from([index]))
    .digest()
    .subarray(0, 16);
  bytes[6] = (bytes[6] & 15) | 128;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};
const routeKeys = [
  'schemaVersion',
  'capturedAtUnixMs',
  'destination',
  'adapterGuid',
  'interfaceLuid',
  'interfaceIndex',
  'source',
  'destinationPrefix',
  'prefixLength',
  'nextHop',
  'routeMetric',
  'protocol',
  'origin',
  'sitePrefixLength',
  'loopback',
  'autoconfigureAddress',
  'publish',
  'immortal',
  'validLifetimeSeconds',
  'preferredLifetimeSeconds',
  'ageSeconds',
];
function routeHash(captures) {
  assert.equal(captures.length, 2);
  const stable = captures.map((capture) => {
    assert.equal(capture.status, 'captured');
    assert.equal(capture.snapshot.loopback, true);
    assert.ok(['127.0.0.1', '::1'].includes(capture.snapshot.destination.ip));
    const row = Object.fromEntries(routeKeys.map((key) => [key, capture.snapshot[key]]));
    row.capturedAtUnixMs = 1;
    row.ageSeconds = 0;
    for (const key of ['validLifetimeSeconds', 'preferredLifetimeSeconds'])
      row[key] = [0, 4294967295].includes(row[key]) ? row[key] : 1;
    return row;
  });
  return jsonHash(['selected-route-v1', stable]);
}

const databases = [];
const copies = mkdtempSync(path.join(tmpdir(), 'epp-repeated-inspect-'));
const sourceHashes = new Map();
const databaseNames = ['experiments.sqlite3', 'measurements.sqlite3', 'recovery.sqlite3'];
const suffixes = ['', '-wal', '-shm', '-journal'];
try {
  // inspect stable copies so sqlite never creates sidecars in service-owned storage.
  for (const name of databaseNames)
    for (const suffix of suffixes) {
      const source = path.join(directory, name + suffix);
      if (suffix && !existsSync(source)) continue;
      const stat = lstatSync(source);
      assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1);
      sourceHashes.set(source, digest(readFileSync(source)));
      copyFileSync(source, path.join(copies, name + suffix));
    }
  const open = (name) => {
    const file = path.join(copies, name);
    const stat = lstatSync(file);
    assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1);
    const database = new DatabaseSync(file, { readOnly: true });
    databases.push(database);
    assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
    return database;
  };
  const experiments = open('experiments.sqlite3');
  const measurements = open('measurements.sqlite3');
  const recovery = open('recovery.sqlite3');
  const head = experiments
    .prepare('SELECT revision,active,payload_json,sha256 FROM experiments WHERE id=?')
    .get(experimentId);
  const snapshot = checkedPayload(head);
  assert.equal(head.active, 0);
  assert.equal(snapshot.revision, head.revision);
  assert.equal(snapshot.state, 'completed');
  assert.equal(snapshot.schemaVersion, 2);
  assert.equal(snapshot.reservedBlocks, 12);
  assert.deepEqual(snapshot.plan.trafficBudget.limits, {
    probeAttempts: 216,
    providerRequests: 0,
    downloadBytes: 0,
    uploadBytes: 0,
  });
  assert.equal(snapshot.plan.trafficBudget.providers.length, 2);
  for (const [index, provider] of snapshot.plan.trafficBudget.providers.entries()) {
    assert.equal(provider.id, `loopback-${index + 1}`);
    assert.deepEqual(provider.perCollection, {
      probeAttempts: 3,
      providerRequests: 0,
      downloadBytes: 0,
      uploadBytes: 0,
    });
    assert.deepEqual(provider.limits, {
      probeAttempts: 108,
      providerRequests: 0,
      downloadBytes: 0,
      uploadBytes: 0,
    });
  }
  assert.equal(snapshot.error, null);
  assert.equal(snapshot.plan.id, experimentId);
  assert.equal(snapshot.plan.blockCount, 12);
  assert.equal(snapshot.blocks.length, 12);
  const checkpointIds = Array.from({ length: 12 }, (_, index) => childId(index));
  assert.deepEqual(snapshot.checkpoints, checkpointIds);
  const receipts = measurements
    .prepare(
      'SELECT run_id,payload_json,sha256 FROM native_measurements WHERE experiment_id=? ORDER BY run_id',
    )
    .all(experimentId);
  assert.equal(receipts.length, 36);
  const records = new Map();
  const selections = ['loopback-1', 'loopback-2'].flatMap((endpointId) => [
    { metricId: `${endpointId}-median`, endpointId, statistic: 'medianMs' },
    { metricId: `${endpointId}-failure`, endpointId, statistic: 'failurePercent' },
  ]);
  for (const row of receipts) {
    const receipt = checkedPayload(row);
    assert.equal(receipt.schemaVersion, 1);
    assert.equal(receipt.benchmarkScope, 'softwareLoopbackLifecycleControl');
    assert.equal(receipt.experimentId, experimentId);
    assert.equal(receipt.rawRunId, row.run_id);
    const raw = measurements
      .prepare('SELECT report_json FROM benchmark_runs WHERE id=?')
      .get(row.run_id);
    assert.equal(digest(raw.report_json), receipt.rawRunSha256);
    const run = JSON.parse(raw.report_json);
    assert.equal(run.id, row.run_id);
    assert.equal(run.status, 'completed');
    assert.equal(run.protocol, 'tcpConnect');
    assert.equal(run.samples.length, 6);
    assert.equal(run.results.length, 2);
    assert.equal(run.config.sampleCount, 3);
    assert.equal(run.config.intervalMs, 250);
    assert.equal(run.config.timeoutMs, 100);
    assert.equal(run.config.aiMode, 'disabled');
    assert.equal(run.routing.status, 'unchanged');
    assert.equal(routeHash(run.routing.before), run.routing.beforeFingerprint);
    assert.equal(routeHash(run.routing.after), run.routing.afterFingerprint);
    assert.equal(run.routing.beforeFingerprint, run.routing.afterFingerprint);
    assert.equal(
      jsonHash([
        'baseline-cohort-v1',
        run.appVersion,
        run.results.map((result) => result.endpoint),
        run.config.sampleCount,
        run.config.intervalMs,
        run.config.timeoutMs,
        run.config.sessionMinutes,
        selections,
      ]),
      snapshot.plan.comparison.cohortSha256,
    );
    const candidate = receipt.configuration === 'candidate';
    assert.ok(candidate || receipt.configuration === 'original');
    assert.equal(candidate, checkpointIds.includes(receipt.checkpointId));
    if (!candidate) assert.equal(receipt.checkpointId, null);
    for (const native of [receipt.nativeBefore, receipt.nativeAfter]) {
      verifyOrigins(native);
      assert.equal(native.adapterGuid, adapterGuid);
      assert.equal(native.addressFamily, family);
      assert.equal(native.alias, `epp-mtu-lab-${adapterGuid}`);
      assert.equal(native.driver.status, 'captured');
      assert.equal(native.driver.identity.infPath.toLowerCase(), 'netloop.inf');
      assert.equal(native.settings.nlMtu, candidate ? 1400 : 1500);
      assert.equal(
        jsonHash(native.settings),
        candidate
          ? snapshot.plan.comparison.candidateConfigurationSha256
          : snapshot.plan.comparison.originalConfigurationSha256,
      );
      assert.equal(
        jsonHash([
          'native-lab-loopback-environment-v2',
          native.adapterGuid,
          native.addressFamily,
          native.os,
          native.driver,
          native.registryOrigins,
          run.routing.beforeFingerprint,
        ]),
        snapshot.plan.comparison.environmentSha256,
      );
    }
    const values = [];
    for (const [index, result] of run.results.entries()) {
      assert.equal(result.endpoint.id, `loopback-${index + 1}`);
      assert.match(result.endpoint.address, index === 0 ? /^127\.0\.0\.1:\d+$/ : /^\[::1\]:\d+$/);
      const samples = run.samples.filter((sample) => sample.endpointId === result.endpoint.id);
      assert.equal(samples.length, 3);
      for (const sample of samples) {
        assert.equal(sample.address, result.endpoint.address);
        assert.equal(sample.error, null);
        assert.ok(Number.isFinite(sample.connectMs) && sample.connectMs >= 0);
      }
      values.push(
        samples.map((sample) => sample.connectMs).sort((first, second) => first - second)[1],
        0,
      );
    }
    records.set(`baseline:${row.run_id}`, { receipt, values });
  }
  const used = new Set();
  let mutators = 0;
  for (const [index, block] of snapshot.blocks.entries()) {
    const checkpointId = checkpointIds[index];
    const documentRow = recovery
      .prepare('SELECT document_json,sha256 FROM checkpoints WHERE id=?')
      .get(checkpointId);
    const document = checkedPayload(documentRow, 'document_json');
    verifyOrigins(document.nativeOriginal);
    verifyPolicy(document);
    assert.equal(document.id, checkpointId);
    assert.equal(document.context.adapterGuid, adapterGuid);
    assert.equal(document.addressFamily, family);
    assert.equal(document.originalMtu, 1500);
    assert.equal(document.proposedMtu, 1400);
    assert.equal(document.leaseExpiresAtUnixMs - document.createdAtUnixMs, 30000);
    let previous = documentRow.sha256;
    const events = recovery
      .prepare(
        'SELECT sequence,event_json,sha256 FROM checkpoint_events WHERE checkpoint_id=? ORDER BY sequence',
      )
      .all(checkpointId);
    assert.ok(events.length >= 4);
    for (const [sequence, row] of events.entries()) {
      const event = checkedPayload(row, 'event_json');
      if (event.observation?.native) verifyOrigins(event.observation.native);
      assert.equal(event.sequence, sequence);
      assert.equal(event.previousSha256, previous);
      previous = row.sha256;
    }
    assert.equal(JSON.parse(events.at(-1).event_json).state, 'restored');
    const commands = recovery
      .prepare(
        'SELECT sequence,document_json,sha256 FROM checkpoint_mutators WHERE checkpoint_id=? ORDER BY sequence',
      )
      .all(checkpointId);
    assert.equal(commands.length, 2);
    previous = documentRow.sha256;
    for (const [sequence, row] of commands.entries()) {
      const command = checkedPayload(row, 'document_json');
      assert.equal(command.checkpointId, checkpointId);
      assert.equal(command.sequence, sequence);
      assert.equal(command.purpose, sequence === 0 ? 'apply' : 'restore');
      assert.equal(command.previousSha256, previous);
      previous = row.sha256;
      mutators++;
    }
    for (const [role, session] of Object.entries(block)) {
      assert.ok(!used.has(session.id));
      used.add(session.id);
      const record = records.get(session.id);
      assert.ok(record);
      assert.deepEqual(session.values, record.values);
      assert.equal(record.receipt.configuration, role === 'candidate' ? 'candidate' : 'original');
      if (role === 'candidate') assert.equal(record.receipt.checkpointId, checkpointId);
      assert.equal(session.environmentSha256, snapshot.plan.comparison.environmentSha256);
      assert.equal(session.cohortSha256, snapshot.plan.comparison.cohortSha256);
      assert.equal(
        session.configurationSha256,
        role === 'candidate'
          ? snapshot.plan.comparison.candidateConfigurationSha256
          : snapshot.plan.comparison.originalConfigurationSha256,
      );
    }
  }
  assert.equal(used.size, 36);
  for (const [source, hash] of sourceHashes)
    assert.equal(
      digest(readFileSync(source)),
      hash,
      'Independent inspection must preserve service-owned bytes',
    );
  console.log(
    JSON.stringify({
      experimentId,
      family,
      blocks: 12,
      rawSessions: 36,
      successfulConnections: 216,
      restoredCheckpoints: 12,
      mutators,
      retainedSettings: false,
    }),
  );
} finally {
  for (const database of databases.reverse()) database.close();
  for (const name of databaseNames)
    for (const suffix of suffixes) {
      const file = path.join(copies, name + suffix);
      if (existsSync(file)) unlinkSync(file);
    }
  rmdirSync(copies);
}
