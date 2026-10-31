import { execFileSync } from 'node:child_process';

const git = (args) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
const names = git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'])
  .split('\0')
  .filter(Boolean);
const findings = [];
const forbiddenPath =
  /(^|\/)(\.env(?:\..*)?|credentials?(?:\..*)?|id_rsa|id_ed25519)$|\.(?:exe|dll|msi|pdb|log|dmp|pfx|p12|pem|key)$|\.(?:db|sqlite3?)(?:-wal|-shm|-journal)?$/i;
const patterns = [
  ['private key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['GitHub credential', /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/],
  ['AWS credential', /\bAKIA[0-9A-Z]{16}\b/],
  ['provider credential', /\bsk-[A-Za-z0-9_-]{24,}\b/],
  [
    'credential assignment',
    /(?:api[_-]?key|auth[_-]?token|client[_-]?secret|password)\s*[:=]\s*["'][A-Za-z0-9_+/=-]{20,}["']/i,
  ],
];

for (const name of names) {
  if (forbiddenPath.test(name) && name !== '.env.example')
    findings.push(`${name}: forbidden private/runtime artifact`);
  const content = git(['show', `:${name}`]);
  if (content.includes('\0')) continue;
  for (const [label, pattern] of patterns) {
    if (pattern.test(content))
      findings.push(`${name}: possible ${label}; inspect locally before committing`);
  }
}
if (findings.length) {
  process.stderr.write(
    `${findings.join('\n')}\nSecret scan failed. No credential values are printed.\n`,
  );
  process.exit(1);
}
console.log(
  `Staged secret scan passed for ${names.length} files. Review the staged diff as well; pattern scanning is not exhaustive.`,
);
