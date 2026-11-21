# Repository instructions

- use camelCase for variables, parameters, functions, and fields wherever language conventions allow it; preserve external interfaces and follow language conventions for types, constants, modules, and files.
- keep comments minimal and lowercase; explain only non-obvious constraints or reasoning.
- never use emojis in source, documentation, configuration, logs, or commits.
- read README.md and the relevant code before editing. use the README's handoff checklist for remaining product scope; do not claim an incomplete stage is the finished optimizer.
- investigate execution paths before editing, use targeted searches, and batch independent reads.
- preserve unrelated changes, reuse helpers, avoid speculative fixes and unrelated refactors.
- keep privileged writes isolated in the dedicated windows service. do not add an arbitrary command, script, registry, or endpoint escape hatch.
- do not mutate the development machine's network configuration or conduct destructive network tests without explicit current authorization.
- before enabling any settings change, require a durable, verified backup of exact original values, adapter guid, and os/driver context. backup failure must block the change. automatic versus static dns/addressing semantics and offline service-owned recovery are mandatory; diagnostic snapshots alone do not prove restorability.
- run relevant checks, inspect the final diff, and state remaining unverified behavior. compilation alone does not prove recovery or performance.
- scan staged files with node scripts/scan-staged.mjs before committing. never commit runtime data, secrets, binaries, or logs.
- use subagents selectively only when independent parallel work provides meaningful value.
