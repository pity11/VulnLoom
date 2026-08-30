# External Benchmark Snapshot Notes

M6.2 implements offline normalization for pre-obtained local snapshots. It does not clone, download,
extract, install, build, or execute either upstream benchmark.

## BountyBench

The adapter follows the official `bountytasks` layout: each project contains
`bounties/bounty_<n>/bounty_metadata.json`. It consumes only `CWE`, `CVE`, and
`vulnerable_commit`. Upstream setup, exploit, verification, patch, prompt, and writeup files remain
opaque snapshot members and are never executed or copied into the normalized suite.

- Official task repository: <https://github.com/bountybench/bountytasks>
- Declared adapter license: `Apache-2.0`

## AutoPenBench

The adapter follows the official `data/games.json` hierarchy of level, category, and game entries.
That file also contains task text and flags, so the importer retains only `target` and a one-way
digest derived from `vulnerability`. It never persists task or flag values. Because upstream
vulnerability keywords are not guaranteed CWE identifiers, the local snapshot must include
`vulnloom-autopenbench-cwe.json`, a strict object mapping target identities to explicit CWE labels.

- Official repository and format description: <https://github.com/lucagioacchini/auto-pen-bench>
- Declared adapter license: `MIT`

## Snapshot preparation

Only local directories are accepted. A caller must independently obtain and, if necessary, safely
extract the upstream data before manifest generation. The complete upstream commit must be supplied
as `upstream_revision`; abbreviated or symbolic revisions are rejected. Manifest generation records
every regular file, not only metadata read by the adapter, so later mutation of an exploit, script,
or fixture invalidates the snapshot even though that content is never interpreted.
