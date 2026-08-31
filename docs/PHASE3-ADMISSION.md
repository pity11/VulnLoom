# Phase 3 Admission Record

## Decision

**PASS.** M4.3 satisfies the production-isolation prerequisites for beginning Phase 3. This decision
does not claim that the Critic, Finding orchestration, or report generation already exists.

The baseline admission run is GitHub Actions
[`33307142075`](https://github.com/pity11/VulnLoom/actions/runs/33307142075) for commit
`9bc669f8e123c8f48e47c690c33559b6014e9e92`. The standard Python CI for the same commit is
[`33307142076`](https://github.com/pity11/VulnLoom/actions/runs/33307142076). Both completed
successfully on 2026-08-30.

The M6.4c analyzer admission run is GitHub Actions
[`33323829710`](https://github.com/pity11/VulnLoom/actions/runs/33323829710) for commit
`3452eca44520d9ca977de9d4021c2ca5347c8900`. The standard Python CI for the same commit is
[`33323829695`](https://github.com/pity11/VulnLoom/actions/runs/33323829695). Both completed
successfully on 2026-08-31 and qualify the M6.4c analyzer rows below.

The M6.4d CodeQL writable-copy admission run is GitHub Actions
[`33354872312`](https://github.com/pity11/VulnLoom/actions/runs/33354872312) for commit
`b6b98da676a07a6b833e4045d8e6fdc309fb2472`. The standard Python CI for the same commit is
[`33354872370`](https://github.com/pity11/VulnLoom/actions/runs/33354872370). Both completed
successfully on 2026-08-31 and qualify the M6.4d analyzer row below.

## Enforced admission criteria

| Boundary | Required proof | Result |
|---|---|---|
| Engine | Rootless daemon, seccomp, cgroup v2, memory limit, CPU quota, and PID limit support | PASS |
| Worker identity | Non-root UID/GID, no capabilities, `NoNewPrivs`, no inherited host secret | PASS |
| Filesystem | Read-only root and source, bounded hardened tmpfs, no Docker socket | PASS |
| Worker network | No default route; cannot reach a live sibling container or daemon gateway | PASS |
| Broker gateway policy | Actual daemon gateways discovered and denied before transport | PASS |
| DNS rebinding | Redirect hop is re-resolved; metadata-address drift is denied before a second socket | PASS |
| Timeout and cleanup | Timed-out Worker is killed; container and anonymous storage absence is verified | PASS |
| Full composition | Rootless Runner, pinned Broker, redacted Evidence, deterministic judge, state transition, and cleanup | PASS |
| Analyzer execution | Versioned Checkov/Kubesec/Trivy resolved to exact image IDs, network-disabled source-only execution, bounded output, M6.3a import, and cleanup | PASS (`33323829710`) |
| Trivy analyzer data | DB v2 is provisioned outside execution, sealed read-only and content-addressed, mounted read-only, reverified after cleanup, and used with the vuln scanner only | PASS (`33323829710`) |
| CodeQL writable-copy boundary | Target-bound DB/query snapshot remains read-only; exact wrapper writes only a bounded tmpfs copy, captures SARIF, imports M6.3a Observations, and cleans the container | PASS (`33354872312`) |
| Four-analyzer qualification fan-in | One Target/Manifest/Scope produces authoritative completed Checkov/Kubesec/Trivy/CodeQL outcomes; missing or drifted cells are rejected before the complete matrix enters M6.3b | Enforced for M6.6 runs |

## Reproduction

The admission workflow is [`.github/workflows/phase3-admission.yml`](../.github/workflows/phase3-admission.yml).
It installs pinned Docker Engine 29.7.2 packages on Ubuntu 24.04, runs the daemon as a delegated
systemd user service, pulls the test fixture image before execution, and then runs all real isolation
and composition probes with the production-default `DockerEnginePolicy`.

Local Docker Desktop probes remain useful regression checks, but their explicit rootful test-only
exception cannot replace this admission workflow.

Beginning with M6.4b, the same workflow provisions Checkov 3.3.15 and Kubesec 2.14.2 before the
test phase. M6.4c additionally provisions Trivy 0.73.0 and its DB v2 outside execution, copies only
`db/metadata.json` and `db/trivy.db` into a read-only sealed directory, then runs all three through
`DockerAnalyzerExecutionService`. Provisioning may access registries; every tested runtime path
uses the inspected image ID, `--pull never`, and `network=none`. The historical M4.3 PASS above
remains unchanged; each analyzer row is PASS only after the updated workflow succeeds.

M6.4d builds a dedicated behavior-fixture image outside tested execution. The fixture performs the
same database `results` write as CodeQL but does not construct or execute a Target. The production
wrapper copies the sealed database into bounded output tmpfs, runs under the existing exact-image,
`--pull never`, `network=none` boundary, streams bounded SARIF, and leaves the original database
without a `results` directory. This row qualifies isolation and lifecycle enforcement; it does not
claim qualification of a real CodeQL bundle, license, query pack, or prebuilt database.

M6.6 keeps the four single-analyzer probes and adds one campaign probe. The campaign executes all
four admitted registrations against the same Target provenance and one authoritative execution
store, confirms that incomplete and drifted matrices leave both qualification and evaluation
stores empty, then requires a complete four-analyzer M6.5 qualification and M6.3b PASS. It adds no
new runtime permission; the existing rootless, exact-image, `--pull never`, `network=none`, bounded
output, mandatory Observation import, immutable analyzer-data, and cleanup checks remain in force.
