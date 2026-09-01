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

The M6.6 four-analyzer qualification admission run is GitHub Actions
[`33397257470`](https://github.com/pity11/VulnLoom/actions/runs/33397257470) for commit
`a7208935134b49b20868a21d228d3f135d2c1cb7`. The standard Python CI for the same commit is
[`33397257608`](https://github.com/pity11/VulnLoom/actions/runs/33397257608). Both completed
successfully on 2026-08-31 and qualify the M6.6 fan-in row below.

The M7.5 provider transport admission run is GitHub Actions
[`33465813508`](https://github.com/pity11/VulnLoom/actions/runs/33465813508) for commit
`5b82317640d70dffca50b877cb466b425d36fb03`. The standard Python CI for the same commit is
[`33465813515`](https://github.com/pity11/VulnLoom/actions/runs/33465813515). Both completed
successfully on 2026-09-01 and qualify the M7.5 provider transport row below.

The M7.6 provider egress lifecycle admission run is GitHub Actions
[`33474110739`](https://github.com/pity11/VulnLoom/actions/runs/33474110739) for commit
`e43b1b9e0a0ce1ee796d01b4fc62e14b26019440`. The standard Python CI for the same commit is
[`33474110527`](https://github.com/pity11/VulnLoom/actions/runs/33474110527). Both completed
successfully on 2026-09-01 and qualify the M7.6 provider egress lifecycle row below.

The M7.7 sealed Responses codec admission run is GitHub Actions
[`33477673827`](https://github.com/pity11/VulnLoom/actions/runs/33477673827) for commit
`c89616f2686a7937118ece6620c3aac5d6331183`. The standard Python CI for the same commit is
[`33477673808`](https://github.com/pity11/VulnLoom/actions/runs/33477673808). Both completed
successfully on 2026-09-01 and qualify the M7.7 provider codec row below.

The M7.8 typed Agent-to-Broker handoff admission run is GitHub Actions
[`33481732221`](https://github.com/pity11/VulnLoom/actions/runs/33481732221) for commit
`2a17eed9368e4220629e1911f6ebf54ba9f3f0fc`. The standard Python CI for the same commit is
[`33481732208`](https://github.com/pity11/VulnLoom/actions/runs/33481732208). Both completed
successfully on 2026-09-01 and qualify the M7.8 Agent tool handoff row below.

The M7.9 sealed Tool Observation continuation admission run is GitHub Actions
[`33493614664`](https://github.com/pity11/VulnLoom/actions/runs/33493614664) for commit
`ad6c88302a2e89b8c6f46aebf575dbe3fb8abc44`. The standard Python CI for the same commit is
[`33493614682`](https://github.com/pity11/VulnLoom/actions/runs/33493614682). Both completed
successfully on 2026-09-01 and qualify the M7.9 Agent Observation continuation row below.

The M7.10 sealed fixed two-tool Agent session admission run is GitHub Actions
[`33509298034`](https://github.com/pity11/VulnLoom/actions/runs/33509298034) for commit
`ed5d55831cd28cfc881629de759a9f316adb757d`. The standard Python CI for the same commit is
[`33509297870`](https://github.com/pity11/VulnLoom/actions/runs/33509297870). Both completed
successfully on 2026-09-01 and qualify the M7.10 Agent session row below.

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
| Four-analyzer qualification fan-in | One Target/Manifest/Scope produces authoritative completed Checkov/Kubesec/Trivy/CodeQL outcomes; missing or drifted cells are rejected before the complete matrix enters M6.3b | PASS (`33397257470`) |
| Provider transport | Fixed isolated subprocess inherits no parent secret/proxy environment, pins a numeric loopback peer while verifying admitted-host TLS, bounds output, kills on timeout, and composes through the typed Runtime without exposing raw credential or response data | PASS (`33465813508`) |
| Provider egress lifecycle | A trusted local issuer policy creates a content-addressed active loopback grant bound into registration; the Runtime reopens and verifies it before DNS/credential/process use, while offline tests enforce expiry, revocation, unfinished-checkpoint, tamper, and cleanup refusal | PASS (`33474110739`) |
| Provider Responses codec | A content-addressed codec emits the fixed non-streaming/non-stored strict-schema request and accepts only one completed assistant output text; the real isolated loopback TLS subprocess proves bounded transport, nested typed decoding, identity checks, and transient-buffer cleanup | PASS (`33477673827`) |
| Agent tool handoff | An authoritative completed Validator Agent intent is bound to an independently constructed exact Broker call; the real pinned Broker re-enforces Scope/Policy/network and imports only digest-bound Evidence metadata into an Observation, while checkpoint, Approval retry, timeout, drift, and no-raw-persistence paths remain fail-closed | PASS (`33481732221`) |
| Agent Observation continuation | Exact completed handoff and Evidence refs are reopened into redacted untrusted context; a derived Validator Task inherits authority and deadline but has no tools and zero tool-call budget, while the real loopback provider and pinned Broker prove one bounded continuation, terminal decision, and cleanup | PASS (`33493614664`) |
| Agent fixed two-tool session | One sealed Session Ledger monotonically accounts for at most three provider turns and two exact read-only Broker commitments; every Observation is rebuilt from verified Evidence, Approval pauses require an explicit one-shot retry, and a third tool proposal, budget drift, or incomplete cleanup fails closed | PASS (`33509298034`) |

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

M7.5 adds a separately marked provider transport probe to the same workflow. It generates an
ephemeral self-signed CA and starts only a loopback TLS fixture for an admitted `.test` hostname.
The real fixed child process receives a minimal environment, connects to the pre-resolved numeric
loopback address, verifies SNI/hostname and peer/TLS evidence, captures a bounded response, and is
forcibly reaped on timeout. A full Runtime composition probe also verifies credential/request/response
cleanup and digest-only attempt/receipt persistence. This PASS proves the subprocess and TLS boundary;
it neither contacts nor qualifies a public model provider, provider-specific protocol, or production
credential.

M7.6 extends the full Runtime composition probe by issuing the loopback transport grant through the
trusted local Authority, atomically publishing its read-only object, completing its lifecycle
checkpoint, and binding its exact ID into model registration before the TLS call. The ordinary CI
suite separately proves that revoked, expired, unfinished, linked, writable, malformed, conflicting,
or Admission-drifted grants stop before DNS and credential acquisition. This remains a local
Control Plane lifecycle proof, not a public-provider call or cryptographic remote-signer qualification.

M7.7 replaces the temporary test-shaped live wire body with the content-addressed
`openai-responses-v1` codec. The same real loopback TLS composition now verifies a fixed
`/v1/responses` request with storage and streaming disabled, a strict Agent decision schema, and no
provider tools or caller parameters. The bounded child response must decode as one completed
assistant `output_text`, exact model identity, typed usage, strict nested JSON, and the existing
`AgentDecisionPayload`; ordinary CI covers incomplete, refusal, native tool-call, duplicate-key,
oversize, timeout, drift, and cleanup refusals. This qualifies the codec and local subprocess
composition only. It does not contact or qualify a public provider, production credential, SDK,
streaming/session behavior, data-residency policy, quota, or operational egress authorization.

M7.8 adds a trusted typed handoff after a completed `tool_proposed` Agent run. The handoff reopens the
authoritative Agent checkpoint, compares its digest-only intent with a Control-Plane-constructed exact
`BrokerCall`, performs static preflight before its own STARTED checkpoint, and then leaves Scope,
Policy, DNS pinning, credential, tool budget, and Approval enforcement to the Broker. The Phase 3
composition connects only to a temporary authorized service through the real pinned transport and
stores the redacted response in the Evidence Store. The resulting `AgentToolObservation` contains
only typed counts, digests, and Evidence refs. This PASS does not qualify Agent-owned sockets,
arbitrary URLs, automatic Approval, public targets, recursive tool loops, Candidate/Finding promotion,
report export, or Submission.

M7.9 extends that composition through exactly one sealed Observation continuation. After the real
loopback provider proposes the precommitted call, the pinned Broker connects only to the temporary
authorized service, Evidence Store captures the redacted content, and the continuation reopens the
authoritative stores to rebuild bounded untrusted context for a second provider turn. The fixture
observes exactly one target request, the continuation terminates without tools, and both child
processes are reaped. Ordinary CI separately covers missing, linked, writable, oversized, or drifted
Evidence; exhausted budgets and deadlines; recursive tool proposals; provider failures; checkpoint
conflicts; recovery refusal; and absence of raw content in SQLite. This PASS does not qualify recursive
tool execution, public providers or targets, automatic Approval, state changes, Target construction,
Candidate/Finding promotion, report export, or Submission.

M7.10 replaces the single continuation limit with one sealed, fixed-shape session: the already
completed first tool round may be followed by at most one further exact call selected from a
content-addressed authorized call set and one terminal provider turn. The same loopback composition
proves two read-only Broker requests, two Evidence-backed Observations, monotonic cumulative budgets,
and complete provider/Broker cleanup. A separate Admission case proves that a third tool proposal is
rejected before another Broker call. Ordinary CI covers Approval pause and explicit retry, unlisted or
repeated commitments, cross-round provenance drift, exhausted budgets, deadlines, transport failure,
checkpoint conflict, recovery refusal, and absence of raw content in SQLite. This PASS does not qualify
dynamic URLs or arguments, public providers or targets, automatic Approval, write tools, Target builds,
arbitrary recursion, Candidate/Finding state changes, report export, or Submission.
