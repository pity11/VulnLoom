# Authorized Red Team

Authorized Red Team is VulnLoom's fourth product entry. It is designed for targets that the operator owns
or is explicitly contracted to assess. This entry does not weaken the shared Scope, Policy, Approval,
Broker, Runner, Evidence, Candidate, Critic, Finding, or Report boundaries.

## First trusted local slice

The first slice establishes the control-plane contract without performing network traffic:

```text
approved Scope + canonical HTTP(S) base URL
  → fixed black/grey-box red-team mode
  → content-addressed Rules of Engagement
  → resumable Flow checkpoint
  → typed read-only Recon action
  → offline fake adapter
  → redacted Observation
  → budget/stop-condition transition
```

`WorkflowMode` separates visibility from execution strength. The current Red Team slice fixes autonomy to
`a2_bounded_execution`, execution to `red_team`, and visibility to `black_box` or `grey_box`. It must not be
described as the future A4 campaign engine.

Rules of Engagement bind the exact Scope version, target, allowed phase, test classes, impact partition,
deadline, action budget, consecutive-failure budget, and an opaque emergency-contact reference. V1 admits
only the `recon` phase and `read_only` impact. State change, real credentials, external callback, lateral
movement, and persistence are explicitly prohibited rather than left implicit.

The target URL must already be canonical, contain no credentials/query/fragment, and exactly match an
approved `NetworkTargetScope` host, scheme, and port. Scope and policy are rechecked before Flow start and
before every new action. A model or adapter cannot add a target or impact class.

## State and recovery

Flow status follows an explicit state machine:

```text
planned → running → completed
                  ↘ cancelled | timed_out | failed | killed
```

Plans, checkpoints, action claims, and observations are stored transactionally in SQLite. Action identity
and idempotency keys are unique. An interrupted adapter leaves a `STARTED` claim; recovery requires the
next numbered attempt and is limited to three. If the third attempt is interrupted, the Flow closes as
`failed` with cleanup unproven. Replaying a completed action is read-only and does not call the adapter.

The Kill Switch remains usable when Scope has been revoked or expired, provided the immutable Scope
identity/version still matches. It can only reduce authority and immediately makes the Flow terminal.

## CLI and API boundary

The local `vulnloom red-team` command exposes the same application service intended for a future HTTP API:

- `start` creates and starts a bounded Flow;
- `prepare-recon` emits a typed action command;
- `run-recon-offline` runs only the deterministic fake adapter;
- `status`, `cancel`, `kill`, and `expire` inspect or narrow Flow state.

There is intentionally no live Recon flag in this slice. The CLI accepts no Cookie, Authorization header,
API key, Provider credential, raw response, shell command, or arbitrary tool identifier. Offline observations
contain only outcome, optional status code, reason code, cleanup proof, redaction proof, and time; admitted live
observations may additionally bind the digest-only Attack Surface Snapshot described below.

## R3: admitted local HTTP Recon

R3 adds one deliberately narrow live path: an `HTTP_HEAD` action may be routed through the existing trusted
Tool Broker only when an immutable, content-addressed `IsolatedLocalReconAdmission` binds one exact private,
non-loopback IPv4 fixture, host, port, scheme, and expiry. The Sandbox Profile must contain exactly the same
single network grant, and the Broker must enforce the admission's exact resolved-IP set. This extra constraint
rejects DNS drift even when the replacement address is another otherwise permitted private address.

The Broker rechecks Scope, Policy, network grant, DNS result, and actual socket peer at every redirect hop.
It performs a credential-free, body-free HEAD with bounded redirects, response bytes, request count, and
connect/read/total time. Socket timeouts become typed Recon timeouts. A cancelled or killed Flow cannot reach
the adapter. No live flag has been added to the normal CLI: the real-socket acceptance test is disabled unless
`VULNLOOM_RED_TEAM_INTEGRATION=1` is set and it starts only a temporary local fixture process.

Successful calls produce a content-addressed `AttackSurfaceSnapshot` embedded in the transactional
Observation. It contains only URL digests, the verified peer, status, redirect count, policy-record digests,
and Evidence references. The Broker Evidence sink allowlists response headers and redacts textual data; raw
URLs, cookies, Authorization material, and raw responses do not enter the Snapshot or Red Team database.

This milestone does not add public scanning, CIDR or path enumeration, active exploitation, credential use,
callbacks, lateral movement, persistence, or model-driven action selection. The next slice can build a bounded
attack-surface reducer over these trusted observations before any stronger action class is considered.

## R4: deterministic Attack Surface inventory

R4 reduces multiple successful R3 observations into an immutable `AttackSurfaceInventory` without making a
network call. A content-addressed `AttackSurfaceReductionPlan` binds the exact Flow plan, authoritative
checkpoint, Target, Scope version, Observation IDs, Snapshot IDs, deadline, budgets, and idempotency key.
Only completed HTTP HEAD actions with successful, redacted, cleanup-complete observations are admitted.

Before a STARTED checkpoint is written, the service reloads every source from the Red Team ledger and checks
the action, Flow, Target, Scope, requested URL digest, observation time, Snapshot identity, and every Evidence
object. Missing Evidence, stale Flow checkpoints, revoked Scope, empty live inputs, or exceeded budgets fail
closed without creating a partial reduction.

Endpoint identity is the stable digest of requested URL digest, final URL digest, and verified peer IP.
Repeated observations merge deterministically into sorted status codes, redirect counts, Observation IDs,
Snapshot IDs, and Evidence references. The Inventory contains no raw URL, request/response body, headers,
Cookie, Authorization material, or provider data.

The reduction ledger has explicit STARTED and COMPLETED states. Completed replay returns the same sealed
Inventory; unfinished work refuses automatic replay and permits only an explicit, maximum-three-attempt
recovery. The CLI exposes `prepare-surface-reduction`, `run-surface-reduction-offline`, and `surface-status`;
these commands reuse the same application service intended for a future API and never invoke Recon adapters.

## R5: verified TLS Service Identity

R5 adds a separate `tls.inspect` Broker capability and a typed, read-only TLS inspection plan. It accepts only
a canonical, query-free HTTPS URL, one test class, and bounded connect/handshake/total time. It has no request
body, headers, credential reference, redirect, protocol downgrade, or arbitrary socket option. The Registry
binds the exact resolver and transport implementation digests, while Scope, Policy, Profile network grant,
DNS result, exact local admission IP set, and actual socket peer are checked before an identity is accepted.

The pinned transport connects to the Broker-selected numeric IP but retains the authorized hostname for SNI
and certificate verification. Its TLS context must require CA verification, hostname verification, and TLS
1.2 or newer. A successful result contains only the endpoint URL digest, verified peer, negotiated TLS version,
cipher name/bits, leaf-certificate SHA-256, Policy digests, and Evidence references. Certificate bytes, subject,
SAN text, raw endpoint, headers, credentials, and provider responses are never returned or persisted.

`ServiceIdentitySnapshot` is deliberately narrower than a generic service fingerprint: it asserts only facts
from that verified TLS session. The R4 reducer now accepts both HTTP Attack Surface and TLS Service Identity
observations, preserves TLS-only inventories, and links identities to matching HTTP endpoints by URL digest and
peer IP. All source action, Flow, Target, Scope, timestamp, Snapshot and Evidence bindings are rechecked before
the transactional reduction completes.

Normal CLI commands still cannot start live network Recon. The TLS acceptance test is disabled unless
`VULNLOOM_RED_TEAM_TLS_INTEGRATION=1` is set; it creates a temporary CA-trusted certificate and a server bound
only to a local private non-loopback address, verifies the pinned TLS session, and proves process cleanup.

## R6: deterministic Attack Surface Drift

R6 compares two completed, content-addressed Inventories without running Recon or opening a socket. A typed
`AttackSurfaceDriftPlan` binds the exact baseline/current reduction and Inventory IDs, stable Target, current
Scope version, resource limits, deadline, and idempotency key. The baseline may come from an older version of
the same Scope, but the current Inventory must match the currently approved Scope; Target and Scope identity
must remain equal, and baseline time must strictly precede current time and comparison time.

The pure comparison groups HTTP endpoints and TLS identities by their digest-only authorized endpoint key.
It reports endpoint addition/removal, peer-set, final-destination, HTTP status, redirect behavior, TLS identity,
TLS version, cipher, and leaf-certificate digest changes. Each changed surface carries only content-addressed
endpoint/Snapshot/Evidence references. A Drift Report is an observation about sealed facts, not a Candidate,
Finding, vulnerability conclusion, state-changing test, or instruction to expand Scope.

Both source outcomes are reloaded from the authoritative reduction ledger and every Evidence object is checked
before claim and completion. The drift ledger uses STARTED/COMPLETED checkpoints, idempotent completed replay,
explicit recovery, and at most three attempts. The CLI commands `prepare-surface-drift`,
`run-surface-drift-offline`, and `surface-drift-status` call the same application service intended for a future
API. They expose no live network switch, raw URL, certificate, response, credential, or Provider material.

## R7: operator-sealed Endpoint Seed Sets

R7 accepts only a finite JSON array of exact paths supplied by an identified operator. Each `EndpointSeedSet`
is content-addressed and binds the current running Flow checkpoint, Target, Scope/version, operator reference,
seal time, expiry, and idempotency key. Paths must be canonical ASCII absolute paths beneath the Flow target's
base path. Schemes, authorities, query strings, fragments, percent encoding, backslashes, repeated slashes,
and dot segments are rejected rather than normalized.

An `EndpointReconPlan` deterministically maps every sealed seed to exactly one `HEAD` step with redirects
disabled. It has explicit step, request, per-request time, total time, and recovery-attempt limits. Preparing a
plan transactionally reserves its request count against the remaining RoE action budget for the exact source
checkpoint, so multiple plans cannot independently spend the same budget.

The application service reloads Scope, Flow, checkpoint, Seed Set, and Plan bindings before dispatch and again
before completion. Adapter results must match the exact step and URL digests; Evidence references must already
exist. Completed runs replay without adapter calls, interruptions remain STARTED for explicit bounded recovery,
and timeout or cleanup failure is represented explicitly. Outcomes and status output contain URL digests, not
raw paths or endpoints.

The CLI provides `seal-endpoint-seeds`, `prepare-endpoint-recon`, `run-endpoint-recon-offline`, and
`endpoint-recon-status`. The seed input is a bounded, no-follow regular file. The only executable adapter in R7
is deterministic and offline. There is deliberately no crawler, wordlist enumeration, discovered-URL queue,
DNS or port discovery, live Endpoint Recon adapter, or public scanning switch.

Local R7 verification completed with 1427 tests passed, 27 integration tests skipped, and 85.85% total
coverage. Ruff, 373 JSON Schema parses, `git diff --check`, and the 451-test CUC/DeepSeek compatibility slice
also passed without making an external model call or network request.

## R8: exact Endpoint execution through the Flow ledger

R8 gives every prepared plan an explicit action-budget reservation. A reservation begins `active`; each
authoritative Flow action consumes exactly one request and the final request moves it to `consumed`. Operator
cancellation and deadline expiry release only the unconsumed remainder. Consumed actions remain in the Flow
checkpoint and cannot be rolled back or made available to another plan.

Endpoint execution now creates deterministic `RedTeamReconCommand` values and reuses the existing transactional
action claim, Observation, checkpoint, Policy and Evidence path. Recovery replays completed actions without a
second Broker call. It rejects a non-authoritative Endpoint plan, a changed Scope, a terminal Flow, an unrelated
action inserted after the source checkpoint, inconsistent reservation progress, or altered Observation lineage.

The pinned HTTP adapter accepts an optional exact URL-digest allowlist. When that allowlist is present,
`max_redirects` must be zero. A successful Endpoint step must return an `AttackSurfaceSnapshot` whose requested
and final URL digests both equal the sealed step, with zero redirects and an existing redacted Evidence object.
Responses cannot add seeds or schedule another request.

The local CLI adds cancellation, expiry and reservation-aware status but intentionally has no live execution
command. Default tests use the fake pinned Broker. The opt-in `VULNLOOM_RED_TEAM_INTEGRATION=1` test extends the
existing isolated private-address fixture to execute a sealed path and prove process cleanup; it never targets a
public service.

Local R8 verification completed with 1438 tests passed, 27 integration tests skipped, and 85.87% total
coverage. Ruff, 374 JSON Schema parses, `git diff --check`, and the 589-pass/9-skip model-provider and
CUC/DeepSeek compatibility slice passed without an external model call or public network request. The opt-in
isolated private-address HTTP process test also passed separately, including the sealed Endpoint path and process
cleanup assertions.

## R9: recurring exact Endpoint check triggers

R9 introduces `EndpointCheckSchedule` as a Control Plane trigger, not a network executor. A schedule seals one
Scope/version, canonical Target, operator reference, exact path set, fixed UTC interval, authorization window,
Flow stop conditions and Endpoint Recon limits. Every due slot creates a new bounded Flow, Seed Set and Recon
Plan; it never reuses a long-running Flow and never calls the Broker or a Recon adapter.

Schedule checkpoints have explicit `active`, `paused`, `cancelled` and `expired` states. Each content-addressed
run is `started`, `materialized`, `timed_out` or `failed`. A STARTED run requires the next numbered recovery
attempt and allows at most three. Replaying a materialized slot returns the existing run without creating a
second Flow. A new slot is rejected while the prior Flow, reservation or Recon run has not reached a provably
clean terminal state.

If materialization crosses its deadline, the service cancels any partially created, unexecuted Endpoint
reservation and Flow before closing the run. Unproven cleanup or exhausted recovery attempts pauses the
schedule fail-closed. Scope expiry/version drift, a foreign operator, invalid path, non-due trigger, overlapping
run and stale checkpoint are rejected transactionally.

The local CLI exposes schedule create, trigger/recover, status, pause/resume, cancel and expire operations over
the same application service intended for a future API. Its projections contain only identifiers, counts,
digests and lifecycle state. There is no daemon, cron parser, public discovery, crawler, live execution flag,
notification adapter or Web UI in R9.

Local R9 verification completed with 1450 tests passed, 27 integration tests skipped, and 85.77% total
coverage. Ruff, 377 JSON Schema parses, `git diff --check`, and the 589-pass/9-skip model-provider and
CUC/DeepSeek compatibility slice passed without an external model call or network request.

## R11.1–R11.2: sealed Attack Graph and isolated execution boundary

R11's first slice extends the read-only RoE into a still-bounded external Web attack-chain control plane.
`AttackGraph` binds an exact Flow, Target, Scope/version, one finite `AttackObjective`, and 3–32
content-addressed `AttackAction` values. Actions form an ordinal DAG: the first and only Initial Access action
declares `state_change`; later actions verify the test session and goal Evidence; the final action is the only
Cleanup action and must directly depend on the Objective verification. Objective Evidence alone leaves the
chain running; terminal success requires successful cleanup. Runtime code cannot insert a node, replace a path,
or skip a dependency.

Every action requires a separate `EXECUTE_RED_TEAM_ACTION` Approval whose digest is the action digest. Initial
Access and Cleanup additionally require the existing Policy Engine's exact `MUTATE_TARGET_STATE` Approval. Approval for
another node, the whole Graph, or an expired action cannot be reused. External callback, lateral movement,
persistence, and real credentials remain prohibited by the RoE. Attack Action schemas contain no callback,
payload, shell, header, Cookie, credential, or response-body field.

`AttackChainCheckpoint` and action claims/Observations are stored transactionally in a separate SQLite ledger.
A completed action replays without another adapter call; interruption permits only the next bounded attempt.
Timeout, failure, unproven cleanup, Scope drift, missing prerequisites, missing Approval, and the parent Flow
Kill Switch all fail closed. Every allow or rejection creates a redacted `AttackActionAuditRecord` containing
only digests, a reason code, Approval IDs, and time.

If a non-cleanup action fails or times out after dispatch, the chain enters `cleanup_required` instead of a
terminal state. Only the graph's already sealed Cleanup action may run, with its own execution and mutation
Approvals; success then records the deferred failed/timed-out terminal result, while cleanup failure closes as
`cleanup_unproven`. This prevents a failure result from silently abandoning test state.

The new `post_exploitation` Sandbox Profile is non-root, read-only-root, capability-free, networkless, and
unable to execute Target code. It mounts immutable Evidence plus bounded scratch and exposes only
`red_team.evidence_read` and `red_team.result_write`. Real Web actions and transport remain outside that Worker.

R11.2 adds `IsolatedAttackChainAdmission` and a trusted adapter that binds one expiring private non-loopback
fixture, exact ordered action/method/URL digests, expected status/body digests, one target-only Validation
Profile grant, and the Broker's exact resolved-IP set. Requests have no body, header, credential, redirect, or
dynamic target field. The Broker rechecks Scope, Policy, mutation Approval, DNS pinning, peer and budgets for
every action; results become digest-only redacted Evidence references.

Default tests remain offline. The explicit `VULNLOOM_R11_ATTACK_CHAIN_INTEGRATION=1` acceptance starts only a
local private-address process and proves the exact `POST → GET → GET → DELETE` chain, goal-before-cleanup
remaining nonterminal, target-state cleanup, process cleanup and sensitive-header redaction. At the R11.2
boundary, attack-path, detection-opportunity and defensive-improvement reporting remained the final slice.

Local R11.2 verification completed with 1499 tests passed, 30 integration tests skipped, 85.42% coverage,
Ruff, 417 JSON Schema parses, and `git diff --check`. The separately enabled private-address process test
passed once. No public target or external model was contacted.

## R11.3: deterministic Attack Path Report

R11.3 closes the defensive reporting slice with a separate `Attack Path Report` domain object. It is not a
disclosure `Report`, does not require or create a Candidate/Finding, and cannot authorize another action. The
plan binds one authoritative successful chain, its final cleaned checkpoint, Target, Scope/version, operator
reference, deadline and idempotency key.

Each successful graph action becomes one digest-only `AttackPathStep`. Its Observation Evidence is checked by
bounded no-follow content-addressed reads before the report checkpoint is claimed. A fixed trusted mapping
creates one typed `DetectionOpportunity` and one finite `DefensiveImprovement` for session creation, session
use, protected-resource access and session revocation. No model or free-form recommendation can add another
path, target, control or claim that current telemetry already detects the action.

The transactional report ledger supports completed replay, conflict rejection, explicit recovery and at most
three attempts. Deadline expiry is a typed terminal outcome. JSON and Markdown artifacts are written through
bounded temporary files into a read-only content-addressed directory, verified with no-follow reads and removed
on failed publication. Artifacts contain action/evidence digests and enums, but no target path, endpoint,
request/response, header, Cookie, credential or secret field.

With the R11.2 isolated multi-step execution proof and this Evidence-backed defensive report, the scoped R11
milestone is complete. This does not enable public scanning, lateral movement, persistence, real credentials,
automatic Finding promotion, external report submission or production-target execution.

Local R11.3 verification completed with 1505 tests passed, 30 integration tests skipped, 85.39% coverage,
Ruff, 424 JSON Schema parses, and `git diff --check`. The isolated private-address process acceptance also
passed again separately. No external model or public target was contacted.

## R11.4: architecture and pressure hardening

R11.4 closes two cross-aggregate failure modes found during an end-to-end architecture review. Each chain now
reserves its complete action count in the authoritative parent Flow ledger before its own ledger is created.
Recon claims and competing chains serialize their budget checks with immediate SQLite transactions, while the
chain ledger retains a second reservation check. A crash between the two ledgers can leave a retryable reserved
budget, but cannot create an executable chain without budget or allow `max_actions` to be exceeded.

The chain contract now seals a separate cleanup deadline: it follows the normal action deadline by no more than
300 seconds and remains inside both Scope and Flow validity. A timeout, kill, cancellation, parent-checkpoint
advance, or interrupted state-changing adapter call therefore cannot be mislabeled as a clean terminal state.
The chain moves to `cleanup_required`, atomically abandons any uncertain started claim, and admits only the
original Cleanup action with fresh exact approvals, current Scope, monotonic parent-ledger provenance, and an
unexpired cleanup window. Deserialized checkpoints also verify their failure count, objective observation, and
all-success shape, while attack reports enforce exact action-to-detection-to-control mappings.

The new offline stress cases cover repeated over-reservation, cross-connection contention, mixed Recon/Chain
budget use, deadline-edge compensation, cleanup-window expiry, kill after confirmed or uncertain mutation,
parent checkpoint drift, idempotent replay, and tampered terminal data. No live network, model, crawler, public
scan, exploit submission, or external service is enabled by this hardening.

Local R11.4 verification completed with 1514 tests passed, 30 integration tests skipped, 85.41% coverage,
Ruff, 424 JSON Schema parses, and `git diff --check`. The opt-in private-process acceptance safely skipped on
this host because no private non-loopback IPv4 was available; it was not counted as a new pass. See
`docs/R11-ARCHITECTURE-HARDENING.md` for the reviewed control/data flows, failure matrix, and residual risks.
