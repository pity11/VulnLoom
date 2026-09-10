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
