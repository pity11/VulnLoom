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
API key, Provider credential, raw response, shell command, or arbitrary tool identifier. Its Observation
schema contains only outcome, optional status code, reason code, cleanup proof, redaction proof, and time.

## Next slice

R3 will add trusted DNS/TLS/HTTP adapters against an isolated local fixture, including resolution and peer
pinning, redirect re-authorization, bounded Evidence capture, timeout/cancel behavior, and actual process or
container cleanup tests. Public scanning, CIDR enumeration, active exploitation, credential use, callbacks,
lateral movement, and persistence remain unavailable.
