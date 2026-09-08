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

The M7.11 immutable Agent session audit admission run is GitHub Actions
[`33517750165`](https://github.com/pity11/VulnLoom/actions/runs/33517750165) for commit
`d2acbcc0225168627b459dbc62e4aaf98ccb52c7`. The standard Python CI for the same commit is
[`33517750294`](https://github.com/pity11/VulnLoom/actions/runs/33517750294). Both completed
successfully on 2026-09-01 and qualify the M7.11 Agent session audit row below.

The M8.1 human Validation Intake admission run is GitHub Actions
[`33524481072`](https://github.com/pity11/VulnLoom/actions/runs/33524481072) for commit
`a27661cd2554128f1ce63b89d9c862e381a89436`. The standard Python CI for the same commit is
[`33524481152`](https://github.com/pity11/VulnLoom/actions/runs/33524481152). Both completed
successfully on 2026-09-01 and qualify the M8.1 Agent Validation Intake row below.

The M8.2 completed Validation outcome binding admission run is GitHub Actions
[`33529822161`](https://github.com/pity11/VulnLoom/actions/runs/33529822161) for commit
`3fffa23583c1c0e2146af55dff1b4789724a8311`. The standard Python CI for the same commit is
[`33529822053`](https://github.com/pity11/VulnLoom/actions/runs/33529822053). Both completed
successfully on 2026-09-02 and qualify the M8.2 Agent Validation outcome binding row below.

The M8.3 human Critic Intake admission run is GitHub Actions
[`33536352834`](https://github.com/pity11/VulnLoom/actions/runs/33536352834) for commit
`38a7635b8803d9c609996dc054347b953af15f9a`. The standard Python CI for the same commit is
[`33536352814`](https://github.com/pity11/VulnLoom/actions/runs/33536352814). Both completed
successfully on 2026-09-02 and qualify the M8.3 human Critic Intake row below.

The M8.4 completed Critic outcome binding admission run is GitHub Actions
[`33605801522`](https://github.com/pity11/VulnLoom/actions/runs/33605801522) for commit
`7bce7f697bcec2ab770a8b72cb1695f01a736916`. The standard Python CI for the same commit is
[`33605801498`](https://github.com/pity11/VulnLoom/actions/runs/33605801498). Both completed
successfully on 2026-09-02 and qualify the M8.4 Critic outcome binding row below.

The M8.5 human Finding promotion Intake admission run is GitHub Actions
[`33609723750`](https://github.com/pity11/VulnLoom/actions/runs/33609723750) for commit
`48e6dc6e84ef38aa729743b29963e3d1fa801964`. The standard Python CI for the same commit is
[`33609723864`](https://github.com/pity11/VulnLoom/actions/runs/33609723864). Both completed
successfully on 2026-09-02 and qualify the M8.5 Finding promotion Intake row below.

The M8.6 Approval-gated deterministic Finding promotion admission run is GitHub Actions
[`33612075599`](https://github.com/pity11/VulnLoom/actions/runs/33612075599) for commit
`be5a403ea953ef12e706b7145068d68c756b10b6`. The standard Python CI for the same commit is
[`33612075640`](https://github.com/pity11/VulnLoom/actions/runs/33612075640). Both completed
successfully on 2026-09-02 and qualify the M8.6 Finding promotion row below.

The M8.7 human Report Intake admission run is GitHub Actions
[`33614573666`](https://github.com/pity11/VulnLoom/actions/runs/33614573666) for commit
`f7262e01863f100b54cf0169566dc5b6e4f1cd0a`. The standard Python CI for the same commit is
[`33614573468`](https://github.com/pity11/VulnLoom/actions/runs/33614573468). Both completed
successfully on 2026-09-02 and qualify the M8.7 human Report Intake row below.

The M8.8 accepted Intake deterministic local draft admission run is GitHub Actions
[`33616668895`](https://github.com/pity11/VulnLoom/actions/runs/33616668895) for commit
`09e3e1e6f50520f23287cb56304b0ade4bc41e28`. The standard Python CI for the same commit is
[`33616668897`](https://github.com/pity11/VulnLoom/actions/runs/33616668897). Both completed
successfully on 2026-09-02 and qualify the M8.8 local Report draft binding row below.

The M8.9 human Report review Intake admission run is GitHub Actions
[`33619141456`](https://github.com/pity11/VulnLoom/actions/runs/33619141456) for commit
`ed2d5e76fffba3ed104bff1fbd91b86f684ea1fb`. The standard Python CI for the same commit is
[`33619141458`](https://github.com/pity11/VulnLoom/actions/runs/33619141458). Both completed
successfully on 2026-09-02 and qualify the M8.9 human Report review Intake row below.

The M8.10 Approval-gated deterministic Report review admission run is GitHub Actions
[`33621891122`](https://github.com/pity11/VulnLoom/actions/runs/33621891122) for commit
`3404fa08d75670062b3d8039351d14fe2f8ff567`. The standard Python CI for the same commit is
[`33621891210`](https://github.com/pity11/VulnLoom/actions/runs/33621891210). Both completed
successfully on 2026-09-02 and qualify the M8.10 Report review execution row below.

The M8.11 human local Report export Intake admission run is GitHub Actions
[`33623614574`](https://github.com/pity11/VulnLoom/actions/runs/33623614574) for commit
`3dac4333b173500d32ac2291765bdf59ef99c130`. The standard Python CI for the same commit is
[`33623614558`](https://github.com/pity11/VulnLoom/actions/runs/33623614558). Both completed
successfully on 2026-09-02 and qualify the M8.11 Report export Intake row below.

The M8.12 Approval-gated deterministic local Report export admission run is GitHub Actions
[`33626287272`](https://github.com/pity11/VulnLoom/actions/runs/33626287272) for commit
`a4b98a1b7b71b3145b26def1230ac584795ad35d`. The standard Python CI for the same commit is
[`33626287258`](https://github.com/pity11/VulnLoom/actions/runs/33626287258). Both completed
successfully on 2026-09-02 and qualify the M8.12 local Report export execution row below.

The M9.1 closed Agent workflow regression admission run is GitHub Actions
[`33629783453`](https://github.com/pity11/VulnLoom/actions/runs/33629783453) for commit
`e1a976937f17c40ccc7c7a2c6b50f81c30b0c6a8`. The standard Python CI for the same commit is
[`33629783383`](https://github.com/pity11/VulnLoom/actions/runs/33629783383). Both completed
successfully on 2026-09-02 and qualify the M9.1 closed workflow regression row below.

The M9.2 sealed negative-path mutation corpus admission run is GitHub Actions
[`33632777116`](https://github.com/pity11/VulnLoom/actions/runs/33632777116) for commit
`20494936a625774363fbbdc8192022802141c5fb`. The standard Python CI for the same commit is
[`33632777250`](https://github.com/pity11/VulnLoom/actions/runs/33632777250). Both completed
successfully on 2026-09-02 and qualify the M9.2 mutation regression row below.

The M9.3 local-source quality benchmark admission run is GitHub Actions
[`33635497035`](https://github.com/pity11/VulnLoom/actions/runs/33635497035) for commit
`920591c7fd5a74f4d7b756431fec3e49942c14d0`. The standard Python CI for the same commit is
[`33635497379`](https://github.com/pity11/VulnLoom/actions/runs/33635497379). Both completed
successfully on 2026-09-02 and qualify the M9.3 local-source quality row below.

The M9.4 cross-framework and safe-negative robustness admission run is GitHub Actions
[`33637781003`](https://github.com/pity11/VulnLoom/actions/runs/33637781003) for commit
`d2b94b6638c697b1a5708d37414f78ecc7f8bab5`. The standard Python CI for the same commit is
[`33637780947`](https://github.com/pity11/VulnLoom/actions/runs/33637780947). Both completed
successfully on 2026-09-02 and qualify the M9.4 local-source robustness row below.

The M9.5 authorized local-pilot readiness admission run is GitHub Actions
[`33641691085`](https://github.com/pity11/VulnLoom/actions/runs/33641691085) for commit
`8653e65f517df21e965571f5950bad0f510b1082`. The standard Python CI for the same commit is
[`33641691100`](https://github.com/pity11/VulnLoom/actions/runs/33641691100). Both completed
successfully on 2026-09-02 and qualify the M9.5 authorized pilot readiness row below.

The M9.6 review-only local shadow pilot admission run is GitHub Actions
[`34027167183`](https://github.com/pity11/VulnLoom/actions/runs/34027167183) for commit
`94b7bb8169790f9f65018d7f4224a30771e7ef9b`. The standard Python CI for the same commit is
[`34027167185`](https://github.com/pity11/VulnLoom/actions/runs/34027167185). Both completed
successfully on 2026-09-06 and qualify the M9.6 local shadow pilot row below.

The M9.7 human pilot Candidate selection admission run is GitHub Actions
[`34033041942`](https://github.com/pity11/VulnLoom/actions/runs/34033041942) for commit
`178062b2538e0a38162c170d5c790368a96c799a`. The standard Python CI for the same commit is
[`34033041866`](https://github.com/pity11/VulnLoom/actions/runs/34033041866). Both completed
successfully on 2026-09-06 and qualify the M9.7 human Candidate selection row below.

The M9.8 pilot-bound human Validation Intake admission run is GitHub Actions
[`34034039079`](https://github.com/pity11/VulnLoom/actions/runs/34034039079) for commit
`a6e3cc85ab784fa8bd5fcd171d681e2fbfc9c7c1`. The standard Python CI for the same commit is
[`34034039075`](https://github.com/pity11/VulnLoom/actions/runs/34034039075). Both completed
successfully on 2026-09-06 and qualify the M9.8 pilot Validation Intake binding row below.

The M9.9 Approval-gated offline pilot Validation admission run is GitHub Actions
[`34035435464`](https://github.com/pity11/VulnLoom/actions/runs/34035435464) for commit
`9aac6169bb5ddfd4a466c83c42dbcd0d308df214`. The standard Python CI for the same commit is
[`34035435470`](https://github.com/pity11/VulnLoom/actions/runs/34035435470). Both completed
successfully on 2026-09-06 and qualify the M9.9 pilot Validation execution row below.

The M9.10 pilot outcome provenance admission run is
[`34041988318`](https://github.com/pity11/VulnLoom/actions/runs/34041988318) for commit
`fe0c96b0c9dcfac6b50c1935c0efe2a7f14c7300`. The same commit passed standard CI
[`34041988283`](https://github.com/pity11/VulnLoom/actions/runs/34041988283).
Both completed successfully on 2026-09-06 UTC.

The M9.11 pilot Critic Intake admission run is
[`34075541690`](https://github.com/pity11/VulnLoom/actions/runs/34075541690) for commit
`ca327345d948d176bbd238d0a4eea6a3effa9dd6`. The same commit passed standard CI
[`34075541729`](https://github.com/pity11/VulnLoom/actions/runs/34075541729).
Both completed successfully on 2026-09-07 UTC.

The M9.12 approved pilot Critic execution admission run is
[`34079581400`](https://github.com/pity11/VulnLoom/actions/runs/34079581400) for commit
`a8c2c2b2db1a3cc6da2453024511173f972ecb71`. The same commit passed standard CI
[`34079581413`](https://github.com/pity11/VulnLoom/actions/runs/34079581413).
Both completed successfully on 2026-09-07 UTC.

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
| Agent session audit | A completed fixed-shape Session is reopened from authoritative Agent, handoff, continuation and Evidence stores; ordered commitments and cumulative budgets are recomputed before a digest-only, read-only audit bundle and deterministic non-authoritative recommendation are published | PASS (`33517750165`) |
| Agent Validation Intake | A human accepts one exact Control-Plane-built ValidationPlan bound to an immutable completed Audit recommendation and CandidateSet; tampering is rejected before checkpoint and Runner, Broker, provider and target call counts remain unchanged | PASS (`33524481072`) |
| Agent Validation outcome binding | One explicitly completed Validation is reopened with its accepted Intake, Audit, Candidate, exact plan, run and Evidence provenance; outcome tampering is rejected before checkpoint and read-only binding leaves Runner, Broker, provider and target call counts unchanged | PASS (`33529822161`) |
| Agent Critic Intake | A human selects one exact independently constructed CriticPlan bound to a reproduced M8.2 outcome, immutable Audit/Candidate provenance and verified Evidence; Intake adds no Critic execution, Candidate mutation, Runner, Broker, provider or target call | PASS (`33536352834`) |
| Agent Critic outcome binding | One explicitly completed deterministic Critic outcome is reopened with its accepted Intake, M8.2 Validation binding, exact plan, review and Evidence provenance; tampering is rejected before checkpoint and binding adds no Critic replay, Candidate mutation, Runner, Broker, provider or target call | PASS (`33605801522`) |
| Agent Finding promotion Intake | A human selects one trusted-control-plane-built exact promotion plan bound to an accepted M8.4 outcome, critic-reviewed Candidate, reproduced Validation, verified Evidence and the authoritative latest duplicate-clear proof; Intake adds no promotion, Finding creation, Runner, Broker, provider or target call | PASS (`33609723750`) |
| Agent local Report draft binding | One human-accepted M8.7 record is reopened with the sealed promotion, Critic, Validation, Evidence catalog and exact ReportDraftPlan; metadata drift is rejected before checkpoint, while one deterministic local DRAFT and prose-free binding add no Runner, Broker, provider, target, approval, export or Submission call | PASS (`33616668895`) |
| Agent Report review Intake | A human selects one exact trusted-control-plane ReportReviewPlan bound to the completed M8.8 DRAFT, immutable artifact, EvidenceBundle and identical ordered Evidence catalog; tampering is rejected before checkpoint and Intake leaves the Report DRAFT with no review, approval, export, Runner, Broker, provider, target or Submission call | PASS (`33619141456`) |
| Agent Report review execution | One accepted M8.9 record is consumed only with a separately issued exact human command and granted `REVIEW_REPORT` Approval; action-digest tampering is rejected before checkpoint, while an explicit `request_changes` transition leaves the source DRAFT immutable and adds no Runner, Broker, provider, target, export or Submission call | PASS (`33621891122`) |
| Agent Report export Intake | A human selects one exact trusted-control-plane ReportExportPlan bound to a completed M8.10 `approve` decision, `HUMAN_APPROVED` Report, review and immutable artifact; plan tampering is rejected before checkpoint and Intake leaves the Report human-approved with no new artifact, export, Runner, Broker, provider, target, destination or Submission call | PASS (`33623614574`) |
| Agent local Report export execution | One accepted M8.11 record is consumed only with a granted exact `EXPORT_REPORT` Approval; action-digest tampering is rejected before checkpoint, while the deterministic local export creates one immutable `EXPORTED` artifact, preserves the source human-approved Report, and adds no Runner, Broker, provider, target, destination, public-network or Submission call | PASS (`33626287272`) |
| Closed Agent workflow regression | One fixed 13-stage M7.11–M8.12 observation binds six human Intake decisions, three exact Approvals, Evidence and immutable Candidate/Report states; the typed gate passes only when provider, Broker, Runner and target counts do not increase after Validation and public-network, build, automatic-Approval and Submission counts remain zero | PASS (`33629783453`) |
| Agent workflow mutation regression | One sealed corpus covers all 23 fixed M9.1 mutations exactly once; immutable expected status and ordered violation codes match 23/23 on Python 3.12/3.13/3.14, including public-network, Target-build, automatic-Approval and Submission failures | PASS (`33632777250`) |
| Local-source Agent quality | Nine sealed local source cases exercise the real archive-ingestion, AST SourceGraph and deterministic Candidate path across eight supported CWE families plus one guarded negative; recall, precision, trace, bound M6.1 Finding/Evidence quality and all forbidden-effect counters pass on Python 3.12/3.13/3.14 | PASS (`33635497379`) |
| Cross-framework static robustness | A code-owned 13-case contract covers five Flask/FastAPI/Django positive paths and eight safe negatives; exact framework, cross-file provenance, per-case call depth, zero parse failures, zero negative Candidates and the shared zero-effect quality gate pass on Python 3.12/3.13/3.14 | PASS (`33637780947`) |
| Authorized local-pilot readiness | One content-addressed local pilot binds an approved Scope, fully verified 18-file Snapshot, rebuilt SourceGraph, five exact proposed Candidates, passing M9.4 quality, ten fixed human gates and eight forbidden capabilities; Python 3.12/3.13/3.14 report zero forbidden effects while the concurrent rootless boundary remains admitted | PASS (`33641691100`) |
| Review-only local shadow pilot | One CLI composition accepts only an already-ingested local Snapshot and exact approved Scope, rebuilds trusted static objects, requires the exact admitted M9.4 baseline, emits proposed-or-empty Candidate review output and selects none; normal CI covers replay, revoked Scope, baseline drift and zero Candidates while the concurrent rootless boundary remains admitted | PASS (`34027167185`) |
| Human pilot Candidate selection | One explicit human command reopens a completed passing readiness result and immutable artifact, verifies exact SourceGraph/CandidateSet/Snapshot/Scope provenance, and uniquely records one still-proposed Candidate; replay, wrong Candidate, failed readiness, timeout, drift, conflict and unfinished recovery add no ValidationPlan or operational authority | PASS (`34033041866`) |
| Pilot-bound human Validation Intake | One exact completed M9.7 selection is uniquely consumed with an independently supplied M8.1 Intake plan, explicit human `accept` command and pre-existing ValidationPlan; authoritative identities, digests, Scope and deadlines are rechecked before a digest-only binding, while replay, drift, timeout and unfinished recovery add no Validation execution, Candidate mutation, Runner/Broker parameters or external effect | PASS (`34034039075`) |
| Approval-gated offline pilot Validation | One completed M9.8 binding and accepted M8.1 record are consumed only with the identical pre-existing ValidationPlan and a separately granted exact `RUN_VALIDATION` Approval; trusted preflight, unique execution checkpoints and digest-only outcome binding enforce replay, drift, timeout, bypass and recovery refusal while the first version rejects all Broker calls and network activity | PASS (`34035435470`) |
| Pilot Validation outcome provenance | A completed M9.9 execution binding and exact M8.2 plan are required; upstream provenance, bare-checkpoint refusal, read-only replay, drift, timeout and STARTED recovery are verified without executing Validation or changing Candidate state | PASS (`34041988283`) |
| Pilot human Critic Intake | Completed M9.10 provenance, reproduced Validation, validated result Candidate, complete Evidence and an independent exact human accept command are required before M8.3 checkpointing; bare Intake, drift, timeout and interrupted state fail closed, and replay never executes Critic or Validation | PASS (`34075541729`) |
| Approval-gated pilot Critic execution | Completed M9.11 provenance and an independent exact RUN_CRITIC Approval gate deterministic review and M8.4 binding; unique consumption, all verdicts, current Evidence, bare-checkpoint refusal, read-only replay and interrupted-state recovery are verified without Validation, target execution, network or Submission | PASS (`34079581413`) |

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

M7.11 extends the same real loopback composition after the completed M7.10 Session. The audit service
reopens the authoritative Session, Agent run, handoff, continuation and Evidence checkpoints, verifies
two ordered Observations, recomputes the final token/step/tool/provider/Broker budget, and publishes a
bounded read-only JSON/Markdown object containing only IDs, digests, typed counts and a deterministic
recommendation. The Admission probe also tampers with the supplied Session-plan binding and proves
rejection before replay or artifact replacement. Ordinary CI covers completed, blocked, failed and
timed-out projections; Evidence drift; early/expired plans; writable artifacts; checkpoint conflicts;
publication cleanup; and absence of URL, credential, provider wire data, tool arguments and Evidence
body content from audit schemas and persistence. This PASS adds no provider or target authority and
does not qualify Candidate/Finding transitions, Validation execution, report export or Submission.

M8.1 consumes that real M7.11 audit artifact only through the read-only artifact store, binds it to an
immutable CandidateSet and a separately constructed local typed ValidationPlan, then records one
explicit human `accept`. The Admission probe first tampers with the ValidationPlan and proves rejection
before the Intake checkpoint. The accepted path leaves Candidate state at `PROPOSED`, target requests
at two, provider attempts at three, and performs no Runner or Broker call. Ordinary CI covers all three
human decisions, non-completed recommendations, expiry, writable CandidateSet objects, digest drift,
unfinished recovery and SQLite/schema absence of executable or sensitive fields. This PASS qualifies
only immutable Intake binding; it does not qualify Validation execution, Approval, Candidate mutation,
Target build, public egress, Finding creation or Submission.

M8.2 explicitly invokes the existing local Validation entry point once after that accepted Intake,
then reopens the completed checkpoint through the read-only binding service. The Admission probe
replaces the stored Runner result identity and proves rejection before any binding checkpoint, restores
the authoritative outcome, and records one digest-only binding. Runner calls remain at one, target
requests remain at two, provider attempts remain at three, and binding adds no Broker or network call.
Ordinary CI covers reproduced, not-reproduced, inconclusive, policy-stopped and timed-out outcomes;
expired/non-accepted Intake, missing/unfinished Validation, Candidate/Target/Scope/plan/run/Evidence
drift, duplicate consumption, unfinished recovery and SQLite/schema absence of request or body data.
This PASS qualifies only provenance binding for an already completed Validation; it does not qualify
automatic Validation, retry, Approval, Candidate mutation, Critic verdict, Finding creation, public
egress, Target build or Submission.

M8.3 extends the same composition by making the explicit local Validation deterministically reproduced,
binding that completed outcome through M8.2, constructing an independent four-angle CriticPlan, and
recording one human `accept`. Critic Intake reopens the Audit artifact, CandidateSet, binding,
Validation checkpoint and Evidence, but never calls `DeterministicCritic`. Runner calls remain at one,
target requests remain at two, provider attempts remain at three, and the original Candidate remains
`PROPOSED`. Ordinary CI covers accept/reject/defer, non-reproduced outcomes, plan drift, Evidence
integrity, duplicate consumption, unfinished recovery and digest-only schema/SQLite persistence. This
PASS qualifies only human selection of an exact CriticPlan; it does not qualify Critic execution,
automatic verdict acceptance, Candidate/Finding promotion, public egress, report export or Submission.

M8.4 then explicitly invokes the existing deterministic Critic once, after the accepted M8.3 record,
and reopens that completed checkpoint through a separate read-only binding service. The Admission
probe replaces the stored Critic rationale and proves rejection before any binding checkpoint,
restores the authoritative outcome, and records one digest-only binding. Runner calls remain at one,
target requests remain at two, provider attempts remain at three, and the original Candidate remains
`PROPOSED`; binding does not replay Critic or copy Evidence content. Ordinary CI covers accepted,
rejected and inconclusive Critic verdicts, exact verdict/state mapping, expiry, completed-outcome
drift, idempotent replay, unfinished recovery, and digest-only schema/SQLite persistence. This PASS
qualifies only provenance binding for an already completed Critic review; it does not qualify
automatic Critic execution, Finding creation, report export, Target build, public egress or Submission.

M8.5 constructs one trusted-control-plane `FindingPromotionPlan` after the accepted M8.4 binding and
publishes a content-addressed human duplicate-clear proof to its authoritative local store. The
Admission probe tampers with the sealed impact field and proves rejection before the Intake
checkpoint, then records one explicit human `accept`. Runner calls remain at one, target requests at
two, provider attempts at three, the Critic-reviewed transient Candidate remains unchanged, and the
authoritative original Candidate remains `PROPOSED`. Ordinary CI covers accept/reject/defer,
rejected/inconclusive Critic outcomes, duplicate and stale-clear proofs, promotion drift, expiry,
conflicting consumption, unfinished recovery, and schema/SQLite absence of promotion prose. This PASS
qualifies only human selection of exact Finding promotion inputs; it does not qualify Candidate
promotion, Finding creation, report generation, public egress, Target build or Submission.

M8.6 consumes that accepted M8.5 record only together with a separately granted
`MUTATE_TARGET_STATE` Approval bound to the exact Intake, PromotionPlan, Candidate, Finding ID,
Target, Scope and fixed effects. The Admission probe first replaces the Approval action digest and
proves rejection before a promotion checkpoint, then invokes the existing pure Candidate-to-Finding
transition and persists one immutable promoted Candidate plus verified Finding. Runner calls remain
at one, target requests at two, provider attempts at three, and the original Candidate remains
`PROPOSED`. Ordinary CI covers pending/denied/revoked Approval, expiry, plan drift, idempotent replay,
conflicts and unfinished recovery. This qualification adds no automatic Approval, Validation or
Critic execution, public egress, Target build, report generation or Submission.

M8.7 constructs one trusted-control-plane `ReportDraftPlan` from the sealed M8.6 promoted Candidate,
verified Finding and authoritative EvidenceBundle. The Admission probe alters the sealed title and
proves rejection before a Report Intake checkpoint, then records one explicit human `accept` without
calling the report service. Runner calls remain at one, target requests at two, provider attempts at
three, and no Report or artifact is created. Ordinary CI covers accept/reject/defer, plan drift,
expiry, idempotency, conflicting report-family consumption, unfinished recovery and SQLite/schema
absence of report prose. This qualification adds no automatic drafting, report approval, export,
public egress, Target build or Submission.

M8.8 consumes only that exact human-accepted M8.7 record, reopens the complete promotion, Critic,
Validation and Evidence provenance, and seals the ordered typed Evidence catalog into a digest-only
execution plan. The Admission probe changes sealed Evidence metadata and proves rejection before a
draft checkpoint, then invokes the existing deterministic offline report service once. The result is
an immutable local artifact that remains `DRAFT` plus a prose-free outcome binding. Runner calls
remain at one, target requests at two, provider attempts at three, and Candidate/Finding state is
unchanged. Ordinary CI covers non-accepted Intake, drift, timeout, pre-existing unbound drafts,
idempotency, conflict, unfinished recovery and schema/SQLite absence of prose. This qualification
adds no report approval, export, public egress, Target build or Submission.

M8.9 reopens that completed M8.8 binding, its authoritative DRAFT and immutable artifact, and the
same ordered typed Evidence catalog, then binds them to one trusted-control-plane `ReportReviewPlan`.
The Admission probe changes the sealed future reviewer and proves rejection before an Intake
checkpoint, then records one explicit human `accept` without calling `HumanReportReviewService`.
The Report remains `DRAFT`; Runner calls remain at one, target requests at two and provider attempts
at three. Ordinary CI covers accept/reject/defer, plan drift, expiry, artifact corruption,
idempotency, conflict, unfinished recovery and schema/SQLite absence of prose. This qualification
adds no report decision, approval, export, public egress, Target build or Submission.

M8.10 consumes the accepted M8.9 record only with a separately issued human `ReportReviewCommand`
and a granted `REVIEW_REPORT` Approval bound to the exact command, DRAFT, artifact, Scope and one
expected state effect. The Admission probe changes the Approval action digest and proves rejection
before an execution checkpoint, then applies an explicitly selected `request_changes` decision
through the existing deterministic review service. The original DRAFT remains immutable; Runner
calls remain at one, target requests at two and provider attempts at three. Ordinary CI covers all
three decisions, pending/denied/revoked Approval, drift, timeout, pre-existing reviews, failure,
idempotency, conflict, recovery and schema/SQLite absence of prose. This qualification adds no
automatic decision, report export, public egress, Target build or Submission.

M8.11 reopens a completed M8.10 binding whose independently commanded and approved decision is
`approve`, verifies the authoritative `HUMAN_APPROVED` Report, review record and immutable artifact,
and binds them to one trusted-control-plane `ReportExportPlan`. The Admission probe changes the
sealed plan digest and proves rejection before an Intake checkpoint, then records an explicit human
accept decision. The Report remains `HUMAN_APPROVED`; Runner calls remain at one, target requests at
two and provider attempts at three. Ordinary CI covers accept/reject/defer, non-approved reviews,
plan drift, timeout, artifact corruption, idempotency, conflict, unfinished recovery and
schema/SQLite absence of prose. This qualification performs no export, accepts no destination, and
adds no public egress, Target build or Submission.

M8.12 consumes the accepted M8.11 record only with a separately granted `EXPORT_REPORT` Approval
bound to the exact plan, human-approved Report, review, artifact, Scope and fixed local effects. The
Admission probe changes the Approval action digest and proves rejection before an execution
checkpoint, then invokes the existing local export service once. The source Report remains
`HUMAN_APPROVED`, while a new immutable local artifact is `EXPORTED`; Runner calls remain at one,
target requests at two and provider attempts at three. Ordinary CI covers pending/denied/revoked
Approval, drift, timeout, write failure, pre-existing export, idempotency, conflict, recovery and
schema/SQLite absence of prose or destinations. This qualification adds no public egress, Target
build, platform credential or Submission.

M9.1 constructs a content-addressed regression observation from the same completed admission
composition: the M7.11 Audit plus every M8.1–M8.12 Intake, outcome and execution checkpoint in its
fixed order. It binds six explicit human Intake records, three exact Approval digests, the combined
Evidence refs, immutable Candidate and Report state snapshots, and counters captured after
Validation and after local export. The pure evaluator reports PASS only when the complete chain is
present, Validation is reproduced, Critic is accepted, all source objects remain immutable, and no
provider, Broker, Runner or target count increases during the later control-plane stages. The fixed
policy also requires zero public-network calls, Target builds, automatic Approvals and Submissions
and rejects attempts to relax those limits. Ordinary CI covers typed failure codes, drift, timeout,
conflict, unfinished recovery, artifact write cleanup, no-follow verification and absence of
operational parameters. This qualification is read-only and adds no execution or disclosure
authority.

M9.2 seals one known-good M9.1 observation with all 23 fixed negative-path mutations and their exact
ordered violation-code expectations. The ordinary CI matrix regenerates the corpus, rejects fixture
drift, and requires 23/23 scenario matches on Python 3.12, 3.13 and 3.14. The cases cover chain
omission and duplicate identity, missing Evidence or human gates, Candidate/Report state drift,
Validation/Critic failure, post-Validation provider/Broker/Runner/target activity, counter
regression, public network, Target build, automatic Approval and Submission. Schema validation
rejects missing cases, reordered coverage, altered expectations and inconsistent match flags. The
concurrent Phase 3 workflow confirms the existing real rootless composition remains admitted; the
M9.2 corpus itself is pure and offline and grants no operational authority.

M9.3 deterministically archives and ingests nine repository-owned Python fixtures, then runs the
real AST Source Mapper and Candidate Generator without importing or executing fixture code. Eight
cases cover every currently supported Candidate CWE and one ownership-guarded case must remain
Candidate-free. The ordinary CI matrix regenerates the content-addressed suite and observations,
requires exact fixture/schema stability, and gates Candidate recall, Candidate precision and static
trace completeness at 1.0. Finding precision and Evidence completeness come only from the exact
policy-bound M6.1 baseline, never from Candidate promotion. The same gate requires zero Runner,
Broker, provider, Target process, public-network, build, automatic-Approval and Submission effects;
the concurrent Phase 3 run confirms the existing real rootless boundary remains admitted.

M9.4 adds five positive Flask/FastAPI/Django paths and eight safe negatives to the same offline
static harness. The positive set covers cross-module calls, Django URL dispatch and FastAPI
dependencies; negative cases retain route input and recognizable sink syntax but pass fixed values,
or enforce a visible ownership guard. A code-owned contract fixes order, disposition, framework,
CWE truth, analyzed-file minimum and call-chain minimum. CI regenerates exact observations and
requires the M9.3 quality fan-in plus complete three-framework coverage, cross-file entry/sink
provenance, zero parse failures and zero negative Candidates. The suite never executes fixture code
and the shared counters remain zero for Runner, Broker, provider, Target process, public network,
build, automatic Approval and Submission; the concurrent rootless Admission run also remains PASS.

M9.5 combines all 18 repository-owned M9.4 source files into one deterministic archive and processes
it through the real safe ingestion, AST mapping and Candidate generation path. The readiness service
re-authorizes the exact Scope, reloads and verifies every Snapshot file, rebuilds SourceGraph and
CandidateSet from trusted code, and checks the sealed M9.4 result before checkpointing. The manifest
retains five Candidates in `PROPOSED`, selects none, and fixes human Candidate selection, six Intake
decisions and three exact Approvals. It also forbids Agent-generated Runner/Broker parameters,
automatic Validation or Candidate mutation, automatic Approval, Target build, public network and
Submission. The standard CI matrix reproduces the same manifest, plan and PASS result with zero
forbidden effects; the concurrent Phase 3 run confirms the real rootless isolation boundary remains
PASS. This admission artifact is readiness evidence only and grants no operational authority.

M9.6 exposes that trusted static/readiness composition as one local operator command for a previously
ingested authorized Snapshot. The command rechecks Scope and Snapshot integrity, rebuilds SourceGraph
and CandidateSet, recomputes the repository-owned M9.4 gate and requires its exact admitted identities
before writing immutable static/readiness artifacts. CI proves deterministic replay, refusal of a
revoked Scope or drifted quality identity, and a valid empty Candidate review queue. Output fixes
selection to empty and leaves every Candidate proposed. The command has no Validation, Runner, Broker,
provider, build, network, Approval, export or Submission operation; the concurrent Phase 3 PASS
confirms the existing real isolation boundary was not regressed.

M9.7 consumes that completed passing readiness checkpoint only through a separately timestamped human
Candidate selection command. Before checkpointing, the service reopens the no-follow readiness
artifact, immutable CandidateSet and SourceGraph, reloads the Snapshot, re-authorizes Scope, and
reconstructs the exact pilot manifest. CI proves one proposed Candidate is recorded without mutation,
completed replay is read-only, and an absent Candidate, failed readiness, revoked Scope, timeout,
binding drift, conflicting selection or unfinished checkpoint fails closed. The digest-only command
and record contain no ValidationPlan, Runner/Broker parameters, credentials, Approval or Submission;
the concurrent Phase 3 PASS confirms the existing real isolation boundary remains intact.

M9.8 reopens that completed M9.7 selection before invoking the existing M8.1 human Intake service. It
requires an independently supplied, already sealed ValidationPlan and an explicit human `accept`
command whose CandidateSet, Candidate, Scope, identities, digests and timing exactly match the selected
still-`PROPOSED` Candidate. A separate STARTED/COMPLETED ledger uniquely consumes the selection,
M8.1 Intake plan and ValidationPlan and stores only a digest-bound result; completed replay is read-only,
while drift, timeout, conflict or an interrupted checkpoint fails closed. CI proves this bridge does not
execute Validation, change Candidate state, derive Runner/Broker parameters, build a Target, access the
network, approve an action or submit anything; the concurrent Phase 3 PASS confirms the real isolation
boundary remains intact.

M9.9 consumes that completed M9.8 binding only after reopening its accepted M8.1 record, immutable
CandidateSet and identical pre-existing ValidationPlan, and after matching a separately human-granted
`RUN_VALIDATION` Approval to a content-addressed action. Trusted preflight runs before checkpointing;
an earlier bare Validation checkpoint is rejected as a bypass. A separate execution ledger uniquely
consumes the M9.8 plan, ValidationPlan and Approval, binds the completed outcome, and makes replay
read-only while interrupted execution requires explicit recovery. CI covers non-granted Approval,
timeout, conflict, Runner result drift, outcome drift and every Broker-call refusal. The first version
uses only the offline Runner, opens no socket, preserves the original proposed Candidate, and adds no
Agent-derived execution parameter, automatic Approval, Target build, Finding promotion or Submission;
the concurrent Phase 3 PASS confirms the real isolation boundary remains intact.


### M9.10 outcome provenance admission

The pilot M8.2 bridge now requires an authoritative completed M9.9 execution binding. Offline tests
cover read-only success and CLI replay, missing/unfinished execution, sealed provenance drift,
Audit/Scope mismatch, pre-existing bare M8.2 checkpoints, deadlines, failed completion and explicit
recovery. Replay verifies the authoritative M8.2 result rather than trusting a cached pilot record.
The tests prohibit Validation execution during CLI binding and preserve the proposed input Candidate.
The exact implementation commit `fe0c96b0c9dcfac6b50c1935c0efe2a7f14c7300` passed
[CI `34041988283`](https://github.com/pity11/VulnLoom/actions/runs/34041988283) and
[Phase 3 Admission `34041988318`](https://github.com/pity11/VulnLoom/actions/runs/34041988318).
Both completed successfully on 2026-09-06 UTC. The new bridge proves provenance checks; the concurrent
rootless Admission run confirms that the existing real isolation boundary remains intact.

Local verification for the 0.58.0 working tree: `673 passed, 19 skipped`, total coverage `85.78%`
(85% required). Ruff, schema regeneration, all benchmark fixture regeneration, M6.1/M6.3 and
M9.2–M9.5 offline gates, and the M9.5 ablation check passed. The skipped opt-in integration tests
were not used to make any new isolation claim.


### M9.11 pilot Critic Intake admission

The pilot Critic Intake bridge reopens completed M9.10 provenance and applies the existing M8.3
reproduced/validated/Evidence and human-command requirements before checkpointing. Local verification
on 0.59.0: `702 passed, 19 skipped`, coverage `85.92%`. Tests cover synthetic offline success,
inconclusive refusal, missing or unfinished upstream state, resealed digest drift, exact command
binding, expired authority, pre-existing bare Intake, completion failure, cleanup, replay and ledger
tampering. CLI tests prohibit Validation, Critic and M9.10 execution while recording Intake.
The exact implementation commit `ca327345d948d176bbd238d0a4eea6a3effa9dd6` passed
[CI `34075541729`](https://github.com/pity11/VulnLoom/actions/runs/34075541729) at
2026-09-07 02:14:03 UTC and
[Phase 3 Admission `34075541690`](https://github.com/pity11/VulnLoom/actions/runs/34075541690)
at 2026-09-07 02:14:47 UTC. The new tests prove pilot Intake provenance; the concurrent rootless
Admission run confirms the existing real isolation boundary remains intact. Synthetic success
fixtures do not claim real-target reproduction.


### M9.12 approved pilot Critic execution admission

The new pilot Critic execution gate requires completed M9.11 provenance and an independent exact
human-granted RUN_CRITIC Approval. It composes existing deterministic Critic review and M8.4 outcome
binding with a uniquely consumed pilot execution ledger. The original CandidateSet remains unchanged;
result Candidate states follow the existing Critic state machine. Default inconclusive Validation
cannot enter Critic. No target process, Runner/Broker/provider, network, build or Submission is added.

Local verification on 0.60.0: `737 passed, 19 skipped`, coverage `85.92%`. Tests cover all three verdicts,
exact/non-granted/wrong/expired Approval, upstream and catalog drift, deadlines, bare Critic/M8.4
checkpoint rejection, replay integrity, failures at all three persistence stages, cleanup and CLI
single-review replay. Successful cases use synthetic offline Evidence, not real-target reproduction.
The exact implementation commit `a8c2c2b2db1a3cc6da2453024511173f972ecb71` passed
[CI `34079581413`](https://github.com/pity11/VulnLoom/actions/runs/34079581413) at
2026-09-07 03:26:46 UTC and
[Phase 3 Admission `34079581400`](https://github.com/pity11/VulnLoom/actions/runs/34079581400)
at 2026-09-07 03:27:01 UTC. The new tests prove Approval-gated pilot Critic execution and outcome
provenance; the concurrent rootless Admission run confirms the existing real isolation boundary
remains intact. Synthetic success fixtures do not claim real-target reproduction.

### M9.13 pilot Finding Intake provenance admission

Version 0.61.0 adds a read-only M9.12 result verifier and a pilot wrapper around M8.5 human Finding
Intake. Accepted Critic provenance, the latest current CLEAR duplicate check, an exact PromotionPlan
and an independent ACCEPT command are mandatory. Current authority is rechecked before checkpointing.
The historical RUN_CRITIC Approval is verified as evidence of completed execution; it does not grant
Finding promotion. No Finding is created and no Candidate, execution, Approval or Submission action
is performed by this gate.

Local verification: `762 passed, 19 skipped`, coverage `86.08%`. The 25 new tests cover successful
admission, nonaccepted verdicts, command/plan/scope/evidence/duplicate drift, missing or unfinished
upstream records, deadlines, bare M8.5 rejection, persistence failures, cleanup, completed-record and
ledger tampering, historical execution-Approval expiry, and CLI read-only replay. Synthetic offline
Evidence proves protocol behavior, not real-target reproduction. M6.1/M6.3 and M9.2–M9.5 regression
gates, M9.5 ablation, schema/fixture regeneration determinism, Ruff and whitespace checks passed.

Implementation commit `204f1ab4ec8210125bd5ef101a68748b859134a5` passed
[CI `34088676591`](https://github.com/pity11/VulnLoom/actions/runs/34088676591) and
[Phase 3 Admission `34088676621`](https://github.com/pity11/VulnLoom/actions/runs/34088676621)
on 2026-09-07 UTC.

### M9.14 approved pilot Finding promotion admission

Version 0.62.0 binds completed M9.13 provenance to an independently approved exact M8.6 promotion
execution plan. Current Scope, accepted Intake, latest CLEAR duplicate proof, PromotionPlan,
Evidence and Approval are rechecked before any checkpoint. The promotion Approval and execution
plan must follow completed pilot Intake. M9.12 Critic Approval cannot authorize promotion.

The local operation persists a verified Finding and promoted Candidate in the M8.6 outcome store,
leaving the source CandidateSet unchanged. A separate pilot ledger uniquely consumes the Intake
binding, execution plan, Approval, record, PromotionPlan and Finding ID. Bare M8.6 checkpoints are
rejected; persistence failures leave STARTED for explicit recovery. Replay revalidates complete
outcome contents and both ledgers without calling promotion execution. The new CLI never executes
Validation, Critic, target code, Runner/Broker/provider, build, network or Submission, and grants no
Approval. Success fixtures contain synthetic offline evidence only.

Local verification: `789 passed, 19 skipped`, coverage `86.17%`. The 27 new tests cover successful
promotion and replay, denied/expired/wrong/early Approval, Scope/plan/command/Evidence drift,
missing or unfinished M9.13, missing and superseded duplicate proofs, bare M8.6 checkpoints,
deadlines, failures at both persistence stages, cleanup, CLI replay and resealed result/ledger
corruption. M6.1/M6.3 and M9.2–M9.5 regression gates, M9.5 ablation, deterministic schema/fixture
regeneration, Ruff and whitespace checks passed. Existing M8.6 and M9.13 regressions also pass.

Implementation commit `ea110e17fd04450943600455dd3eba3d3be14760` passed
[CI `34089910194`](https://github.com/pity11/VulnLoom/actions/runs/34089910194) and
[Phase 3 Admission `34089910201`](https://github.com/pity11/VulnLoom/actions/runs/34089910201)
on 2026-09-07 UTC.

### M9.15 standalone fixed Provider probe admission

Version 0.63.0 adds a fixed-content, zero-tool Provider probe independent of the research pilot.
Preparation seals an exact bounded configuration and requires an existing inference egress grant,
without resolving DNS or reading credentials. Execution requires explicit CLI network opt-in,
rechecks the grant, and invokes the existing pinned subprocess HTTPS adapter and Responses codec.
Neither command issues Approval or egress grants. No research Target, source, Evidence or custom
prompt can be supplied; only the fixed completion sentinel passes response verification.

The dedicated ledger uniquely consumes plan, idempotency key and grant, including failed attempts.
Replay reads the result without a second provider call; interrupted persistence requires explicit
recovery. Results contain only stable status, validated usage counts, process/cleanup flags and
attempt/receipt digests. CLI errors never print input, raw provider text or exception details.
Unknown errors cannot claim verified cleanup. Transport/codec timeouts, request/response bytes and
output tokens are bounded; these limits do not constitute a provider-account currency cap.

Local verification: `813 passed, 19 skipped`, coverage `86.25%`. The 24 new tests cover fixed-message
success, zero-tool behavior, replay and grant/key conflicts, expired/future/drifted plans, missing
and revoked grants, revocation between preflight and transport, forbidden DNS, missing credential,
timeout, unexpected secret-bearing errors, mismatched/blocked/tool-proposal responses, cleanup,
interrupted writes, ledger drift, CLI opt-in, sanitized errors and bounded no-follow file reads.
Schema/fixture regeneration determinism, M6.1/M6.3 and M9.2–M9.5 gates, M9.5 ablation, Ruff and
whitespace checks passed.

New tests use fake DNS/process exchange. No real API key was read and no public Provider was called.
Existing opt-in loopback TLS/Phase 3 tests cover the reused transport boundary; they do not certify
real Provider/model compatibility or research effectiveness. Production credentials, exact provider
configuration, account quota and a real smoke result remain operator-supplied admission evidence.
See `docs/PROVIDER-PROBE.md`. Implementation commit
`dc245e2d98353702da3ee9a45f016d3eb0a6e05b` passed
[CI `34091685590`](https://github.com/pity11/VulnLoom/actions/runs/34091685590) and
[Phase 3 Admission `34091685606`](https://github.com/pity11/VulnLoom/actions/runs/34091685606).
These results are separate from real Provider verification.

### M9.16 CUC fixed Chat probe preparation

Version 0.64.0 adds a CUC-only fixed Chat probe. The operator supplied the endpoint
`https://openai.cuc.edu.cn/v1/chat/completions`, request model `cuc/deepseek` and exact accepted
response identities `deepseek-v4-flash` / `deepseek-v4-flash-0731`. The codec sends only a fixed PONG
request, requires one stopped assistant PONG with bounded valid usage and rejects all other model
identities, tool calls, refusals, multiple choices, malformed/oversized responses and content drift.
It is not a general Chat Completions Agent adapter. Original Responses identity checks are unchanged.

Configuration pins the CUC hostname and real `CUC_DEEPSEEK_API_KEY` reference, excluding shim dummy
credentials. It reuses the existing isolated pinned HTTPS process; no loopback/plaintext exception
is added. `provider-cuc-probe-config` checks an existing issued grant and prints only non-secret
configuration. It does not issue, approve or renew grants. The selected response identity is recorded
in the sealed probe result; legacy M9.15 results retain their content identity when this optional
field is absent. Completed CUC replay requires the response-model observation.

Local verification: `843 passed, 19 skipped`, coverage `86.34%`. Thirty new tests cover both exact
backend identities, forbidden logical/prefix/unknown/case variants, content/tool/refusal/role/finish
mismatches, multiple choices, invalid usage, duplicate JSON, oversized payloads, wrong fixed fixture,
resealed endpoint/model/credential/alias changes, encode/decode timeout, cleanup, CLI config/run/replay,
interrupted persistence, missing served-model observations and legacy result identity. All use
synthetic keys and fake DNS/process exchange. M6.1/M6.3 and M9.2–M9.5 gates, M9.5 ablation,
schema/fixture determinism, Ruff and whitespace checks passed.

### M9.16 safe diagnostics and real CUC observation (2026-09-07)

The operator subsequently supplied the repository-local credential and explicitly authorized
one fixed PONG test, then one further test after diagnostic hardening. Each used a separate
short-lived inference grant and consumed exactly one probe attempt; both grants were revoked.
The first rejected result had insufficient diagnostic detail. The second rejected result records:

- `failure_stage=response_codec`, `error_code=response_shape_mismatch`
- `http_status=200`, `network_opened=true`, `tls_version=TLSv1.3`
- `captured_response_bytes=772`, `process_started=true`, `cleanup_verified=true`
- No trusted receipt or validated response model; reported token counts remain zero and do not
  establish actual account billing.

Result identity: `d8e350b04992af7822740c941db23f8c1077b4e6415e996b5f9a8a6c91fc4381`.
This establishes HTTPS connectivity and an HTTP 200 response, but not CUC protocol acceptance.
No raw response, authentication header, exception text or credential was persisted. The specific
shape mismatch remains unresolved; there was no further request or relaxation of acceptance rules.

Local diagnostic verification: 866 passed, 19 skipped, coverage 86.33%. Separate real loopback TLS
verification: 7 passed, 1 skipped (the Docker composition case). New synthetic tests cover closed
metadata, malformed/duplicate JSON, HTTP rejection, TLS/connect/timeout failures, cleanup, distinct
codec categories, sealed-result tampering, legacy identity and body-free idempotent persistence.
Four new loopback cases exercise HTTP 401/403/404 and certificate rejection through the real child
process. These checks do not substitute for full remote Phase 3 Admission or real CUC acceptance.


#### Follow-up structural diagnostics (2026-09-07)

Two subsequent, separate operator-directed diagnostic observations retained the original acceptance
rules. Attempt 003 returned HTTP 200 / TLSv1.3 / 772 bytes and was rejected with
`response_root_extra_fields`. Attempt 004 returned HTTP 200 / TLSv1.3 / 778 bytes with the same
rejection and these closed-vocabulary observations:

- `root_kv_transfer_params_null`, `root_prompt_logprobs_null`, `root_prompt_token_ids_null`
- `root_other_fields`, `message_function_call_null`, `message_other_fields`

The response still contains unrecognized root and message fields. No arbitrary field names, values,
body or exception text were persisted. This evidence does not yet establish a complete minimal
compatibility change. Acceptance rules remain unchanged; no post-fix validation was attempted.
Both attempts completed cleanup and their separate short-lived grants were revoked. There was no
retry of an existing plan. Result identities:

- 003: `dfb959fbb7c852f3a9f8116829bd644e62409ffcaa9a12939206219dd0f7fe8d`
- 004: `b44cef6425e2dc62c5b4ccd9c03d85f446637314a7c8aaae1987f79975d37ffd`

Further compatibility work needs the gateway field schema, without response values or credentials.

Follow-up local verification: 885 passed, 23 skipped, coverage 86.33%; Ruff, whitespace
and deterministic schema regeneration passed. Existing sealed probe results remain readable.


#### Explicit vLLM empty-extension compatibility and live-005 (2026-09-07)

Reviewed the official [vLLM chat protocol](https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/openai/chat_completion/protocol.py).
The fixed CUC codec implementation is now version 2 with the exact empty-extension policy included
in its implementation digest. Old configurations/plans cannot silently consume the new policy.
This is a narrow fixed-PONG subset, not acceptance of the entire vLLM protocol. It rejects unknown
fields at root, choice, message and usage; extension values must be null or the prescribed typed
empty value. Function calls must be null; tool calls must be null or an empty list. Core model,
content, finish reason and usage checks remain mandatory. Existing `reasoning_content` handling
remains bounded and discards its text; the newly recognized `reasoning` accepts only null/empty.

The single post-patch live test returned HTTP 200 / TLSv1.3 / 772 bytes, confirming these null fields:

- root: `ec_transfer_params`, `kv_transfer_params`, `metrics`, `prompt_logprobs`, `prompt_text`,
  `prompt_token_ids`
- choice: `routed_experts`, `stop_reason`, `token_ids`
- message: `annotations`, `audio`, `function_call`, `reasoning`
- usage: `prompt_tokens_details`, plus an unresolved `usage_other_fields` observation

Root/choice/message schema checks passed, but the response content was not exactly PONG.
Result: `rejected`, `response_codec / response_content_mismatch`, no trusted receipt or validated
completion. Usage validation occurs after content validation, so the additional usage fields are
an observation of a further compatibility gap, not a validated usage result. No content, dynamic
field names, response body or credentials were retained. Cleanup was verified and the temporary
egress grant was revoked. No additional call followed this verification.

Result identity: `7ac6c6ec9a57da95d3952fddbb87a404f2c0304ef72911fa02aaa530518e1125`.
Local verification: 967 passed, 23 skipped, coverage 86.35%. Targeted probe/diagnostic regression:
178 passed, including explicit empty-extension success, payload and falsey wrong-type rejection,
unknown-field rejection at every level, strict core rejection, cleanup, idempotency and old codec
identity rejection. Real CUC acceptance remains pending content and usage compatibility evidence.


#### PONG content classification and bounded usage, live-006 (2026-09-07)

Codec implementation v3 adds a closed content classifier (type/exact/trimmed/casefold/punctuation/
empty/other). Only exact PONG or `content.strip() == "PONG"` is accepted. Classification is persisted
as an optional enum; no text, text prefix or content digest is added to diagnostics. Missing
classification is omitted from serialization to preserve prior sealed result identity.

Usage now explicitly recognizes `prompt_tokens_details`, `completion_tokens_details` and
`reasoning_tokens`. Details may be null or closed dictionaries of bounded nonnegative integers:
prompt details allow cached/audio token counts; completion details allow reasoning/audio/accepted
prediction/rejected prediction counts. Each count is bounded by its respective prompt/completion
count. Top-level reasoning tokens must be an integer within completion tokens. Booleans, negative
counts, unknown fields and total-token disagreement reject; no accounting rule was relaxed.
`cached_tokens` is observed at usage level but is accepted only inside prompt details.

The operator limited this stage to one new PONG grant and request. After 994 offline tests passed,
live-006 returned HTTP 200 / TLSv1.3 / 778 bytes, but classification was
`response_content_punctuation_match`. This is explicitly outside the accepted exact/trimmed policy.
`usage_other_fields` remains present; because content validation failed first, usage was not accepted.
Result status is rejected, receipt is null, response model is null, and cleanup is verified. The
grant was revoked and no retry or second request occurred in this stage. Result identity:
`b78a7dc447a1473249b756875bc25d4a711084f9b757572e41ff3cb2290b91bf`.

Local verification: 994 passed, 23 skipped, coverage 86.39%. New coverage includes all content
categories, whitespace acceptance, case/punctuation/free-text rejection, bounded details, unknown
usage, boolean/negative/out-of-range counts and total mismatch. PONG Admission remains incomplete;
there is no passed record or stage-two live structured-call acceptance record. General adapter
work has not started. No research-provider registration or tool execution was enabled.


#### Closed punctuation variants and DeepSeek cache fields, live-007 (2026-09-07)

Codec implementation v4 accepts only the trimmed strings `PONG`, `PONG.`, `PONG!` and backtick-wrapped
PONG. Case changes, substring matches, additional punctuation and arbitrary text remain rejected.
The exact accepted set is included in the implementation digest. The existing closed content
classification is retained; no content is persisted.

Reviewed the [DeepSeek Chat Completions API](https://api-docs.deepseek.com/zh-cn/api/create-chat-completion/).
The usage allowlist adds only `prompt_cache_hit_tokens` and `prompt_cache_miss_tokens`. Each supplied
value must be a nonnegative integer within prompt tokens; when both exist their sum must equal
prompt tokens. Invalid values or the cache equation produce `usage_cache_mismatch`. The total-token
equation and unknown-field rejection remain unchanged. Both field names have fixed observations.

After full offline regression, the operator-authorized single live-007 request returned HTTP 200 /
TLSv1.3 / 772 bytes. Content classified as punctuation_match and passed the v4 content policy, but
usage failed with `usage_unknown_fields`. Neither cache field was observed, so this response does
not support the hypothesis that those two fields caused the previous unknown-usage rejection.
`usage_prompt_tokens_details_null` and `usage_other_fields` remain the usage observations.

Result: rejected; receipt and response_model null; cleanup_verified true. Grant revoked. No retry
or additional request occurred. Result identity:
`e2980cf46b86eebf96a9f23335386b6bf5c5e5694adfe034140f74475d452f80`.
The remaining blocker is the actual gateway usage field definition. No raw response, dynamic
field name, credential or exception text was saved, and PONG Admission is still incomplete.

Local verification: 1017 passed, 23 skipped, coverage 86.40%; targeted probe/diagnostic tests:
228 passed. New cases cover exact punctuation allowlisting, near-match rejection, cache splits,
single cache fields, booleans, negatives, overflow, null/string/float values, unknown usage and
unchanged total accounting. Schema regeneration and existing sealed results are checked separately.


#### Bounded unknown-key fingerprints and live-008/009 (2026-09-07)

A new optional diagnostic records at most 32 unknown usage keys. The eight operator-reviewed
candidate names use a closed enum; all other keys are represented only by SHA-256 of their UTF-8
names. Each entry records only null/int/dict/other, never the value; booleans classify as other.
Overflow sets a truncation flag and does not change unknown-field rejection. Empty diagnostic
fields are omitted so existing sealed results retain their identity.

The one diagnostic request (live-008) observed three unknown integer fields, with no match in the
eight initial candidates. A reviewed local dictionary matched all three hashes without more
network requests:

| Reviewed field | SHA-256 of name |
| --- | --- |
| time_per_output_token_ms | add553a6a63dcf3effcbbdc058483f6e3264404ac057d553cc112d1a25e93094 |
| time_to_first_token_ms | b23058322ea3b7b6663703c169f0dc22f3e04bbc9ef39cf0dae8a618b40ac0dd |
| tokens_per_second | 02a44d781333dac43c120a4d74ac2f377da4e69be68f438eb6a1b038f70334a5 |

Codec implementation v5 includes these three exact optional usage names and their bounds in its
digest: timings must be integers in 0..10000 ms; throughput must be an integer in 0..1000000.
These are the local acceptance bounds, not measured server values or an asserted upstream contract.
Core token accounting, total equality and other unknown-field rejection are unchanged.

After offline regression, the separately authorized final live-009 request returned HTTP 200 /
TLSv1.3 / 776 bytes and exact PONG. All usage field names were recognized, but the result rejected
with `usage_metrics_mismatch`: at least one metric violated type or bounds. The saved record cannot
identify which metric or which type/range condition failed. No metric values or raw response were
saved, so no negative-sentinel or changed-unit explanation is asserted. Receipt and response model
remain null; cleanup is verified. Both grants were revoked; no further request followed live-009.

Result identities:

- live-008: `5fa69f0554f4930e23ab88d3fbb31bdbeeaa2a6eebff65d34e7fc1a44d6fac6b`
- live-009: `4fbc4081b944653c45947383720ad2b2f23595c61b0757944b63933a84b4484f`

Local verification: 1053 passed, 23 skipped, coverage 86.41%. New tests cover candidate/type enums,
unknown-key hashing without values, count limits, malformed identities, sealed persistence and
replay, and each metric's zero/upper boundary, negative/overflow/bool/float/null/string/dict rejection.
PONG Admission still awaits a compatible, verified metrics contract; identifying the fields alone
does not satisfy the required passed result. No general CUC research adapter was enabled.


#### Fixed PONG Admission passed: finite numeric metrics, live-010 (2026-09-07)

Codec implementation v6 corrects the three timing/rate fields to finite JSON numbers (int or float)
within the existing nonnegative bounds, explicitly excluding booleans. Token counts remain strict
integers and both total-token and cache equations remain enforced. The sealed implementation digest
records the numeric policy and tuple type declarations. The predicate avoids overflow when parsing
very large integers. New optional `metric_issues` diagnostics identify only the fixed metric name
and type/non_finite/negative/above_limit reason; no values or exception text are recorded. Empty
issues are omitted to preserve historical sealed result identities.

After full offline regression, one operator-authorized request completed successfully:

- `status=passed`, `response_model=deepseek-v4-flash-0731`
- `receipt_digest=b258028adeeddbc87cf06a9f86bfd3f5fc61aacc83d8f2f9c2254f4417cecb75`
- `cleanup_verified=true`, `process_started=true`
- HTTP 200, TLSv1.3, response 772 bytes
- Validated input tokens 10, output tokens 4
- `content_classification=response_content_punctuation_match`, accepted by the explicit v4+ policy
- Result ID: `a204b843419035391ceb1e33e37e3280db60e1bcc29a09aa3327d8f0f340d3b8`

The short-lived grant was revoked after this single request; no retry or additional live request
was made for this change. No raw response, content, performance metric values or credentials were
saved. Earlier rejected results are retained without being reclassified. This observation validates
the new numeric policy for this request; it does not reconstruct the exact cause of live-009.

Local verification: 1080 passed, 23 skipped, coverage 86.41%. Added cases cover integer/float zero,
normal fractions and float upper bounds; NaN, positive/negative infinity, negatives, over-limit
floats, boolean/string/dict/null and oversized integers reject. Schema determinism and all ten
historical sealed results are verified. The fixed PONG Admission gate is now passed; this does not
constitute general Chat codec acceptance, research provider registration or remote CI acceptance
for the uncommitted patch. General no-tool structured CUC compatibility remains a separate task.

#### Fixed JSON compatibility acceptance passed (2026-09-08)

The user explicitly requested live structured acceptance after offline implementation.
`cuc-structured-live-001` sent one code-owned synthetic JSON request using
`cuc-chat-structured-probe-v1`, with zero tools, no source or research context,
256 output tokens maximum and the existing bounded pinned HTTPS subprocess.
The existing `operator-cuc-smoke` policy issued a 120-second MODEL_INFERENCE
grant. Execution reused `.vulnloom/m916-cuc-live-010/egress` and its sibling
`probe.db`; it did not replace the authority or execution ledger to retry.

- `status=passed`, `response_model=deepseek-v4-flash-0731`
- HTTP 200, TLSv1.3, response 799 bytes
- Validated input tokens 34, output tokens 10
- `content_classification=response_content_exact`: the fixed JSON schema passed
- `process_started=true`, `cleanup_verified=true`
- Result ID: `2076564db4fa12489986392051c610af0a56e5f2aad7054925cafe1f220ade8e`
- Receipt digest: `b12bec49674321708a4a453f4ac6bcacbe500546a07a4236224399a3a6ef4b54`
- Completion: `2026-09-08T01:49:38.220543Z`

The grant was revoked in the execution cleanup path. Subsequent offline checks
validated the sealed config/plan/result binding, exactly one completed ledger
entry for the grant, equality of persisted and exported results, and revoked
authorization status. No retry or additional provider request was made.
Secret-free records are under `.vulnloom/cuc-structured-live-001/`; raw response
text, reasoning and credentials were not printed or archived.

Before calling the provider, 307 probe regression tests passed and a local
credential/config preflight completed without network access. The prior full
offline run had 1122 passed, 23 integration tests deselected, coverage 86.45%.
This acceptance proves the fixed JSON probe only, not a general Chat interface,
model-driven research, target validation, or an autonomous tool workflow.
