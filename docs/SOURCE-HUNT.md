# Source Hunt V1

Source Hunt is VulnLoom's trusted local white-box workflow. It operates only on an already-ingested,
authorized `TargetSnapshot`; it does not clone repositories, access public targets, or invoke a model by
itself.

## Implemented vertical slice

```text
approved Snapshot + Scope
  → integrity-checked Python/JavaScript/TypeScript navigation index
  → bounded, resumable investigation
  → redacted on-demand source windows
  → PROPOSED Candidate
  → exact Build/Harness/Fuzz/Sanitizer/PoV sandbox plan
  → Approval Gate + isolated Runner
  → Evidence + ValidationRun
  → independent Critic
  → approval-bound Finding
  → evidence-backed report draft
```

The application services are provider-neutral and reusable by a future HTTP API. An `SourceInvestigator`
adapter receives only typed observations; provider credentials and network transport remain behind the
trusted model adapter boundary. A failed model decision does not mutate the investigation checkpoint.

Repository processing is bounded by file count, aggregate bytes, per-file bytes, partition size, query
count, observation count, and deadlines. Source files are not copied into the index. Each requested source
window is opened beneath the exact materialized Snapshot without following symlinks, checked against its
manifest size and SHA-256, limited to a small line/byte window, and redacted before persistence or model
exposure.

Candidate materialization is deliberately one-way into the shared domain: Source Hunt can create only a
`PROPOSED` Candidate. Validation requires a fixed five-stage plan and exact `RUN_UNTRUSTED_BUILD`
approval. Promotion re-reads the authoritative Validation and Critic stores and requires a separate exact
`MUTATE_TARGET_STATE` approval; a proposal or model response cannot directly create a Finding.

Every successful execution stage must also publish exactly one typed, content-addressed receipt. Receipts
form a digest chain beginning at the Candidate digest. Fuzz receipts require non-zero coverage and a Crash
fingerprint; Sanitizer and PoV receipts must preserve that fingerprint, and the final receipt must explicitly
prove independent replay. Free-form logs can accompany a receipt but cannot substitute for one.

## Local CLI contract

The `vulnloom source-hunt` command contains the stable local control surface:

- `start`, `query`, `status`, `complete`, `cancel`, and `expire` manage investigation checkpoints;
- `materialize-candidate` validates a typed proposal and writes an immutable CandidateSet;
- `prepare-execution` creates the fixed, deterministic sandbox plan and reports the required approval
  digest.

`prepare-execution` accepts an image digest and tool-registry digest, never an arbitrary command. Actual
execution is intentionally deployment-owned: the trusted Control Plane must provide registered
`source.build`, `source.harness`, `source.fuzz`, `source.sanitizer`, and `source.pov_replay` adapters plus an
approval record. The default test suite uses the fake Runner; the opt-in Docker test proves the complete
five-container isolation and cleanup boundary without accessing a network.

## Current boundary

V1 completes the safe Source Hunt orchestration and shared Candidate-to-report evidence chain. The Python
adapter provides AST navigation; JavaScript/TypeScript currently provides conservative navigation only.
Dedicated C/C++ build recipes, coverage-guided fuzzer implementations, ASAN/UBSAN parsing, automatic
harness synthesis, patch generation, and blind-holdout quality gates remain R9 depth work. Until a
registered adapter supplies genuine stage evidence, the typed five-stage receipt contract must not be
described as an actual fuzzing or sanitizer result.

No Source Hunt command accepts a Provider secret, full private endpoint, disclosure token, or raw
Authorization response. Network integration and real model calls remain explicit, disabled-by-default
activities outside this workflow.
