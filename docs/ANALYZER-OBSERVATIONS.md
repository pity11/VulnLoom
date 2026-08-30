# Precomputed Analyzer Observations

M6.3a normalizes already-generated local outputs from CodeQL SARIF 2.1.0, Trivy JSON, Checkov JSON,
and Kubesec JSON. VulnLoom does not install or execute these analyzers in this milestone and does not
download rules, vulnerability databases, images, or result files.

Execution planning is a separate boundary described in
[`ANALYZER-EXECUTION.md`](ANALYZER-EXECUTION.md). M6.4a only validates an offline execution
protocol and intentionally produces no result snapshot; this importer still accepts only an exact,
already sealed local output file.

## Trust boundary

1. The operator seals a local regular file with its Target ID/version, tool version, rules digest,
   size, and SHA-256. An optional local CWE map is sealed in the same snapshot.
2. `AnalyzerImportPlan` binds that snapshot to one exact adapter digest, resource limits, a deadline,
   and an idempotency key.
3. The service uses bounded no-follow reads, strict UTF-8 JSON with duplicate-key rejection, and
   validates the digest of the bytes actually parsed.
4. A versioned adapter emits normalized observations and typed exclusions. A second integrity check
   detects mutations during normalization.
5. SQLite records STARTED/COMPLETED state and the result is atomically published as a read-only,
   content-addressed local object.

## CWE mapping

CodeQL and Trivy native CWE labels are normalized when present. A sealed sidecar may supply missing
labels with a JSON object whose keys are exact upstream rule IDs and whose values are one CWE string
or an array of CWE strings. Checkov and Kubesec commonly require this map. Missing entries produce
`missing_cwe_mapping` exclusions; invalid or stale entries reject the import.

## Non-promotion rule

`AnalyzerObservationSet` is not `BenchmarkObservationSet`. It has no Candidate state, Validation
result, Critic verdict, Evidence count, or Finding identity. A tool result is therefore incapable of
creating a Finding. Any future production use must first enter deterministic Candidate generation
and then pass the existing Approval, Validation, independent Critic, Evidence, and duplicate gates.

## Explicit benchmark alignment

M6.3b evaluates normalized observations only through a sealed `AnalyzerTruthAlignment`. Each binding
pins a case to one exact ObservationSet digest for an analyzer. Each match names the case,
ObservationSet, Observation, ground-truth identity, and a CWE present on both sides. Equal CWE labels
without an explicit match are false positives, not detections.

The reducer emits aggregate and per-analyzer recall, precision, duplicate, and exclusion metrics.
Policies can require a complete case×analyzer matrix and compare an exact-suite baseline. Evaluation
is checkpointed and produces immutable local JSON/Markdown, but it never changes production domain
state or executes an analyzer.

## Deliberately absent

- analyzer execution or arbitrary commands;
- URLs, network access, rule/database/image downloads, or Docker access;
- credentials, provider tokens, disclosure adapters, or Submission;
- raw analyzer messages, secret matches, Kubernetes object identities, or raw rule IDs in artifacts
  and CLI summaries.
