# Precomputed Analyzer Observations

M6.3a normalizes already-generated local outputs from CodeQL SARIF 2.1.0, Trivy JSON, Checkov JSON,
and Kubesec JSON. VulnLoom does not install or execute these analyzers in this milestone and does not
download rules, vulnerability databases, images, or result files.

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

## Deliberately absent

- analyzer execution or arbitrary commands;
- URLs, network access, rule/database/image downloads, or Docker access;
- credentials, provider tokens, disclosure adapters, or Submission;
- raw analyzer messages, secret matches, Kubernetes object identities, or raw rule IDs in artifacts
  and CLI summaries.
