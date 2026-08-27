# VulnLoom

VulnLoom is a vulnerability research agent for **explicitly authorized targets**. It finds security candidates in source code, APIs, and cloud-native configuration, validates them in isolated environments, challenges them through an independent review step, and produces auditable report drafts for human review.

The goal is not autonomous exploitation of public targets. VulnLoom is designed to improve the recall, evidence quality, and reporting efficiency of white-box security research while enforcing scope, network boundaries, credential isolation, and human approval in code.

## Initial scope

- White-box analysis of Python Web and API projects.
- Controlled dynamic validation in local Docker Compose test environments.
- IDOR/BOLA, SSRF, path traversal, injection, insecure deserialization, authorization flaws, and sensitive data exposure.
- Human-reviewable report drafts for vendors, EduSRC, CNVD/CNNVD, and similar disclosure channels.
- No scanning of unauthorized public targets, automatic platform submission, or automatic CVE requests.

## Core principles

1. **A Candidate is not a Finding.** An agent may propose a candidate, but it only becomes a finding after reproducible evidence and an independent disproof check pass deterministic gates.
2. **The Control Plane owns privileged actions.** Workers do not receive platform credentials, change authorization scope, or submit reports.
3. **Every validation uses an ephemeral sandbox.** Source code is mounted read-only, output is stored separately, and network access is denied by default.
4. **Tools go through a Broker.** Agents receive typed, limited, and auditable capabilities instead of an unrestricted host shell.
5. **Evidence comes before narrative.** Every impact claim in a report must trace back to code, an observed request and response, or a reproducible test.
6. **Human approval is mandatory where it matters.** State-changing tests, external callbacks, real credentials, and report submission require explicit approval.

## Documentation

- [CONTEXT.md](./CONTEXT.md): domain terminology and shared language.
- [AGENTS.md](./AGENTS.md): mandatory engineering constraints for coding agents.
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md): layers, components, and deployment topology.
- [docs/WORKFLOW.md](./docs/WORKFLOW.md): agent orchestration, state machines, and verdict rules.
- [docs/SECURITY.md](./docs/SECURITY.md): sandbox, network, credential, attachment, and evidence security.
- [docs/DATA-MODEL.md](./docs/DATA-MODEL.md): core entities and domain events.
- [docs/ROADMAP.md](./docs/ROADMAP.md): milestones and acceptance criteria.
- [docs/REFERENCE-PROJECTS.md](./docs/REFERENCE-PROJECTS.md): reference projects, adopted ideas, and rejected assumptions.

## Project layout

```text
VulnLoom/
├── apps/                   # CLI and future API entry points
├── src/vulnloom/
│   ├── domain/             # Domain objects, state machines, and policy
│   ├── orchestrator/       # DAG scheduling, budgets, verdicts, and approval gates
│   ├── agents/             # Agent roles and structured output protocols
│   ├── broker/             # Typed tool mediation and permission checks
│   ├── runners/            # Docker/rootless sandbox runners
│   ├── analyzers/          # AST, Semgrep, and future CodeQL adapters
│   ├── validators/         # HTTP, browser, and test-script validators
│   ├── evidence/           # Redaction, hashing, and evidence indexing
│   ├── reporting/          # Report templates and exporters
│   └── adapters/           # Target, model, and disclosure adapters
├── policies/               # Scope, network, tool, and resource policies
├── prompts/                # Versioned prompts
├── schemas/                # JSON Schema contracts
├── sandboxes/              # Images and runtime profiles
├── benchmarks/             # Test targets, ground truth, and evaluation scripts
├── tests/
└── docs/
```

## First end-to-end path

The initial product path is deliberately narrow:

```text
Approved scope
→ Import one Python Web repository
→ Produce static security signals
→ Build a cross-file SourceGraph
→ Let a human select one Candidate
→ Start the test application in Docker
→ Validate the Candidate
→ Run an independent Critic
→ Produce a Markdown report draft
```

Public asset discovery, automatic submission, and general-purpose autonomous shell access remain out of scope until this path meets its precision, isolation, and evidence-retention goals.

## Current implementation

### Phase 0: domain and safety foundation

- Immutable Pydantic domain models and exported JSON Schema contracts.
- Separate Candidate state machine and deterministic Candidate-to-Finding gate.
- Scope Policy Engine and approvals bound to specific action digests.
- Evidence redaction, content addressing, and integrity verification.
- SQLite event log with idempotency conflict detection.
- Typed Control Plane/Worker protocol and an explicit Worker environment allowlist.
- `engagement-create`, `scope-approve`, and `status` CLI commands.
- An OpenAI-compatible model-provider configuration boundary; no network model call is made yet.

### M1: secure target ingestion

- Streaming, size-limited quarantine for ZIP and TAR artifacts.
- Member-by-member archive extraction without `extractall()`.
- Validation of normalized paths, symbolic links, special files, file counts, individual sizes, total expanded size, and compression ratio.
- Exact commit pinning for local Git repositories by reading Git objects without checkout, hooks, or target-code execution.
- Static classification of Kubernetes, Helm, Terraform, Dockerfile, and Compose files.
- Registration of OCI image references by `sha256` digest without pulling images or connecting to Docker.
- Atomic, read-only Target Snapshots with file-level SHA-256 manifests and idempotent reuse.
- Idempotent `TargetIngested` events; failures and timeouts do not leave partial snapshots.

### M2: Python Web Source Mapper

- Python AST indexing without importing or executing target code.
- Route discovery for Flask, FastAPI, Starlette, and Django.
- Structured functions, cross-file calls, authentication and authorization guards, ownership checks, dangerous sinks, and input-propagation paths.
- Content-addressed `SourceGraph` and `StaticSignal` output. A signal is a hypothesis for validation, never a Finding.
- File size and SHA-256 verification before analysis; tampering, path escape, resource-limit violations, and timeouts fail closed.
- Optional Semgrep adapter restricted to pre-registered local rules, with metrics and version checks disabled and no inherited API keys.
- Idempotent `SourceGraphBuilt` summary events. Full graphs are stored separately as read-only objects instead of being copied into the normal event log.

## Local development

VulnLoom requires Python 3.12 or later.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest --cov=vulnloom --cov-report=term-missing
.venv/bin/python scripts/export_schemas.py
```

## Basic usage

Target ingestion requires an approved Scope that is still valid and explicitly includes either the artifact digest or the Git URL and commit.

```bash
vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  artifact-quarantine --engagement-id <uuid> --source source.zip

# Add the returned source_name, kind, and artifact_id to a Scope,
# then have that Scope approved by an authorized reviewer.
vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  target-ingest-archive --scope-file scope.json --source source.zip

vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  target-ingest-git --scope-file scope.json --source /local/repo \
  --repository-url https://example.invalid/project.git --commit <full-commit>

vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  target-register-image --scope-file scope.json \
  --image-ref ghcr.io/example/app --digest sha256:<digest>

# Build an offline Python Web SourceGraph from a verified filesystem snapshot.
vulnloom --db .vulnloom/events.db --store .vulnloom/targets \
  source-map --snapshot-id <manifest-sha256> \
  --analysis-store .vulnloom/analysis
```

## Model credential boundary

The Control Plane resolves model API keys through `ModelProviderConfig.api_key_env` immediately before a provider request. Keys do not appear in `TaskEnvelope`, Worker environments, event logs, or Evidence summaries. `.env.example` lists variable names only, and real `.env` files are ignored by Git.

## Safety status

VulnLoom is under active development. The current release provides the trusted domain foundation, secure local target ingestion, and offline static source mapping. Dynamic validation, autonomous report generation, disclosure-platform integration, and CVE workflows are not implemented yet.

Use VulnLoom only on systems, source code, and test environments for which you have explicit authorization.
