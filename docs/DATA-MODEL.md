# 数据模型

## 1. 聚合关系

```text
Engagement
├── Scope (versioned)
├── Target*
│   ├── Signal*
│   ├── Candidate*
│   │   ├── ValidationRun*
│   │   └── EvidenceBundle*
│   └── Finding*
│       └── Report*
└── ApprovalRequest*
```

## 2. 核心对象

### Scope

```yaml
scope_id: uuid
version: integer
authority_reference: string
valid_from: datetime
valid_until: datetime
repositories: []
artifacts: []
network_targets: []
allowed_identities: []
allowed_test_classes: []
denied_actions: []
rate_limits: {}
approval_requirements: []
approved_by: string
```

### Artifact 与 Target Snapshot

```yaml
artifact:
  artifact_id: sha256
  engagement_id: uuid
  kind: source_archive | iac_bundle | git_repository | oci_image
  source_name: string
  source_ref: string
  original_size: integer
  detected_format: zip | tar | git | oci-manifest
  quarantine_ref: string | null

target_snapshot:
  target: Target
  artifact: Artifact
  manifest:
    manifest_id: sha256
    target_version: string
    files:
      - path: normalized/path
        size: integer
        sha256: string
        category: enum
    total_size: integer
  root_ref: string | null
```

Artifact 进入 quarantine 不代表它已在 Scope 内；只有名称、类型和 digest（或 Git URL 与 commit）匹配已批准 Scope 后，才可以生成 Target Snapshot。

### Candidate

```yaml
candidate_id: uuid
target_id: uuid
title: string
cwe: string
entry_point: SourceLocation
sink: SourceLocation
code_path: []
preconditions: []
security_invariant: string
hypothesis: string
signals: []
cheapest_disproof: string
duplicate_fingerprint: string
state: enum
```

### ValidationRun

```yaml
run_id: uuid
candidate_id: uuid
target_version: string
scope_version: integer
sandbox_image_digest: string
policy_digest: string
plan: []
started_at: datetime
finished_at: datetime
result: reproduced | not_reproduced | inconclusive | policy_stopped
side_effects: []
evidence_refs: []
resource_usage: {}
```

### Evidence

```yaml
evidence_id: sha256
kind: source | http | log | screenshot | test | policy
source_ref: string
captured_at: datetime
producer: string
target_version: string
redaction_policy: string
content_ref: string
summary: string
```

### Finding

```yaml
finding_id: uuid
candidate_id: uuid
root_cause: string
affected_versions: []
preconditions: []
impact: string
severity_assessment: {}
validation_runs: []
evidence_bundle_id: uuid
duplicate_family_id: uuid
state: verified | withdrawn | fixed
```

### Report

```yaml
report_id: uuid
finding_id: uuid
channel: generic | edusrc | cnvd | vendor | cve-draft
version: integer
title: string
summary: string
reproduction: []
impact: string
remediation: string
evidence_refs: []
redaction_status: passed | failed
review_status: draft | approved | exported | submitted
```

## 3. 领域事件

- `ScopeApproved`
- `TargetIngested`
- `SignalObserved`
- `CandidateProposed`
- `CandidateRejected`
- `ValidationPlanned`
- `ApprovalGranted`
- `ValidationStarted`
- `EvidenceCaptured`
- `ValidationCompleted`
- `CandidateMarkedDuplicate`
- `FindingVerified`
- `ReportDrafted`
- `ReportApproved`
- `ReportExported`

事件只记录已经发生的领域事实。模型的自然语言输出先经过 schema 校验和命令处理，不能直接写事件流。

## 4. 不变量

- 一个 Finding 必须属于一个 Candidate。
- 一个 Finding 至少引用一个成功 Validation Run。
- Validation Run 的 Scope 和 Target 版本不可为空。
- Report 只能引用 Finding 已批准的 Evidence Bundle。
- Submission 必须引用未过期 ApprovalRequest。
- 相同 `duplicate_fingerprint` 的 Finding 必须先进行人工根因确认。
