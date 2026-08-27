---
status: accepted
---

# 分离 Quarantine Artifact 与 Target Snapshot

VulnLoom 将原始输入先保存为内容寻址的 quarantine Artifact，只有其名称、类型和摘要匹配已批准 Scope 后，才逐成员校验并原子发布为独立的只读 Target Snapshot。直接在解压目录或 Git 工作树上分析虽然更简单，但会混淆“已接收”与“已授权”、允许输入变化污染证据，也难以对失败清理和重复导入给出确定语义；分离两层的代价是额外存储和 Manifest 管理。
