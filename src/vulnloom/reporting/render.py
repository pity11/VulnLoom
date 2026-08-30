"""Deterministic Markdown rendering without Evidence body disclosure."""

from __future__ import annotations

from vulnloom.domain.models import Report, ReportChannel, ReportSectionKind

_HEADINGS = {
    ReportChannel.GENERIC: {
        ReportSectionKind.SUMMARY: "Summary",
        ReportSectionKind.CODE_LOCATION: "Code location",
        ReportSectionKind.REQUEST_RESPONSE: "Request and response observation",
        ReportSectionKind.REPRODUCTION: "Reproduction",
        ReportSectionKind.IMPACT: "Impact",
        ReportSectionKind.REMEDIATION: "Remediation",
    },
    ReportChannel.EDUSRC: {
        ReportSectionKind.SUMMARY: "漏洞概述",
        ReportSectionKind.CODE_LOCATION: "代码位置",
        ReportSectionKind.REQUEST_RESPONSE: "请求与响应观测",
        ReportSectionKind.REPRODUCTION: "复现步骤",
        ReportSectionKind.IMPACT: "漏洞影响",
        ReportSectionKind.REMEDIATION: "修复建议",
    },
    ReportChannel.CNVD: {
        ReportSectionKind.SUMMARY: "漏洞描述",
        ReportSectionKind.CODE_LOCATION: "受影响位置",
        ReportSectionKind.REQUEST_RESPONSE: "验证观测",
        ReportSectionKind.REPRODUCTION: "验证步骤",
        ReportSectionKind.IMPACT: "危害",
        ReportSectionKind.REMEDIATION: "修复方案",
    },
    ReportChannel.VENDOR: {
        ReportSectionKind.SUMMARY: "Executive summary",
        ReportSectionKind.CODE_LOCATION: "Affected code",
        ReportSectionKind.REQUEST_RESPONSE: "Observed behavior",
        ReportSectionKind.REPRODUCTION: "Reproduction steps",
        ReportSectionKind.IMPACT: "Security impact",
        ReportSectionKind.REMEDIATION: "Recommended remediation",
    },
    ReportChannel.CVE_DRAFT: {
        ReportSectionKind.SUMMARY: "Description",
        ReportSectionKind.CODE_LOCATION: "Affected component",
        ReportSectionKind.REQUEST_RESPONSE: "Technical observation",
        ReportSectionKind.REPRODUCTION: "Reproduction",
        ReportSectionKind.IMPACT: "Impact",
        ReportSectionKind.REMEDIATION: "Remediation",
    },
}


def render_markdown(report: Report) -> str:
    headings = _HEADINGS[report.channel]
    lines = [
        f"# {_escape_markdown(report.title)}",
        "",
        f"Report ID: `{report.report_id}`  ",
        f"Finding ID: `{report.finding_id}`  ",
        f"Target version: `{_escape_markdown(report.target_version)}`",
        "",
    ]
    reproduction_index = 0
    for section in report.sections:
        heading = headings[section.kind]
        if section.kind is ReportSectionKind.REPRODUCTION:
            reproduction_index += 1
            heading = f"{heading} {reproduction_index}"
        lines.extend((f"## {heading}", "", _escape_markdown(section.text), ""))
        if section.evidence_refs:
            lines.append(
                "Evidence: " + ", ".join(f"`{ref}`" for ref in section.evidence_refs)
            )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _escape_markdown(value: str) -> str:
    escaped = value.replace("\\", "\\\\")
    for character in ("`", "!", "[", "]"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
