"""Code-owned probe fixtures, never supplied by a model or research target."""

from vulnloom.domain.digests import canonical_digest

PROBE_SUMMARY = canonical_digest("vulnloom-provider-probe-v1")
PROBE_TEXT = (
    "This is a synthetic connectivity check, with no target or research task. "
    "Return only the complete decision with summary_digest=" + PROBE_SUMMARY + ". "
    "Use supporting_ref_digests=[] and tool_call=null. Do not propose tools."
)
PROBE_DIGEST = canonical_digest(PROBE_TEXT)
CUC_PROBE_TEXT = "Reply with exactly PONG."
CUC_PROBE_DIGEST = canonical_digest(
    {
        "probe": "cuc-chat-pong-v1",
        "request": CUC_PROBE_TEXT,
        "expected_response": "PONG",
    }
)
CUC_RESPONSE_MODELS = ("deepseek-v4-flash", "deepseek-v4-flash-0731")
