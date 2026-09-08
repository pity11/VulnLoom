"""Loopback-only, no-script human review UI for Candidate recommendations."""

# ruff: noqa: E501

import html
import re
import secrets
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from vulnloom.domain.models import utc_now

from .selection_models import CandidateRecommendationSelectionDecision

CSS = """
:root{color-scheme:dark;--bg:#0f172a;--card:#192134;--muted:#a9b7ca;--text:#f8fafc;
--border:#334155;--focus:#93c5fd;--accept:#34d399;--reject:#f87171;--defer:#fbbf24}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55
system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{width:min(960px,100%);margin:auto;
padding:32px 24px 64px}header{margin-bottom:32px}h1{font-size:clamp(1.75rem,5vw,2.6rem);
line-height:1.12;margin:0 0 10px}h2{font-size:1.2rem;margin:0 0 12px}p{max-width:72ch}
.eyebrow{color:var(--accept);font-size:.78rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase}
.muted{color:var(--muted)}.grid{display:grid;gap:16px}.card{background:var(--card);border:1px solid
var(--border);border-radius:14px;padding:20px}.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));
gap:12px}.fact{background:#111a2e;border-radius:10px;padding:12px}.label{display:block;color:var(--muted);
font-size:.78rem;margin-bottom:3px}.value{overflow-wrap:anywhere}.badge{display:inline-flex;border:1px solid
var(--border);border-radius:999px;padding:4px 10px;font-size:.8rem;font-weight:700}.questions{padding-left:22px}
.actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:24px}.button,button{min-height:48px;border-radius:10px;
border:1px solid var(--border);padding:11px 18px;font:inherit;font-weight:700;cursor:pointer;text-decoration:none;
display:inline-flex;align-items:center;justify-content:center;background:#243148;color:var(--text);transition:background .2s;
touch-action:manipulation}.skip{position:absolute;left:16px;top:-80px;background:var(--text);color:var(--bg);
padding:10px 14px;border-radius:8px;z-index:10}.skip:focus{top:16px}
button:hover,.button:hover{background:#30415f}.accept{background:#047857;border-color:#10b981}.accept:hover{background:#059669}
.reject{background:#991b1b;border-color:#ef4444}.reject:hover{background:#b91c1c}.defer{background:#854d0e;
border-color:#f59e0b}.defer:hover{background:#a16207}button:active,.button:active{filter:brightness(1.18)}
button:focus-visible,.button:focus-visible,a:focus-visible{
outline:3px solid var(--focus);outline-offset:3px}.warning{border-left:4px solid var(--defer);padding-left:16px}
code{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}dl{margin:0}
dt{color:var(--muted);font-size:.8rem;margin-top:12px}dd{margin:2px 0 0;overflow-wrap:anywhere}
@media(max-width:600px){main{padding:24px 16px 48px}.facts{grid-template-columns:1fr}.actions{display:grid}
.button,button{width:100%}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
"""


def _page(title, body):
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>{CSS}</style></head><body><a class="skip" href="#main">跳到主要内容</a>
<main id="main" tabindex="-1">{body}</main></body></html>""".encode()


def _short(value):
    return html.escape(str(value)[:12])


class CandidateRecommendationReviewApplication:
    def __init__(self, service, *, reviewer_id, csrf_token=None, now=utc_now):
        if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", reviewer_id):
            raise ValueError("reviewer id rejected")
        self.service = service
        self.reviewer_id = reviewer_id
        self.csrf_token = csrf_token or secrets.token_urlsafe(32)
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", self.csrf_token):
            raise ValueError("CSRF token rejected")
        self.now = now
        self.pending = {}

    def index(self):
        now = self.now()
        selections = self.service.selection_store.list_completed()
        status = {item.admission_record_id: item.decision.value for item in selections}
        cards = []
        admissions = self.service.recommendation_store.list_completed()
        if len(admissions) > 100:
            raise ValueError("review item limit exceeded")
        for admission in admissions:
            _, recommendation, candidate = self.service.review_item(admission.record_id, at=now)
            state = status.get(admission.record_id, "pending")
            cards.append(
                f"""<article class="card"><div class="eyebrow">{html.escape(state)}</div>
<h2>{html.escape(candidate.title)}</h2><p class="muted">{html.escape(candidate.cwe)} · 模型优先级
<span class="badge">{html.escape(recommendation.priority.value)}</span></p>
<p>{html.escape(recommendation.rationale)}</p><a class="button" href="/review?id={admission.record_id}">
查看并决定</a></article>"""
            )
        content = (
            "".join(cards)
            or '<section class="card"><p>当前没有可审阅的 Recommendation。</p></section>'
        )
        return _page(
            "VulnLoom 人工审阅",
            f"""<header><div class="eyebrow">Local review console</div><h1>Candidate 人工审阅</h1>
<p class="muted">仅显示权威账本中已完成且正文绑定通过的 Recommendation。任何决定都不会启动动态验证。</p>
</header><section class="grid">{content}</section>""",
        )

    def review(self, record_id):
        admission, recommendation, candidate = self.service.review_item(record_id, at=self.now())
        prior = tuple(
            item
            for item in self.service.selection_store.list_completed()
            if item.admission_record_id == admission.record_id
        )
        questions = (
            "".join(f"<li>{html.escape(item)}</li>" for item in recommendation.review_questions)
            or "<li>模型未提出额外问题。</li>"
        )
        locations = "".join(
            f"<li><code>{html.escape(item.path)}:{item.line}</code> · {html.escape(item.symbol or '—')}</li>"
            for item in recommendation.cited_locations
        )
        if prior and prior[-1].decision in {
            CandidateRecommendationSelectionDecision.ACCEPT,
            CandidateRecommendationSelectionDecision.REJECT,
        }:
            actions = (
                '<section class="card"><h2>该建议已完成终态选择</h2>'
                f"<p>当前决定：<strong>{html.escape(prior[-1].decision.value)}</strong>。</p>"
                '<div class="actions"><a class="button" href="/">返回列表</a></div></section>'
            )
        else:
            actions = f"""<form method="post" action="/prepare">
<input type="hidden" name="csrf" value="{html.escape(self.csrf_token)}">
<input type="hidden" name="record_id" value="{admission.record_id}"><div class="actions">
<button class="accept" name="decision" value="accept">接受并准备选择</button>
<button class="reject" name="decision" value="reject">拒绝此建议</button>
<button class="defer" name="decision" value="defer">稍后处理</button></div></form>"""
        return _page(
            "审阅 Candidate",
            f"""<header><a href="/">返回列表</a><div class="eyebrow">Human decision required</div>
<h1>{html.escape(candidate.title)}</h1><p class="muted">系统当前不会自动选择或验证此 Candidate。</p></header>
<section class="card"><div class="facts"><div class="fact"><span class="label">CWE</span>
<span class="value">{html.escape(candidate.cwe)}</span></div><div class="fact"><span class="label">候选置信度</span>
<span class="value">{candidate.confidence:.2f}</span></div><div class="fact"><span class="label">模型优先级</span>
<span class="value">{html.escape(recommendation.priority.value)}</span></div><div class="fact">
<span class="label">Admission</span><code>{_short(admission.record_id)}…</code></div></div></section>
<section class="card"><h2>模型建议</h2><p>{html.escape(recommendation.rationale)}</p>
<h2>建议核查的问题</h2><ol class="questions">{questions}</ol><h2>引用位置</h2>
<ol class="questions">{locations}</ol></section><section class="card warning"><h2>决定的含义</h2>
<p>接受只生成可供 Validation Intake 核验的选择记录；仍需单独审批 Validation Plan。拒绝和稍后处理都不会修改 Candidate。</p></section>
{actions}""",
        )

    def prepare(self, form):
        self._csrf(form)
        if set(form) != {"csrf", "record_id", "decision"}:
            raise ValueError("selection form fields rejected")
        decision = CandidateRecommendationSelectionDecision(form["decision"])
        now = self.now()
        command = self.service.prepare(
            admission_record_id=form["record_id"],
            decision=decision,
            reviewer_id=self.reviewer_id,
            decided_at=now,
            expires_at=now + timedelta(seconds=120),
            idempotency_key="web-selection:" + secrets.token_hex(16),
        )
        self.pending = {key: value for key, value in self.pending.items() if value.expires_at > now}
        if len(self.pending) >= 32:
            raise ValueError("too many pending selections")
        self.pending[command.command_id] = command
        labels = {"accept": "接受", "reject": "拒绝", "defer": "稍后处理"}
        return _page(
            "确认人工选择",
            f"""<header><div class="eyebrow">Confirm exact command</div><h1>确认人工选择</h1>
<p class="muted">这是写入账本前的最后一步。请核对决定与绑定摘要。</p></header><section class="card">
<dl><dt>决定</dt><dd>{labels[command.decision.value]}</dd><dt>审阅者</dt><dd>{html.escape(command.reviewer_id)}</dd>
<dt>Candidate</dt><dd><code>{command.candidate_id}</code></dd><dt>Admission record</dt>
<dd><code>{command.admission_record_id}</code></dd><dt>Command digest</dt><dd><code>{command.command_id}</code></dd>
<dt>有效期</dt><dd>{html.escape(command.expires_at.isoformat())}</dd></dl></section>
<form method="post" action="/record"><input type="hidden" name="csrf" value="{html.escape(self.csrf_token)}">
<input type="hidden" name="command_id" value="{command.command_id}"><input type="hidden" name="confirm" value="yes">
<div class="actions"><button class="accept" type="submit">确认写入选择账本</button>
<a class="button" href="/review?id={command.admission_record_id}">返回修改</a></div></form>""",
        )

    def record(self, form):
        self._csrf(form)
        if set(form) != {"csrf", "command_id", "confirm"} or form["confirm"] != "yes":
            raise ValueError("selection confirmation rejected")
        command = self.pending.get(form["command_id"])
        if command is None:
            raise ValueError("pending selection unavailable")
        record = self.service.record(command, now=self.now())
        self.pending.pop(command.command_id, None)
        eligibility = (
            "可提交给 Validation Intake 重新核验"
            if record.eligible_for_validation_intake
            else "不会进入 Validation Intake"
        )
        return _page(
            "选择已记录",
            f"""<header><div class="eyebrow">Completed</div><h1>选择已写入账本</h1></header>
<section class="card"><p><strong>{html.escape(record.decision.value)}</strong> · {eligibility}</p>
<p class="muted">Candidate 未修改；动态验证仍需要独立计划与 Approval Gate。</p>
<dl><dt>Selection record</dt><dd><code>{record.record_id}</code></dd></dl></section>
<div class="actions"><a class="button" href="/">返回列表</a></div>""",
        )

    def _csrf(self, form):
        if not secrets.compare_digest(form.get("csrf", ""), self.csrf_token):
            raise ValueError("CSRF rejected")


class LoopbackReviewServer(HTTPServer):
    allow_reuse_address = False
    request_queue_size = 8

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address


def _handler(application):
    class Handler(BaseHTTPRequestHandler):
        server_version = "VulnLoomReview/1"
        sys_version = ""

        def do_GET(self):
            try:
                self._origin()
                route = urlsplit(self.path)
                if route.path == "/":
                    body = application.index()
                elif route.path == "/review":
                    fields = parse_qs(route.query, strict_parsing=True, max_num_fields=2)
                    if set(fields) != {"id"} or len(fields["id"]) != 1:
                        raise ValueError("review query rejected")
                    body = application.review(fields["id"][0])
                elif route.path == "/healthz" and not route.query:
                    self._send(b'{"status":"ok"}', content_type="application/json")
                    return
                else:
                    self.send_error(404)
                    return
                self._send(body)
            except Exception:
                self._send(
                    _page(
                        "请求被拒绝",
                        '<section class="card"><h1>请求被拒绝</h1><p>输入、状态或权威绑定未通过。</p><a href="/">返回列表</a></section>',
                    ),
                    status=400,
                )

        def do_POST(self):
            try:
                self._origin(require_origin=True)
                route = urlsplit(self.path)
                if route.query or route.path not in {"/prepare", "/record"}:
                    self.send_error(404)
                    return
                content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
                length = int(self.headers.get("Content-Length", "-1"))
                if content_type != "application/x-www-form-urlencoded" or not 0 <= length <= 8192:
                    raise ValueError("request body rejected")
                raw = self.rfile.read(length).decode("utf-8", "strict")
                parsed = parse_qs(
                    raw, keep_blank_values=True, strict_parsing=True, max_num_fields=8
                )
                if any(len(value) != 1 for value in parsed.values()):
                    raise ValueError("duplicate form field rejected")
                form = {key: value[0] for key, value in parsed.items()}
                body = (
                    application.prepare(form)
                    if route.path == "/prepare"
                    else application.record(form)
                )
                self._send(body)
            except Exception:
                self._send(
                    _page(
                        "操作被拒绝",
                        '<section class="card"><h1>操作被拒绝</h1><p>未写入选择记录。请返回并重新核验。</p><a href="/">返回列表</a></section>',
                    ),
                    status=400,
                )

        def _origin(self, require_origin=False):
            host = self.headers.get("Host", "")
            allowed = {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }
            if host not in allowed:
                raise ValueError("host rejected")
            origin = self.headers.get("Origin")
            if require_origin and origin not in {f"http://{item}" for item in allowed}:
                raise ValueError("origin rejected")

        def _send(self, body, *, status=200, content_type="text/html; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            return

    return Handler


def create_review_server(application, *, port):
    server = LoopbackReviewServer(("127.0.0.1", port), _handler(application))
    server.server_port = server.server_address[1]
    if server.server_address[0] != "127.0.0.1":
        server.server_close()
        raise ValueError("review UI did not bind loopback")
    return server
