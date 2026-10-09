"""PhishScope - report.py: JSON and HTML (also used for PDF) exports. Only defanged data is emitted."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from jinja2 import Environment, select_autoescape

from enrichment import fmt_vt

COLORS = {"low": "#1e8e3e", "suspicious": "#d68a00", "malicious": "#c62828"}

TEMPLATE = """<html><head><meta charset="utf-8"><title>PhishScope Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;font-size:10pt;color:#111}
h1{font-size:18pt;margin-bottom:0} h2{font-size:12pt;border-bottom:1px solid #999;margin-top:18px}
table{border-collapse:collapse;width:100%} td,th{border:1px solid #bbb;padding:3px 5px;text-align:left;vertical-align:top}
th{background:#eee} .score{font-size:20pt;font-weight:bold;color:{{ color }};} .muted{color:#666}
</style></head><body>
<h1>PhishScope Analyst Report</h1>
<p class="muted">Generated {{ generated }} UTC &middot; File: {{ filename }}</p>
<p><span class="score">{{ res.total }}/100</span> &nbsp; <b style="color:{{ color }}">{{ res.verdict }}</b></p>

<h2>Score breakdown</h2>
<table><tr><th>Pts</th><th>Rule</th><th>Evidence</th></tr>
{% for r in res.rules %}<tr><td>+{{ r.points }}</td><td>{{ r.title }}</td><td>{{ r.evidence }}</td></tr>
{% else %}<tr><td colspan="3">No rules triggered.</td></tr>{% endfor %}</table>

{% if pe.warnings %}<h2>Warnings</h2><ul>{% for w in pe.warnings %}<li>{{ w }}</li>{% endfor %}</ul>{% endif %}

<h2>Headers &amp; authentication</h2>
<table>{% for k, v in headers %}<tr><th width="18%">{{ k }}</th><td>{{ v }}</td></tr>{% endfor %}
<tr><th>SPF / DKIM / DMARC</th><td>{{ pe.auth.spf }} / {{ pe.auth.dkim }} / {{ pe.auth.dmarc }}</td></tr>
<tr><th>Origin IP</th><td>{{ origin }}</td></tr></table>

<h2>Hop trace</h2>
<table><tr><th>#</th><th>From</th><th>IP</th><th>By</th><th>Timestamp</th><th>Delay (s)</th></tr>
{% for h in hops %}<tr><td>{{ h.index }}</td><td>{{ h.from_host }}</td><td>{{ h.ip }}</td><td>{{ h.by_host }}</td><td>{{ h.timestamp }}</td><td>{{ h.delay_s if h.delay_s is not none else '' }}</td></tr>{% endfor %}</table>

<h2>URLs ({{ pe.urls|length }})</h2>
<table><tr><th>Defanged URL</th><th>Source</th><th>Flags</th><th>VirusTotal</th></tr>
{% for u in pe.urls %}<tr><td>{{ u.defanged }}</td><td>{{ u.source }}</td><td>{{ u.flags|map(attribute=0)|join(', ') }}</td><td>{{ vt(u.intel.get('vt')) }}</td></tr>{% endfor %}</table>

<h2>Attachments ({{ pe.attachments|length }})</h2>
<table><tr><th>Name</th><th>Size</th><th>Detected</th><th>SHA-256</th><th>Flags</th><th>VT</th></tr>
{% for a in pe.attachments %}<tr><td>{{ a.filename }}</td><td>{{ a.size }}</td><td>{{ a.detected_type }}</td><td style="font-size:8pt">{{ a.sha256 }}</td><td>{{ a.flags|map(attribute=0)|join(', ') }}</td><td>{{ vt(a.intel.get('vt')) }}</td></tr>{% endfor %}</table>

<h2>Domain intelligence</h2>
<table><tr><th>Domain</th><th>Created</th><th>Age (days)</th><th>Registrar</th></tr>
{% for d, i in pe.domain_intel.items() %}{% set w = i.get('whois') or {} %}<tr><td>{{ d.replace('.', '[.]') }}</td><td>{{ w.get('created','') }}</td><td>{{ w.get('age_days','') }}</td><td>{{ w.get('registrar','') or w.get('error','') }}</td></tr>{% endfor %}</table>
</body></html>"""


def to_dict(pe, res) -> dict:
    d = pe.to_dict()
    d.pop("raw_text", None)                      # large; available in the UI
    return {"tool": "PhishScope 1.0", "generated_utc": datetime.now(timezone.utc).isoformat(),
            "score": res.to_dict(), "email": d}


def to_json(pe, res) -> str:
    return json.dumps(to_dict(pe, res), indent=2, default=str)


def to_html(pe, res) -> str:
    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    tpl = env.from_string(TEMPLATE)
    return tpl.render(pe=pe, res=res, color=COLORS[res.level], vt=fmt_vt,
                      generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
                      filename=pe.path.replace("\\", "/").rsplit("/", 1)[-1],
                      headers=list(pe.headers.items()), hops=pe.hops,
                      origin=pe.origin_ip.replace(".", "[.]") or "unknown")
