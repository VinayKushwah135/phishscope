"""
PhishScope - scorer.py
Rule-based composite score (0-100) with a transparent per-rule breakdown.
  0-25 Clean / Low Risk | 26-60 Suspicious | 61-100 Highly Malicious / Phishing
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

HEADER_RULES = {
    "RETURN_PATH_MISMATCH": ("Return-Path domain differs from From domain", 10),
    "REPLY_TO_MISMATCH": ("Reply-To domain differs from From domain", 8),
    "DISPLAY_NAME_SPOOF": ("Display name deception (embeds another address/domain)", 15),
    "DISPLAY_NAME_BRAND": ("Display name impersonates a brand", 15),
    "NO_FROM": ("Missing From address", 10),
}
URL_RULES = {
    "HOMOGLYPH": ("Homoglyph (Unicode look-alike) brand domain", 25),
    "TYPOSQUAT": ("Typosquatted brand domain (Levenshtein match)", 20),
    "PUNYCODE": ("Punycode / IDN domain in link", 15),
    "BRAND_SUBDOMAIN": ("Brand name used as subdomain of unrelated domain", 15),
    "BRAND_LOOKALIKE": ("Domain embeds brand name (e.g. brand-secure.tld)", 15),
    "ANCHOR_MISMATCH": ("Link text shows a different domain than the real target", 15),
    "HIDDEN_LINK": ("Hidden / invisible link in HTML", 10),
    "IP_URL": ("Link uses a raw IP address", 10),
    "URL_USERINFO": ("'user@host' obfuscation in URL", 10),
    "SHORTENER": ("URL shortener conceals destination", 5),
    "SUSPICIOUS_TLD": ("High-abuse TLD", 5),
}
ATT_RULES = {
    "DISGUISED_EXECUTABLE": ("Executable disguised as a different file type", 35),
    "MAGIC_MISMATCH": ("File extension does not match magic bytes", 20),
    "HIGH_RISK_EXT": ("High-risk executable/script attachment", 20),
    "MACRO_ENABLED": ("Macro-enabled Office document", 20),
    "DOUBLE_EXT": ("Double-extension filename trick", 20),
    "RTLO_SPOOF": ("Right-to-left override in filename", 25),
    "ARCHIVE_EXECUTABLE": ("Archive contains executable/script", 20),
    "ENCRYPTED_ARCHIVE": ("Password-protected archive", 10),
    "ARCHIVE": ("Archive / disk-image attachment", 5),
}


@dataclass
class Rule:
    id: str
    title: str
    points: int
    evidence: str = ""


@dataclass
class ScoreResult:
    total: int
    verdict: str
    level: str
    rules: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def level_for(score: int):
    if score <= 25:
        return "low", "Clean / Low Risk"
    if score <= 60:
        return "suspicious", "Suspicious"
    return "malicious", "Highly Malicious / Phishing"


def score(pe) -> ScoreResult:
    rules: list[Rule] = []

    def add(rid, title, pts, ev=""):
        rules.append(Rule(rid, title, pts, ev))

    # --- authentication ------------------------------------------------------
    a = pe.auth
    for mech, table in (("spf", {"fail": 15, "softfail": 8, "permerror": 5, "temperror": 3}),
                        ("dkim", {"fail": 10, "permerror": 5}),
                        ("dmarc", {"fail": 15})):
        pts = table.get(a.get(mech, "none"), 0)
        if pts:
            add(f"{mech.upper()}_{a[mech].upper()}", f"{mech.upper()} result: {a[mech]}", pts)
    if not pe.auth_present:
        add("NO_AUTH_RESULTS", "No SPF/DKIM/DMARC verdicts in headers", 5)

    # --- header spoofing -----------------------------------------------------
    for code, (title, pts) in HEADER_RULES.items():
        ev = [d for c, d in pe.header_flags if c == code]
        if ev:
            add(code, title, pts, "; ".join(ev[:2]))

    # --- URLs ----------------------------------------------------------------
    for code, (title, pts) in URL_RULES.items():
        ev = [f"{u.defanged} ({d})" for u in pe.urls for c, d in u.flags if c == code]
        if ev:
            add(code, f"{title} [{len(ev)}x]", pts, "; ".join(ev[:3]))

    # --- keywords ------------------------------------------------------------
    if pe.keyword_hits:
        cats = sorted({c for c, _ in pe.keyword_hits})
        add("SOCIAL_ENGINEERING", "Social-engineering language (" + ", ".join(cats) + ")",
            min(15, 3 * len(pe.keyword_hits)), "; ".join(f"'{p}'" for _, p in pe.keyword_hits[:5]))

    # --- attachments ---------------------------------------------------------
    for code, (title, pts) in ATT_RULES.items():
        ev = [f"{at.filename}: {d}" for at in pe.attachments for c, d in at.flags if c == code]
        if ev:
            add(code, f"{title} [{len(ev)}x]", pts, "; ".join(ev[:3]))

    # --- threat intel --------------------------------------------------------
    def mal(d):
        return (d or {}).get("malicious", 0) if (d or {}).get("status") == "ok" else 0

    worst = max(pe.urls, key=lambda u: mal(u.intel.get("vt")), default=None)
    if worst and mal(worst.intel.get("vt")) > 0:
        n = mal(worst.intel["vt"])
        add("VT_URL", f"VirusTotal flags a URL as malicious ({n} engines)", 30 if n >= 3 else 15, worst.defanged)
    for at in pe.attachments:
        n = mal(at.intel.get("vt"))
        if n:
            add("VT_FILE", f"VirusTotal flags attachment hash ({n} engines)", 40 if n >= 3 else 20,
                f"{at.filename} sha256={at.sha256[:16]}…")
            break
    for ip, intel in pe.ip_intel.items():
        ab = (intel.get("abuseipdb") or {}).get("score", 0)
        if ab >= 40:
            add("ABUSEIPDB", f"AbuseIPDB confidence {ab}% for relay/origin IP", 20 if ab >= 75 else 12,
                ip.replace(".", "[.]"))
            break
    for ip, intel in pe.ip_intel.items():
        if mal(intel.get("virustotal")) >= 3:
            add("VT_IP", "VirusTotal flags origin/relay IP", 15, ip.replace(".", "[.]"))
            break
    young = [(d, i["whois"]["age_days"]) for d, i in pe.domain_intel.items()
             if (i.get("whois") or {}).get("age_days") is not None and i["whois"]["age_days"] < 30]
    if young:
        add("YOUNG_DOMAIN", "Newly registered domain (< 30 days)", 20,
            "; ".join(f"{d.replace('.', '[.]')} ({age}d)" for d, age in young[:3]))
    bad = [d for d, i in pe.domain_intel.items() if (i.get("urlscan") or {}).get("malicious")]
    if bad:
        add("URLSCAN_MALICIOUS", "URLScan.io verdict: malicious", 20, "; ".join(d.replace(".", "[.]") for d in bad[:3]))

    total = min(100, sum(r.points for r in rules))
    lvl, verdict = level_for(total)
    return ScoreResult(total, verdict, lvl, sorted(rules, key=lambda r: -r.points))
