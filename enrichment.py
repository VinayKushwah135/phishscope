"""
PhishScope - enrichment.py
Threat-intelligence connectors: VirusTotal, AbuseIPDB, URLScan.io (search only) and WHOIS.

  * Missing keys never crash the run - the affected lookups are skipped and a warning is
    added to `pe.warnings` (shown in the UI).
  * Per-service rate limiters; 401/403/429 disable that service for the rest of the run.
  * Only *lookups* are performed. Nothing is submitted for scanning and no suspicious URL
    is ever fetched from this machine.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone

import requests

_DOMAIN_OK = re.compile(r"^[a-z0-9.-]{3,253}$")


def fmt_vt(d) -> str:
    if not d:
        return "—"
    if d.get("status") == "not_found":
        return "not in VT"
    total = sum(d.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    return f"{d.get('malicious', 0)}/{total} malicious"


class RateLimiter:
    def __init__(self, interval: float):
        self.interval, self._last, self._lock = interval, 0.0, threading.Lock()

    def wait(self):
        with self._lock:
            gap = time.monotonic() - self._last
            if gap < self.interval:
                time.sleep(self.interval - gap)
            self._last = time.monotonic()


class Enricher:
    def __init__(self, keys: dict, progress=None, max_urls: int = 12, timeout: int = 15):
        self.keys, self.max_urls, self.timeout = keys, max_urls, timeout
        self.progress = progress or (lambda m: None)
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "PhishScope/1.0"
        self.warnings: list[str] = []
        self._disabled: set[str] = set()
        # VirusTotal public API: 4 requests/minute
        self.vt_rl = RateLimiter(15.5 if keys.get("vt_free", True) else 0.3)
        self.abuse_rl, self.urlscan_rl = RateLimiter(1.0), RateLimiter(2.0)

    # -- plumbing ----------------------------------------------------------- #
    def _warn(self, msg: str):
        if msg not in self.warnings:
            self.warnings.append(msg)

    def _get(self, svc, url, headers=None, params=None, limiter=None):
        if svc in self._disabled:
            return None
        if limiter:
            limiter.wait()
        try:
            r = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            self._warn(f"{svc}: network error ({type(e).__name__})")
            return None
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                return None
        if r.status_code == 404:
            return {"_not_found": True}
        if r.status_code in (401, 403):
            self._warn(f"{svc}: API key rejected (HTTP {r.status_code}) - service disabled for this run.")
            self._disabled.add(svc)
        elif r.status_code == 429:
            self._warn(f"{svc}: rate limit / quota reached - remaining lookups skipped.")
            self._disabled.add(svc)
        else:
            self._warn(f"{svc}: unexpected HTTP {r.status_code}")
        return None

    # -- connectors --------------------------------------------------------- #
    def vt(self, kind: str, ident: str):
        key = self.keys.get("vt")
        if not key:
            return None
        if kind == "url":
            ident = base64.urlsafe_b64encode(ident.encode()).decode().strip("=")
        ep = {"url": "urls", "ip": "ip_addresses", "file": "files"}[kind]
        d = self._get("VirusTotal", f"https://www.virustotal.com/api/v3/{ep}/{ident}",
                      {"x-apikey": key}, limiter=self.vt_rl)
        if d is None:
            return None
        if d.get("_not_found"):
            return {"status": "not_found"}
        st = d.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"status": "ok", **{k: st.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")}}

    def abuseipdb(self, ip: str):
        key = self.keys.get("abuseipdb")
        if not key:
            return None
        d = self._get("AbuseIPDB", "https://api.abuseipdb.com/api/v2/check",
                      {"Key": key, "Accept": "application/json"},
                      {"ipAddress": ip, "maxAgeInDays": 90}, self.abuse_rl)
        x = (d or {}).get("data")
        if not x:
            return None
        return {"score": x.get("abuseConfidenceScore", 0), "reports": x.get("totalReports", 0),
                "country": x.get("countryCode"), "isp": x.get("isp")}

    def urlscan(self, domain: str):
        """Search prior public scans (passive - does not trigger a new scan)."""
        if not _DOMAIN_OK.match(domain):
            return None
        h = {"API-Key": self.keys["urlscan"]} if self.keys.get("urlscan") else {}
        d = self._get("URLScan.io", "https://urlscan.io/api/v1/search/", h,
                      {"q": f"page.domain:{domain}", "size": 5}, self.urlscan_rl)
        if d is None:
            return None
        res = d.get("results") or []
        if not res:
            return {"status": "no_scans", "scans": 0}
        out = {"status": "ok", "scans": len(res)}
        ru = res[0].get("result", "")
        if ru.startswith("https://urlscan.io/"):
            v = self._get("URLScan.io", ru, h, limiter=self.urlscan_rl) or {}
            ov = (v.get("verdicts") or {}).get("overall") or {}
            out.update(malicious=bool(ov.get("malicious")), score=ov.get("score"))
        return out

    def whois(self, domain: str):
        if not _DOMAIN_OK.match(domain):
            return None
        try:
            import whois as pw
        except ImportError:
            self._warn("python-whois is not installed - domain age unavailable.")
            return None
        ex = ThreadPoolExecutor(1)              # python-whois has no timeout of its own
        try:
            w = ex.submit(pw.whois, domain).result(timeout=20)
        except FutureTimeout:
            return {"error": "timeout"}
        except Exception as e:
            return {"error": type(e).__name__}
        finally:
            ex.shutdown(wait=False)
        c = getattr(w, "creation_date", None)
        if isinstance(c, list):
            c = min((x for x in c if isinstance(x, datetime)), default=None)
        if not isinstance(c, datetime):
            return {"error": "no creation date", "registrar": getattr(w, "registrar", None)}
        if c.tzinfo:
            c = c.astimezone(timezone.utc).replace(tzinfo=None)
        return {"created": c.date().isoformat(), "age_days": (datetime.utcnow() - c).days,
                "registrar": getattr(w, "registrar", None)}

    # -- orchestration ------------------------------------------------------ #
    def enrich(self, pe):
        k = self.keys
        if not k.get("vt"):
            self._warn("VirusTotal key not set - URL / IP / hash reputation skipped.")
        if not k.get("abuseipdb"):
            self._warn("AbuseIPDB key not set - IP abuse scoring skipped.")
        if not k.get("urlscan"):
            self._warn("URLScan.io key not set - using unauthenticated search (lower limits).")

        ips = []
        for h in pe.hops:
            try:
                if h.ip and h.ip not in ips and ipaddress.ip_address(h.ip).is_global:
                    ips.append(h.ip)
            except ValueError:
                pass
        for ip in ips[:5]:
            self.progress(f"IP reputation: {ip}")
            pe.ip_intel[ip] = {"abuseipdb": self.abuseipdb(ip), "virustotal": self.vt("ip", ip)}

        for a in pe.attachments:
            if a.size:
                self.progress(f"VirusTotal hash lookup: {a.sha256[:16]}…")
                a.intel["vt"] = self.vt("file", a.sha256)

        ordered = sorted(pe.urls, key=lambda u: -len(u.flags))[: self.max_urls]
        for u in ordered:
            self.progress(f"VirusTotal URL: {u.defanged[:60]}")
            u.intel["vt"] = self.vt("url", u.url)

        sender = pe.headers.get("From", "").split("@")[-1].strip(" >").lower()
        domains = []
        for d in [sender] + [u.domain for u in pe.urls]:
            if d and d not in domains and not re.fullmatch(r"[\d.]+", d):
                domains.append(d)
        for d in domains[:10]:
            self.progress(f"WHOIS + URLScan: {d.replace('.', '[.]')}")
            pe.domain_intel[d] = {"whois": self.whois(d), "urlscan": self.urlscan(d)}

        pe.warnings.extend(w for w in self.warnings if w not in pe.warnings)
        return pe
