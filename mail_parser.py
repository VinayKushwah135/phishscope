"""
PhishScope - mail_parser.py
Ingestion layer + static analysis: headers / auth / hops, URLs & content, attachments.

SAFETY MODEL
  * Attachments exist only as in-memory bytes: hashed, sniffed, listed - never written
    to disk and never executed. Archives are inspected by member *name* only.
  * Every URL is defanged before it leaves this module for display or logging.
"""
from __future__ import annotations

import email
import hashlib
import io
import ipaddress
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import regex as re          # superset of stdlib re
except ImportError:             # pragma: no cover
    import re
import jellyfish
import tldextract
from bs4 import BeautifulSoup

try:
    import magic as _libmagic   # optional: extra human-readable file description
except Exception:               # pragma: no cover
    _libmagic = None

_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # offline snapshot
MAX_RAW = 400_000

# --------------------------------------------------------------------------- #
# Defanging
# --------------------------------------------------------------------------- #
URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)


def defang(url: str) -> str:
    """https://evil.com/a -> hxxps[://]evil[.]com/a (all dots defanged)."""
    u = re.sub(r"^http", "hxxp", url.strip(), flags=re.I)
    return u.replace("://", "[://]").replace(".", "[.]")


def defang_text(text: str) -> str:
    """Defang every URL inside free text (used for raw/MIME views)."""
    return URL_RE.sub(lambda m: defang(m.group(0)), text)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Hop:
    index: int
    from_host: str = ""
    ip: str = ""
    by_host: str = ""
    timestamp: str = ""
    delay_s: Optional[int] = None
    raw: str = ""


@dataclass
class UrlInfo:
    url: str                      # kept internally; UI/report use `defanged`
    defanged: str
    host: str = ""
    domain: str = ""
    source: str = "plain"         # plain | anchor | hidden | embedded
    anchor_text: str = ""
    flags: list = field(default_factory=list)   # [(CODE, detail)]
    intel: dict = field(default_factory=dict)


@dataclass
class AttachmentInfo:
    filename: str
    size: int
    declared_type: str
    detected_type: str
    magic_desc: str
    md5: str
    sha1: str
    sha256: str
    flags: list = field(default_factory=list)
    archive_members: list = field(default_factory=list)
    intel: dict = field(default_factory=dict)


@dataclass
class ParsedEmail:
    path: str
    headers: dict = field(default_factory=dict)
    hops: list = field(default_factory=list)
    origin_ip: str = ""
    auth: dict = field(default_factory=dict)
    auth_present: bool = False
    header_flags: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    keyword_hits: list = field(default_factory=list)   # [(category, phrase)]
    warnings: list = field(default_factory=list)
    ip_intel: dict = field(default_factory=dict)
    domain_intel: dict = field(default_factory=dict)
    raw_text: str = ""

    def to_dict(self):
        return asdict(self)


# --------------------------------------------------------------------------- #
# Brand / heuristic tables
# --------------------------------------------------------------------------- #
BRANDS = ["paypal", "microsoft", "office365", "apple", "amazon", "google", "netflix",
          "facebook", "linkedin", "docusign", "dropbox", "fedex", "chase", "wellsfargo",
          "bankofamerica", "coinbase", "instagram", "whatsapp", "adobe", "hdfcbank",
          "icicibank", "paytm", "outlook", "binance", "citibank", "hsbc"]
BRAND_ALLOW = {"microsoftonline", "office", "live", "icloud", "amazonaws", "gmail",
               "googleapis", "gstatic", "youtube", "googleusercontent"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
              "rebrand.ly", "shorturl.at", "tiny.cc", "buff.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq",
                   "icu", "rest", "support", "cyou", "sbs"}
CONFUSABLES = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
               "і": "i", "ѕ": "s", "ј": "j", "ο": "o", "α": "a", "ν": "v", "ɡ": "g"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})

KEYWORDS = {
    "urgency": [r"immediate action", r"act now", r"within 24 hours", r"\burgent(ly)?\b",
                r"expires? (today|soon)", r"final (notice|warning)", r"last warning"],
    "fear": [r"account (has been |is )?(suspended|locked|limited|compromised|disabled)",
             r"unauthori[sz]ed (login|access|activity|transaction)", r"security alert",
             r"legal action", r"unusual (sign-?in|activity)"],
    "financial": [r"wire transfer", r"bank transfer", r"gift ?cards?", r"payment (is )?overdue",
                  r"update (your )?(payment|billing)", r"\bbitcoin\b", r"change of bank",
                  r"invoice attached"],
    "credential": [r"verify your (account|identity|password|email)",
                   r"confirm your (password|credentials|identity)",
                   r"log ?in to (verify|restore|confirm)", r"click (here|below) to"],
    "reward": [r"you(?:'ve| have) won", r"claim your (prize|reward|refund)"],
}

# --------------------------------------------------------------------------- #
# Loading (.eml / .msg)
# --------------------------------------------------------------------------- #
def _msg_to_email(path: Path) -> EmailMessage:
    """Rebuild an RFC-822 message from an Outlook .msg (via extract-msg), in memory."""
    import extract_msg
    m = extract_msg.Message(str(path))
    try:
        em = EmailMessage()
        skip = {"content-type", "content-transfer-encoding", "mime-version", "content-disposition"}
        hdr = getattr(m, "header", None)
        if hdr:
            for k, v in hdr.items():
                if k.lower() in skip:
                    continue
                try:
                    em[k] = " ".join(str(v).split())
                except Exception:
                    pass
        else:
            for k, v in (("From", m.sender), ("To", m.to), ("Subject", m.subject), ("Date", str(m.date or ""))):
                try:
                    em[k] = v or ""
                except Exception:
                    pass
        em.set_content(m.body or " ")
        html = m.htmlBody
        if html:
            em.add_alternative(html.decode("utf-8", "replace") if isinstance(html, bytes) else html,
                               subtype="html")
        for att in m.attachments:
            data = getattr(att, "data", None)
            if isinstance(data, bytes):
                name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "unnamed"
                em.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
        return em
    finally:
        m.close()


def load_email(path):
    p = Path(path)
    if p.suffix.lower() == ".msg":
        msg = _msg_to_email(p)
        return msg, msg.as_string(policy=policy.default)
    raw = p.read_bytes()
    return email.message_from_bytes(raw, policy=policy.default), raw.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# Header & authentication engine
# --------------------------------------------------------------------------- #
def _reg(host: str) -> str:
    e = _TLD(host or "")
    return (e.registered_domain or host or "").lower()


def _hstr(msg, key) -> str:
    try:
        return " ".join(str(msg.get(key, "") or "").split())
    except Exception:
        return ""


_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
_IPV6 = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{3,}[0-9a-fA-F])\]")


def _ips(text: str):
    out = []
    for c in _IPV4.findall(text) + _IPV6.findall(text):
        try:
            out.append(str(ipaddress.ip_address(c)))
        except ValueError:
            pass
    return out


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_hops(msg):
    """Received headers, returned chronologically (origin first)."""
    raws = [" ".join(str(r).split()) for r in msg.get_all("Received", [])][::-1]
    hops, prev = [], None
    for i, raw in enumerate(raws, 1):
        frm = re.search(r"\bfrom\s+(\S+)", raw, re.I)
        by = re.search(r"\bby\s+(\S+)", raw, re.I)
        from_clause = re.split(r"\bby\b", raw, maxsplit=1, flags=re.I)[0]
        ips = _ips(from_clause)
        ip = next((x for x in ips if _is_public(x)), ips[0] if ips else "")
        ts, delay = "", None
        if ";" in raw:
            try:
                dt = parsedate_to_datetime(raw.rsplit(";", 1)[-1].strip())
                ts = dt.isoformat()
                if prev:
                    delay = int((dt - prev).total_seconds())
                prev = dt
            except Exception:
                ts = raw.rsplit(";", 1)[-1].strip()
        hops.append(Hop(i, frm.group(1) if frm else "", ip, by.group(1) if by else "", ts, delay, raw))
    return hops


def parse_auth(msg):
    res, found = {"spf": "none", "dkim": "none", "dmarc": "none"}, set()
    ar = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    for mech, val in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", ar, re.I):
        m = mech.lower()
        if m not in found:
            res[m], _ = val.lower(), found.add(m)
    if "spf" not in found:
        mm = re.match(r"\s*([a-z]+)", _hstr(msg, "Received-SPF"), re.I)
        if mm:
            res["spf"] = mm.group(1).lower()
            found.add("spf")
    return res, bool(found)


def analyze_headers(msg, pe: ParsedEmail):
    keys = ["From", "To", "Cc", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID"]
    pe.headers = {k: _hstr(msg, k) for k in keys}
    name, addr = parseaddr(pe.headers["From"])
    from_dom = addr.split("@")[-1].lower() if "@" in addr else ""
    from_reg = _reg(from_dom)
    fl = pe.header_flags

    if not addr:
        fl.append(("NO_FROM", "Missing or unparsable From address"))
    _, rp = parseaddr(pe.headers["Return-Path"])
    if rp and "@" in rp and _reg(rp.split("@")[-1]) != from_reg:
        fl.append(("RETURN_PATH_MISMATCH", f"Return-Path domain {defang(rp.split('@')[-1])} != From domain {defang(from_dom)}"))
    _, rt = parseaddr(pe.headers["Reply-To"])
    if rt and "@" in rt and _reg(rt.split("@")[-1]) != from_reg:
        fl.append(("REPLY_TO_MISMATCH", f"Reply-To domain {defang(rt.split('@')[-1])} differs from From domain"))

    lname = name.lower()
    shown = [d for d in re.findall(r"[\w.-]+\.[a-z]{2,}", lname) if _TLD(d).suffix]
    if "@" in name or any(_reg(d) != from_reg for d in shown):
        fl.append(("DISPLAY_NAME_SPOOF", f"Display name '{defang(name)}' embeds an address/domain that differs from real sender"))
    else:
        label = _TLD(from_dom).domain
        for b in BRANDS:
            if re.search(rf"\b{b}\b", lname) and b not in label:
                fl.append(("DISPLAY_NAME_BRAND", f"Display name claims '{b}' but sender domain is {defang(from_dom)}"))
                break

    pe.hops = parse_hops(msg)
    pe.origin_ip = next((h.ip for h in pe.hops if h.ip and _is_public(h.ip)), "")
    pe.auth, pe.auth_present = parse_auth(msg)


# --------------------------------------------------------------------------- #
# URL & content engine
# --------------------------------------------------------------------------- #
_HIDDEN = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?![.\d])|max-height\s*:\s*0", re.I)
_PRIO = {"plain": 0, "embedded": 1, "anchor": 2, "hidden": 3}


def _body_parts(msg):
    text, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ct = part.get_content_type()
        if ct not in ("text/plain", "text/html"):
            continue
        try:
            s = part.get_content()
        except Exception:
            s = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        (text if ct == "text/plain" else html).append(s)
    return "\n".join(text), "\n".join(html)


def _norm_label(label: str) -> str:
    label = "".join(CONFUSABLES.get(c, c) for c in label)
    return label.translate(LEET).replace("rn", "m").replace("vv", "w")


def analyze_url(u: UrlInfo):
    try:
        p = urlparse(u.url)
        host = (p.hostname or "").lower()
    except ValueError:
        u.flags.append(("MALFORMED", "Unparsable URL"))
        return
    u.host = host
    if "@" in (p.netloc or ""):
        u.flags.append(("URL_USERINFO", "'user@host' trick in URL"))
    try:
        ipaddress.ip_address(host)
        u.flags.append(("IP_URL", "Link points at a raw IP address"))
        u.domain = host
        return
    except ValueError:
        pass

    ext = _TLD(host)
    u.domain = ext.registered_domain or host
    label = ext.domain.lower()
    decoded = host
    if "xn--" in host:
        try:
            decoded = host.encode("ascii").decode("idna")
        except Exception:
            pass
        u.flags.append(("PUNYCODE", f"Punycode host decodes to '{decoded}'"))
    elif not host.isascii():
        u.flags.append(("PUNYCODE", "Non-ASCII (IDN) host"))
    dlabel = _TLD(decoded).domain.lower() if decoded != host else label

    if u.domain in SHORTENERS:
        u.flags.append(("SHORTENER", "URL shortener hides real destination"))
    if ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        u.flags.append(("SUSPICIOUS_TLD", f"High-abuse TLD .{ext.suffix}"))

    if label in BRAND_ALLOW:
        return
    for b in BRANDS:
        mapped = "".join(CONFUSABLES.get(c, c) for c in dlabel)
        if mapped == b and label != b:                  # e.g. Cyrillic 'а' in "pаypal"
            u.flags.append(("HOMOGLYPH", f"Unicode look-alike of '{b}'"))
            break
        if label == b:
            continue                                    # legitimate brand domain (any ccTLD)
        norm = _norm_label(dlabel)
        dist = jellyfish.levenshtein_distance(dlabel, b)
        if len(b) >= 5 and (norm == b or 0 < dist <= 2):
            u.flags.append(("TYPOSQUAT", f"'{dlabel}' ~ '{b}' (Levenshtein {dist})"))
            break
        if b in ext.subdomain.lower().split("."):
            u.flags.append(("BRAND_SUBDOMAIN", f"Brand '{b}' used as subdomain of {defang(u.domain)}"))
            break
        parts = [_norm_label(x) for x in re.split(r"[-_]", dlabel)]
        if b in parts and len(dlabel) > len(b):
            u.flags.append(("BRAND_LOOKALIKE", f"Domain label embeds brand '{b}'"))
            break


def extract_urls(text: str, html_src: str):
    found: dict[str, UrlInfo] = {}

    def add(url, source, anchor=""):
        url = url.strip().rstrip(".,;:!?")
        if not re.match(r"https?://", url, re.I):
            return None
        cur = found.get(url)
        if cur is None:
            found[url] = cur = UrlInfo(url=url, defanged=defang(url), source=source, anchor_text=anchor)
        elif _PRIO[source] > _PRIO[cur.source]:
            cur.source = source
            cur.anchor_text = anchor or cur.anchor_text
        return cur

    for m in URL_RE.findall(text):
        add(m, "plain")
    if html_src:
        soup = BeautifulSoup(html_src, "html.parser")
        for m in URL_RE.findall(soup.get_text(" ")):
            add(m, "plain")
        for a in soup.find_all("a", href=True):
            hidden = any(_HIDDEN.search(t.get("style", "") or "") for t in [a, *a.parents] if hasattr(t, "get"))
            ui = add(a["href"], "hidden" if hidden else "anchor", a.get_text(" ", strip=True))
            if ui is None:
                continue
            if hidden:
                ui.flags.append(("HIDDEN_LINK", "Link inside invisible element"))
            txt = a.get_text(" ", strip=True)
            if re.fullmatch(r"(https?://)?[\w.-]+\.[a-z]{2,}(/\S*)?", txt, re.I):
                shown = _reg(urlparse(txt if "//" in txt else "//" + txt).hostname or "")
                real = _reg(urlparse(a["href"]).hostname or "")
                if shown and real and shown != real:
                    ui.flags.append(("ANCHOR_MISMATCH", f"Text shows {defang(txt)} but links to {defang(a['href'])}"))
        for tag in soup.find_all(["img", "iframe", "form"]):
            src = tag.get("src") or tag.get("action")
            if src:
                add(src, "embedded")
    for ui in found.values():
        analyze_url(ui)
    return list(found.values())


def scan_keywords(text: str):
    low, hits = text.lower(), []
    for cat, pats in KEYWORDS.items():
        for p in pats:
            m = re.search(p, low)
            if m:
                hits.append((cat, m.group(0)))
    return hits


# --------------------------------------------------------------------------- #
# Attachment & payload engine (memory only)
# --------------------------------------------------------------------------- #
SIGS = [(b"MZ", "exe", "Windows executable (PE)"), (b"%PDF", "pdf", "PDF document"),
        (b"PK\x03\x04", "zip", "ZIP container"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "OLE2 (legacy Office/MSI)"),
        (b"Rar!", "rar", "RAR archive"), (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
        (b"\x89PNG", "png", "PNG image"), (b"\xff\xd8\xff", "jpg", "JPEG image"), (b"GIF8", "gif", "GIF image"),
        (b"\x7fELF", "elf", "ELF executable"), (b"{\\rtf", "rtf", "RTF document"), (b"\x1f\x8b", "gz", "GZIP archive"),
        (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk", "Windows shortcut (LNK)")]
EXT_OK = {"exe": {"exe"}, "dll": {"exe"}, "scr": {"exe"}, "pdf": {"pdf"}, "docx": {"docx"}, "docm": {"docx"},
          "xlsx": {"xlsx"}, "xlsm": {"xlsx"}, "pptx": {"pptx"}, "pptm": {"pptx"}, "doc": {"ole", "rtf"},
          "xls": {"ole"}, "ppt": {"ole"}, "msi": {"ole"}, "zip": {"zip", "jar"}, "rar": {"rar"}, "7z": {"7z"},
          "png": {"png"}, "jpg": {"jpg"}, "jpeg": {"jpg"}, "gif": {"gif"}, "rtf": {"rtf"}, "iso": {"iso"},
          "lnk": {"lnk"}, "txt": {"text"}, "csv": {"text"}, "html": {"html"}, "htm": {"html"},
          "js": {"text", "script"}, "vbs": {"text", "script"}, "ps1": {"text", "script"},
          "bat": {"text", "script"}, "cmd": {"text", "script"}}
EXEC_EXT = {"exe", "scr", "vbs", "vbe", "js", "jse", "wsf", "bat", "cmd", "ps1", "msi", "jar", "lnk",
            "hta", "dll", "com", "pif"}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlam", "dotm"}
ARCHIVE_EXT = {"zip", "rar", "7z", "iso", "img", "gz"}


def sniff(data: bytes):
    """Return (kind, description, zip_members) from magic bytes - never trusts the filename."""
    head = data[:16]
    if data[0x8001:0x8006] == b"CD001":
        return "iso", "ISO 9660 disk image", []
    for sig, kind, desc in SIGS:
        if head.startswith(sig):
            if kind == "zip":
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        names = z.namelist()[:60]
                    if "[Content_Types].xml" in names or any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
                        k = "docx" if any(n.startswith("word/") for n in names) else \
                            "xlsx" if any(n.startswith("xl/") for n in names) else "pptx"
                        return k, f"OOXML ({k})", names
                    if "META-INF/MANIFEST.MF" in names:
                        return "jar", "Java archive (JAR)", names
                    return "zip", desc, names
                except Exception:
                    return "zip", desc + " (unreadable)", []
            return kind, desc, []
    try:
        s = data[:600].decode("utf-8")
        low = s.lstrip().lower()
        if low.startswith(("<!doctype html", "<html", "<script")):
            return "html", "HTML document", []
        if s.startswith("#!") or low.startswith(("powershell", "@echo", "wscript", "var ", "function")):
            return "script", "Script text", []
        return "text", "Plain text", []
    except UnicodeDecodeError:
        return "unknown", "Unknown binary", []


def analyze_attachments(msg):
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        if not (fname or part.get_content_disposition() == "attachment"):
            continue
        try:
            data = part.get_payload(decode=True)
            if data is None and part.get_content_type() == "message/rfc822":
                data = part.get_payload(0).as_bytes()
            data = data or b""
        except Exception:
            data = b""
        fname = fname or "unnamed"
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        kind, desc, members = sniff(data)
        a = AttachmentInfo(
            filename=defang(fname) if URL_RE.search(fname) else fname, size=len(data),
            declared_type=part.get_content_type(), detected_type=desc,
            magic_desc=(_libmagic.from_buffer(data[:4096]) if _libmagic and data else ""),
            md5=hashlib.md5(data).hexdigest(), sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(), archive_members=members)
        f = a.flags
        if ext in EXEC_EXT:
            f.append(("HIGH_RISK_EXT", f"Executable/script extension .{ext}"))
        if ext in MACRO_EXT:
            f.append(("MACRO_ENABLED", f"Macro-enabled Office extension .{ext}"))
        if ext in ARCHIVE_EXT:
            f.append(("ARCHIVE", f"Archive/disk-image .{ext}"))
        if any("vbaProject.bin" in n for n in members):
            f.append(("MACRO_ENABLED", "OOXML package contains vbaProject.bin (VBA macros)"))
        if kind in ("exe", "elf") and ext not in ("exe", "dll", "scr", "com", "sys"):
            f.append(("DISGUISED_EXECUTABLE", f"Executable content saved as .{ext or '(none)'}"))
        elif ext in EXT_OK and kind not in EXT_OK[ext] and kind != "unknown":
            f.append(("MAGIC_MISMATCH", f"Extension .{ext} but content is {desc}"))
        if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\s*\.(exe|scr|js|vbs|bat|cmd|lnk|hta|iso|zip)$", fname, re.I):
            f.append(("DOUBLE_EXT", "Double extension hides real file type"))
        if "\u202e" in fname:
            f.append(("RTLO_SPOOF", "Right-to-left override character in filename"))
        if members and any(m.rsplit(".", 1)[-1].lower() in EXEC_EXT for m in members if "." in m):
            f.append(("ARCHIVE_EXECUTABLE", "Archive contains executable/script members"))
        if kind == "zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    if any(i.flag_bits & 1 for i in z.infolist()[:60]):
                        f.append(("ENCRYPTED_ARCHIVE", "Password-protected archive (evades scanning)"))
            except Exception:
                pass
        out.append(a)
    return out


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def _analyze(msg, raw: str, label: str) -> ParsedEmail:
    pe = ParsedEmail(path=label)
    analyze_headers(msg, pe)
    text, html_src = _body_parts(msg)
    pe.urls = extract_urls(text, html_src)
    plain_from_html = BeautifulSoup(html_src, "html.parser").get_text(" ") if html_src else ""
    pe.keyword_hits = scan_keywords(f"{pe.headers.get('Subject', '')} {text} {plain_from_html}")
    pe.attachments = analyze_attachments(msg)
    note = "\n\n[... truncated for display ...]" if len(raw) > MAX_RAW else ""
    pe.raw_text = defang_text(raw[:MAX_RAW]) + note      # defanged before it can reach the UI
    return pe


def parse_email(path) -> ParsedEmail:
    """Analyze an .eml / .msg file on disk (read-only)."""
    msg, raw = load_email(path)
    return _analyze(msg, raw, str(path))


def parse_raw(raw, label: str = "Pasted email") -> ParsedEmail:
    """Analyze raw RFC-822 source pasted by the analyst (full message or headers only)."""
    b = raw.encode("utf-8", "replace") if isinstance(raw, str) else raw
    b = b.lstrip(b"\r\n \t\xef\xbb\xbf")
    warn = None
    if re.match(rb"From \S+ ", b):                      # mbox 'From ' separator line
        b = b.split(b"\n", 1)[-1]
    if not re.match(rb"[!-9;-~]+:", b):                # first line is not a header
        b = b"\n" + b
        warn = "Pasted text does not start with email headers - analyzed as body only (no header/auth checks)."
    msg = email.message_from_bytes(b, policy=policy.default)
    pe = _analyze(msg, b.decode("utf-8", "replace"), label)
    if warn:
        pe.warnings.append(warn)
    elif not msg.get_all("Received") and not pe.auth_present:
        pe.warnings.append("No Received/Authentication-Results headers found - paste the FULL original source for hop and SPF/DKIM/DMARC analysis.")
    return pe
