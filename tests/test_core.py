"""Headless tests for the analysis engines (no GUI, no network)."""
from pathlib import Path

import mail_parser as mp
import report
from scorer import score

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample_phish.eml"


def test_defang():
    assert mp.defang("https://evil.com/a.php") == "hxxps[://]evil[.]com/a[.]php"
    assert "http://" not in mp.defang_text("go to http://bad.example.com now")


def test_sample_is_malicious():
    res = score(mp.parse_email(SAMPLE))
    assert res.total >= 61 and res.level == "malicious"


def test_sample_findings():
    pe = mp.parse_email(SAMPLE)
    assert pe.auth["spf"] == "fail" and pe.auth["dmarc"] == "fail"
    assert pe.origin_ip == "45.33.32.156" and len(pe.hops) == 2
    codes = {c for a in pe.attachments for c, _ in a.flags}
    assert {"DOUBLE_EXT", "DISGUISED_EXECUTABLE"} <= codes
    assert any(c == "HIDDEN_LINK" for u in pe.urls for c, _ in u.flags)


def test_benign_is_low(tmp_path):
    p = tmp_path / "ok.eml"
    p.write_text("From: Alice <alice@example.org>\nTo: bob@example.org\nSubject: Lunch?\n"
                 "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
                 "Receipt: https://www.paypal.com/ and https://amazon.in/\n")
    assert score(mp.parse_email(p)).level == "low"


def test_url_heuristics():
    def flags(url):
        u = mp.UrlInfo(url=url, defanged=mp.defang(url))
        mp.analyze_url(u)
        return {c for c, _ in u.flags}
    assert "TYPOSQUAT" in flags("https://paypa1.com/login")
    assert "BRAND_SUBDOMAIN" in flags("https://paypal.com.evil-host.top/x")
    assert "IP_URL" in flags("http://198.51.100.9/a")
    assert not flags("https://www.paypal.com/signin")
    cyr = "https://p\u0430ypal.com/"                      # Cyrillic 'а'
    host = "p\u0430ypal.com".encode("idna").decode()
    assert {"PUNYCODE", "HOMOGLYPH"} <= flags(f"https://{host}/")


def test_pasted_text_paths():
    raw = SAMPLE.read_text().replace("\n", "\r\n")        # CRLF as copied from webmail
    assert score(mp.parse_raw(raw)).level == "malicious"
    assert mp.parse_raw("just a body with urgent https://bit.ly/x").warnings
    assert mp.parse_raw("Subject: hi\nFrom: a@b.com\n\nhello").warnings


def test_reports_never_leak_live_urls():
    pe = mp.parse_email(SAMPLE)
    res = score(pe)
    html = report.to_html(pe, res)
    assert "http://" not in html and "https://" not in html
    assert "https://" not in pe.raw_text
    assert '"total"' in report.to_json(pe, res)
