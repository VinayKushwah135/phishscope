# 🎣 PhishScope

**Email phishing analyzer & threat-intelligence parser** — a local desktop app (PyQt5) that ingests raw
emails (`.eml`, `.msg`, or pasted source), extracts indicators of compromise, enriches them with threat-intel
APIs and produces an explainable 0–100 risk score and an analyst report.

![python](https://img.shields.io/badge/python-3.10%E2%80%933.12-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

## Features
| Area | What it does |
|---|---|
| **Ingestion** | Paste raw source, drag & drop, or browse `.eml` / `.msg` (Outlook) |
| **Headers** | From / To / Cc / Reply-To / Return-Path / Subject / Date / Message-ID, spoof checks (Return-Path & Reply-To mismatch, display-name deception), `Received` hop trace with delays, SPF / DKIM / DMARC verdicts |
| **URLs & content** | Plain, anchor and hidden links; anchor-text vs. real-target mismatch; auto-defanging; punycode / IDN / homoglyph and Levenshtein typosquat detection; shorteners, IP URLs, risky TLDs; social-engineering keyword scan |
| **Attachments** | In-memory only; MD5 / SHA-1 / SHA-256; magic-byte vs. extension spoofing; macro, executable, double-extension, RTLO, encrypted-archive detection; archive member listing |
| **Threat intel** | VirusTotal (URL / IP / file hash), AbuseIPDB, URLScan.io (passive search), WHOIS domain age (< 30 days flagged) |
| **Scoring** | Transparent rule matrix: 0–25 Clean · 26–60 Suspicious · 61–100 Highly Malicious / Phishing, with per-rule evidence |
| **Reports** | Export JSON, HTML or PDF (all URLs defanged) |

## Quick start
```bash
git clone https://github.com/<your-user>/phishscope.git
cd phishscope
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py                    # or: python main.py samples/sample_phish.eml
```
Platform notes
* **Linux:** `sudo apt install libmagic1`; if Qt complains about `xcb`: `sudo apt install libxcb-cursor0 libxcb-xinerama0`.
* **macOS:** `brew install libmagic`; on Apple Silicon use `pip install python-magic` if `python-magic-bin` fails.
* **Windows:** nothing extra (`python-magic-bin` bundles libmagic). Use Python 3.9–3.12.

## Usage
1. **Paste** the full message source (Gmail: ⋮ → *Show original*; Thunderbird: *View → Message Source*), **drop** a file, or **Browse** (Ctrl+O).
2. Press **Analyze** (Ctrl+Enter). Untick *Online threat-intel lookups* for a fully offline, static analysis.
3. Review *Overview*, *Headers & Hops*, *URLs & Domains*, *Attachments*, *Raw / MIME*. Double-click any table cell (or Ctrl+C on rows) to copy a defanged IOC.
4. Export JSON / HTML / PDF from the sidebar.

Try the bundled sample: `samples/sample_phish.eml` (harmless — the "executable" is a stub header) scores **100**.

## API keys (optional)
Missing keys never crash a scan — those lookups are skipped with a warning. Provide keys via the **API keys** dialog or,
preferably, environment variables (the dialog stores keys unencrypted in local Qt settings):
```bash
export PHISHSCOPE_VT_KEY=...  PHISHSCOPE_ABUSEIPDB_KEY=...  PHISHSCOPE_URLSCAN_KEY=...
```
VirusTotal's free tier is throttled to 4 requests/min (about 15 s per lookup, max 12 URLs per run).

## Project layout
| File | Role |
|---|---|
| `main.py` | Entry point |
| `gui.py` | PyQt5 UI, custom dark theme, QThread worker |
| `mail_parser.py` | Ingestion, headers/auth/hops, URL & keyword engines, attachment engine, defanging |
| `enrichment.py` | VirusTotal / AbuseIPDB / URLScan / WHOIS connectors with rate limiting |
| `scorer.py` | Rule table → score, verdict, breakdown (tune weights here) |
| `report.py` | JSON and Jinja2 HTML report (PDF is rendered from the HTML by Qt) |
| `tests/` | Headless pytest suite (`pip install -r requirements-dev.txt && pytest`) |

## Safety design
* Attachments exist only as in-memory bytes — hashed and sniffed, **never written to disk or executed**; archives are listed by name only.
* URLs are defanged (`hxxps[://]evil[.]tld`) in every table, log, raw view and report; HTML bodies are never rendered.
* Enrichment is lookup-only: nothing is submitted for scanning and no URL from the email is fetched from your machine.
* Still, treat real phishing samples as live malware: analyze them inside a VM and don't commit them to this repo (`.gitignore` excludes `real_samples/`).

## Limitations
Rule weights are heuristics — the score is for triage, not a verdict. Legitimate mailing lists can trip Return-Path /
Reply-To rules. The brand list used for typosquat checks lives in `mail_parser.BRANDS`. `.msg` support relies on
`extract-msg` and has had less testing than `.eml`.

## Contributing
Issues and PRs welcome. Run `pytest` before submitting; add a test for any new detection rule.

## Disclaimer & license
For defensive security and education. You are responsible for complying with the terms of the third-party APIs you use.
Released under the [MIT License](LICENSE).
