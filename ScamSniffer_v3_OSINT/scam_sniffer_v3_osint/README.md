# SCAM SNIFFER v3.0 — OSINT EDITION
## Singapore Forum & Threat Intelligence Scanner

<img width="1405" height="888" alt="image" src="https://github.com/user-attachments/assets/cc41dfa0-74f9-47aa-973a-c79e81079b99" />


---

## Quick Start

1. Install **Python 3.10+** from [python.org](https://python.org) — check "Add to PATH"
2. Double-click **`RUN.bat`**
3. Click **OSINT SCAN**

Zero dependencies beyond Python standard library.

---

## OSINT Sources

| Source | What it does | Rate |
|---|---|---|
| **Reddit** | Searches r/singapore, r/scams, r/askSingapore, r/SGExams, r/singaporefi via public JSON API | ~1 req/1.2s |
| **HardwareZone** | Scrapes Singapore's largest forum (EDMW etc) via DuckDuckGo site: search | ~1 req/1s |
| **Google News** | Fetches Singapore-localized RSS news feed for each keyword | ~1 req/0.5s |
| **DuckDuckGo** | Supplementary web results via DDG Lite | ~1 req/1s |
| **Google Dorks** | Pre-built advanced search queries (forum posts, exposed data, phishing sites, Telegram groups) | ~1 req/1.5s |
| **Paste Sites** | Searches pastebin.com, rentry.co, ghostbin for Singapore data leaks | ~1 req/1.5s |
| **Telegram** | Finds public Telegram groups/channels mentioning Singapore scams | ~1 req/1.5s |
| **WHOIS/DNS** | DNS resolution, reverse DNS, SSL certificate analysis on suspicious domains found during scan | auto |

---

## Google Dork Categories

| Category | Example Dorks |
|---|---|
| Forum Discussions | `site:reddit.com singapore scam`, `site:hardwarezone.com.sg investment scam` |
| Exposed Data | `site:pastebin.com singapore phone`, `"singapore" filetype:csv email` |
| Phishing Sites | `intitle:"DBS" login -site:dbs.com.sg`, `intitle:"SingPass" -site:singpass.gov.sg` |
| Telegram & Social | `site:t.me singapore investment group`, `"t.me" singapore scam` |

---

## Features

- **7 OSINT sources** — all free, no API keys
- **30+ pre-built keywords** across 4 categories (Scam Reports, Propaganda/POFMA, Forum Chatter, Dark Patterns)
- **20+ Google dork queries** pre-configured for Singapore threat hunting
- **Domain Recon tab** — paste any suspicious domain for instant DNS/SSL/WHOIS analysis
- **Automatic WHOIS** on non-mainstream domains discovered during scan
- **Reddit engagement metrics** — upvotes and comment counts shown
- **Deduplication** — same URL won't appear twice even across multiple sources
- **Tabbed results** — Scan Results + Domain Recon in separate tabs
- **Live OSINT log** — see every request, response, and error in real-time
- **CSV export** — includes OSINT source column for filtering
- **Rate-limited** — built-in delays to avoid getting blocked

---

## CSV Export Columns

| Column | Description |
|---|---|
| title | Article/post/page title |
| source | Website, subreddit, or forum |
| url | Direct link |
| snippet | Summary or post excerpt |
| date | Publication date |
| threat_level | High / Medium / Low |
| keyword | Search keyword that found this |
| osint_source | Which OSINT source (Reddit, Google News, HWZ, etc) |
| metadata | Extra info (Reddit scores, etc) |
| scanned_at | Timestamp of scan |

---

## Domain Recon

Type any suspicious domain (e.g. `dbs-login-verify.com`) into the Domain Recon field and hit Scan:

- **DNS Resolution** — does it resolve? What IP?
- **Reverse DNS** — who owns that IP?
- **SSL Certificate** — who issued it? What's the CN? When does it expire?
- **Red Flag Analysis** — flags free SSL certs (common in phishing), missing SSL, dead domains

Also runs automatically on non-mainstream domains discovered during the main scan.

---

## Files

| File | Purpose |
|---|---|
| `scam_sniffer_osint.py` | Main application (~750 lines, single file) |
| `RUN.bat` | Windows launcher |
| `osint_config.json` | Auto-created settings file |
