# SCAM SNIFFER v3.0 OSINT — Developer Guide

> How to read, modify, and extend the codebase.
> Single file: `scam_sniffer_osint.py` (~1,530 lines)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [File Structure & Code Map](#2-file-structure--code-map)
3. [How a Scan Works (End to End)](#3-how-a-scan-works-end-to-end)
4. [Adding a New OSINT Source](#4-adding-a-new-osint-source)
5. [Adding / Removing Keywords](#5-adding--removing-keywords)
6. [Adding / Removing Google Dorks](#6-adding--removing-google-dorks)
7. [Modifying Threat Classification](#7-modifying-threat-classification)
8. [Modifying the Search Engine Stack](#8-modifying-the-search-engine-stack)
9. [Adding Subreddits](#9-adding-subreddits)
10. [Changing the UI Theme](#10-changing-the-ui-theme)
11. [Changing Rate Limits / Delays](#11-changing-rate-limits--delays)
12. [Modifying CSV Export Columns](#12-modifying-csv-export-columns)
13. [Adding a WHOIS Domain to the Mainstream Exclusion List](#13-adding-a-domain-to-the-whois-exclusion-list)
14. [Troubleshooting Common Issues](#14-troubleshooting-common-issues)

---

## 1. Architecture Overview

```
scam_sniffer_osint.py
│
├── DATA LAYER (lines 49–155)
│   ├── KEYWORD_PRESETS      — dict of category → keyword list
│   ├── GOOGLE_DORKS         — dict of dork category → query list
│   ├── SG_SUBREDDITS        — list of subreddit names
│   └── OSINT_SOURCES        — list of (label, key, default_on) tuples
│
├── CONFIG (lines 158–200)
│   ├── C = {}               — color theme dictionary
│   ├── load_config()        — reads osint_config.json
│   └── save_config()        — writes osint_config.json
│
├── UTILITIES (lines 203–275)
│   ├── strip_html()         — removes HTML tags from text
│   ├── extract_domain()     — extracts domain from URL
│   ├── safe_request()       — HTTP GET with UA rotation, SSL bypass
│   └── classify_threat()    — rule-based High/Medium/Low classification
│
├── SCANNER FUNCTIONS (lines 277–745)
│   ├── scan_reddit()            — Reddit RSS + web search fallback
│   ├── scan_reddit_subreddit()  — subreddit-specific scan
│   ├── scan_google_news()       — Google News RSS (SG localized)
│   ├── scan_duckduckgo_lite()   — multi-engine web search wrapper
│   ├── _web_search_multi()      — DDG HTML → Bing → DDG Lite
│   ├── scan_whois_dns()         — DNS/SSL certificate recon
│   ├── scan_hwz_forum()         — HardwareZone via web search
│   ├── scan_paste_sites()       — paste site search
│   ├── scan_telegram_mentions() — Telegram group/channel search
│   ├── scan_google_dorks()      — Google dork execution
│   ├── scan_facebook()          — Facebook public post search
│   └── scan_instagram()         — Instagram public post search
│
├── GUI APPLICATION (lines 748–1515)
│   └── class OsintScamSniffer
│       ├── __init__()           — state, config, theme, UI build
│       ├── _apply_theme()       — ttk dark theme styles
│       ├── _build_ui()          — left panel + right panel + log
│       ├── _scan_thread()       — main scan orchestration (background thread)
│       ├── _start_scan()        — validates, resets, launches thread
│       ├── _recon_domain()      — manual domain recon from UI
│       ├── _export()            — CSV export with file dialog
│       └── log() / log_safe()   — thread-safe logging to console
│
└── ENTRY POINT (lines 1518–1530)
    └── main()                   — creates Tk root, sets DPI, runs app
```

---

## 2. File Structure & Code Map

| Line Range | Section | What It Does |
|---|---|---|
| 1–46 | Module docstring + imports | Standard library imports, optional `anthropic` import |
| 49–155 | **Data declarations** | All keyword lists, dork queries, subreddits, source definitions |
| 158–200 | **Config + theme** | Color dict `C`, JSON config load/save |
| 203–275 | **Utilities** | HTML stripping, domain extraction, HTTP requests, threat classification |
| 277–415 | **Reddit scanners** | RSS parsing, web search fallback, Atom XML parsing |
| 417–460 | **Google News scanner** | RSS feed parsing with SG localization |
| 462–645 | **Search engine stack** | Multi-engine web search with circuit breaker |
| 648–745 | **Specialized scanners** | WHOIS/DNS, HWZ, paste sites, Telegram, dorks, Facebook, Instagram |
| 748–1515 | **GUI application** | Full tkinter application class |
| 1518–1530 | **Entry point** | `main()` function |

---

## 3. How a Scan Works (End to End)

When the user clicks **OSINT SCAN**, here is the execution flow:

```
User clicks "OSINT SCAN"
        │
        ▼
_start_scan()
  ├── Validates: at least 1 source + 1 keyword enabled
  ├── Resets: results list, abort flag, treeview
  ├── Updates UI: disables buttons, shows progress bar
  └── Launches: threading.Thread(target=_scan_thread)
        │
        ▼
_scan_thread()  (runs in background)
  ├── Collects active keywords via _get_keywords()
  ├── Collects active dorks via _get_active_dorks()
  ├── Checks which OSINT sources are enabled
  ├── Resets circuit breakers for search engines
  │
  ├── Phase 1: REDDIT        (if enabled)
  │   ├── For each keyword → scan_reddit()
  │   └── For each subreddit × ["scam","fraud"] → scan_reddit_subreddit()
  │
  ├── Phase 2: GOOGLE NEWS   (if enabled)
  │   └── For each keyword → scan_google_news()
  │
  ├── [Reset circuit breakers]
  │
  ├── Phase 3: HARDWAREZONE  (if enabled)
  │   └── For each keyword → scan_hwz_forum()
  │
  ├── Phase 4: WEB SEARCH    (if enabled)
  │   └── For each keyword → scan_duckduckgo_lite() → _web_search_multi()
  │
  ├── Phase 5: FACEBOOK      (if enabled)
  │   └── For each keyword → scan_facebook()
  │
  ├── Phase 6: INSTAGRAM     (if enabled)
  │   └── For each keyword → scan_instagram()
  │
  ├── [Reset circuit breakers]
  │
  ├── Phase 7: GOOGLE DORKS  (individually toggled)
  │   └── For each active dork query → scan_google_dorks()
  │
  ├── Phase 8: PASTE SITES   (if enabled, uses hardcoded terms)
  │   └── For each term → scan_paste_sites()
  │
  ├── Phase 9: TELEGRAM      (if enabled, uses hardcoded terms)
  │   └── For each term → scan_telegram_mentions()
  │
  └── Phase 10: WHOIS/DNS    (if enabled, auto-discovers domains)
      └── For each non-mainstream domain found → scan_whois_dns()
```

**Result flow:** Each scanner returns a list of dicts. The `add()` helper deduplicates by URL, appends to `self.results`, and calls `_add_tree()` on the main thread to update the UI.

**Every result dict has this shape:**

```python
{
    "title":        "Article or post title",
    "source":       "straitstimes.com" or "r/singapore",
    "url":          "https://...",
    "snippet":      "Summary text...",
    "date":         "2026-01-15" or "Unknown",
    "threat_level": "High" | "Medium" | "Low",
    "keyword":      "Singapore scam alert",
    "osint_source": "Google News" | "Reddit" | "HardwareZone" | etc.,
    "metadata":     "" (extra info, e.g. Reddit scores),
    "scanned_at":   "2026-06-06 16:30:00",
}
```

---

## 4. Adding a New OSINT Source

This is the most common modification. Follow these 3 steps:

### Step 1: Register the source (~line 145)

Open `OSINT_SOURCES` and add a tuple:

```python
OSINT_SOURCES = [
    ("Reddit (SG subs)", "reddit", True),
    # ... existing sources ...
    ("My New Source", "my_source", False),  # ← ADD THIS
    #   ↑ UI label      ↑ key       ↑ default on/off
]
```

The **key** (second value) is used throughout the code to reference this source. Keep it short, lowercase, no spaces.

### Step 2: Write the scanner function (~line 735)

Add your scanner function after the existing ones. It **must** return a list of result dicts:

```python
def scan_my_source(keyword, log_fn=None):
    """Search My Source for scam mentions."""
    # Log what you're doing (shows in the OSINT LOG panel)
    if log_fn: log_fn(f"  [MYSOURCE] Searching: {keyword}")

    results = []

    try:
        # Option A: Use the multi-engine web search
        query = f'site:example.com {keyword}'
        results = _web_search_multi(query, log_fn=log_fn)

        # Option B: Fetch a specific API/RSS/page directly
        # url = f"https://api.example.com/search?q={urllib.parse.quote(keyword)}"
        # data = safe_request(url)
        # ... parse data ...

        # Tag results with your source name
        for r in results:
            r["osint_source"] = "My Source"

        if log_fn and results:
            log_fn(f"  [MYSOURCE] ✓ {len(results)} results")

    except Exception as e:
        if log_fn: log_fn(f"  [MYSOURCE] ✗ Error: {e}", "error")

    return results
```

**Key rules for scanner functions:**

- First parameter is always `keyword` (string)
- Last parameter is always `log_fn=None` (callable or None)
- Must return a `list` of result dicts (empty list if nothing found)
- Each result dict must have all the keys shown in Section 3
- Use `safe_request(url)` for HTTP — it handles SSL, UA rotation, timeouts
- Use `_web_search_multi(query, log_fn)` for web searches — it handles engine failover
- Use `classify_threat(text)` to auto-classify threat level
- Tag `r["osint_source"]` so the CSV export shows where results came from

### Step 3: Wire it into the scan thread (~line 1345)

Find `_scan_thread()` and add a new phase block. Insert it in the order you want it to run:

```python
        # ── N. My New Source ──
        if sources.get("my_source") and not self.abort_flag:
            self.log_safe("══ MY SOURCE SCAN ══", "purple")
            for kw in keywords:
                if self.abort_flag: break
                progress(f"MySource: {kw}")
                add(scan_my_source(kw, log_fn=self.log_safe))
                time.sleep(3)  # delay between requests
```

**Also update `_count_tasks()`** so the progress bar is accurate:

```python
def _count_tasks(self):
    # ... existing code ...
    if sources.get("my_source"): count += len(kws)  # ← ADD THIS
    return count
```

That's it. The source will appear as a checkbox in the left panel automatically.

---

## 5. Adding / Removing Keywords

### Add a keyword to an existing category (~line 53)

Find `KEYWORD_PRESETS` and add to the relevant list:

```python
KEYWORD_PRESETS = {
    "Scam Reports": [
        "Singapore scam alert",
        "Singapore phishing scam",
        # ... existing ...
        "Singapore QR code scam",  # ← ADD HERE
    ],
```

The keyword will appear in the expandable section under that category.

### Add a new keyword category

Add a new key to the dict:

```python
KEYWORD_PRESETS = {
    # ... existing categories ...
    "Crypto & DeFi": [
        "Singapore crypto rug pull",
        "Singapore DeFi scam",
        "Singapore NFT fraud",
        "Singapore Bitcoin scam",
    ],
}
```

The UI auto-generates the expandable section — no UI code changes needed.

### Remove a keyword

Delete the line from the list. Remove an entire category by deleting the key.

---

## 6. Adding / Removing Google Dorks

### Add a dork query to an existing category (~line 96)

```python
GOOGLE_DORKS = {
    "Forum Discussions": [
        'site:reddit.com singapore scam',
        # ... existing ...
        'site:quora.com singapore scam',  # ← ADD HERE
    ],
```

### Add a new dork category

```python
GOOGLE_DORKS = {
    # ... existing ...
    "Government Advisories": [
        'site:police.gov.sg scam advisory',
        'site:csa.gov.sg cyber alert',
        'site:mha.gov.sg scam warning',
    ],
}
```

### Remove a dork

Delete the line. Remove an entire category by deleting the key.

---

## 7. Modifying Threat Classification

The threat classifier is at **line 258**, function `classify_threat(text)`.

### How it works

```python
def classify_threat(text):
    t = text.lower()

    # Words that signal HIGH threat (active harm, law enforcement, data exposure)
    high = ["victim", "lost", "million", "arrested", "police report", ...]

    # Words that signal MEDIUM threat (general scam/fraud mentions)
    med = ["scam", "phishing", "fake", "fraud", "suspicious", ...]

    h = sum(1 for s in high if s.lower() in t)  # count high-signal matches
    m = sum(1 for s in med if s.lower() in t)    # count medium-signal matches

    if h >= 2: return "High"          # 2+ high signals = High
    elif h >= 1 or m >= 2: return "Medium"  # 1 high OR 2+ medium = Medium
    return "Low"                       # everything else = Low
```

### To add new threat signal words

Add to the `high` or `med` list:

```python
high = ["victim", "lost", "million", ..., "ransomware", "extortion"]  # ← add here
med = ["scam", "phishing", ..., "impersonation", "catfish"]           # ← add here
```

### To change the classification thresholds

Modify the if/elif conditions:

```python
# More aggressive (flags more as High)
if h >= 1: return "High"
elif m >= 1: return "Medium"

# More conservative (flags less as High)
if h >= 3: return "High"
elif h >= 1 or m >= 3: return "Medium"
```

### To add a new threat level (e.g. "Critical")

1. Add the logic in `classify_threat()`:
   ```python
   if h >= 4: return "Critical"
   elif h >= 2: return "High"
   ```

2. Add the color in `_build_ui()` tree tags (~line 982):
   ```python
   self.tree.tag_configure("critical", foreground="#ff0000")
   ```

3. Update `_update_summary()` to count it.

---

## 8. Modifying the Search Engine Stack

The multi-engine search system is at **line 462**.

### Engine order

```python
def _web_search_multi(query, log_fn=None):
    engines = [
        ("ddg_html", _search_ddg_html),    # Try first
        ("bing", _search_bing),             # Fallback 1
        ("ddg_lite", _search_ddg_lite_raw), # Fallback 2
    ]
```

**To change the order**, rearrange the list. For example, to try Bing first:

```python
    engines = [
        ("bing", _search_bing),
        ("ddg_html", _search_ddg_html),
        ("ddg_lite", _search_ddg_lite_raw),
    ]
```

### Circuit breaker

After 3 consecutive failures, an engine is skipped for the rest of that scan phase:

```python
_ENGINE_MAX_FAILS = 3  # Change this to adjust tolerance
```

Circuit breakers reset between major scan phases (Reddit → News → Web search, etc.).

### Adding a new search engine

1. Write a search function following this pattern:

```python
def _search_my_engine(query, log_fn=None):
    """My custom search engine."""
    encoded = urllib.parse.quote(query)
    url = f"https://search.example.com/?q={encoded}"

    if log_fn: log_fn(f"  [MYENGINE] {query[:55]}...")

    html = safe_request(url, timeout=20)
    results = []

    # Parse the HTML to extract results
    # Each result needs: title, source, url, snippet, date, threat_level,
    #                     keyword, osint_source, metadata, scanned_at
    # ...

    if len(results) == 0:
        raise Exception("No results parsed from MyEngine")  # triggers fallback
    return results
```

2. Add to the engines list:

```python
    engines = [
        ("ddg_html", _search_ddg_html),
        ("my_engine", _search_my_engine),  # ← ADD
        ("bing", _search_bing),
        ("ddg_lite", _search_ddg_lite_raw),
    ]
```

3. Register in the circuit breaker dict (line 466):

```python
_engine_failures = {"ddg_html": 0, "bing": 0, "ddg_lite": 0, "my_engine": 0}
```

---

## 9. Adding Subreddits

Find `SG_SUBREDDITS` at **line 138**:

```python
SG_SUBREDDITS = [
    "singapore", "SGExams", "askSingapore",
    "singaporefi", "scams", "Scams",
    "personalfinance",  # ← ADD NEW ONES HERE
]
```

Each subreddit is searched for `"scam"` and `"fraud"` automatically. To change the search terms, edit the scan thread (~line 1287):

```python
for term in ["scam", "fraud", "phishing"]:  # ← add terms here
```

---

## 10. Changing the UI Theme

All colors are in the `C` dict at **line 162**:

```python
C = {
    "bg":       "#080b10",   # main background
    "bg2":      "#0e1219",   # secondary background (input fields, table)
    "bg3":      "#151b25",   # tertiary background (buttons, headers)
    "border":   "#1c2333",   # border color
    "brd_hi":   "#283044",   # highlighted border
    "fg":       "#c0c8d8",   # main text color
    "dim":      "#4a5568",   # dimmed text
    "accent":   "#00ffc8",   # primary accent (not used much in v3)
    "acc2":     "#00aa88",   # secondary accent
    "red":      "#ff4455",   # High threat / errors
    "orange":   "#ff9f43",   # Medium threat / warnings
    "green":    "#00d68f",   # Low threat / success
    "blue":     "#4da6ff",   # export button / links
    "purple":   "#b680ff",   # scan phase headers in log
    "yellow":   "#ffd93d",   # unused (available)
    "cyan":     "#22d3ee",   # title, accents, selected items
}
```

**To make a light theme**, swap the background/foreground values:

```python
C = {
    "bg":    "#ffffff",
    "bg2":   "#f8fafc",
    "bg3":   "#e2e8f0",
    "fg":    "#1e293b",
    "dim":   "#94a3b8",
    # ... etc
}
```

**To change fonts**, find `font=("Consolas", ...)` in `_apply_theme()` (~line 780) and replace `"Consolas"` with your preferred monospace font.

---

## 11. Changing Rate Limits / Delays

All delays are in `_scan_thread()`. Find the `time.sleep()` calls:

```
Phase        | Delay  | Why
-------------|--------|----------------------------------
Reddit       | 2s     | Reddit rate limits aggressively
Google News  | 1s     | RSS feeds are lenient
HardwareZone | 3s     | Uses web search (DDG/Bing)
Web Search   | 3s     | DDG/Bing rate limits
Facebook     | 3s     | Uses web search
Instagram    | 3s     | Uses web search
Google Dorks | 4s     | Advanced queries look suspicious
Paste Sites  | 4s     | Sensitive queries
Telegram     | 4s     | Sensitive queries
```

**To speed up (risk getting blocked):**
```python
time.sleep(1)  # faster but may trigger rate limits
```

**To slow down (more reliable):**
```python
time.sleep(5)  # slower but almost never blocked
```

**HTTP request timeout** is in `safe_request()` (~line 241):
```python
def safe_request(url, timeout=20):  # ← change default timeout here
```

---

## 12. Modifying CSV Export Columns

The CSV export is in `_export()` (~line 1490). The columns are defined by `fieldnames`:

```python
w = csv.DictWriter(f, fieldnames=[
    "title", "source", "url", "snippet", "date",
    "threat_level", "keyword", "osint_source", "metadata", "scanned_at"
])
```

**To add a column:**

1. Add the field name to `fieldnames`:
   ```python
   fieldnames=[..., "my_field"]
   ```

2. Make sure every scanner function includes the field in its result dict:
   ```python
   results.append({
       ...,
       "my_field": "some value",
   })
   ```

**To remove a column**, delete it from `fieldnames`. The data will still exist in memory but won't be exported.

**To rename a column header**, use `csv.writer` instead and write headers manually.

---

## 13. Adding a Domain to the WHOIS Exclusion List

When WHOIS/DNS Recon is enabled, it auto-scans non-mainstream domains found during the scan. Mainstream domains are skipped to avoid wasting time on Reddit, Google, etc.

Find the list at ~**line 1367**:

```python
mainstream = [
    "reddit.com", "google.com", "straitstimes.com",
    "channelnewsasia.com", "mothership.sg", "todayonline.com",
    "yahoo.com", "bbc.com", "hardwarezone.com.sg",
    "duckduckgo.com", "t.me", "telegram.org",
    "pastebin.com", "twitter.com", "facebook.com",
    "instagram.com", "mustsharenews.com",
    "theindependent.sg", "asiaone.com",
    "tiktok.com",  # ← ADD NEW DOMAINS HERE
]
```

The match uses `in` (substring), so adding `"google.com"` also excludes `"news.google.com"`, `"mail.google.com"`, etc.

---

## 14. Troubleshooting Common Issues

### "HTTP Error 403: Blocked"
- **Cause:** The website is blocking your requests (rate limit or bot detection).
- **Fix:** The multi-engine system should auto-switch. If all engines fail, increase `time.sleep()` delays or wait 10–15 minutes for rate limits to reset.

### "urlopen error timed out"
- **Cause:** The request took longer than 20 seconds.
- **Fix:** Increase timeout in `safe_request()`, or check your internet connection.

### "All engines failed for: ..."
- **Cause:** DDG HTML, Bing, and DDG Lite all failed or timed out.
- **Fix:** Usually temporary. Wait a few minutes. If persistent, your IP may be temporarily blocked — try from a different network or VPN.

### Circuit breaker skipping engines too aggressively
- **Cause:** `_ENGINE_MAX_FAILS = 3` may be too low for unstable connections.
- **Fix:** Increase to 5 or higher:
  ```python
  _ENGINE_MAX_FAILS = 5
  ```

### Results have wrong threat level
- **Fix:** Add more keywords to `high` or `med` lists in `classify_threat()`. See Section 7.

### UI looks wrong / fonts missing
- **Cause:** Consolas font not installed (rare on Windows 11, common on Linux/Mac).
- **Fix:** Change font in `_apply_theme()` to `"Courier New"` or `"monospace"`.

### Config not saving
- **Cause:** File permission issue on `osint_config.json`.
- **Fix:** Delete `osint_config.json` and restart. It will be recreated.

---

## Quick Reference: Adding Things

| I want to... | Edit this | Section |
|---|---|---|
| Add a keyword | `KEYWORD_PRESETS` dict | §5 |
| Add a keyword category | `KEYWORD_PRESETS` dict (new key) | §5 |
| Add a Google dork | `GOOGLE_DORKS` dict | §6 |
| Add a dork category | `GOOGLE_DORKS` dict (new key) | §6 |
| Add an OSINT source | `OSINT_SOURCES` + scanner function + `_scan_thread()` | §4 |
| Add a subreddit | `SG_SUBREDDITS` list | §9 |
| Add a threat signal word | `classify_threat()` high/med lists | §7 |
| Add a search engine | `_web_search_multi()` engines list | §8 |
| Add a CSV column | `_export()` fieldnames | §12 |
| Skip a domain in WHOIS | `mainstream` list in `_scan_thread()` | §13 |
| Change colors | `C` dict | §10 |
| Change scan speed | `time.sleep()` in `_scan_thread()` | §11 |
