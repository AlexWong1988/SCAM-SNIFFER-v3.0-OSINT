"""
╔══════════════════════════════════════════════════════════════╗
║  SCAM SNIFFER v3.0 — OSINT EDITION                          ║
║  Singapore Threat Intelligence & Forum Scanner               ║
║  Portable Windows 11 Desktop Edition                         ║
╚══════════════════════════════════════════════════════════════╝

OSINT sources:
  1. Reddit        — r/singapore, r/scams, r/SGExams etc.
  2. HardwareZone  — Singapore's largest forum (EDMW, etc.)
  3. Google Dorking — site-specific deep searches
  4. Google News   — Singapore-localized RSS
  5. DuckDuckGo    — supplementary web results
  6. WHOIS/DNS     — domain intelligence on suspicious URLs
  7. Paste Sites   — exposed data & credential dumps
  8. Social Media  — Telegram, Twitter/X mentions

No API key needed. Pure OSINT.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import csv
import json
import os
import sys
import re
import socket
import urllib.request
import urllib.parse
import urllib.error
import ssl
import xml.etree.ElementTree as ET
from datetime import datetime
from html import unescape
from html.parser import HTMLParser
from collections import defaultdict

# ─── Optional imports ─────────────────────────────────────────
ANTHROPIC_AVAILABLE = False
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════
#  OSINT KEYWORD PRESETS
# ═══════════════════════════════════════════════════════════════

KEYWORD_PRESETS = {
    "Scam Reports": [
        "Singapore scam alert",
        "Singapore phishing scam",
        "Singapore investment scam warning",
        "Singapore job scam recruitment",
        "Singapore love scam romance",
        "Singapore crypto scam",
        "Singapore bank scam SMS OTP",
        "Singapore CPF scam call",
        "Singapore impersonation scam police",
    ],
    "Propaganda & POFMA": [
        "Singapore fake news POFMA",
        "Singapore disinformation campaign",
        "Singapore foreign interference online",
        "Singapore deepfake political",
        "Singapore propaganda misleading",
        "Singapore misinformation social media",
    ],
    "Forum Chatter": [
        "kena scam Singapore",
        "scam or not Singapore",
        "got scammed Singapore help",
        "Singapore number calling scam",
        "Singapore WhatsApp scam group",
        "Singapore Telegram scam investment",
        "Singapore Carousell scammer",
        "money game Singapore",
        "ponzi scheme Singapore",
    ],
    "Dark Patterns": [
        "Singapore phone number leak",
        "Singapore data breach exposed",
        "Singapore credentials dump",
        "Singapore NRIC leaked",
        "Singapore SingPass phishing",
        "Singapore bank phishing site",
    ],
}

# ─── OSINT Google Dork templates ──────────────────────────────

GOOGLE_DORKS = {
    "Forum Discussions": [
        'site:reddit.com singapore scam',
        'site:reddit.com/r/singapore scam OR phishing OR fraud',
        'site:hardwarezone.com.sg scam OR kena OR cheated',
        'site:forums.hardwarezone.com.sg investment scam',
        'site:mothership.sg scam OR fraud',
        'site:mustsharenews.com scam',
    ],
    "Exposed Data": [
        'site:pastebin.com singapore phone OR NRIC OR email',
        'site:rentry.co singapore scam',
        '"singapore" filetype:csv email phone',
        'intext:"singapore" intext:"password" site:pastebin.com',
    ],
    "Phishing Sites": [
        'intitle:"DBS" OR intitle:"OCBC" OR intitle:"UOB" login -site:dbs.com.sg -site:ocbc.com -site:uob.com.sg',
        'intitle:"SingPass" login -site:singpass.gov.sg',
        'intitle:"CPF" login -site:cpf.gov.sg',
    ],
    "Telegram & Social": [
        'site:t.me singapore investment group',
        'site:t.me singapore earn money',
        '"t.me" singapore scam OR fraud',
        'site:twitter.com singapore scam alert',
    ],
    "Facebook": [
        'site:facebook.com singapore scam alert',
        'site:facebook.com singapore scam warning group',
        'site:facebook.com singapore investment scam',
        'site:facebook.com "singapore" "kena scam"',
        'site:facebook.com singapore phishing fraud',
    ],
    "Instagram": [
        'site:instagram.com singapore scam',
        'site:instagram.com singapore fraud warning',
        'site:instagram.com singapore fake account scam',
    ],
}

# ─── SG Subreddits to scan ────────────────────────────────────

SG_SUBREDDITS = [
    "singapore", "SGExams", "askSingapore",
    "singaporefi", "scams", "Scams",
]

# ─── OSINT Source definitions (label, key, default on) ────────

OSINT_SOURCES = [
    ("Reddit (SG subs)", "reddit", True),
    ("HardwareZone Forum", "hwz", True),
    ("Google News SG", "news", True),
    ("DuckDuckGo / Bing Web", "ddg", True),
    ("Facebook", "facebook", True),
    ("Instagram", "instagram", True),
    ("Paste Sites", "paste", False),
    ("Telegram Mentions", "telegram", False),
    ("WHOIS/DNS Recon", "whois", False),
]


# ═══════════════════════════════════════════════════════════════
#  DARK THEME
# ═══════════════════════════════════════════════════════════════

C = {
    "bg":       "#080b10",
    "bg2":      "#0e1219",
    "bg3":      "#151b25",
    "border":   "#1c2333",
    "brd_hi":   "#283044",
    "fg":       "#c0c8d8",
    "dim":      "#4a5568",
    "accent":   "#00ffc8",
    "acc2":     "#00aa88",
    "red":      "#ff4455",
    "orange":   "#ff9f43",
    "green":    "#00d68f",
    "blue":     "#4da6ff",
    "purple":   "#b680ff",
    "yellow":   "#ffd93d",
    "cyan":     "#22d3ee",
}


# ═══════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "osint_config.json")

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_config(d):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(d, f, indent=2)
    except:
        pass


# ═══════════════════════════════════════════════════════════════
#  UTILITY
# ═══════════════════════════════════════════════════════════════

class HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result = []
    def handle_data(self, d):
        self.result.append(d)
    def get_text(self):
        return "".join(self.result)

def strip_html(html_str):
    s = HTMLStripper()
    try:
        s.feed(unescape(html_str or ""))
    except:
        return html_str or ""
    return s.get_text().strip()

def extract_domain(url):
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.replace("www.", "")
    except:
        return ""

import random as _random

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

def safe_request(url, timeout=20):
    """Make a safe HTTP GET request with error handling and UA rotation."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={
        "User-Agent": _random.choice(_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,en-SG;q=0.8",
        "Accept-Encoding": "identity",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="replace")

def classify_threat(text):
    """Rule-based threat classification."""
    t = text.lower()
    high = ["victim", "lost", "million", "arrested", "police report", "warning",
            "urgent", "syndicate", "convicted", "crackdown", "malware", "data breach",
            "identity theft", "POFMA", "correction direction", "leaked", "exposed",
            "credential", "dump", "nric", "singpass"]
    med = ["scam", "phishing", "fake", "fraud", "suspicious", "beware", "advisory",
           "propaganda", "misleading", "disinformation", "deepfake", "ponzi",
           "money game", "kena", "cheated"]

    h = sum(1 for s in high if s.lower() in t)
    m = sum(1 for s in med if s.lower() in t)

    if h >= 2: return "High"
    elif h >= 1 or m >= 2: return "Medium"
    return "Low"


# ═══════════════════════════════════════════════════════════════
#  OSINT SCANNERS
# ═══════════════════════════════════════════════════════════════

def scan_reddit(keyword, log_fn=None):
    """Search Reddit via RSS feed (no auth needed) + multi-engine web fallback."""
    results = []
    encoded = urllib.parse.quote(keyword)

    # Method 1: Reddit RSS (still public on some networks)
    rss_url = f"https://www.reddit.com/search.rss?q={encoded}&sort=new&limit=10"
    if log_fn: log_fn(f"  [REDDIT] RSS search: {keyword}")

    try:
        data = safe_request(rss_url)
        results = _parse_reddit_rss(data, keyword)
        if log_fn: log_fn(f"  [REDDIT] ✓ {len(results)} posts via RSS")
        if results:
            return results
    except Exception as e:
        if log_fn: log_fn(f"  [REDDIT] RSS blocked, switching to web search...", "warn")

    # Method 2: Multi-engine web search (DDG HTML → Bing → DDG Lite)
    try:
        results = _web_search_multi(f"site:reddit.com {keyword}", log_fn=log_fn)
        for r in results:
            r["osint_source"] = "Reddit"
        if log_fn and results:
            log_fn(f"  [REDDIT] ✓ {len(results)} posts via web search")
        elif log_fn:
            log_fn(f"  [REDDIT] No results for: {keyword}", "warn")
    except Exception as e2:
        if log_fn: log_fn(f"  [REDDIT] ✗ All methods failed: {e2}", "error")

    return results


def scan_reddit_subreddit(subreddit, keyword, log_fn=None):
    """Search a specific subreddit via RSS + multi-engine web fallback."""
    results = []
    encoded = urllib.parse.quote(keyword)

    # Method 1: Subreddit RSS
    rss_url = f"https://www.reddit.com/r/{subreddit}/search.rss?q={encoded}&sort=new&limit=8&restrict_sr=on"
    if log_fn: log_fn(f"  [REDDIT] r/{subreddit} RSS: {keyword}")

    try:
        data = safe_request(rss_url)
        results = _parse_reddit_rss(data, keyword, subreddit)
        if log_fn and results: log_fn(f"  [REDDIT] ✓ {len(results)} from r/{subreddit}")
        if results:
            return results
    except Exception as e:
        if log_fn: log_fn(f"  [REDDIT] r/{subreddit} RSS blocked, trying web search...", "warn")

    # Method 2: Multi-engine fallback
    try:
        results = _web_search_multi(f"site:reddit.com/r/{subreddit} {keyword}", log_fn=log_fn)
        for r in results:
            r["osint_source"] = "Reddit"
            r["source"] = f"r/{subreddit}"
        if log_fn and results:
            log_fn(f"  [REDDIT] ✓ {len(results)} from r/{subreddit} via web search")
    except Exception as e2:
        if log_fn: log_fn(f"  [REDDIT] ✗ r/{subreddit} all methods failed: {e2}", "error")

    return results


def _parse_reddit_rss(xml_data, keyword, subreddit=None):
    """Parse Reddit Atom/RSS feed into result dicts."""
    results = []

    # Reddit RSS uses Atom format with namespace
    # Strip namespace for easier parsing
    xml_clean = re.sub(r'\sxmlns[^"]*"[^"]*"', '', xml_data)
    xml_clean = re.sub(r'<(/?)feed', r'<\1feed', xml_clean)

    try:
        root = ET.fromstring(xml_clean)
    except ET.ParseError:
        # Try regex fallback for mangled XML
        entries = re.findall(
            r'<entry>(.*?)</entry>', xml_data, re.DOTALL
        )
        for entry_xml in entries[:10]:
            title = re.search(r'<title>(.*?)</title>', entry_xml, re.DOTALL)
            link = re.search(r'<link\s+href="([^"]+)"', entry_xml)
            content = re.search(r'<content[^>]*>(.*?)</content>', entry_xml, re.DOTALL)
            updated = re.search(r'<updated>(.*?)</updated>', entry_xml)
            author = re.search(r'<name>(.*?)</name>', entry_xml)

            title_text = strip_html(title.group(1)) if title else ""
            link_url = link.group(1) if link else ""
            snippet = strip_html(content.group(1))[:300] if content else ""
            date_str = updated.group(1)[:10] if updated else "Unknown"

            # Extract subreddit from link
            sub_match = re.search(r'/r/(\w+)/', link_url)
            src = f"r/{sub_match.group(1)}" if sub_match else f"r/{subreddit}" if subreddit else "Reddit"

            results.append({
                "title": title_text[:200], "source": src, "url": link_url,
                "snippet": snippet, "date": date_str,
                "threat_level": classify_threat(title_text + " " + snippet),
                "keyword": keyword, "osint_source": "Reddit",
                "metadata": "", "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
        return results

    # Normal XML parsing path
    entries = root.findall(".//entry")
    if not entries:
        entries = root.findall("entry")

    for entry in entries[:10]:
        title_el = entry.find("title")
        link_el = entry.find("link")
        content_el = entry.find("content")
        updated_el = entry.find("updated")

        title_text = strip_html(title_el.text) if title_el is not None and title_el.text else ""
        link_url = link_el.get("href", "") if link_el is not None else ""
        snippet = strip_html(content_el.text)[:300] if content_el is not None and content_el.text else ""
        date_str = updated_el.text[:10] if updated_el is not None and updated_el.text else "Unknown"

        sub_match = re.search(r'/r/(\w+)/', link_url)
        src = f"r/{sub_match.group(1)}" if sub_match else f"r/{subreddit}" if subreddit else "Reddit"

        results.append({
            "title": title_text[:200], "source": src, "url": link_url,
            "snippet": snippet, "date": date_str,
            "threat_level": classify_threat(title_text + " " + snippet),
            "keyword": keyword, "osint_source": "Reddit",
            "metadata": "", "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    return results


def scan_google_news(keyword, log_fn=None):
    """Google News RSS - Singapore localized."""
    results = []
    encoded = urllib.parse.quote(keyword)
    url = f"https://news.google.com/rss/search?q={encoded}&hl=en-SG&gl=SG&ceid=SG:en"

    if log_fn: log_fn(f"  [NEWS] Google News: {keyword}")

    try:
        data = safe_request(url)
        root = ET.fromstring(data)
        items = root.findall(".//item")

        if log_fn: log_fn(f"  [NEWS] ✓ {len(items)} articles")

        for item in items[:8]:
            title = strip_html(item.findtext("title", ""))
            link = item.findtext("link", "")
            pub = item.findtext("pubDate", "Unknown")
            desc = strip_html(item.findtext("description", ""))
            source = item.findtext("source", "") or extract_domain(link)

            if pub and pub != "Unknown":
                try:
                    from email.utils import parsedate_to_datetime
                    pub = parsedate_to_datetime(pub).strftime("%Y-%m-%d")
                except:
                    pub = pub[:16]

            results.append({
                "title": title[:200], "source": source, "url": link,
                "snippet": desc[:300], "date": pub,
                "threat_level": classify_threat(title + " " + desc),
                "keyword": keyword, "osint_source": "Google News",
                "metadata": "", "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
    except Exception as e:
        if log_fn: log_fn(f"  [NEWS] ✗ Error: {e}", "error")

    return results


def scan_duckduckgo_lite(query, log_fn=None):
    """Multi-engine web search: DDG HTML → Bing → DDG Lite. Auto-switches on failure."""
    return _web_search_multi(query, log_fn=log_fn)


# ─── MULTI-ENGINE SEARCH with Circuit Breaker ────────────────

_engine_failures = {"ddg_html": 0, "bing": 0, "ddg_lite": 0}
_ENGINE_MAX_FAILS = 3  # After 3 consecutive failures, skip engine

def _reset_engine(engine):
    _engine_failures[engine] = 0

def _fail_engine(engine):
    _engine_failures[engine] += 1

def _engine_ok(engine):
    return _engine_failures[engine] < _ENGINE_MAX_FAILS


def _web_search_multi(query, log_fn=None):
    """Try multiple search engines in order. Circuit breaker skips broken ones."""
    import time

    engines = [
        ("ddg_html", _search_ddg_html),
        ("bing", _search_bing),
        ("ddg_lite", _search_ddg_lite_raw),
    ]

    for engine_name, engine_fn in engines:
        if not _engine_ok(engine_name):
            continue

        try:
            results = engine_fn(query, log_fn)
            if results:
                _reset_engine(engine_name)
                return results
            # Empty results isn't a failure, try next
        except Exception as e:
            _fail_engine(engine_name)
            fails = _engine_failures[engine_name]
            if log_fn:
                if fails >= _ENGINE_MAX_FAILS:
                    log_fn(f"  [{engine_name.upper()}] ✗ {e} — CIRCUIT OPEN (skipping)", "error")
                else:
                    log_fn(f"  [{engine_name.upper()}] ✗ {e} — trying next engine ({fails}/{_ENGINE_MAX_FAILS})", "warn")

    if log_fn:
        log_fn(f"  [SEARCH] All engines failed for: {query[:50]}", "error")
    return []


def _search_ddg_html(query, log_fn=None):
    """DuckDuckGo HTML endpoint (different from Lite, different rate limits)."""
    encoded = urllib.parse.quote(query)
    url = f"https://html.duckduckgo.com/html/?q={encoded}"

    if log_fn: log_fn(f"  [DDG-HTML] {query[:55]}...")

    html = safe_request(url, timeout=20)
    results = []

    # DDG HTML uses class="result__a" for links and class="result__snippet" for snippets
    links = re.findall(
        r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        html, re.DOTALL
    )
    snippets = re.findall(
        r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
        html, re.DOTALL
    )

    # Fallback patterns if class names differ
    if not links:
        links = re.findall(
            r'<a[^>]*rel="nofollow"[^>]*href="(?:(?:\/\/duckduckgo\.com\/l\/\?[^"]*uddg=)?([^"&]+))"[^>]*>\s*(.*?)\s*</a>',
            html, re.DOTALL
        )
    if not snippets:
        snippets = re.findall(
            r'<td[^>]*class="result-snippet"[^>]*>(.*?)</td>',
            html, re.DOTALL
        )

    count = min(len(links), 6)
    if log_fn: log_fn(f"  [DDG-HTML] ✓ {count} results")

    for i in range(count):
        raw_url = links[i][0]
        # Decode URL-encoded redirects
        if '%' in raw_url:
            raw_url = urllib.parse.unquote(raw_url)
        title = strip_html(links[i][1])
        snippet = strip_html(snippets[i]) if i < len(snippets) else ""

        results.append({
            "title": title[:200], "source": extract_domain(raw_url),
            "url": raw_url, "snippet": snippet[:300], "date": "Unknown",
            "threat_level": classify_threat(title + " " + snippet),
            "keyword": query, "osint_source": "DuckDuckGo",
            "metadata": "", "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    if count == 0:
        raise Exception("No results parsed from DDG HTML")
    return results


def _search_bing(query, log_fn=None):
    """Bing web search scraping — no API key needed."""
    encoded = urllib.parse.quote(query)
    url = f"https://www.bing.com/search?q={encoded}&setlang=en&cc=SG"

    if log_fn: log_fn(f"  [BING] {query[:55]}...")

    html = safe_request(url, timeout=20)
    results = []

    # Bing results: <li class="b_algo"> blocks
    blocks = re.findall(r'<li class="b_algo">(.*?)</li>', html, re.DOTALL)

    if log_fn: log_fn(f"  [BING] ✓ {len(blocks)} results")

    for block in blocks[:6]:
        link_match = re.search(r'<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>', block, re.DOTALL)
        snippet_match = re.search(r'<p[^>]*>(.*?)</p>', block, re.DOTALL)

        if not link_match:
            continue

        link_url = link_match.group(1)
        title = strip_html(link_match.group(2))
        snippet = strip_html(snippet_match.group(1)) if snippet_match else ""

        # Try to extract date from snippet
        date = "Unknown"
        date_match = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2})', snippet)
        if date_match:
            date = date_match.group(1)

        results.append({
            "title": title[:200], "source": extract_domain(link_url),
            "url": link_url, "snippet": snippet[:300], "date": date,
            "threat_level": classify_threat(title + " " + snippet),
            "keyword": query, "osint_source": "Bing",
            "metadata": "", "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    if len(results) == 0:
        raise Exception("No results parsed from Bing")
    return results


def _search_ddg_lite_raw(query, log_fn=None):
    """DuckDuckGo Lite (original, last resort)."""
    encoded = urllib.parse.quote(query)
    url = f"https://lite.duckduckgo.com/lite/?q={encoded}"

    if log_fn: log_fn(f"  [DDG-LITE] {query[:55]}...")

    html = safe_request(url, timeout=20)
    results = []

    links = re.findall(r'<a[^>]*rel="nofollow"[^>]*href="([^"]+)"[^>]*>\s*(.*?)\s*</a>', html, re.DOTALL)
    snippets = re.findall(r'<td[^>]*class="result-snippet"[^>]*>(.*?)</td>', html, re.DOTALL)

    count = min(len(links), 6)
    if log_fn: log_fn(f"  [DDG-LITE] ✓ {count} results")

    for i in range(count):
        link_url = links[i][0]
        title = strip_html(links[i][1])
        snippet = strip_html(snippets[i]) if i < len(snippets) else ""

        results.append({
            "title": title[:200], "source": extract_domain(link_url),
            "url": link_url, "snippet": snippet[:300], "date": "Unknown",
            "threat_level": classify_threat(title + " " + snippet),
            "keyword": query, "osint_source": "DuckDuckGo",
            "metadata": "", "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    if count == 0:
        raise Exception("No results parsed from DDG Lite")
    return results


def scan_whois_dns(domain, log_fn=None):
    """Basic DNS/WHOIS recon on a suspicious domain."""
    info = {}
    if log_fn: log_fn(f"  [DNS] Looking up: {domain}")

    try:
        ip = socket.gethostbyname(domain)
        info["ip"] = ip
        if log_fn: log_fn(f"  [DNS] ✓ Resolves to {ip}")
    except:
        info["ip"] = "NXDOMAIN"
        if log_fn: log_fn(f"  [DNS] ✗ Domain does not resolve")

    # Reverse DNS
    try:
        if info["ip"] != "NXDOMAIN":
            reverse = socket.gethostbyaddr(info["ip"])
            info["reverse_dns"] = reverse[0]
    except:
        info["reverse_dns"] = "N/A"

    # Check SSL cert
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            info["ssl_issuer"] = dict(x[0] for x in cert.get("issuer", [()])).get("organizationName", "Unknown")
            info["ssl_expiry"] = cert.get("notAfter", "Unknown")
            info["ssl_subject"] = dict(x[0] for x in cert.get("subject", [()])).get("commonName", "Unknown")
            if log_fn: log_fn(f"  [SSL] ✓ Cert by {info['ssl_issuer']}, CN={info['ssl_subject']}")
    except Exception as e:
        info["ssl_issuer"] = "N/A"
        info["ssl_expiry"] = "N/A"
        if log_fn: log_fn(f"  [SSL] ✗ No SSL or error: {e}")

    return info


def scan_hwz_forum(keyword, log_fn=None):
    """Search HardwareZone Singapore forums via Google."""
    query = f"site:hardwarezone.com.sg {keyword}"
    if log_fn: log_fn(f"  [HWZ] Searching HardwareZone: {keyword}")
    return scan_duckduckgo_lite(query, log_fn)


def scan_paste_sites(keyword, log_fn=None):
    """Search for paste site mentions."""
    query = f'site:pastebin.com OR site:rentry.co OR site:ghostbin.com "{keyword}"'
    if log_fn: log_fn(f"  [PASTE] Searching paste sites: {keyword}")
    results = scan_duckduckgo_lite(query, log_fn)
    for r in results:
        r["osint_source"] = "Paste Sites"
        r["threat_level"] = "High"  # Paste site hits are always suspicious
    return results


def scan_telegram_mentions(keyword, log_fn=None):
    """Search for Telegram group/channel mentions."""
    query = f'site:t.me OR "t.me/" {keyword}'
    if log_fn: log_fn(f"  [TELEGRAM] Searching Telegram mentions: {keyword}")
    results = scan_duckduckgo_lite(query, log_fn)
    for r in results:
        r["osint_source"] = "Telegram"
    return results


def scan_google_dorks(dork_query, log_fn=None):
    """Execute a Google dork via multi-engine search."""
    results = scan_duckduckgo_lite(dork_query, log_fn)
    for r in results:
        r["osint_source"] = "Google Dork"
    return results


def scan_facebook(keyword, log_fn=None):
    """Search Facebook public posts/groups for scam mentions."""
    query = f'site:facebook.com {keyword}'
    if log_fn: log_fn(f"  [FACEBOOK] Searching: {keyword}")
    results = _web_search_multi(query, log_fn=log_fn)
    for r in results:
        r["osint_source"] = "Facebook"
    if log_fn and results: log_fn(f"  [FACEBOOK] ✓ {len(results)} results")
    return results


def scan_instagram(keyword, log_fn=None):
    """Search Instagram public posts for scam mentions."""
    query = f'site:instagram.com {keyword}'
    if log_fn: log_fn(f"  [INSTAGRAM] Searching: {keyword}")
    results = _web_search_multi(query, log_fn=log_fn)
    for r in results:
        r["osint_source"] = "Instagram"
    if log_fn and results: log_fn(f"  [INSTAGRAM] ✓ {len(results)} results")
    return results


# ═══════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════

class OsintScamSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("SCAM SNIFFER v3.0 OSINT — Singapore Threat Intelligence")
        self.root.geometry("1400x860")
        self.root.minsize(1050, 700)
        self.root.configure(bg=C["bg"])

        self.results = []
        self.scanning = False
        self.abort_flag = False
        self.cat_vars = {}          # cat_name → BooleanVar (category toggle)
        self.kw_vars = {}           # keyword_string → BooleanVar (individual keyword toggle)
        self.dork_vars = {}         # dork_cat → BooleanVar
        self.dork_item_vars = {}    # dork_query → BooleanVar
        self.osint_vars = {}        # source_key → BooleanVar
        self.custom_keywords = []
        self.domain_queue = []
        self._expand_state = {}     # section_id → bool (expanded or not)

        cfg = load_config()
        self.custom_keywords = cfg.get("custom_keywords", [])

        self._apply_theme()
        self._build_ui()

        # Restore
        for kw in self.custom_keywords:
            self.custom_listbox.insert(tk.END, kw)
        self._update_count()

    def _apply_theme(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["fg"], fieldbackground=C["bg2"],
                     bordercolor=C["border"], troughcolor=C["bg2"], font=("Consolas", 10))
        s.configure("TFrame", background=C["bg"])
        s.configure("TLabel", background=C["bg"], foreground=C["fg"], font=("Consolas", 10))
        s.configure("Dim.TLabel", background=C["bg"], foreground=C["dim"], font=("Consolas", 9))
        s.configure("Title.TLabel", background=C["bg"], foreground=C["cyan"], font=("Consolas", 16, "bold"))
        s.configure("Sec.TLabel", background=C["bg"], foreground=C["dim"], font=("Consolas", 9, "bold"))
        s.configure("Source.TLabel", background=C["bg"], foreground=C["purple"], font=("Consolas", 9, "bold"))
        s.configure("TButton", background=C["bg3"], foreground=C["fg"], bordercolor=C["brd_hi"],
                     padding=(10, 5), font=("Consolas", 10, "bold"))
        s.map("TButton", background=[("active", C["brd_hi"]), ("disabled", C["bg2"])],
               foreground=[("disabled", C["dim"])])
        s.configure("Scan.TButton", background=C["bg3"], foreground=C["cyan"],
                     bordercolor=C["acc2"], padding=(14, 7), font=("Consolas", 11, "bold"))
        s.configure("Stop.TButton", background=C["bg3"], foreground=C["red"],
                     bordercolor="#882233", padding=(14, 7), font=("Consolas", 11, "bold"))
        s.configure("Export.TButton", background=C["bg3"], foreground=C["blue"],
                     bordercolor="#335588", padding=(10, 5), font=("Consolas", 10, "bold"))
        s.configure("TCheckbutton", background=C["bg"], foreground=C["fg"], font=("Consolas", 9))
        s.map("TCheckbutton", background=[("active", C["bg"])], foreground=[("active", C["cyan"])])
        s.configure("TEntry", fieldbackground=C["bg2"], foreground=C["fg"],
                     bordercolor=C["border"], insertcolor=C["cyan"], font=("Consolas", 10))
        s.configure("Horizontal.TProgressbar", background=C["cyan"], troughcolor=C["bg2"])
        s.configure("Treeview", background=C["bg2"], foreground=C["fg"], fieldbackground=C["bg2"],
                     bordercolor=C["border"], rowheight=26, font=("Consolas", 9))
        s.configure("Treeview.Heading", background=C["bg3"], foreground=C["dim"],
                     bordercolor=C["border"], font=("Consolas", 9, "bold"))
        s.map("Treeview", background=[("selected", "#162030")], foreground=[("selected", C["cyan"])])
        s.configure("TLabelframe", background=C["bg"], foreground=C["dim"], bordercolor=C["border"])
        s.configure("TLabelframe.Label", background=C["bg"], foreground=C["dim"], font=("Consolas", 9, "bold"))
        s.configure("TNotebook", background=C["bg"], bordercolor=C["border"])
        s.configure("TNotebook.Tab", background=C["bg3"], foreground=C["dim"],
                     padding=(10, 4), font=("Consolas", 9, "bold"))
        s.map("TNotebook.Tab",
               background=[("selected", C["bg"]), ("active", C["brd_hi"])],
               foreground=[("selected", C["cyan"])])

    def _build_ui(self):
        # ── HEADER ──
        hdr = ttk.Frame(self.root)
        hdr.pack(fill="x", padx=14, pady=(10, 0))
        ttk.Label(hdr, text="⦿ SCAM SNIFFER v3 OSINT", style="Title.TLabel").pack(side="left")
        ttk.Label(hdr, text="Forum & Intelligence Scanner", style="Dim.TLabel").pack(side="left", padx=(10, 0), pady=(4, 0))
        self.status_lbl = ttk.Label(hdr, text="● STANDBY", style="Dim.TLabel")
        self.status_lbl.pack(side="right")

        tk.Frame(self.root, height=1, bg=C["border"]).pack(fill="x", padx=14, pady=(8, 0))

        # ── BODY ──
        body = tk.PanedWindow(self.root, orient="horizontal", bg=C["bg"], sashwidth=4, bd=0)
        body.pack(fill="both", expand=True, padx=14, pady=8)

        # ═══ LEFT PANEL ═══
        left = ttk.Frame(body)
        body.add(left, width=290, minsize=250)

        canvas = tk.Canvas(left, bg=C["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(left, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bind mousewheel
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        lf = scroll_frame  # shorthand

        # ── Helper: Expandable Section ──
        def make_expandable(parent, section_id, title, items, var_dict,
                            has_parent_toggle=True, default_on=True, item_prefix="  "):
            """Create an expandable section with parent checkbox + child items."""
            self._expand_state[section_id] = False  # start collapsed

            # Header frame
            hdr_frame = tk.Frame(parent, bg=C["bg"])
            hdr_frame.pack(fill="x", pady=(2, 0))

            # Expand arrow
            arrow_lbl = tk.Label(hdr_frame, text="▶", bg=C["bg"], fg=C["dim"],
                                  font=("Consolas", 8), cursor="hand2")
            arrow_lbl.pack(side="left", padx=(0, 2))

            # Parent checkbox
            if has_parent_toggle:
                parent_var = tk.BooleanVar(value=default_on)
                var_dict["__parent__" + section_id] = parent_var
                cb = ttk.Checkbutton(hdr_frame, text=f"{title} ({len(items)})",
                                      variable=parent_var,
                                      command=lambda: _toggle_children(section_id, parent_var.get()))
                cb.pack(side="left")
            else:
                tk.Label(hdr_frame, text=f"{title} ({len(items)})", bg=C["bg"],
                         fg=C["fg"], font=("Consolas", 9, "bold"), cursor="hand2").pack(side="left")

            # Children frame (hidden by default)
            children_frame = tk.Frame(parent, bg=C["bg"])
            children_frame.pack(fill="x")
            children_frame.pack_forget()  # hidden

            # Create child checkboxes
            child_vars = []
            for item in items:
                v = tk.BooleanVar(value=default_on)
                var_dict[item] = v
                child_vars.append(v)
                cf = tk.Frame(children_frame, bg=C["bg"])
                cf.pack(fill="x")
                ttk.Checkbutton(cf, text=f"{item_prefix}{item[:45]}{'…' if len(item) > 45 else ''}",
                                 variable=v, command=self._update_count).pack(anchor="w")

            def _toggle_expand(event=None):
                expanded = self._expand_state[section_id]
                if expanded:
                    children_frame.pack_forget()
                    arrow_lbl.configure(text="▶")
                else:
                    children_frame.pack(fill="x")
                    arrow_lbl.configure(text="▼")
                self._expand_state[section_id] = not expanded
                # Update scroll region
                parent.update_idletasks()
                canvas.configure(scrollregion=canvas.bbox("all"))

            def _toggle_children(sid, state):
                for cv in child_vars:
                    cv.set(state)
                self._update_count()

            arrow_lbl.bind("<Button-1>", _toggle_expand)
            hdr_frame.bind("<Button-1>", _toggle_expand)

            return child_vars

        # ═══ OSINT SOURCES ═══
        ttk.Label(lf, text="OSINT SOURCES", style="Sec.TLabel").pack(anchor="w", pady=(4, 4))
        for label, key, default in OSINT_SOURCES:
            var = tk.BooleanVar(value=default)
            self.osint_vars[key] = var
            ttk.Checkbutton(lf, text=f"  {label}", variable=var,
                             command=self._update_count).pack(anchor="w", pady=1)

        tk.Frame(lf, height=1, bg=C["border"]).pack(fill="x", pady=(8, 4))

        # ═══ KEYWORD CATEGORIES (expandable) ═══
        ttk.Label(lf, text="KEYWORD CATEGORIES", style="Sec.TLabel").pack(anchor="w", pady=(4, 4))
        for cat, kws in KEYWORD_PRESETS.items():
            make_expandable(lf, f"kw_{cat}", cat, kws, self.kw_vars, default_on=True)

        tk.Frame(lf, height=1, bg=C["border"]).pack(fill="x", pady=(8, 4))

        # ═══ GOOGLE DORKS (expandable) ═══
        ttk.Label(lf, text="GOOGLE DORKS", style="Sec.TLabel").pack(anchor="w", pady=(4, 4))
        for dk, queries in GOOGLE_DORKS.items():
            make_expandable(lf, f"dork_{dk}", dk, queries, self.dork_item_vars,
                            default_on=True, item_prefix="  ")

        tk.Frame(lf, height=1, bg=C["border"]).pack(fill="x", pady=(8, 4))

        # Custom keywords
        ttk.Label(lf, text="CUSTOM KEYWORDS", style="Sec.TLabel").pack(anchor="w", pady=(0, 4))
        kw_row = ttk.Frame(lf)
        kw_row.pack(fill="x", pady=(0, 4))
        self.custom_entry = ttk.Entry(kw_row, width=20)
        self.custom_entry.pack(side="left", fill="x", expand=True)
        self.custom_entry.bind("<Return>", lambda e: self._add_kw())
        ttk.Button(kw_row, text="+", width=3, command=self._add_kw).pack(side="right", padx=(4, 0))

        self.custom_listbox = tk.Listbox(lf, height=3, bg=C["bg2"], fg=C["fg"],
                                          selectbackground=C["brd_hi"], selectforeground=C["cyan"],
                                          borderwidth=1, relief="solid", highlightthickness=0,
                                          font=("Consolas", 9))
        self.custom_listbox.pack(fill="x", pady=(0, 4))
        ttk.Button(lf, text="Remove", command=self._rm_kw).pack(anchor="w", pady=(0, 6))

        # Domain recon input
        ttk.Label(lf, text="DOMAIN RECON", style="Sec.TLabel").pack(anchor="w", pady=(4, 4))
        dom_row = ttk.Frame(lf)
        dom_row.pack(fill="x", pady=(0, 4))
        self.domain_entry = ttk.Entry(dom_row, width=20)
        self.domain_entry.pack(side="left", fill="x", expand=True)
        self.domain_entry.insert(0, "e.g. suspicious-site.com")
        self.domain_entry.bind("<FocusIn>", lambda e: self.domain_entry.delete(0, tk.END) if "e.g." in self.domain_entry.get() else None)
        ttk.Button(dom_row, text="Scan", width=5, command=self._recon_domain).pack(side="right", padx=(4, 0))

        ttk.Label(lf, text="", style="Dim.TLabel").pack()

        # Count & buttons
        self.count_lbl = ttk.Label(lf, text="", style="Dim.TLabel")
        self.count_lbl.pack(pady=(0, 6))

        tk.Frame(lf, height=1, bg=C["border"]).pack(fill="x", pady=4)

        self.scan_btn = ttk.Button(lf, text="▶  OSINT SCAN", style="Scan.TButton", command=self._start_scan)
        self.scan_btn.pack(fill="x", pady=(6, 4))
        self.stop_btn = ttk.Button(lf, text="■  ABORT", style="Stop.TButton", command=self._stop, state="disabled")
        self.stop_btn.pack(fill="x", pady=(0, 4))
        self.export_btn = ttk.Button(lf, text="⬇  EXPORT CSV", style="Export.TButton",
                                      command=self._export, state="disabled")
        self.export_btn.pack(fill="x", pady=(0, 4))
        self.clear_btn = ttk.Button(lf, text="✕  CLEAR", command=self._clear, state="disabled")
        self.clear_btn.pack(fill="x")

        # ═══ RIGHT PANEL ═══
        right = ttk.Frame(body)
        body.add(right, minsize=550)

        # Progress
        self.prog_frame = ttk.Frame(right)
        self.prog_lbl = ttk.Label(self.prog_frame, text="", style="Dim.TLabel")
        self.prog_lbl.pack(anchor="w")
        self.prog_bar = ttk.Progressbar(self.prog_frame, mode="determinate")
        self.prog_bar.pack(fill="x", pady=(4, 0))

        # Summary
        self.sum_lbl = ttk.Label(right, text="", style="Dim.TLabel")
        self.sum_lbl.pack(anchor="w", pady=(0, 4))

        # Notebook for results + domain recon
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1: Results
        tab_results = ttk.Frame(self.notebook)
        self.notebook.add(tab_results, text=" 🔍 SCAN RESULTS ")

        cols = ("threat", "source_type", "title", "source", "date", "keyword", "snippet", "url")
        self.tree = ttk.Treeview(tab_results, columns=cols, show="headings", selectmode="browse")
        for col, w in zip(cols, [60, 85, 200, 100, 80, 120, 260, 160]):
            self.tree.heading(col, text=col.upper().replace("_", " "))
            self.tree.column(col, width=w, minwidth=50)

        sy = ttk.Scrollbar(tab_results, orient="vertical", command=self.tree.yview)
        sx = ttk.Scrollbar(tab_results, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        tab_results.grid_rowconfigure(0, weight=1)
        tab_results.grid_columnconfigure(0, weight=1)

        self.tree.tag_configure("high", foreground=C["red"])
        self.tree.tag_configure("medium", foreground=C["orange"])
        self.tree.tag_configure("low", foreground=C["green"])
        self.tree.bind("<Double-1>", self._open_url)

        # Tab 2: Domain Recon
        tab_recon = ttk.Frame(self.notebook)
        self.notebook.add(tab_recon, text=" 🌐 DOMAIN RECON ")

        self.recon_text = tk.Text(tab_recon, bg="#080a0f", fg=C["fg"], insertbackground=C["cyan"],
                                   borderwidth=0, highlightthickness=0, font=("Consolas", 10),
                                   wrap="word", state="disabled")
        recon_sb = ttk.Scrollbar(tab_recon, orient="vertical", command=self.recon_text.yview)
        self.recon_text.configure(yscrollcommand=recon_sb.set)
        self.recon_text.pack(side="left", fill="both", expand=True)
        recon_sb.pack(side="right", fill="y")

        self.recon_text.tag_configure("header", foreground=C["cyan"], font=("Consolas", 11, "bold"))
        self.recon_text.tag_configure("key", foreground=C["purple"])
        self.recon_text.tag_configure("val", foreground=C["fg"])
        self.recon_text.tag_configure("warn", foreground=C["orange"])
        self.recon_text.tag_configure("ok", foreground=C["green"])
        self.recon_text.tag_configure("bad", foreground=C["red"])

        # LOG CONSOLE
        ttk.Label(right, text="OSINT LOG", style="Sec.TLabel").pack(anchor="w", pady=(6, 2))
        log_frame = ttk.Frame(right)
        log_frame.pack(fill="x")

        self.log_text = tk.Text(log_frame, height=7, bg="#060810", fg=C["dim"],
                                 insertbackground=C["cyan"], borderwidth=1, relief="solid",
                                 highlightthickness=0, font=("Consolas", 9), wrap="word", state="disabled")
        log_sb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_sb.pack(side="right", fill="y")

        self.log_text.tag_configure("info", foreground=C["dim"])
        self.log_text.tag_configure("success", foreground=C["green"])
        self.log_text.tag_configure("warn", foreground=C["orange"])
        self.log_text.tag_configure("error", foreground=C["red"])
        self.log_text.tag_configure("accent", foreground=C["cyan"])
        self.log_text.tag_configure("purple", foreground=C["purple"])

    # ── Logging ──

    def log(self, msg, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{ts}] {msg}\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def log_safe(self, msg, tag="info"):
        self.root.after(0, self.log, msg, tag)

    # ── Helpers ──

    def _update_count(self):
        total = self._count_tasks()
        self.count_lbl.configure(text=f"{total} scan tasks queued")

    def _count_tasks(self):
        count = 0
        kws = self._get_keywords()
        sources = {k: v.get() for k, v in self.osint_vars.items()}

        if sources.get("reddit"): count += len(kws) + len(SG_SUBREDDITS) * 2
        if sources.get("news"): count += len(kws)
        if sources.get("ddg"): count += len(kws)
        if sources.get("hwz"): count += len(kws)
        if sources.get("facebook"): count += len(kws)
        if sources.get("instagram"): count += len(kws)
        if sources.get("paste"): count += 3
        if sources.get("telegram"): count += 3

        # Count active dorks
        count += len(self._get_active_dorks())

        return count

    def _get_keywords(self):
        """Get all active keywords from keyword categories."""
        kws = []
        for cat, cat_kws in KEYWORD_PRESETS.items():
            for kw in cat_kws:
                if kw in self.kw_vars and self.kw_vars[kw].get():
                    kws.append(kw)
        kws.extend(self.custom_keywords)
        return kws

    def _get_active_dorks(self):
        """Get all active dork queries."""
        dorks = []
        for dk_cat, queries in GOOGLE_DORKS.items():
            for q in queries:
                if q in self.dork_item_vars and self.dork_item_vars[q].get():
                    dorks.append(q)
        return dorks

    def _add_kw(self):
        kw = self.custom_entry.get().strip()
        if kw and kw not in self.custom_keywords:
            self.custom_keywords.append(kw)
            self.custom_listbox.insert(tk.END, kw)
            self.custom_entry.delete(0, tk.END)
            self._update_count()
            self._save()

    def _rm_kw(self):
        sel = self.custom_listbox.curselection()
        if sel:
            self.custom_keywords.pop(sel[0])
            self.custom_listbox.delete(sel[0])
            self._update_count()
            self._save()

    def _save(self):
        save_config({
            "custom_keywords": self.custom_keywords,
        })

    def _open_url(self, event):
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0], "values")
            url = vals[7] if len(vals) > 7 else ""
            if url.startswith("http"):
                import webbrowser
                webbrowser.open(url)

    # ── Domain Recon ──

    def _recon_domain(self):
        domain = self.domain_entry.get().strip()
        if not domain or "e.g." in domain:
            return

        # Clean domain
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

        self.notebook.select(1)  # Switch to recon tab
        self.recon_text.configure(state="normal")
        self.recon_text.insert("end", f"\n{'═'*60}\n", "header")
        self.recon_text.insert("end", f"  DOMAIN RECON: {domain}\n", "header")
        self.recon_text.insert("end", f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "info")
        self.recon_text.insert("end", f"{'═'*60}\n\n", "header")

        def run():
            info = scan_whois_dns(domain, log_fn=self.log_safe)

            def show():
                self.recon_text.configure(state="normal")

                # IP
                ip = info.get("ip", "?")
                tag = "ok" if ip != "NXDOMAIN" else "bad"
                self.recon_text.insert("end", "  IP Address:      ", "key")
                self.recon_text.insert("end", f"{ip}\n", tag)

                # Reverse DNS
                rdns = info.get("reverse_dns", "N/A")
                self.recon_text.insert("end", "  Reverse DNS:     ", "key")
                self.recon_text.insert("end", f"{rdns}\n", "val")

                # SSL
                issuer = info.get("ssl_issuer", "N/A")
                self.recon_text.insert("end", "\n  SSL Certificate:\n", "key")
                self.recon_text.insert("end", f"    Issuer:        ", "key")
                self.recon_text.insert("end", f"{issuer}\n", "val")
                self.recon_text.insert("end", f"    Subject CN:    ", "key")
                self.recon_text.insert("end", f"{info.get('ssl_subject', 'N/A')}\n", "val")
                self.recon_text.insert("end", f"    Expires:       ", "key")
                self.recon_text.insert("end", f"{info.get('ssl_expiry', 'N/A')}\n", "val")

                # Warnings
                self.recon_text.insert("end", "\n  Analysis:\n", "key")
                warnings = []
                if ip == "NXDOMAIN":
                    warnings.append("⚠ Domain does not resolve — may be dead or taken down")
                if issuer == "N/A":
                    warnings.append("⚠ No SSL certificate — suspicious for a bank/gov site")
                if issuer and "Let's Encrypt" in str(issuer):
                    warnings.append("ℹ Free SSL (Let's Encrypt) — common for phishing sites")

                if warnings:
                    for w in warnings:
                        self.recon_text.insert("end", f"    {w}\n", "warn")
                else:
                    self.recon_text.insert("end", "    ✓ No obvious red flags\n", "ok")

                self.recon_text.insert("end", "\n")
                self.recon_text.see("end")
                self.recon_text.configure(state="disabled")

            self.root.after(0, show)

        threading.Thread(target=run, daemon=True).start()

    # ── Main Scan ──

    def _scan_thread(self):
        keywords = self._get_keywords()
        sources = {k: v.get() for k, v in self.osint_vars.items()}
        active_dorks = self._get_active_dorks()
        total = self._count_tasks()
        step = [0]

        def progress(label):
            step[0] += 1
            self.root.after(0, self._set_progress, label, step[0], total)

        def add(results):
            if results:
                # Deduplicate by URL
                existing = {r["url"] for r in self.results}
                new = [r for r in results if r["url"] not in existing]
                if new:
                    self.results.extend(new)
                    self.root.after(0, self._add_tree, new)

        import time

        # Reset search engine circuit breakers at start
        for eng in _engine_failures:
            _engine_failures[eng] = 0

        self.log_safe("Search engines: DDG HTML → Bing → DDG Lite (auto-failover)", "info")

        # ── 1. Reddit ──
        if sources.get("reddit") and not self.abort_flag:
            self.log_safe("══ REDDIT SCAN ══", "purple")

            # General search
            for kw in keywords:
                if self.abort_flag: break
                progress(f"Reddit: {kw}")
                add(scan_reddit(kw, log_fn=self.log_safe))
                time.sleep(2)  # Reddit rate limit

            # Subreddit-specific
            for sub in SG_SUBREDDITS:
                if self.abort_flag: break
                for term in ["scam", "fraud"]:
                    progress(f"r/{sub}: {term}")
                    add(scan_reddit_subreddit(sub, term, log_fn=self.log_safe))
                    time.sleep(2)

        # ── 2. Google News ──
        if sources.get("news") and not self.abort_flag:
            self.log_safe("══ GOOGLE NEWS SCAN ══", "purple")
            for kw in keywords:
                if self.abort_flag: break
                progress(f"News: {kw}")
                add(scan_google_news(kw, log_fn=self.log_safe))
                time.sleep(1)

        # Reset engines before web search-heavy phases
        for eng in _engine_failures:
            _engine_failures[eng] = 0

        # ── 3. HardwareZone ──
        if sources.get("hwz") and not self.abort_flag:
            self.log_safe("══ HARDWAREZONE FORUM SCAN ══", "purple")
            for kw in keywords:
                if self.abort_flag: break
                progress(f"HWZ: {kw}")
                r = scan_hwz_forum(kw, log_fn=self.log_safe)
                for item in r:
                    item["osint_source"] = "HardwareZone"
                add(r)
                time.sleep(3)

        # ── 4. DuckDuckGo / Bing Web ──
        if sources.get("ddg") and not self.abort_flag:
            self.log_safe("══ WEB SEARCH SCAN ══", "purple")
            for kw in keywords:
                if self.abort_flag: break
                progress(f"Web: {kw}")
                add(scan_duckduckgo_lite(kw, log_fn=self.log_safe))
                time.sleep(3)

        # ── 5. Facebook ──
        if sources.get("facebook") and not self.abort_flag:
            self.log_safe("══ FACEBOOK SCAN ══", "purple")
            for kw in keywords:
                if self.abort_flag: break
                progress(f"Facebook: {kw}")
                add(scan_facebook(kw, log_fn=self.log_safe))
                time.sleep(3)

        # ── 6. Instagram ──
        if sources.get("instagram") and not self.abort_flag:
            self.log_safe("══ INSTAGRAM SCAN ══", "purple")
            for kw in keywords:
                if self.abort_flag: break
                progress(f"Instagram: {kw}")
                add(scan_instagram(kw, log_fn=self.log_safe))
                time.sleep(3)

        # Reset engines before dork phase
        for eng in _engine_failures:
            _engine_failures[eng] = 0

        # ── 7. Google Dorks (individual queries) ──
        if active_dorks and not self.abort_flag:
            self.log_safe(f"══ GOOGLE DORKS ({len(active_dorks)} queries) ══", "purple")
            for q in active_dorks:
                if self.abort_flag: break
                progress(f"Dork: {q[:40]}")
                add(scan_google_dorks(q, log_fn=self.log_safe))
                time.sleep(4)  # Dorks are suspicious, go slower

        # ── 8. Paste Sites ──
        if sources.get("paste") and not self.abort_flag:
            self.log_safe("══ PASTE SITE SCAN ══", "purple")
            for term in ["Singapore phone number", "Singapore NRIC", "Singapore email password"]:
                if self.abort_flag: break
                progress(f"Paste: {term}")
                add(scan_paste_sites(term, log_fn=self.log_safe))
                time.sleep(4)

        # ── 9. Telegram ──
        if sources.get("telegram") and not self.abort_flag:
            self.log_safe("══ TELEGRAM SCAN ══", "purple")
            for term in ["Singapore investment group", "Singapore earn money", "Singapore trading signal"]:
                if self.abort_flag: break
                progress(f"Telegram: {term}")
                add(scan_telegram_mentions(term, log_fn=self.log_safe))
                time.sleep(4)

        # ── 8. WHOIS on discovered domains ──
        if sources.get("whois") and not self.abort_flag:
            suspicious_domains = set()
            for r in self.results:
                d = extract_domain(r.get("url", ""))
                if d and d not in suspicious_domains and len(suspicious_domains) < 10:
                    # Only recon non-mainstream domains
                    mainstream = ["reddit.com", "google.com", "straitstimes.com", "channelnewsasia.com",
                                  "mothership.sg", "todayonline.com", "yahoo.com", "bbc.com",
                                  "hardwarezone.com.sg", "duckduckgo.com", "t.me", "telegram.org",
                                  "pastebin.com", "twitter.com", "facebook.com", "instagram.com",
                                  "mustsharenews.com", "theindependent.sg", "asiaone.com"]
                    if not any(m in d for m in mainstream):
                        suspicious_domains.add(d)

            if suspicious_domains:
                self.log_safe(f"══ WHOIS/DNS RECON ({len(suspicious_domains)} domains) ══", "purple")
                for domain in suspicious_domains:
                    if self.abort_flag: break
                    progress(f"WHOIS: {domain}")
                    info = scan_whois_dns(domain, log_fn=self.log_safe)
                    # Add to recon tab
                    self.root.after(0, self._add_recon_result, domain, info)

        self.root.after(0, self._scan_done)

    def _start_scan(self):
        total = self._count_tasks()
        if total == 0:
            messagebox.showwarning("Nothing to scan", "Enable at least one source and keyword category.")
            return

        self._save()
        self.results = []
        self.abort_flag = False
        self.scanning = True
        self.tree.delete(*self.tree.get_children())

        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.export_btn.configure(state="disabled")
        self.clear_btn.configure(state="disabled")
        self.status_lbl.configure(text="● SCANNING", foreground=C["orange"])
        self.prog_frame.pack(fill="x", pady=(0, 4), before=self.sum_lbl)
        self.prog_bar["value"] = 0

        self.log(f"{'═'*50}", "accent")
        self.log(f"  OSINT SCAN STARTED — {total} tasks", "accent")
        self.log(f"{'═'*50}", "accent")

        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _stop(self):
        self.abort_flag = True
        self.status_lbl.configure(text="● ABORTING...", foreground=C["red"])

    def _set_progress(self, label, current, total):
        self.prog_lbl.configure(text=f"[{current}/{total}] {label}")
        self.prog_bar["maximum"] = total
        self.prog_bar["value"] = current

    def _add_tree(self, new_results):
        for r in new_results:
            threat = r.get("threat_level", "Low")
            self.tree.insert("", "end", values=(
                threat,
                r.get("osint_source", ""),
                r.get("title", "")[:70],
                r.get("source", ""),
                r.get("date", ""),
                r.get("keyword", "")[:30],
                r.get("snippet", "")[:100],
                r.get("url", ""),
            ), tags=(threat.lower(),))
        self._update_summary()

    def _update_summary(self):
        h = sum(1 for r in self.results if r.get("threat_level") == "High")
        m = sum(1 for r in self.results if r.get("threat_level") == "Medium")
        lo = sum(1 for r in self.results if r.get("threat_level") == "Low")

        # Source breakdown
        src_counts = defaultdict(int)
        for r in self.results:
            src_counts[r.get("osint_source", "?")] += 1
        src_str = "  |  ".join(f"{s}: {c}" for s, c in sorted(src_counts.items()))

        self.sum_lbl.configure(
            text=f"TOTAL: {len(self.results)}  |  ● {h} High  ● {m} Med  ● {lo} Low  |  {src_str}"
        )

    def _add_recon_result(self, domain, info):
        self.recon_text.configure(state="normal")
        ip = info.get("ip", "?")
        tag = "ok" if ip != "NXDOMAIN" else "bad"
        self.recon_text.insert("end", f"\n  ── {domain} ──\n", "header")
        self.recon_text.insert("end", f"  IP: ", "key")
        self.recon_text.insert("end", f"{ip}  ", tag)
        ssl_cn = info.get("ssl_subject", "N/A")
        self.recon_text.insert("end", f"| SSL: ", "key")
        self.recon_text.insert("end", f"{info.get('ssl_issuer', 'N/A')} (CN={ssl_cn})\n", "val")
        self.recon_text.see("end")
        self.recon_text.configure(state="disabled")

    def _scan_done(self):
        self.scanning = False
        self.prog_frame.pack_forget()
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

        if self.results:
            self.export_btn.configure(state="normal")
            self.clear_btn.configure(state="normal")
            self.status_lbl.configure(text=f"● DONE — {len(self.results)} intel", foreground=C["cyan"])
            self.log(f"═══ SCAN COMPLETE — {len(self.results)} unique results ═══", "success")
        else:
            self.status_lbl.configure(text="● DONE — No results", foreground=C["orange"])
            self.log("═══ SCAN COMPLETE — No results ═══", "warn")

        self._update_summary()

    def _clear(self):
        self.results = []
        self.tree.delete(*self.tree.get_children())
        self.sum_lbl.configure(text="")
        self.export_btn.configure(state="disabled")
        self.clear_btn.configure(state="disabled")
        self.status_lbl.configure(text="● STANDBY", foreground=C["dim"])

    def _export(self):
        if not self.results:
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All", "*.*")],
            initialfile=f"osint_sniffer_sg_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            title="Export OSINT Results"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fieldnames=[
                    "title", "source", "url", "snippet", "date",
                    "threat_level", "keyword", "osint_source", "metadata", "scanned_at"
                ])
                w.writeheader()
                w.writerows(self.results)

            self.log(f"Exported {len(self.results)} results → {path}", "success")
            messagebox.showinfo("Export OK", f"Saved {len(self.results)} results to:\n{path}")
        except Exception as e:
            self.log(f"Export failed: {e}", "error")
            messagebox.showerror("Export Error", str(e))


# ═══════════════════════════════════════════════════════════════

def main():
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    OsintScamSniffer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
