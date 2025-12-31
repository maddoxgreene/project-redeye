#!/usr/bin/env python3
"""
Project Redeye (stdlib-only)

- Double-click friendly: prompts for domain/options when no args
- Passive subdomain discovery: crt.sh, Wayback, HackerTarget (best-effort)
- Scope enforcement
- DNS A/AAAA
- HTTP probe (http/https): status, final URL, title, server, content-type
- Optional TCP connect port scan
- Reports: JSON, CSV, Markdown
- Crash logging: redeye_last_crash.txt

Only run on targets you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# =========================
# WINDOWS RED TEXT (NO ANSI)
# =========================

class RedConsole:
    """
    Forces red text on Windows using Console API.
    Avoids ANSI sequences that show as ←[91m on some consoles.
    """
    def __init__(self) -> None:
        self.is_windows = (os.name == "nt")
        self.ok = False
        self._ct = None
        self._h = None
        self._default = None

        if not self.is_windows:
            return

        try:
            import ctypes
            self._ct = ctypes
            k32 = ctypes.windll.kernel32
            self._h = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE

            # Get default console color attributes
            csbi = ctypes.create_string_buffer(22)
            if k32.GetConsoleScreenBufferInfo(self._h, csbi):
                self._default = int.from_bytes(csbi.raw[4:6], "little")
            else:
                self._default = 7  # gray

            self.ok = True
        except Exception:
            self.ok = False

    def _set_red(self) -> None:
        if not self.ok:
            return
        try:
            k32 = self._ct.windll.kernel32
            # bright red: FOREGROUND_RED (0x0004) + FOREGROUND_INTENSITY (0x0008)
            k32.SetConsoleTextAttribute(self._h, 0x0004 | 0x0008)
        except Exception:
            pass

    def _reset(self) -> None:
        if not self.ok:
            return
        try:
            k32 = self._ct.windll.kernel32
            k32.SetConsoleTextAttribute(self._h, int(self._default) if self._default is not None else 7)
        except Exception:
            pass

    def print_red(self, msg: str) -> None:
        if self.is_windows and self.ok:
            self._set_red()
            print(msg)
            self._reset()
        else:
            # Non-windows: keep it simple to avoid ANSI weirdness
            print(msg)

    def input_red(self, prompt: str) -> str:
        if self.is_windows and self.ok:
            self._set_red()
            try:
                return input(prompt)
            finally:
                self._reset()
        return input(prompt)

RED = RedConsole()

def log(msg: str) -> None:
    RED.print_red(f"[+] {msg}")

def warn(msg: str) -> None:
    RED.print_red(f"[!] {msg}")

def banner() -> None:
    RED.print_red("")
    RED.print_red("=== PROJECT REDEYE ===")
    RED.print_red("")


def pause_if_windows() -> None:
    if os.name == "nt":
        try:
            RED.input_red("\nPress ENTER to exit...")
        except Exception:
            pass


# =========================
# MODELS
# =========================

@dataclass
class DNSRecord:
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)

@dataclass
class HTTPProbe:
    url: str
    final_url: str
    status: int
    title: str = ""
    server: str = ""
    content_type: str = ""

@dataclass
class PortOpen:
    port: int
    protocol: str = "tcp"
    state: str = "open"

@dataclass
class Asset:
    host: str
    dns: DNSRecord = field(default_factory=DNSRecord)
    http: List[HTTPProbe] = field(default_factory=list)
    ports: List[PortOpen] = field(default_factory=list)

@dataclass
class Report:
    target: str
    started_at: str
    finished_at: str
    config: Dict[str, object]
    counts: Dict[str, int]
    source_stats: Dict[str, int]
    assets: List[Asset]


# =========================
# CONSTANTS
# =========================

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0",
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389,
    443, 445, 465, 587, 636, 993, 995, 1433, 1521, 1723, 2049,
    2375, 2376, 3000, 3306, 3389, 4000, 4444, 5000, 5432, 5601,
    5672, 5900, 6379, 6443, 6667, 7001, 8000, 8008, 8080, 8081,
    8443, 9000, 9090, 9200, 9300, 11211, 27017
]


# =========================
# SAFE OUTPUT DIRECTORY FIX
# =========================

def script_dir() -> Path:
    try:
        return Path(__file__).resolve().parent
    except Exception:
        return Path.cwd()

def _try_mkdir(p: Path) -> bool:
    try:
        p.mkdir(parents=True, exist_ok=True)
        # quick write test (CFA/OneDrive sometimes blocks create OR write)
        test_file = p / ".redeye_write_test.tmp"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return True
    except Exception:
        return False

def safe_out_root(out_arg: str) -> Path:
    """
    Guarantees a writable root output directory.

    Rules:
    - Default: <script_dir>/reports
    - Relative paths: <script_dir>/<out_arg>
    - If user enters Documents/Desktop: map to the real user folder + /redeye_reports
    - If blocked: fall back to %TEMP%/redeye_reports
    - If still blocked: fall back to <script_dir>/reports
    """
    base = script_dir()
    out_arg = (out_arg or "reports").strip()

    # Map common aliases on Windows
    candidate: Path
    if os.name == "nt":
        user = Path(os.path.expanduser("~"))
        low = out_arg.lower().strip("\\/ ")
        if low in ("documents", "my documents", "docs"):
            candidate = user / "Documents" / "redeye_reports"
        elif low in ("desktop",):
            candidate = user / "Desktop" / "redeye_reports"
        else:
            p = Path(out_arg)
            candidate = p if p.is_absolute() else (base / p)
    else:
        p = Path(out_arg)
        candidate = p if p.is_absolute() else (base / p)

    # 1) try requested candidate
    if _try_mkdir(candidate):
        return candidate

    # 2) temp fallback (most reliable)
    tmp_base = Path(os.environ.get("TEMP") or os.environ.get("TMP") or str(base))
    tmp = tmp_base / "redeye_reports"
    if _try_mkdir(tmp):
        warn(f"Output blocked. Using TEMP instead: {tmp}")
        return tmp

    # 3) script folder fallback
    final = base / "reports"
    _try_mkdir(final)
    warn(f"Output blocked. Using script reports folder: {final}")
    return final


# =========================
# HELPERS
# =========================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def is_valid_domain(d: str) -> bool:
    d = d.strip().lower().rstrip(".")
    return bool(re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", d))

def in_scope(host: str, domain: str) -> bool:
    h = host.strip().lower().rstrip(".")
    d = domain.strip().lower().rstrip(".")
    return h == d or h.endswith("." + d)

def uniq_sorted(items: Iterable[str]) -> List[str]:
    return sorted({i.strip().lower().rstrip(".") for i in items if i and i.strip()})

def parse_title(html: str) -> str:
    m = TITLE_RE.search(html or "")
    if not m:
        return ""
    t = re.sub(r"\s+", " ", m.group(1)).strip()
    return t[:200]

def decode_body(body: bytes) -> str:
    if not body:
        return ""
    for enc in ("utf-8", "latin-1"):
        try:
            return body.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""

def read_url(url: str, timeout: int, ctx: Optional[ssl.SSLContext]) -> Tuple[int, bytes, str, Dict[str, str]]:
    headers = {"User-Agent": random.choice(UA_POOL)}
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            body = resp.read() or b""
            final_url = resp.geturl() or url
            hdrs = {}
            try:
                for k, v in resp.headers.items():
                    hdrs[str(k).lower()] = str(v)
            except Exception:
                pass
            return status, body, final_url, hdrs
    except HTTPError as e:
        try:
            body = e.read() or b""
        except Exception:
            body = b""
        return int(getattr(e, "code", 0) or 0), body, url, {}
    except (URLError, ssl.SSLError):
        return 0, b"", url, {}
    except Exception:
        return 0, b"", url, {}

def safe_workers(n: int, low: int, high: int) -> int:
    try:
        n = int(n)
    except Exception:
        n = low
    return max(low, min(high, n))

def parse_ports(s: str) -> List[int]:
    s = (s or "").strip().lower()
    if not s or s == "common":
        return COMMON_PORTS
    if "-" in s:
        a, b = s.split("-", 1)
        lo = max(1, int(a))
        hi = min(65535, int(b))
        if lo > hi:
            lo, hi = hi, lo
        return list(range(lo, hi + 1))
    out: List[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        p = int(part)
        if 1 <= p <= 65535:
            out.append(p)
    return out


# =========================
# ENUMERATION (PASSIVE)
# =========================

def fetch_crtsh(domain: str, timeout: int, verify_tls: bool) -> Set[str]:
    out: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()  # noqa: SLF001
    status, body, _, _ = read_url(url, timeout=timeout, ctx=ctx)
    if status != 200 or not body:
        return out

    text = decode_body(body)

    try:
        data = json.loads(text)
        if isinstance(data, list):
            for row in data:
                name = str(row.get("name_value", "")).strip()
                if not name:
                    continue
                for n in name.splitlines():
                    n = n.strip().lower().rstrip(".")
                    if n.startswith("*."):
                        n = n[2:]
                    if in_scope(n, domain):
                        out.add(n)
            return out
    except Exception:
        pass

    # regex fallback if crt.sh returns weird output
    for m in re.findall(r'"name_value"\s*:\s*"([^"]+)"', text):
        for n in m.split("\\n"):
            n = n.strip().lower().rstrip(".")
            if n.startswith("*."):
                n = n[2:]
            if in_scope(n, domain):
                out.add(n)

    return out

def fetch_hackertarget(domain: str, timeout: int) -> Set[str]:
    out: Set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    status, body, _, _ = read_url(url, timeout=timeout, ctx=ssl._create_unverified_context())  # noqa: SLF001
    if status != 200 or not body:
        return out
    text = decode_body(body)
    if "error" in text.lower():
        return out
    for line in text.splitlines():
        host = line.split(",")[0].strip().lower().rstrip(".")
        if in_scope(host, domain):
            out.add(host)
    return out

def fetch_wayback(domain: str, timeout: int, verify_tls: bool) -> Set[str]:
    out: Set[str] = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()  # noqa: SLF001
    status, body, _, _ = read_url(url, timeout=timeout, ctx=ctx)
    if status != 200 or not body:
        return out
    text = decode_body(body)
    try:
        data = json.loads(text)
        if not isinstance(data, list):
            return out
        for row in data[1:]:
            if not row:
                continue
            u = row[0]
            try:
                host = (urlparse(u).hostname or "").lower().rstrip(".")
            except Exception:
                continue
            if in_scope(host, domain):
                out.add(host)
    except Exception:
        return out
    return out

def passive_enum(domain: str, timeout: int, jitter: float, verify_tls: bool) -> Tuple[Set[str], Dict[str, int]]:
    sources = [
        ("crtsh", lambda: fetch_crtsh(domain, timeout, verify_tls)),
        ("hackertarget", lambda: fetch_hackertarget(domain, timeout)),
        ("wayback", lambda: fetch_wayback(domain, timeout, verify_tls)),
    ]
    found: Set[str] = set()
    stats: Dict[str, int] = {}
    for name, fn in sources:
        time.sleep(max(0.0, float(jitter)))
        try:
            subs = fn()
        except Exception:
            subs = set()
        stats[name] = len(subs)
        found |= subs
        log(f"Passive {name} -> {len(subs)}")
    found.add(domain)
    return found, stats


# =========================
# DNS
# =========================

def resolve_host(host: str) -> DNSRecord:
    rec = DNSRecord()
    try:
        for res in socket.getaddrinfo(host, None):
            ip = res[4][0]
            if ":" in ip:
                if ip not in rec.aaaa:
                    rec.aaaa.append(ip)
            else:
                if ip not in rec.a:
                    rec.a.append(ip)
    except Exception:
        pass
    rec.a.sort()
    rec.aaaa.sort()
    return rec

def dns_enrich(hosts: Iterable[str], workers: int) -> Dict[str, DNSRecord]:
    out: Dict[str, DNSRecord] = {}
    hosts_list = list(hosts)
    workers = safe_workers(workers, 1, 150)
    log(f"DNS enrichment ({workers} workers)…")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(resolve_host, h): h for h in hosts_list}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                out[h] = fut.result()
            except Exception:
                out[h] = DNSRecord()
    return out


# =========================
# HTTP
# =========================

def probe_one(url: str, timeout: int, verify_tls: bool) -> Optional[HTTPProbe]:
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()  # noqa: SLF001
    status, body, final_url, hdrs = read_url(url, timeout=timeout, ctx=ctx)
    if status == 0:
        return None
    html = decode_body(body[:200000])
    title = parse_title(html)
    return HTTPProbe(
        url=url,
        final_url=final_url,
        status=int(status),
        title=title,
        server=(hdrs.get("server", "") or "")[:120],
        content_type=(hdrs.get("content-type", "") or "")[:120],
    )

def http_probe(hosts: Iterable[str], workers: int, timeout: int, verify_tls: bool) -> Dict[str, List[HTTPProbe]]:
    out: Dict[str, List[HTTPProbe]] = {h: [] for h in hosts}
    workers = safe_workers(workers, 1, 120)
    urls: List[Tuple[str, str]] = []
    for h in hosts:
        urls.append((h, f"https://{h}"))
        urls.append((h, f"http://{h}"))
    log(f"HTTP probing ({workers} workers)…")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_one, url, timeout, verify_tls): (host, url) for host, url in urls}
        for fut in as_completed(futs):
            host, _ = futs[fut]
            try:
                res = fut.result()
                if res:
                    out[host].append(res)
            except Exception:
                continue
    for h in out:
        out[h].sort(key=lambda p: (0 if p.url.startswith("https://") else 1, p.url))
    return out


# =========================
# PORT SCAN (OPTIONAL)
# =========================

def tcp_is_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def port_scan(
    hosts: Iterable[str],
    dns_map: Dict[str, DNSRecord],
    ports: List[int],
    workers: int,
    timeout: float,
    max_ips_per_host: int,
) -> Dict[str, List[PortOpen]]:
    out: Dict[str, List[PortOpen]] = {h: [] for h in hosts}

    workers = safe_workers(workers, 1, 400)
    timeout = max(0.1, float(timeout))
    max_ips_per_host = max(1, int(max_ips_per_host))

    tasks: List[Tuple[str, str, int]] = []
    for h in hosts:
        ips = (dns_map.get(h) or DNSRecord()).a[:max_ips_per_host]
        for ip in ips:
            for p in ports:
                tasks.append((h, ip, int(p)))

    if not tasks:
        return out

    log(f"Port scan ({workers} workers) across {len(tasks)} checks…")

    def work(t: Tuple[str, str, int]) -> Tuple[str, int, bool]:
        h, ip, p = t
        return h, p, tcp_is_open(ip, p, timeout)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(work, t): t for t in tasks}
        for fut in as_completed(futs):
            try:
                host, port, ok = fut.result()
                if ok:
                    out[host].append(PortOpen(port=port))
            except Exception:
                continue

    for h in out:
        out[h].sort(key=lambda x: x.port)
    return out


# =========================
# REPORTING
# =========================

def write_outputs(report: Report, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "report.json").write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")

    with (out_dir / "report.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "a", "aaaa", "http_url", "status", "title", "server", "content_type", "ports"])
        for a in report.assets:
            a_ips = ",".join(a.dns.a)
            a_aaaa = ",".join(a.dns.aaaa)
            ports = ",".join(str(p.port) for p in a.ports)
            if a.http:
                for hp in a.http:
                    w.writerow([a.host, a_ips, a_aaaa, hp.final_url, hp.status, hp.title, hp.server, hp.content_type, ports])
            else:
                w.writerow([a.host, a_ips, a_aaaa, "", "", "", "", "", ports])

    md: List[str] = []
    md.append(f"# Project Redeye Report: `{report.target}`")
    md.append("")
    md.append(f"- Started: {report.started_at}")
    md.append(f"- Finished: {report.finished_at}")
    md.append("")
    md.append("## Counts")
    for k, v in report.counts.items():
        md.append(f"- {k}: {v}")
    md.append("")
    md.append("## Passive source stats")
    for k, v in report.source_stats.items():
        md.append(f"- {k}: {v}")
    md.append("")
    for a in report.assets:
        md.append(f"## {a.host}")
        md.append("")
        md.append(f"- A: {', '.join(a.dns.a) if a.dns.a else 'none'}")
        md.append(f"- AAAA: {', '.join(a.dns.aaaa) if a.dns.aaaa else 'none'}")
        if a.ports:
            md.append(f"- Open ports: {', '.join(str(p.port) for p in a.ports)}")
        else:
            md.append("- Open ports: none (or not scanned)")
        if a.http:
            md.append("")
            md.append("| URL | Status | Title | Server | Type |")
            md.append("|---|---:|---|---|---|")
            for hp in a.http:
                md.append(f"| {hp.final_url} | {hp.status} | {hp.title} | {hp.server} | {hp.content_type} |")
        md.append("")
    (out_dir / "report.md").write_text("\n".join(md), encoding="utf-8")


# =========================
# UI / CLI
# =========================

def prompt_yes_no(msg: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    while True:
        ans = RED.input_red(f"{msg} [{d}]: ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False

def prompt_int(msg: str, default: int, low: int, high: int) -> int:
    while True:
        ans = RED.input_red(f"{msg} [{default}]: ").strip()
        if not ans:
            return default
        try:
            v = int(ans)
            return max(low, min(high, v))
        except Exception:
            warn("Enter a number.")

def prompt_str(msg: str, default: str) -> str:
    ans = RED.input_red(f"{msg} [{default}]: ").strip()
    return ans if ans else default

def interactive_config() -> argparse.Namespace:
    banner()
    RED.print_red("Only run on targets you are authorized to test.\n")

    domain = RED.input_red("Target domain (example.com): ").strip().lower().rstrip(".")
    while not is_valid_domain(domain):
        domain = RED.input_red("Invalid domain. Try again (example.com): ").strip().lower().rstrip(".")

    # IMPORTANT: default is SAFE
    out = prompt_str("Output folder", "reports")
    timeout = prompt_int("HTTP timeout seconds", 15, 3, 60)
    verify_tls = prompt_yes_no("Verify TLS certificates?", default=False)
    jitter = float(prompt_str("Passive source jitter seconds", "0.2"))

    dns_workers = prompt_int("DNS workers", 80, 1, 150)
    http_workers = prompt_int("HTTP workers", 60, 1, 120)

    scan_ports = prompt_yes_no("Enable port scan (TCP connect)?", default=False)
    ports = "common"
    port_workers = 200
    port_timeout = 0.7
    max_ips = 2

    if scan_ports:
        ports = prompt_str("Ports (common OR 80,443 OR 1-1024)", "common")
        port_workers = prompt_int("Port scan workers", 200, 1, 400)
        port_timeout = float(prompt_str("Per-port timeout seconds", "0.7"))
        max_ips = prompt_int("Max IPs per host (A records) to scan", 2, 1, 5)

    verbose = prompt_yes_no("Verbose logging?", default=True)

    return argparse.Namespace(
        domain=domain,
        out=out,
        timeout=timeout,
        verify_tls=verify_tls,
        jitter=jitter,
        dns_workers=dns_workers,
        http_workers=http_workers,
        scan_ports=scan_ports,
        ports=ports,
        port_workers=port_workers,
        port_timeout=port_timeout,
        max_ips=max_ips,
        verbose=verbose,
    )

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="redeye", description="Project Redeye")
    ap.add_argument("domain", nargs="?", help="Target domain (example.com)")
    ap.add_argument("--out", default="reports", help="Output folder")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--verify-tls", action="store_true")
    ap.add_argument("--jitter", type=float, default=0.2)
    ap.add_argument("--dns-workers", type=int, default=80)
    ap.add_argument("--http-workers", type=int, default=60)
    ap.add_argument("--scan-ports", action="store_true")
    ap.add_argument("--ports", default="common")
    ap.add_argument("--port-workers", type=int, default=200)
    ap.add_argument("--port-timeout", type=float, default=0.7)
    ap.add_argument("--max-ips", type=int, default=2)
    ap.add_argument("--verbose", action="store_true")

    args = ap.parse_args(argv)
    if not args.domain:
        return interactive_config()
    return args


# =========================
# MAIN
# =========================

def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    domain = args.domain.strip().lower().rstrip(".")
    if not is_valid_domain(domain):
        warn(f"Invalid domain: {domain}")
        return 2

    banner()
    log(f"Starting on {domain}")

    candidates, source_stats = passive_enum(
        domain=domain,
        timeout=int(args.timeout),
        jitter=float(args.jitter),
        verify_tls=bool(args.verify_tls),
    )

    candidates = {h for h in candidates if in_scope(h, domain)}
    candidates = set(uniq_sorted(candidates))
    log(f"Candidates (scoped): {len(candidates)}")

    dns_map = dns_enrich(candidates, workers=int(args.dns_workers))
    resolved = [h for h in candidates if (dns_map.get(h) and (dns_map[h].a or dns_map[h].aaaa))]
    log(f"Resolved hosts: {len(resolved)}")

    http_map = http_probe(
        resolved,
        workers=int(args.http_workers),
        timeout=int(args.timeout),
        verify_tls=bool(args.verify_tls),
    )
    http_alive = sum(1 for h in resolved if http_map.get(h))
    log(f"HTTP alive hosts: {http_alive}")

    ports_map: Dict[str, List[PortOpen]] = {h: [] for h in resolved}
    ports_list: List[int] = []
    if bool(args.scan_ports):
        ports_list = parse_ports(str(args.ports))
        ports_map = port_scan(
            resolved,
            dns_map,
            ports=ports_list,
            workers=int(args.port_workers),
            timeout=float(args.port_timeout),
            max_ips_per_host=int(args.max_ips),
        )

    assets: List[Asset] = []
    for h in resolved:
        assets.append(
            Asset(
                host=h,
                dns=dns_map.get(h, DNSRecord()),
                http=http_map.get(h, []),
                ports=ports_map.get(h, []),
            )
        )
    assets.sort(key=lambda a: (1 if a.http else 0, len(a.ports), a.host), reverse=True)

    started = utc_now()
    finished = utc_now()

    report = Report(
        target=domain,
        started_at=started,
        finished_at=finished,
        config={
            "timeout": int(args.timeout),
            "verify_tls": bool(args.verify_tls),
            "dns_workers": int(args.dns_workers),
            "http_workers": int(args.http_workers),
            "scan_ports": bool(args.scan_ports),
            "ports": ("common" if str(args.ports).lower() == "common" else ports_list),
            "port_workers": int(args.port_workers),
            "port_timeout": float(args.port_timeout),
            "max_ips": int(args.max_ips),
        },
        counts={
            "candidates_total": len(candidates),
            "hosts_resolved": len(resolved),
            "http_alive_hosts": http_alive,
            "total_assets": len(assets),
        },
        source_stats=source_stats,
        assets=assets,
    )

    # CRITICAL FIX: always resolve to a writable location
    out_root = safe_out_root(str(args.out))
    out_dir = out_root / domain / datetime.now().strftime("%Y%m%d_%H%M%S")
    write_outputs(report, out_dir)

    log(f"Done. Output folder: {out_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        msg = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        try:
            Path("redeye_last_crash.txt").write_text(msg, encoding="utf-8")
        except Exception:
            pass
        warn("REDEYE CRASHED. Traceback saved to redeye_last_crash.txt")
        print(msg)
        pause_if_windows()
        raise
    finally:
        pause_if_windows()
