#!/usr/bin/env python3
"""
Project Redeye

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
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class WinConsole:
    def __init__(self) -> None:
        self._win = (os.name == "nt")
        self._ok = False
        self._ct = None
        self._h = None
        self._default = 7

        if not self._win:
            return

        try:
            import ctypes
            self._ct = ctypes
            k32 = ctypes.windll.kernel32
            self._h = k32.GetStdHandle(-11)

            csbi = ctypes.create_string_buffer(22)
            if k32.GetConsoleScreenBufferInfo(self._h, csbi):
                self._default = int.from_bytes(csbi.raw[4:6], "little")

            self._ok = True
        except Exception:
            self._ok = False

    def _set_red(self) -> None:
        if not (self._win and self._ok):
            return
        try:
            self._ct.windll.kernel32.SetConsoleTextAttribute(self._h, 0x0004 | 0x0008)
        except Exception:
            pass

    def _reset(self) -> None:
        if not (self._win and self._ok):
            return
        try:
            self._ct.windll.kernel32.SetConsoleTextAttribute(self._h, int(self._default))
        except Exception:
            pass

    def red_print(self, text: str) -> None:
        if self._win and self._ok:
            self._set_red()
            print(text)
            self._reset()
        else:
            print(text)

    def red_input(self, prompt: str) -> str:
        if self._win and self._ok:
            self._set_red()
            try:
                return input(prompt)
            finally:
                self._reset()
        return input(prompt)

    @property
    def is_windows(self) -> bool:
        return self._win


console = WinConsole()


def info(msg: str) -> None:
    console.red_print(f"[+] {msg}")


def warn(msg: str) -> None:
    console.red_print(f"[!] {msg}")


def pause_exit() -> None:
    if console.is_windows:
        try:
            console.red_input("\nPress ENTER to exit...")
        except Exception:
            pass


@dataclass
class DNSRecord:
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)


@dataclass
class HTTPResult:
    url: str
    final_url: str
    status: int
    title: str = ""
    server: str = ""
    content_type: str = ""


@dataclass
class OpenPort:
    port: int
    protocol: str = "tcp"
    state: str = "open"


@dataclass
class Asset:
    host: str
    dns: DNSRecord = field(default_factory=DNSRecord)
    http: List[HTTPResult] = field(default_factory=list)
    ports: List[OpenPort] = field(default_factory=list)


@dataclass
class Report:
    target: str
    started_at: str
    finished_at: str
    config: Dict[str, object]
    counts: Dict[str, int]
    source_stats: Dict[str, int]
    assets: List[Asset]


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389,
    443, 445, 465, 587, 636, 993, 995, 1433, 1521, 1723, 2049,
    2375, 2376, 3000, 3306, 3389, 4000, 4444, 5000, 5432, 5601,
    5672, 5900, 6379, 6443, 6667, 7001, 8000, 8008, 8080, 8081,
    8443, 9000, 9090, 9200, 9300, 11211, 27017
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def valid_domain(d: str) -> bool:
    d = d.strip().lower().rstrip(".")
    return bool(re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", d))


def in_scope(host: str, domain: str) -> bool:
    h = host.strip().lower().rstrip(".")
    d = domain.strip().lower().rstrip(".")
    return h == d or h.endswith("." + d)


def normalize_hosts(items: Iterable[str]) -> List[str]:
    out = {x.strip().lower().rstrip(".") for x in items if x and x.strip()}
    return sorted(out)


def parse_title(html: str) -> str:
    m = TITLE_RE.search(html or "")
    if not m:
        return ""
    t = re.sub(r"\s+", " ", m.group(1)).strip()
    return t[:200]


def decode_bytes(data: bytes) -> str:
    if not data:
        return ""
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc, errors="ignore")
        except Exception:
            pass
    return ""


def script_dir() -> Path:
    try:
        return Path(__file__).resolve().parent
    except Exception:
        return Path.cwd()


def can_write(p: Path) -> bool:
    try:
        p.mkdir(parents=True, exist_ok=True)
        t = p / ".redeye_tmp"
        t.write_text("ok", encoding="utf-8")
        t.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def pick_output_root(out_arg: str) -> Path:
    base = script_dir()
    out_arg = (out_arg or "reports").strip()

    if os.name == "nt":
        user = Path(os.path.expanduser("~"))
        key = out_arg.lower().strip("\\/ ")
        if key in ("documents", "my documents", "docs"):
            candidate = user / "Documents" / "redeye_reports"
        elif key == "desktop":
            candidate = user / "Desktop" / "redeye_reports"
        else:
            p = Path(out_arg)
            candidate = p if p.is_absolute() else (base / p)
    else:
        p = Path(out_arg)
        candidate = p if p.is_absolute() else (base / p)

    if can_write(candidate):
        return candidate

    tmp_base = Path(os.environ.get("TEMP") or os.environ.get("TMP") or str(base))
    tmp = tmp_base / "redeye_reports"
    if can_write(tmp):
        warn(f"Output blocked. Using: {tmp}")
        return tmp

    fallback = base / "reports"
    can_write(fallback)
    warn(f"Output blocked. Using: {fallback}")
    return fallback


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


def fetch_url(url: str, timeout: int, ctx: Optional[ssl.SSLContext]) -> Tuple[int, bytes, str, Dict[str, str]]:
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


def from_crtsh(domain: str, timeout: int, verify_tls: bool) -> Set[str]:
    out: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()  # noqa: SLF001

    status, body, _, _ = fetch_url(url, timeout=timeout, ctx=ctx)
    if status != 200 or not body:
        return out

    text = decode_bytes(body)
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for row in data:
                raw = str(row.get("name_value", "")).strip()
                if not raw:
                    continue
                for name in raw.splitlines():
                    name = name.strip().lower().rstrip(".")
                    if name.startswith("*."):
                        name = name[2:]
                    if in_scope(name, domain):
                        out.add(name)
            return out
    except Exception:
        pass

    for m in re.findall(r'"name_value"\s*:\s*"([^"]+)"', text):
        for name in m.split("\\n"):
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if in_scope(name, domain):
                out.add(name)

    return out


def from_hackertarget(domain: str, timeout: int) -> Set[str]:
    out: Set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    status, body, _, _ = fetch_url(url, timeout=timeout, ctx=ssl._create_unverified_context())  # noqa: SLF001
    if status != 200 or not body:
        return out

    text = decode_bytes(body)
    if "error" in text.lower():
        return out

    for line in text.splitlines():
        host = line.split(",")[0].strip().lower().rstrip(".")
        if in_scope(host, domain):
            out.add(host)

    return out


def from_wayback(domain: str, timeout: int, verify_tls: bool) -> Set[str]:
    out: Set[str] = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()  # noqa: SLF001

    status, body, _, _ = fetch_url(url, timeout=timeout, ctx=ctx)
    if status != 200 or not body:
        return out

    text = decode_bytes(body)
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
    found: Set[str] = set()
    stats: Dict[str, int] = {}

    sources = [
        ("crtsh", lambda: from_crtsh(domain, timeout, verify_tls)),
        ("hackertarget", lambda: from_hackertarget(domain, timeout)),
        ("wayback", lambda: from_wayback(domain, timeout, verify_tls)),
    ]

    for name, fn in sources:
        time.sleep(max(0.0, float(jitter)))
        try:
            subs = fn()
        except Exception:
            subs = set()
        stats[name] = len(subs)
        found |= subs
        info(f"{name}: {len(subs)}")

    found.add(domain)
    return found, stats


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
    hosts_list = list(hosts)
    workers = safe_workers(workers, 1, 150)
    out: Dict[str, DNSRecord] = {}

    info(f"DNS workers: {workers}")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(resolve_host, h): h for h in hosts_list}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                out[h] = fut.result()
            except Exception:
                out[h] = DNSRecord()

    return out


def probe_one(url: str, timeout: int, verify_tls: bool) -> Optional[HTTPResult]:
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()  # noqa: SLF001

    status, body, final_url, hdrs = fetch_url(url, timeout=timeout, ctx=ctx)
    if status == 0:
        return None

    html = decode_bytes(body[:200000])
    return HTTPResult(
        url=url,
        final_url=final_url,
        status=int(status),
        title=parse_title(html),
        server=(hdrs.get("server", "") or "")[:120],
        content_type=(hdrs.get("content-type", "") or "")[:120],
    )


def http_probe(hosts: Iterable[str], workers: int, timeout: int, verify_tls: bool) -> Dict[str, List[HTTPResult]]:
    hosts_list = list(hosts)
    workers = safe_workers(workers, 1, 120)
    out: Dict[str, List[HTTPResult]] = {h: [] for h in hosts_list}

    pairs: List[Tuple[str, str]] = []
    for h in hosts_list:
        pairs.append((h, f"https://{h}"))
        pairs.append((h, f"http://{h}"))

    info(f"HTTP workers: {workers}")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_one, u, timeout, verify_tls): (h, u) for h, u in pairs}
        for fut in as_completed(futs):
            host, _ = futs[fut]
            try:
                r = fut.result()
                if r:
                    out[host].append(r)
            except Exception:
                pass

    for h in out:
        out[h].sort(key=lambda p: (0 if p.url.startswith("https://") else 1, p.url))

    return out


def tcp_open(ip: str, port: int, timeout: float) -> bool:
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
    max_ips: int,
) -> Dict[str, List[OpenPort]]:
    hosts_list = list(hosts)
    workers = safe_workers(workers, 1, 400)
    timeout = max(0.1, float(timeout))
    max_ips = max(1, int(max_ips))

    out: Dict[str, List[OpenPort]] = {h: [] for h in hosts_list}
    tasks: List[Tuple[str, str, int]] = []

    for h in hosts_list:
        ips = (dns_map.get(h) or DNSRecord()).a[:max_ips]
        for ip in ips:
            for p in ports:
                tasks.append((h, ip, int(p)))

    if not tasks:
        return out

    info(f"Port workers: {workers} (checks: {len(tasks)})")

    def work(t: Tuple[str, str, int]) -> Tuple[str, int, bool]:
        h, ip, p = t
        return h, p, tcp_open(ip, p, timeout)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(work, t): t for t in tasks}
        for fut in as_completed(futs):
            try:
                host, port, ok = fut.result()
                if ok:
                    out[host].append(OpenPort(port=port))
            except Exception:
                pass

    for h in out:
        out[h].sort(key=lambda x: x.port)

    return out


def write_reports(report: Report, out_dir: Path) -> None:
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

    lines: List[str] = []
    lines.append(f"# Project Redeye Report: `{report.target}`")
    lines.append("")
    lines.append(f"- Started: {report.started_at}")
    lines.append(f"- Finished: {report.finished_at}")
    lines.append("")
    lines.append("## Counts")
    for k, v in report.counts.items():
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("## Sources")
    for k, v in report.source_stats.items():
        lines.append(f"- {k}: {v}")
    lines.append("")
    for a in report.assets:
        lines.append(f"## {a.host}")
        lines.append("")
        lines.append(f"- A: {', '.join(a.dns.a) if a.dns.a else 'none'}")
        lines.append(f"- AAAA: {', '.join(a.dns.aaaa) if a.dns.aaaa else 'none'}")
        lines.append(f"- Open ports: {', '.join(str(p.port) for p in a.ports) if a.ports else 'none (or not scanned)'}")
        if a.http:
            lines.append("")
            lines.append("| URL | Status | Title | Server | Type |")
            lines.append("|---|---:|---|---|---|")
            for hp in a.http:
                lines.append(f"| {hp.final_url} | {hp.status} | {hp.title} | {hp.server} | {hp.content_type} |")
        lines.append("")
    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def ask_bool(prompt: str, default: bool) -> bool:
    tail = "Y/n" if default else "y/N"
    while True:
        s = console.red_input(f"{prompt} [{tail}]: ").strip().lower()
        if not s:
            return default
        if s in ("y", "yes"):
            return True
        if s in ("n", "no"):
            return False


def ask_int(prompt: str, default: int, lo: int, hi: int) -> int:
    while True:
        s = console.red_input(f"{prompt} [{default}]: ").strip()
        if not s:
            return default
        try:
            v = int(s)
            return max(lo, min(hi, v))
        except Exception:
            warn("Enter a number.")


def ask_str(prompt: str, default: str) -> str:
    s = console.red_input(f"{prompt} [{default}]: ").strip()
    return s if s else default


def interactive_args() -> argparse.Namespace:
    console.red_print("")
    console.red_print("Project Redeye")
    console.red_print("")

    domain = console.red_input("Target domain: ").strip().lower().rstrip(".")
    while not valid_domain(domain):
        domain = console.red_input("Invalid domain. Try again: ").strip().lower().rstrip(".")

    out = ask_str("Output folder", "reports")
    timeout = ask_int("HTTP timeout seconds", 15, 3, 60)
    verify_tls = ask_bool("Verify TLS certificates?", False)
    jitter = float(ask_str("Passive source jitter seconds", "0.2"))

    dns_workers = ask_int("DNS workers", 80, 1, 150)
    http_workers = ask_int("HTTP workers", 60, 1, 120)

    scan_ports = ask_bool("Enable port scan?", False)

    ports = "common"
    port_workers = 200
    port_timeout = 0.7
    max_ips = 2

    if scan_ports:
        ports = ask_str("Ports (common OR 80,443 OR 1-1024)", "common")
        port_workers = ask_int("Port scan workers", 200, 1, 400)
        port_timeout = float(ask_str("Per-port timeout seconds", "0.7"))
        max_ips = ask_int("Max A records per host to scan", 2, 1, 5)

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
    )


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="redeye", description="Project Redeye")
    p.add_argument("domain", nargs="?", help="Target domain (example.com)")
    p.add_argument("--out", default="reports", help="Output folder")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--verify-tls", action="store_true")
    p.add_argument("--jitter", type=float, default=0.2)
    p.add_argument("--dns-workers", type=int, default=80)
    p.add_argument("--http-workers", type=int, default=60)
    p.add_argument("--scan-ports", action="store_true")
    p.add_argument("--ports", default="common")
    p.add_argument("--port-workers", type=int, default=200)
    p.add_argument("--port-timeout", type=float, default=0.7)
    p.add_argument("--max-ips", type=int, default=2)

    args = p.parse_args(argv)
    if not args.domain:
        return interactive_args()
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    domain = args.domain.strip().lower().rstrip(".")
    if not valid_domain(domain):
        warn("Invalid domain.")
        return 2

    info(f"Target: {domain}")

    subs, source_stats = passive_enum(
        domain=domain,
        timeout=int(args.timeout),
        jitter=float(args.jitter),
        verify_tls=bool(args.verify_tls),
    )

    subs = {h for h in subs if in_scope(h, domain)}
    subs = set(normalize_hosts(subs))
    info(f"Candidates: {len(subs)}")

    dns_map = dns_enrich(subs, workers=int(args.dns_workers))
    resolved = [h for h in subs if (dns_map.get(h) and (dns_map[h].a or dns_map[h].aaaa))]
    info(f"Resolved: {len(resolved)}")

    http_map = http_probe(
        resolved,
        workers=int(args.http_workers),
        timeout=int(args.timeout),
        verify_tls=bool(args.verify_tls),
    )
    http_alive = sum(1 for h in resolved if http_map.get(h))
    info(f"HTTP alive: {http_alive}")

    ports_map: Dict[str, List[OpenPort]] = {h: [] for h in resolved}
    ports_list: List[int] = []
    if bool(args.scan_ports):
        ports_list = parse_ports(str(args.ports))
        ports_map = port_scan(
            resolved,
            dns_map,
            ports=ports_list,
            workers=int(args.port_workers),
            timeout=float(args.port_timeout),
            max_ips=int(args.max_ips),
        )

    assets: List[Asset] = []
    for h in resolved:
        assets.append(Asset(host=h, dns=dns_map.get(h, DNSRecord()), http=http_map.get(h, []), ports=ports_map.get(h, [])))

    assets.sort(key=lambda a: (1 if a.http else 0, len(a.ports), a.host), reverse=True)

    report = Report(
        target=domain,
        started_at=utc_now(),
        finished_at=utc_now(),
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
            "candidates_total": len(subs),
            "hosts_resolved": len(resolved),
            "http_alive_hosts": http_alive,
            "total_assets": len(assets),
        },
        source_stats=source_stats,
        assets=assets,
    )

    out_root = pick_output_root(str(args.out))
    out_dir = out_root / domain / datetime.now().strftime("%Y%m%d_%H%M%S")
    write_reports(report, out_dir)

    info(f"Saved: {out_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        try:
            Path("redeye_last_crash.txt").write_text(tb, encoding="utf-8")
        except Exception:
            pass
        warn("Crash logged to redeye_last_crash.txt")
        print(tb)
        pause_exit()
        raise
    finally:
        pause_exit()
