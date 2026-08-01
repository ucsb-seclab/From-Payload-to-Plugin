
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import logging
import base64
import os
import resource
import re
import sys
import time
import math
import shutil
from collections import defaultdict
from contextlib import asynccontextmanager

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    BarColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
)
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, unquote_to_bytes, urljoin, urlparse
from itertools import count

import httpx
try:
    import h2  # type: ignore  # noqa: F401

    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

try:
    import uvloop
    UVLOOP_AVAILABLE = True
except ImportError:
    UVLOOP_AVAILABLE = False

DEFAULT_HEADERS = {
    "accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "accept-language": "en-US,en;q=0.9",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "user-agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    ),
}

VERSION_QUERY_KEYS = ("ver", "version", "v")
VERSION_FILENAME_PATTERN = re.compile(r"(?:-|_)(\d+(?:\.\d+){0,3})")
JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")

@dataclass(slots=True)
class ScriptRef:

    source_url: Optional[str]
    inline_code: Optional[str]
    position: int

class _ScriptHTMLParser(HTMLParser):

    def __init__(self, document_url):
        super().__init__(convert_charrefs=True)
        self._document_url = document_url
        self._base_url = document_url
        self._base_overridden = False
        self._buffer: List[str] = []
        self._collect_inline = False
        self._position = 0
        self.scripts: List[ScriptRef] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            if tag.lower() == "base":
                attr_dict = {name.lower(): (value or "")
                             for name, value in attrs}
                href = attr_dict.get("href", "").strip()
                if href and not self._base_overridden:
                    self._base_url = urljoin(self._document_url, href)
                    self._base_overridden = True
            return
        attr_dict = {name.lower(): (value or "") for name, value in attrs}
        script_type = attr_dict.get("type", "").lower()
        if script_type and not any(token in script_type for token in ("javascript", "ecmascript", "module")):
            return
        src = attr_dict.get("src")
        if src:
            normalized = urljoin(self._base_url, src.strip())
            self.scripts.append(
                ScriptRef(source_url=normalized, inline_code=None, position=self._position))
            self._position += 1
            self._collect_inline = False
            self._buffer.clear()
        else:
            self._collect_inline = True
            self._buffer.clear()

    def handle_data(self, data):
        if self._collect_inline:
            self._buffer.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._collect_inline:
            inline = "".join(self._buffer).strip()
            if inline:
                self.scripts.append(
                    ScriptRef(source_url=None, inline_code=inline,
                              position=self._position)
                )
                self._position += 1
            self._collect_inline = False
            self._buffer.clear()

@dataclass
class StatsSnapshot:
    total: int
    processed: int
    successes: int
    failures: int
    external_scripts: int
    inline_scripts: int
    started_at: float
    failure_reasons: Dict[str, int]
    failure_notes: Dict[str, int]

class RunStats:
    def __init__(self, total):
        self.total = total
        self.processed = 0
        self.successes = 0
        self.failures = 0
        self.external_scripts = 0
        self.inline_scripts = 0
        self.started_at = time.time()
        self.failure_reasons: Dict[str, int] = defaultdict(int)
        self.failure_notes: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def record_result(
        self,
        success: bool,
        external: int,
        inline: int,
        failure_reason: Optional[str] = None,
        failure_context: Optional[str] = None,
    ):
        async with self._lock:
            self.processed += 1
            if success:
                self.successes += 1
            else:
                self.failures += 1
                reason = failure_reason or "unknown"
                self.failure_reasons[reason] += 1
                if failure_context:
                    self.failure_notes[failure_context] += 1
            self.external_scripts += external
            self.inline_scripts += inline

    async def snapshot(self):
        async with self._lock:
            return StatsSnapshot(
                total=self.total,
                processed=self.processed,
                successes=self.successes,
                failures=self.failures,
                external_scripts=self.external_scripts,
                inline_scripts=self.inline_scripts,
                started_at=self.started_at,
                failure_reasons=dict(self.failure_reasons),
                failure_notes=dict(self.failure_notes),
            )

class AdaptiveConcurrencyLimiter:

    def __init__(self, initial):
        self._limit = max(1, initial)
        self._sem = asyncio.Semaphore(self._limit)
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def slot(self):
        await self._sem.acquire()
        try:
            yield
        finally:
            self._sem.release()

    async def set_limit(self, new_limit):
        new_limit = max(1, new_limit)
        async with self._lock:
            if new_limit == self._limit:
                return
            if new_limit > self._limit:
                for _ in range(new_limit - self._limit):
                    self._sem.release()
            else:
                reduce_by = self._limit - new_limit
                for _ in range(reduce_by):
                    await self._sem.acquire()
            self._limit = new_limit

    @property
    def limit(self):
        return self._limit

def _sanitize_version(candidate):
    stripped = candidate.strip()
    if not stripped:
        return None
    if re.fullmatch(r"\d+(?:\.\d+){0,3}", stripped):
        return stripped
    return None

def extract_version(parsed_url):
    query = parse_qs(parsed_url.query)
    for key in VERSION_QUERY_KEYS:
        if key in query and query[key]:
            version = _sanitize_version(query[key][0])
            if version:
                return version, f"query:{key}"
    filename = Path(parsed_url.path).name
    match = VERSION_FILENAME_PATTERN.search(filename)
    if match:
        version = _sanitize_version(match.group(1))
        if version:
            return version, "filename"
    return None, None

def detect_wordpress_component(script_url):
    parsed = urlparse(script_url)
    path = parsed.path
    lowered = path.lower()
    markers = [
        ("plugin", "/wp-content/plugins/"),
        ("plugin", "/wp-content/mu-plugins/"),
        ("theme", "/wp-content/themes/"),
    ]
    for kind, marker in markers:
        idx = lowered.find(marker)
        if idx == -1:
            continue
        start = idx + len(marker)
        remainder = path[start:]
        if not remainder:
            continue
        parts = remainder.split("/")
        if not parts:
            continue
        name = parts[0]
        version, evidence = extract_version(parsed)
        return kind, name, version, evidence
    return None

def looks_like_js(url, content_type, sniff):
    content_type = (content_type or "").lower()
    if "javascript" in content_type or "ecmascript" in content_type:
        return True
    if content_type in {"text/plain", "application/octet-stream"}:
        return True
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in JS_EXTENSIONS):
        return True
    stripped = sniff.lstrip()
    js_tokens = (
        b"var ",
        b"let ",
        b"const ",
        b"function",
        b"(function",
        b"(()=>",
        b"import ",
        b"export ",
        b"/*!",
        b"/*",
        b"//",
        b"'use strict'",
        b'"use strict"',
    )
    for token in js_tokens:
        if stripped.startswith(token):
            return True
    return False

def is_http_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https")

def is_data_uri(url):
    return url.strip().lower().startswith("data:")

async def store_data_uri_script(
    data_url: str,
    dest_dir: Path,
    index: int,
    max_bytes: Optional[int],
):
    header, sep, payload = data_url.partition(",")
    if not sep:
        return None, 0, "malformed_data_uri"
    meta = header[5:]  # drop "data:"
    is_base64 = any(token.lower() == "base64" for token in meta.split(";"))
    try:
        if is_base64:
            raw = base64.b64decode(payload, validate=True)
        else:
            raw = unquote_to_bytes(payload)
    except Exception as exc:  # noqa: BLE001
        return None, 0, f"data_uri_decode_error:{exc}"
    if not raw:
        return None, 0, "data_uri_empty"
    if max_bytes is not None and len(raw) > max_bytes:
        raw = raw[:max_bytes]
    dest = dest_dir / f"external_data_{index:04d}.js"
    await asyncio.to_thread(dest_dir.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(dest.write_bytes, raw)
    return dest, len(raw), None

def count_targets(path):
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            count += 1
    return count

def read_cpu_times():
    try:
        with open("/proc/stat", "r", encoding="utf-8") as handle:
            line = handle.readline()
    except FileNotFoundError:
        return None
    parts = line.split()
    if parts[0] != "cpu":
        return None
    values = list(map(int, parts[1:]))
    total = sum(values)
    idle = values[3]
    return total, idle

def read_net_bytes(iface):
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as handle:
            for line in handle:
                if ":" not in line:
                    continue
                name, data = line.split(":", 1)
                if name.strip() == iface:
                    parts = data.split()
                    if len(parts) < 9:
                        return None
                    rx = int(parts[0])
                    tx = int(parts[8])
                    return rx, tx
    except FileNotFoundError:
        return None
    return None

def read_disk_bytes():
    try:
        with open("/proc/diskstats", "r", encoding="utf-8") as handle:
            read_sectors = 0
            write_sectors = 0
            for line in handle:
                parts = line.split()
                if len(parts) < 14:
                    continue
                name = parts[2]
                if name.startswith("loop") or name.startswith("ram") or name.startswith("fd"):
                    continue
                read_sectors += int(parts[5])
                write_sectors += int(parts[9])
            sector_size = 512
            return read_sectors * sector_size, write_sectors * sector_size
    except FileNotFoundError:
        return None
    except Exception:
        return None

def detect_primary_iface(preferred):
    if preferred:
        return preferred
    try:
        best_iface = None
        best_bytes = -1
        with open("/proc/net/dev", "r", encoding="utf-8") as handle:
            for line in handle:
                if ":" not in line:
                    continue
                name, data = line.split(":", 1)
                iface = name.strip()
                if iface == "lo" or iface.startswith(("docker", "veth", "br", "virbr")):
                    continue
                parts = data.split()
                if len(parts) < 9:
                    continue
                rx_bytes = int(parts[0])
                tx_bytes = int(parts[8])
                operstate_path = Path(f"/sys/class/net/{iface}/operstate")
                if operstate_path.exists():
                    try:
                        if operstate_path.read_text(encoding="utf-8").strip() != "up":
                            continue
                    except Exception:
                        pass
                total_bytes = rx_bytes + tx_bytes
                if total_bytes > best_bytes:
                    best_bytes = total_bytes
                    best_iface = iface
        return best_iface
    except FileNotFoundError:
        return None

def iter_targets(source):
    with source.open("r", encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            yield raw

def normalize_target(raw):
    candidate = raw.strip()
    if not candidate:
        raise ValueError("Empty target")
    parsed = urlparse(candidate)
    if parsed.scheme:
        return candidate
    return f"https://{candidate}"

async def fetch_html(
    client: httpx.AsyncClient,
    target: str,
    max_bytes: int,
):
    try:
        async with client.stream("GET", target, headers=DEFAULT_HEADERS) as response:
            status = response.status_code
            resolved = str(response.url)
            content_type = response.headers.get("content-type", "").lower()
            if status >= 400:
                return None, resolved, status, f"HTTP {status}"
            if "text/html" not in content_type and "xml" not in content_type:
                return None, resolved, status, f"content-type={content_type or 'unknown'}"

            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) >= max_bytes:
                    break
            encoding = response.encoding or "utf-8"
            try:
                html = body.decode(encoding, errors="replace")
            except LookupError as exc:
                logging.warning("Decode error for %s: %s", target, exc)
                return None, resolved, status, "decode_error"
            return html, resolved, status, None
    except RuntimeError as exc:
        if "client has been closed" in str(exc).lower():
            logging.info("HTTP client closed while fetching %s", target)
            return None, None, None, "client_closed"
        raise
    except httpx.TimeoutException as exc:
        logging.warning("Timeout while fetching %s: %s", target, exc)
        exc_name = exc.__class__.__name__.lower()
        timeout_map = {
            "readtimeout": "timeout_read",
            "writetimeout": "timeout_write",
            "connecttimeout": "timeout_connect",
            "pooltimeout": "timeout_pool",
            "timeoutexception": "timeout",
        }
        return None, None, None, timeout_map.get(exc_name, "timeout")
    except httpx.RequestError as exc:
        logging.warning("Request error for %s: %s", target, exc)
        return None, None, None, str(exc)
    return None, None, None, "unknown error"

NOTE_KEYWORDS = (
    ("non_html", ("content-type=",)),
    ("dns_error", ("name or service not known", "failure in name resolution",
     "dns error", "temporary failure in name resolution")),
    ("connection_reset", ("connection reset", "server disconnected without sending a response",
     "reset by peer", "remote end closed", "connection aborted", "connection closed")),
    ("connection_refused", ("connection refused",)),
    ("network_unreachable", ("network is unreachable", "no route to host")),
    ("timeout_read", ("timeout_read", "read timeout")),
    ("timeout_connect", ("timeout_connect", "connect timeout")),
    ("timeout_write", ("timeout_write", "write timeout")),
    ("timeout_pool", ("timeout_pool", "pool timeout")),
    ("timeout", ("timeout", "timed out")),
    ("stream_closed", ("client_closed", "server closed connection", "stream closed")),
    ("tls_error", ("ssl", "tls", "certificate", "handshake")),
    ("decode_error", ("decode_error", "codec can't decode", "unknown encoding")),
    ("os_resource_error", ("too many open files",
     "no file descriptors", "resource temporarily unavailable")),
)

def classify_fetch_failure(status, note):
    normalized_note = (note or "").strip().lower()
    if normalized_note:
        for reason, needles in NOTE_KEYWORDS:
            if any(needle in normalized_note for needle in needles):
                return reason
    if status is not None:
        if status >= 400:
            return f"http_{status}"
        return f"status_{status}"
    return "html_unavailable"

def hashed_value(value, length = 16):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]

def slugify_host(url):
    parsed = urlparse(url)
    candidate = parsed.netloc or parsed.path or url
    slug = re.sub(r"[^A-Za-z0-9.-]+", "_", candidate)
    return slug[:100] or "root"

async def download_script(
    client: httpx.AsyncClient,
    url: str,
    dest_dir: Path,
    index: int,
    max_bytes: Optional[int],
    chunk_size: int,
):
    file_name = f"external_{index:04d}_{hashed_value(url, 12)}.js"
    target_path = dest_dir / file_name
    target_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        async with client.stream("GET", url, headers=DEFAULT_HEADERS) as response:
            status = response.status_code
            if status >= 400:
                return None, 0, status, f"HTTP {status}"
            content_type = response.headers.get("content-type", "")
            written = 0
            sniffed = False
            file_handle = None
            try:
                async for chunk in response.aiter_bytes(chunk_size):
                    if not sniffed:
                        sniff = chunk[:1024]
                        if not looks_like_js(url, content_type, sniff):
                            note = (
                                f"content-type={content_type or 'unknown'}; "
                                "sniff=not_js"
                            )
                            return None, 0, status, note
                        await asyncio.to_thread(target_path.parent.mkdir, parents=True, exist_ok=True)
                        file_handle = await asyncio.to_thread(target_path.open, "wb")
                        sniffed = True
                    assert file_handle is not None
                    await asyncio.to_thread(file_handle.write, chunk)
                    written += len(chunk)
                    if max_bytes is not None and written >= max_bytes:
                        break
            finally:
                if file_handle:
                    await asyncio.to_thread(file_handle.close)
        return target_path, written, status, None
    except RuntimeError as exc:
        if "client has been closed" in str(exc).lower():
            logging.info("HTTP client closed while downloading %s", url)
            return None, 0, None, "client_closed"
        raise
    except httpx.RequestError as exc:
        logging.debug("Failed to download %s: %s", url, exc)
        return None, 0, None, str(exc)

async def store_inline_script(
    target_dir: Path,
    inline: str,
    idx: int,
    position: int,
    max_bytes: Optional[int],
):
    encoded = inline.encode("utf-8")
    if max_bytes is not None and len(encoded) > max_bytes:
        encoded = encoded[:max_bytes]

    await asyncio.to_thread(target_dir.mkdir, parents=True, exist_ok=True)
    target_path = target_dir / "inline_combined.js"

    header = (
        f"// --- INLINE SCRIPT #{idx:04d} (position={position}) START ---\n"
    ).encode("utf-8")
    footer = f"// --- INLINE SCRIPT #{idx:04d} END ---\n".encode("utf-8")

    def append_inline():
        mode = "wb" if idx == 0 else "ab"
        with target_path.open(mode) as handle:
            if idx == 0:
                handle.write(b"// Aggregated inline scripts\n\n")
            else:
                handle.write(b"\n")
            handle.write(header)
            start_offset = handle.tell()
            handle.write(encoded)
            end_offset = handle.tell()
            handle.write(b"\n")
            handle.write(footer)
        return start_offset, end_offset - start_offset

    start_offset, length = await asyncio.to_thread(append_inline)
    return target_path, length, start_offset

async def write_metadata(domain_dir, metadata, index_rows: Sequence[Sequence[str]]):
    await asyncio.to_thread(lambda: (domain_dir / "logs").mkdir(exist_ok=True, parents=True))
    await asyncio.to_thread(lambda: (domain_dir / "loaded_js").mkdir(exist_ok=True, parents=True))

    metadata_path = domain_dir / "metadata.json"
    await asyncio.to_thread(metadata_path.write_text, json.dumps(metadata, indent=2), encoding="utf-8")

    index_path = domain_dir / "loaded_js" / "index.csv"

    def write_csv():
        with index_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                ["position", "kind", "source", "bytes", "stored_at"])
            writer.writerows(index_rows)

    await asyncio.to_thread(write_csv)

async def write_logs(domain_dir, lines):
    logs_dir = domain_dir / "logs"
    await asyncio.to_thread(logs_dir.mkdir, parents=True, exist_ok=True)
    log_path = logs_dir / "requests.log"
    text = "\n".join(lines).strip()
    if text:
        content = text + "\n"
    else:
        content = ""
    await asyncio.to_thread(log_path.write_text, content, encoding="utf-8")

def add_fingerprint(collection, name, version, evidence, source):
    entry = collection.setdefault(
        name,
        {"name": name, "versions": [], "evidence": [], "sources": []},
    )
    if version and version not in entry["versions"]:
        entry["versions"].append(version)
    if evidence and evidence not in entry["evidence"]:
        entry["evidence"].append(evidence)
    if source not in entry["sources"]:
        entry["sources"].append(source)

def serialize_fingerprints(collection):
    result = []
    for entry in collection.values():
        entry["versions"].sort()
        entry["evidence"].sort()
        entry["sources"].sort()
        result.append(entry)
    return sorted(result, key=lambda item: item["name"])

def auto_tune_runtime(args: argparse.Namespace):
    cpu_count = os.cpu_count() or 4
    if args.concurrency is None:
        args.concurrency = max(8, min(2000, cpu_count * 12))

    if args.script_concurrency is None:
        args.script_concurrency = max(4, min(64, cpu_count * 2))

    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    fd_budget = max(1024, soft_limit - 1024)

    if args.max_connections is None:
        estimated = args.concurrency * args.script_concurrency * 2
        args.max_connections = min(
            max(estimated, args.concurrency * 20), fd_budget)
    else:
        args.max_connections = min(args.max_connections, fd_budget)

    if args.max_keepalive_connections is None:
        suggested = max(args.concurrency * 2, 100)
        args.max_keepalive_connections = min(suggested, args.max_connections)
    else:
        args.max_keepalive_connections = min(
            args.max_keepalive_connections, args.max_connections)

    logging.info(
        "Autotuned: concurrency=%s script_concurrency=%s max_connections=%s max_keepalive=%s (cpu=%s, fd_limit=%s)",
        args.concurrency,
        args.script_concurrency,
        args.max_connections,
        args.max_keepalive_connections,
        cpu_count,
        soft_limit,
    )

def format_duration(seconds):
    if seconds is None or seconds < 0 or math.isinf(seconds):
        return "n/a"
    seconds = int(seconds)
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"

async def status_reporter(
    queue: asyncio.Queue,
    stats: RunStats,
    interval: float,
    iface: Optional[str],
    stop_event: asyncio.Event,
):
    prev_cpu = read_cpu_times()
    prev_net = read_net_bytes(iface) if iface else None
    prev_disk = read_disk_bytes()
    prev_time = time.time()
    console = Console()
    progress = Progress(
        TextColumn("Progress"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
    )
    task_id = progress.add_task("Domains", total=max(1, stats.total))
    cpu_percent = None
    rx_mbps = tx_mbps = None
    disk_read = disk_write = None
    rate = 0.0
    eta = None

    def build_render(snapshot, cpu_percent, rx_mbps, tx_mbps, disk_read, disk_write, rate, eta):
        progress.update(task_id, total=max(1, snapshot.total),
                        completed=snapshot.processed)
        stats_table = Table.grid(expand=True)
        stats_table.add_row(progress)
        stats_table.add_row(
            f"[cyan]Success[/cyan] {snapshot.successes}    "
            f"[magenta]Fail[/magenta] {snapshot.failures}    "
            f"[yellow]Queue[/yellow] {queue.qsize()}    "
            f"[green]Rate[/green] {rate:.2f}/s    "
            f"[green]ETA[/green] {format_duration(eta)}"
        )
        stats_table.add_row(
            f"Scripts external={snapshot.external_scripts} inline={snapshot.inline_scripts}"
        )
        metrics = []
        if cpu_percent is not None:
            metrics.append(f"CPU {cpu_percent:5.1f}%")
        if rx_mbps is not None and tx_mbps is not None:
            metrics.append(f"NET {rx_mbps:5.1f}↓ / {tx_mbps:5.1f}↑ Mbps")
        if disk_read is not None and disk_write is not None:
            metrics.append(f"DISK {disk_read:4.1f}R / {disk_write:4.1f}W MB/s")
        if metrics:
            stats_table.add_row("   ".join(metrics))
        return Panel(stats_table, title="JS Harvester Dashboard", border_style="cyan", padding=(1, 2))

    with Live(console=console, refresh_per_second=4, screen=True) as live:
        while not stop_event.is_set():
            await asyncio.sleep(interval)
            now = time.time()
            snapshot = await stats.snapshot()

            cpu_percent = None
            cpu_times = read_cpu_times()
            if cpu_times and prev_cpu:
                total_delta = cpu_times[0] - prev_cpu[0]
                idle_delta = cpu_times[1] - prev_cpu[1]
                if total_delta > 0:
                    cpu_percent = max(
                        0.0, min(100.0, (1 - idle_delta / total_delta) * 100))
            prev_cpu = cpu_times or prev_cpu

            rx_mbps = tx_mbps = None
            if iface:
                net_bytes = read_net_bytes(iface)
                if net_bytes and prev_net:
                    elapsed = max(now - prev_time, 1e-6)
                    rx_mbps = ((net_bytes[0] - prev_net[0])
                               * 8) / (1_000_000 * elapsed)
                    tx_mbps = ((net_bytes[1] - prev_net[1])
                               * 8) / (1_000_000 * elapsed)
                prev_net = net_bytes or prev_net

            disk_read = disk_write = None
            disk_bytes = read_disk_bytes()
            if disk_bytes and prev_disk:
                elapsed = max(now - prev_time, 1e-6)
                disk_read = (disk_bytes[0] - prev_disk[0]
                             ) / (1_000_000 * elapsed)
                disk_write = (disk_bytes[1] - prev_disk[1]
                              ) / (1_000_000 * elapsed)
            prev_disk = disk_bytes or prev_disk
            prev_time = now

            elapsed = now - snapshot.started_at
            rate = snapshot.processed / elapsed if elapsed > 0 else 0.0
            remaining = snapshot.total - snapshot.processed
            eta = remaining / rate if rate > 0 else None

            renderable = build_render(
                snapshot, cpu_percent, rx_mbps, tx_mbps, disk_read, disk_write, rate, eta)
            live.update(renderable, refresh=True)

        snapshot = await stats.snapshot()
        renderable = build_render(
            snapshot, cpu_percent, rx_mbps, tx_mbps, disk_read, disk_write, rate, eta)
        live.update(renderable, refresh=True)

async def adaptive_concurrency_manager(
    stats: RunStats,
    limiter: AdaptiveConcurrencyLimiter,
    args: argparse.Namespace,
    stop_event: asyncio.Event,
    iface: Optional[str],
):
    prev_snapshot = await stats.snapshot()
    prev_net = read_net_bytes(iface) if iface else None
    prev_time = time.time()
    min_batch = max(10, args.adaptive_min_batch)

    while True:
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=args.adaptive_interval)
            break
        except asyncio.TimeoutError:
            pass

        snapshot = await stats.snapshot()
        processed_delta = snapshot.processed - prev_snapshot.processed
        timeout_delta = snapshot.failure_reasons.get(
            "timeout_connect", 0) - prev_snapshot.failure_reasons.get("timeout_connect", 0)
        reset_delta = snapshot.failure_reasons.get(
            "connection_reset", 0) - prev_snapshot.failure_reasons.get("connection_reset", 0)
        problematic = max(0, timeout_delta) + max(0, reset_delta)
        ratio = problematic / processed_delta if processed_delta > 0 else 0.0

        network_saturated = False
        now = time.time()
        if iface:
            net_bytes = read_net_bytes(iface)
            if net_bytes and prev_net:
                elapsed = max(now - prev_time, 1e-6)
                total_mbps = (
                    (net_bytes[0] - prev_net[0]) + (net_bytes[1] - prev_net[1])) * 8 / (1_000_000 * elapsed)
                target_bw = args.adaptive_network_target_mbps
                if target_bw and total_mbps >= target_bw:
                    network_saturated = True
            if net_bytes:
                prev_net = net_bytes
        prev_time = now

        prev_snapshot = snapshot

        current = limiter.limit
        target = current

        if processed_delta >= max(min_batch, args.adaptive_step):
            if ratio >= args.adaptive_reduce_threshold or network_saturated:
                target = max(args.adaptive_min_concurrency,
                             current - args.adaptive_step)
            elif ratio <= args.adaptive_increase_threshold and not network_saturated:
                target = min(args.adaptive_max_concurrency,
                             current + args.adaptive_step)

        if target != current:
            await limiter.set_limit(target)
            logging.info(
                "Adaptive concurrency adjusted to %s (window_processed=%s timeout_ratio=%.3f network_saturated=%s)",
                target,
                processed_delta,
                ratio,
                network_saturated,
            )

async def process_target(
    raw_target: str,
    client: httpx.AsyncClient,
    output_root: Path,
    args: argparse.Namespace,
    stats: RunStats,
):
    external_count = 0
    inline_count = 0
    success = False
    failure_reason: Optional[str] = None
    failure_context: Optional[str] = None
    try:
        try:
            normalized = normalize_target(raw_target)
        except ValueError:
            logging.debug("Skipping empty line %r", raw_target)
            failure_reason = "invalid_target"
            return False, external_count, inline_count, failure_reason, failure_context

        max_retries = 2

        def is_transient_error(status, note):
            if status is not None:
                return status >= 500
            note = (note or "").lower()
            transient_keywords = (
                "timeout", "connection", "reset", "closed",
                "handshake", "protocol", "dns", "resolution",
                "network", "stream"
            )
            return any(k in note for k in transient_keywords)

        html = None
        for attempt in range(max_retries):
            html, resolved, html_status, html_note = await fetch_html(client, normalized, args.max_html_bytes)
            if html:
                break
            if not is_transient_error(html_status, html_note):
                break
            await asyncio.sleep(0.5 + (0.1 * attempt))

        if not html and args.http2 and is_transient_error(html_status, html_note):
            logging.info(
                "Falling back to HTTP/1.1 for %s (error=%s)", normalized, html_note)
            try:
                async with httpx.AsyncClient(
                    http2=False,
                    verify=False,
                    limits=httpx.Limits(max_connections=5,
                                        max_keepalive_connections=5),
                    timeout=httpx.Timeout(args.timeout),
                    headers=DEFAULT_HEADERS,
                    follow_redirects=True,
                ) as h1_client:
                    html, resolved, html_status, html_note = await fetch_html(h1_client, normalized, args.max_html_bytes)
            except Exception:
                pass

        slug_source = resolved or normalized
        slug = slugify_host(slug_source)
        domain_hash = hashed_value(slug_source, 12)
        domain_dir = output_root / f"{slug}_{domain_hash}"
        inline_dir = domain_dir / "loaded_js" / "inline"
        external_dir = domain_dir / "loaded_js" / "external"
        log_lines: List[str] = []
        log_lines.append(
            f"HTML_FETCH status={html_status if html_status is not None else 'ERR'} "
            f"url={resolved or normalized} note={html_note or 'ok'}"
        )
        if not html or not resolved:
            failure_reason = classify_fetch_failure(html_status, html_note)
            failure_context = (
                f"html status={html_status if html_status is not None else 'ERR'} "
                f"note={html_note or 'unknown'}"
            )
            log_lines.append(
                f"FAILURE reason={failure_reason} context={failure_context}")
            await write_logs(domain_dir, log_lines)
            logging.info(
                "No HTML for %s (status=%s note=%s reason=%s)",
                normalized,
                html_status if html_status is not None else "ERR",
                html_note or "unknown",
                failure_reason,
            )
            return False, external_count, inline_count, failure_reason, failure_context

        parser = _ScriptHTMLParser(resolved)
        parser.feed(html)
        scripts = parser.scripts
        if not scripts:
            logging.info("No scripts discovered for %s", resolved)
            failure_reason = "no_scripts_found"
            log_lines.append(
                "FAILURE reason=no_scripts_found context=no_script_tags")
            await write_logs(domain_dir, log_lines)
            return False, external_count, inline_count, failure_reason, failure_context

        index_rows: List[List[str]] = []
        external_index_counter = count()
        script_tasks: List[asyncio.Task] = []
        script_semaphore = asyncio.Semaphore(max(1, args.script_concurrency))
        plugin_fingerprints: dict = {}
        theme_fingerprints: dict = {}

        for script in scripts:
            if script.source_url:
                if is_data_uri(script.source_url):
                    stored_path, size, note = await store_data_uri_script(
                        script.source_url,
                        external_dir,
                        next(external_index_counter),
                        args.max_inline_bytes,
                    )
                    if stored_path:
                        rel_path = str(stored_path.relative_to(domain_dir))
                        index_rows.append(
                            [
                                str(script.position),
                                "data",
                                script.source_url[:128] +
                                ("..." if len(script.source_url) > 128 else ""),
                                str(size),
                                rel_path,
                            ]
                        )
                        external_count += 1
                        log_lines.append(
                            f"SCRIPT_DATA stored={rel_path} bytes={size}"
                        )
                    else:
                        log_lines.append(
                            f"SCRIPT_DATA skipped note={note or 'unknown'}"
                        )
                    continue

                if not is_http_url(script.source_url):
                    log_lines.append(
                        f"SCRIPT_SKIP_UNSUPPORTED url={script.source_url}"
                    )
                    continue

                idx = next(external_index_counter)

                async def fetch_external(script_ref: ScriptRef, order):
                    async with script_semaphore:
                        result = await download_script(
                            client,
                            script_ref.source_url,
                            external_dir,
                            order,
                            args.max_script_bytes,
                            args.chunk_size,
                        )
                    stored_path, size, status, note = result
                    return script_ref, order, stored_path, size, status, note

                script_tasks.append(asyncio.create_task(
                    fetch_external(script, idx)))
            else:
                stored_path, size, start_offset = await store_inline_script(
                    inline_dir,
                    script.inline_code or "",
                    inline_count,
                    script.position,
                    args.max_inline_bytes,
                )
                index_rows.append(
                    [
                        str(script.position),
                        "inline",
                        "inline",
                        str(size),
                        f"{stored_path.relative_to(domain_dir)}#range={start_offset}:{size}",
                    ]
                )
                inline_count += 1
                log_lines.append(
                    f"INLINE_STORED file={stored_path.relative_to(domain_dir)} bytes={size}"
                )

        if script_tasks:
            for task in asyncio.as_completed(script_tasks):
                script_ref, order, stored_path, size, status, note = await task
                if stored_path:
                    rel_path = str(stored_path.relative_to(domain_dir))
                    index_rows.append(
                        [
                            str(script_ref.position),
                            "external",
                            script_ref.source_url,
                            str(size),
                            rel_path,
                        ]
                    )
                    external_count += 1
                    log_lines.append(
                        f"SCRIPT_FETCH status={status if status is not None else 'OK'} "
                        f"url={script_ref.source_url} stored={rel_path} bytes={size}"
                    )
                    fingerprint = detect_wordpress_component(
                        script_ref.source_url)
                    if fingerprint:
                        kind, name, version, evidence = fingerprint
                        if kind == "plugin":
                            add_fingerprint(
                                plugin_fingerprints, name, version, evidence, script_ref.source_url)
                        else:
                            add_fingerprint(
                                theme_fingerprints, name, version, evidence, script_ref.source_url)
                else:
                    log_lines.append(
                        f"SCRIPT_FETCH status={status if status is not None else 'ERR'} "
                        f"url={script_ref.source_url} note={note or 'skipped'}"
                    )

        metadata = {
            "input": raw_target,
            "resolved_url": resolved,
            "scripts_total": len(scripts),
            "external_count": external_count,
            "inline_count": inline_count,
            "wordpress_fingerprints": {
                "plugins": serialize_fingerprints(plugin_fingerprints),
                "themes": serialize_fingerprints(theme_fingerprints),
            },
        }
        await write_metadata(domain_dir, metadata, index_rows)
        await write_logs(domain_dir, log_lines)
        logging.info(
            "Captured %s scripts (%s external, %s inline) for %s",
            len(scripts),
            external_count,
            inline_count,
            resolved,
        )
        success = True
        failure_reason = None
    except Exception:
        if not failure_reason:
            failure_reason = "exception"
        logging.exception("Failed to process %s", raw_target)
    finally:
        await stats.record_result(
            success,
            external_count,
            inline_count,
            failure_reason=failure_reason,
            failure_context=failure_context,
        )
    return success, external_count, inline_count, failure_reason, failure_context

async def worker(
    queue: asyncio.Queue,
    result_queue: asyncio.Queue,
    client: httpx.AsyncClient,
    output_root: Path,
    args: argparse.Namespace,
    stats: RunStats,
    limiter: AdaptiveConcurrencyLimiter,
):
    while True:
        payload = await queue.get()
        if payload is None:
            queue.task_done()
            break
        job_id, item = payload
        result: Tuple[bool, int, int, Optional[str], Optional[str]] = (
            False, 0, 0, "exception", "worker_initial")
        try:
            async with limiter.slot():
                result = await process_target(item, client, output_root, args, stats)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logging.exception("Worker failed on %s: %s", item, exc)
            result = (False, 0, 0, "exception", str(exc))
        finally:
            await result_queue.put((job_id, item, *result))
            queue.task_done()

async def execute_attempt(
    attempt_targets: Sequence[Tuple[int, str]],
    client: httpx.AsyncClient,
    output_root: Path,
    args: argparse.Namespace,
    iface: Optional[str],
):
    if not attempt_targets:
        return []
    stats = RunStats(len(attempt_targets))
    queue: asyncio.Queue = asyncio.Queue(maxsize=max(args.concurrency * 4, 1))
    result_queue: asyncio.Queue = asyncio.Queue()

    initial_limit = args.adaptive_min_concurrency if args.adaptive_concurrency else args.concurrency
    limiter = AdaptiveConcurrencyLimiter(initial_limit)
    stop_event = asyncio.Event()

    workers = [
        asyncio.create_task(
            worker(queue, result_queue, client, output_root, args, stats, limiter))
        for _ in range(args.concurrency)
    ]

    status_task = None
    if args.dashboard and args.status_interval > 0:
        status_task = asyncio.create_task(
            status_reporter(queue, stats, args.status_interval,
                            iface, stop_event)
        )

    adaptive_task = None
    if args.adaptive_concurrency:
        adaptive_task = asyncio.create_task(
            adaptive_concurrency_manager(
                stats, limiter, args, stop_event, iface)
        )

    for payload in attempt_targets:
        await queue.put(payload)
    for _ in workers:
        await queue.put(None)

    await queue.join()
    await asyncio.gather(*workers)
    stop_event.set()
    if status_task:
        await status_task
    if adaptive_task:
        await adaptive_task

    results: List[Tuple[int, str, bool, int,
                        int, Optional[str], Optional[str]]] = []
    for _ in range(len(attempt_targets)):
        job_id, raw_target, success, external_count, inline_count, failure_reason, failure_context = await result_queue.get()
        results.append((job_id, raw_target, success, external_count,
                       inline_count, failure_reason, failure_context))
    return results

async def run(args: argparse.Namespace):
    output_root = Path(args.output).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    targets_path = Path(args.targets)
    all_targets = [(idx, target)
                   for idx, target in enumerate(iter_targets(targets_path))]
    total_targets = len(all_targets)
    if total_targets == 0:
        logging.warning("No targets found in %s", targets_path)
        return
    target_states = {
        job_id: {
            "target": target,
            "attempts": 0,
            "success": False,
            "external": 0,
            "inline": 0,
            "failure_reason": None,
            "failure_context": None,
        }
        for job_id, target in all_targets
    }

    max_connections = args.max_connections or max(
        args.concurrency * 20, args.concurrency)
    max_keepalive = args.max_keepalive_connections or max(
        args.concurrency * 2, 100)

    limits = httpx.Limits(
        max_connections=max_connections,
        max_keepalive_connections=max_keepalive,
        keepalive_expiry=args.keepalive,
    )

    timeout = httpx.Timeout(args.timeout)

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        http2=args.http2,
        follow_redirects=True,
        headers=DEFAULT_HEADERS,
        verify=False,
    ) as client:
        iface = detect_primary_iface(args.status_iface)
        started_at = time.time()
        remaining = list(all_targets)
        attempt = 1
        while attempt <= args.max_attempts and remaining:
            logging.info("Attempt %d: processing %d target(s)",
                         attempt, len(remaining))
            attempt_results = await execute_attempt(remaining, client, output_root, args, iface)
            next_remaining: List[Tuple[int, str]] = []
            success_this_attempt = 0
            for job_id, raw_target, success, external_count, inline_count, failure_reason, failure_context in attempt_results:
                state = target_states[job_id]
                state["attempts"] += 1
                if success:
                    state["success"] = True
                    state["external"] = external_count
                    state["inline"] = inline_count
                    state["failure_reason"] = None
                    state["failure_context"] = None
                    success_this_attempt += 1
                else:
                    state["success"] = False
                    state["external"] = 0
                    state["inline"] = 0
                    state["failure_reason"] = failure_reason
                    state["failure_context"] = failure_context
                    next_remaining.append((job_id, raw_target))
            logging.info(
                "Attempt %d finished: %d succeeded, %d remaining",
                attempt,
                success_this_attempt,
                len(next_remaining),
            )
            remaining = next_remaining
            attempt += 1
        ended_at = time.time()

    successes = sum(1 for state in target_states.values() if state["success"])
    failures = total_targets - successes
    external_total = sum(state["external"] for state in target_states.values())
    inline_total = sum(state["inline"] for state in target_states.values())
    failure_reasons: Dict[str, int] = defaultdict(int)
    failure_notes: Dict[str, int] = defaultdict(int)
    for state in target_states.values():
        if not state["success"]:
            reason = state["failure_reason"] or "unknown"
            failure_reasons[reason] += 1
            note = state["failure_context"]
            if note:
                failure_notes[note] += 1

    if failures:
        logging.warning(
            "Failed to capture scripts for %s target(s) after %s attempt(s)", failures, args.max_attempts)

    summary = {
        "total_targets": total_targets,
        "processed": total_targets,
        "successes": successes,
        "failures": failures,
        "external_scripts": external_total,
        "inline_scripts": inline_total,
        "started_at": started_at,
        "ended_at": ended_at,
        "failure_reasons": dict(failure_reasons),
        "failure_notes": dict(failure_notes),
        "max_attempts": args.max_attempts,
    }
    summary["duration_seconds"] = summary["ended_at"] - summary["started_at"]
    summary_path = output_root / "run_summary.json"
    await asyncio.to_thread(summary_path.write_text, json.dumps(summary, indent=2), encoding="utf-8")
    logging.info(
        "Run summary: processed=%s success=%s failure=%s (written to %s)",
        summary["processed"],
        summary["successes"],
        summary["failures"],
        summary_path,
    )

def parse_args():
    parser = argparse.ArgumentParser(
        description="Asynchronously download inline/external JS for a list of domains",
    )
    parser.add_argument(
        "--targets",
        required=True,
        help="Path to a file containing domains/URLs (one per line)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Directory where harvested data will be stored",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Number of concurrent fetchers (default: auto based on CPU count)",
    )
    parser.add_argument(
        "--adaptive-concurrency",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Dynamically raise/lower concurrency based on timeout and network pressure",
    )
    parser.add_argument(
        "--adaptive-min-concurrency",
        type=int,
        default=None,
        help="Minimum concurrency when adaptive mode is enabled (default: 25%% of --concurrency)",
    )
    parser.add_argument(
        "--adaptive-max-concurrency",
        type=int,
        default=None,
        help="Maximum concurrency when adaptive mode is enabled (default: --concurrency)",
    )
    parser.add_argument(
        "--adaptive-step",
        type=int,
        default=20,
        help="How many workers to add/remove per adjustment when adaptive mode is enabled (default: 20)",
    )
    parser.add_argument(
        "--adaptive-interval",
        type=float,
        default=20.0,
        help="Seconds between adaptive tuning checks (default: 20)",
    )
    parser.add_argument(
        "--adaptive-reduce-threshold",
        type=float,
        default=0.15,
        help="Reduce concurrency if timeout ratio exceeds this fraction (default: 0.15)",
    )
    parser.add_argument(
        "--adaptive-increase-threshold",
        type=float,
        default=0.05,
        help="Increase concurrency when timeout ratio stays below this fraction (default: 0.05)",
    )
    parser.add_argument(
        "--adaptive-min-batch",
        type=int,
        default=200,
        help="Minimum processed targets in a window before adaptive decisions are made (default: 200)",
    )
    parser.add_argument(
        "--adaptive-network-target-mbps",
        type=float,
        default=None,
        help="Optional throughput ceiling; if combined RX/TX Mbps exceeds this value, concurrency is reduced",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Total timeout per request in seconds (default: 30)",
    )
    parser.add_argument(
        "--keepalive",
        type=float,
        default=30.0,
        help="Max seconds to keep idle HTTP connections around (default: 30)",
    )
    parser.add_argument(
        "--max-html-bytes",
        type=int,
        default=1_500_000,
        help="Ceiling for HTML download size per domain (default: 1.5MB)",
    )
    parser.add_argument(
        "--max-script-bytes",
        type=int,
        default=None,
        help="Optional ceiling for external JS download size (default: unlimited)",
    )
    parser.add_argument(
        "--max-inline-bytes",
        type=int,
        default=None,
        help="Optional ceiling for inline or data URI scripts (default: unlimited)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=64 * 1024,
        help="Chunk size used when streaming JS files (default: 64KB)",
    )
    parser.add_argument(
        "--script-concurrency",
        type=int,
        default=None,
        help="Max number of external scripts fetched concurrently per domain (default: auto)",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=3,
        help="Maximum number of attempts per target before giving up (default: 3)",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        help="Upper bound for simultaneous HTTP connections (default: auto based on concurrency and ulimit)",
    )
    parser.add_argument(
        "--max-keepalive-connections",
        type=int,
        help="Upper bound for pooled keep-alive connections (default: auto sized to connection pool)",
    )
    parser.add_argument(
        "--status-interval",
        type=float,
        default=10.0,
        help="Seconds between status updates (default: 10, set to 0 to disable)",
    )
    parser.add_argument(
        "--status-iface",
        help="Network interface name for status throughput (default: auto-detect non-loopback)",
    )
    parser.add_argument(
        "--dashboard",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Show interactive terminal dashboard (default: enabled)",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Logging level (default: OFF when dashboard is enabled, INFO otherwise). Use OFF to silence logs.",
    )
    parser.add_argument(
        "--http2",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable HTTP/2 (requires the 'h2' package). Disable with --no-http2.",
    )
    args = parser.parse_args()
    level_name = (args.log_level.upper() if args.log_level else (
        "OFF" if args.dashboard else "INFO"))
    if level_name == "OFF":
        logging.basicConfig(level=logging.CRITICAL + 10)
    else:
        logging.basicConfig(
            format="%(asctime)s %(levelname)s %(message)s",
            level=getattr(logging, level_name, logging.INFO),
        )
    auto_tune_runtime(args)
    if args.adaptive_min_concurrency is None:
        args.adaptive_min_concurrency = max(1, args.concurrency // 4)
    if args.adaptive_max_concurrency is None:
        args.adaptive_max_concurrency = args.concurrency
    if args.adaptive_min_concurrency > args.adaptive_max_concurrency:
        args.adaptive_min_concurrency = args.adaptive_max_concurrency
    args.adaptive_step = max(1, args.adaptive_step)
    args.adaptive_interval = max(1.0, args.adaptive_interval)
    args.adaptive_min_batch = max(10, args.adaptive_min_batch)
    if args.adaptive_increase_threshold > args.adaptive_reduce_threshold:
        args.adaptive_increase_threshold = args.adaptive_reduce_threshold
    args.max_attempts = max(1, args.max_attempts)
    if args.http2 and not H2_AVAILABLE:
        logging.warning(
            "HTTP/2 requested but the 'h2' package is missing. Falling back to HTTP/1.1.")
        args.http2 = False
    return args

def main():
    args = parse_args()
    asyncio.run(run(args))

if __name__ == "__main__":
    if UVLOOP_AVAILABLE:
        try:
            uvloop.install()
        except Exception:
            pass
    main()
