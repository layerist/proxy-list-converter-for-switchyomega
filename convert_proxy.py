#!/usr/bin/env python3
"""
Reliable Proxy List Converter v4
================================

Converts proxy lists to a SwitchyOmega-compatible JSON configuration.

Accepted formats:
    host:port:user:password
    http://host:port:user:password
    socks5://host:port:user:password
    http://user:password@host:port
    socks5://user:password@[2001:db8::1]:1080

Important features:
- IPv4, IPv6 and IDN host support.
- Passwords containing ':' are supported.
- URL-encoded credentials are decoded.
- Bounded producer/worker queues with deadlock-safe cancellation and failure propagation.
- Coalescing DNS cache: repeated hosts are resolved only once.
- Optional real proxy handshake check, including authentication.
- Atomic output writes.
- Optional rejected-line report with precise failure reasons.
- Accurate parse/network statistics and safer HTTP header limits.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import ipaddress
import json
import logging
import os
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Iterable, Iterator, Literal, Optional, Sequence
from urllib.parse import unquote, urlsplit

ENCODING = "utf-8"
EXIT_FAILURE = 1

SCHEMA_VERSION = 2
REVISION_ID = "190a4bca575"
DEFAULT_REVISION_ID = "1908e30c31b"
DEFAULT_PROXY_COLOR = "#ca0"
AUTO_SWITCH_NAME = "+auto switch"
PROXY_GROUP_NAME = "+proxy"
PROXY_PREFIX = "+m"

SUPPORTED_SCHEMES = frozenset({"http", "https", "socks5"})
DEFAULT_SCHEME = "http"
BYPASS_PATTERNS = ("127.0.0.1", "::1", "localhost")

DEFAULT_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 100
DEFAULT_QUEUE_MULTIPLIER = 4
DEFAULT_PROGRESS_EVERY = 1000
DEFAULT_CHECK_TARGET = "example.com:443"
MAX_HTTP_RESPONSE = 16 * 1024
HTTP_READ_CHUNK = 2048
MAX_INPUT_LINE = 64 * 1024

DedupeMode = Literal["full", "endpoint"]
CheckMode = Literal["none", "tcp", "proxy"]


@dataclass(frozen=True, slots=True)
class ProxyEntry:
    scheme: str
    host: str
    port: int
    username: str
    password: str

    def dedupe_key(self, mode: DedupeMode) -> tuple[object, ...]:
        if mode == "endpoint":
            return self.scheme, self.host, self.port
        return self.scheme, self.host, self.port, self.username, self.password

    def sort_key(self) -> tuple[object, ...]:
        return self.host, self.port, self.scheme, self.username, self.password


@dataclass(frozen=True, slots=True)
class RejectedLine:
    line_no: int
    reason: str
    line: str


@dataclass(slots=True)
class Stats:
    total: int = 0
    parsed: int = 0
    valid: int = 0
    invalid: int = 0
    duplicates: int = 0
    dns_failed: int = 0
    tcp_failed: int = 0
    proxy_failed: int = 0


@dataclass(frozen=True, slots=True)
class Settings:
    resolve: bool
    check_mode: CheckMode
    timeout: float
    check_host: str
    check_port: int


WorkItem = tuple[int, str] | None
@dataclass(frozen=True, slots=True)
class ResultItem:
    line_no: int
    line: str
    parsed: bool
    proxy: Optional[ProxyEntry]
    reason: Optional[str]


ResultQueueItem = ResultItem


def setup_logging(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("proxy_converter")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s: %(message)s", datefmt="%H:%M:%S"
    ))
    logger.addHandler(handler)
    return logger


def iter_proxy_lines(path: Path) -> Iterator[tuple[int, str]]:
    with path.open("r", encoding=ENCODING, errors="replace") as file:
        for line_no, raw_line in enumerate(file, 1):
            line = raw_line.strip().lstrip("\ufeff")
            if line and not line.startswith("#"):
                if len(line) > MAX_INPUT_LINE:
                    # Keep processing deterministic and avoid pathological input records.
                    yield line_no, line[:MAX_INPUT_LINE + 1]
                else:
                    yield line_no, line


def _atomic_text_writer(destination: Path):
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent, text=True
    )
    try:
        with os.fdopen(fd, "w", encoding=ENCODING, newline="\n") as file:
            yield file
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp_name, destination)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)


_atomic_text_writer = contextlib.contextmanager(_atomic_text_writer)


def write_json_atomic(data: dict[str, object], destination: Path) -> None:
    with _atomic_text_writer(destination) as file:
        json.dump(data, file, indent=4, ensure_ascii=False)
        file.write("\n")


def write_rejected_atomic(rejected: Sequence[RejectedLine], destination: Path) -> None:
    with _atomic_text_writer(destination) as file:
        for item in sorted(rejected, key=lambda value: value.line_no):
            file.write(f"{item.line_no}\t{item.reason}\t{item.line}\n")


def normalize_host(host: str) -> Optional[str]:
    host = host.strip()
    if not host:
        return None

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    if any(ch.isspace() for ch in host) or any(ch in host for ch in "/:@[]"):
        return None

    host = host.rstrip(".").lower()
    if not host:
        return None

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(ascii_host) > 253:
        return None

    for label in ascii_host.split("."):
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        if not all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in label):
            return None

    return ascii_host


class AsyncDNSCache:
    """Caches completed lookups and coalesces concurrent lookups per host."""

    def __init__(self) -> None:
        self._cache: dict[str, bool] = {}
        self._inflight: dict[str, asyncio.Task[bool]] = {}
        self._lock = asyncio.Lock()

    async def resolve(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass

        async with self._lock:
            cached = self._cache.get(host)
            if cached is not None:
                return cached
            task = self._inflight.get(host)
            if task is None:
                task = asyncio.create_task(asyncio.to_thread(self._resolve_blocking, host))
                self._inflight[host] = task

        try:
            result = await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except Exception:
            result = False

        async with self._lock:
            self._cache[host] = result
            self._inflight.pop(host, None)
        return result

    @staticmethod
    def _resolve_blocking(host: str) -> bool:
        try:
            socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            return True
        except OSError:
            return False


def parse_port(raw: str) -> Optional[int]:
    raw = raw.strip()
    if not raw.isascii() or not raw.isdecimal():
        return None
    port = int(raw)
    return port if 1 <= port <= 65535 else None


def split_scheme(line: str) -> tuple[str, str] | None:
    if "://" not in line:
        return DEFAULT_SCHEME, line
    scheme, rest = line.split("://", 1)
    scheme = scheme.strip().lower()
    return (scheme, rest.strip()) if scheme in SUPPORTED_SCHEMES else None


def make_proxy(scheme: str, host: str, raw_port: str | int,
               username: str, password: str) -> Optional[ProxyEntry]:
    normalized_host = normalize_host(host)
    port = raw_port if isinstance(raw_port, int) else parse_port(raw_port)
    username = unquote(username.strip())
    password = unquote(password.strip())

    if (
        normalized_host is None
        or port is None
        or not username
        or not password
        or not credentials_are_safe(username, password)
    ):
        return None
    return ProxyEntry(scheme, normalized_host, port, username, password)


def parse_standard_url(line: str) -> Optional[ProxyEntry]:
    if "://" not in line or "@" not in line:
        return None
    try:
        parsed = urlsplit(line)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if scheme not in SUPPORTED_SCHEMES or not host or port is None:
        return None
    if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        return None
    return make_proxy(scheme, host, port, parsed.username or "", parsed.password or "")


def parse_legacy_proxy(line: str) -> Optional[ProxyEntry]:
    scheme_and_rest = split_scheme(line)
    if scheme_and_rest is None:
        return None
    scheme, rest = scheme_and_rest

    if rest.startswith("["):
        end = rest.find("]")
        if end < 0 or not rest[end + 1:].startswith(":"):
            return None
        host = rest[1:end]
        parts = rest[end + 2:].split(":", 2)
        if len(parts) != 3:
            return None
        raw_port, username, password = parts
    else:
        parts = rest.split(":", 3)
        if len(parts) != 4:
            return None
        host, raw_port, username, password = parts

    return make_proxy(scheme, host, raw_port, username, password)


def parse_proxy(line: str) -> Optional[ProxyEntry]:
    return parse_standard_url(line) or parse_legacy_proxy(line)


def format_authority(host: str, port: int) -> str:
    """Return RFC-compatible host:port authority, bracketing IPv6 literals."""
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return f"{host}:{port}"
    return f"[{host}]:{port}" if parsed.version == 6 else f"{host}:{port}"


def credentials_are_safe(username: str, password: str) -> bool:
    """Reject credentials that could inject protocol delimiters/control bytes."""
    return not any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in username + password)


async def close_writer(writer: asyncio.StreamWriter | None) -> None:
    """Best-effort stream shutdown that never masks the original network result."""
    if writer is None:
        return
    writer.close()
    with contextlib.suppress(OSError, asyncio.TimeoutError, ConnectionError):
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)


async def open_proxy_connection(proxy: ProxyEntry, timeout: float):
    ssl_context = None
    server_hostname = None
    if proxy.scheme == "https":
        ssl_context = ssl.create_default_context()
        server_hostname = proxy.host

    return await asyncio.wait_for(
        asyncio.open_connection(
            proxy.host,
            proxy.port,
            ssl=ssl_context,
            server_hostname=server_hostname,
        ),
        timeout=timeout,
    )


async def check_tcp(proxy: ProxyEntry, timeout: float) -> bool:
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await open_proxy_connection(proxy, timeout)
        return True
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False
    finally:
        await close_writer(writer)


async def read_http_headers(reader: asyncio.StreamReader, timeout: float) -> bytes:
    """Read only the HTTP header block, enforcing a hard byte limit while reading."""
    deadline = asyncio.get_running_loop().time() + timeout
    data = bytearray()

    while b"\r\n\r\n" not in data:
        if len(data) >= MAX_HTTP_RESPONSE:
            raise ValueError("oversized HTTP response")

        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError

        chunk = await asyncio.wait_for(
            reader.read(min(HTTP_READ_CHUNK, MAX_HTTP_RESPONSE - len(data))),
            remaining,
        )
        if not chunk:
            raise asyncio.IncompleteReadError(bytes(data), None)
        data.extend(chunk)

    header_end = data.find(b"\r\n\r\n") + 4
    return bytes(data[:header_end])


async def check_http_proxy(proxy: ProxyEntry, target_host: str,
                           target_port: int, timeout: float) -> bool:
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await open_proxy_connection(proxy, timeout)
        credentials = base64.b64encode(
            f"{proxy.username}:{proxy.password}".encode(ENCODING)
        ).decode("ascii")
        authority = format_authority(target_host, target_port)
        request = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"Proxy-Authorization: Basic {credentials}\r\n"
            "Proxy-Connection: close\r\n"
            "User-Agent: proxy-list-converter/4\r\n\r\n"
        ).encode("ascii")
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout)
        response = await read_http_headers(reader, timeout)
        first_line = response.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first_line.split(" ", 2)
        return len(parts) >= 2 and parts[1].isdigit() and 200 <= int(parts[1]) < 300
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError, asyncio.IncompleteReadError):
        return False
    finally:
        await close_writer(writer)


async def check_socks5_proxy(proxy: ProxyEntry, target_host: str,
                             target_port: int, timeout: float) -> bool:
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await open_proxy_connection(proxy, timeout)

        # Offer username/password authentication only.
        writer.write(b"\x05\x01\x02")
        await asyncio.wait_for(writer.drain(), timeout)
        if await asyncio.wait_for(reader.readexactly(2), timeout) != b"\x05\x02":
            return False

        username = proxy.username.encode(ENCODING)
        password = proxy.password.encode(ENCODING)
        if len(username) > 255 or len(password) > 255:
            return False
        writer.write(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
        await asyncio.wait_for(writer.drain(), timeout)
        auth_reply = await asyncio.wait_for(reader.readexactly(2), timeout)
        if auth_reply != b"\x01\x00":
            return False

        try:
            target_ip = ipaddress.ip_address(target_host)
        except ValueError:
            try:
                encoded_host = target_host.encode("idna")
            except UnicodeError:
                return False
            if len(encoded_host) > 255:
                return False
            address = b"\x03" + bytes([len(encoded_host)]) + encoded_host
        else:
            address = (b"\x01" if target_ip.version == 4 else b"\x04") + target_ip.packed

        writer.write(b"\x05\x01\x00" + address + target_port.to_bytes(2, "big"))
        await asyncio.wait_for(writer.drain(), timeout)
        head = await asyncio.wait_for(reader.readexactly(4), timeout)
        if head[0] != 5 or head[1] != 0:
            return False

        atyp = head[3]
        if atyp == 1:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout)
        elif atyp == 4:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout)
        elif atyp == 3:
            length = (await asyncio.wait_for(reader.readexactly(1), timeout))[0]
            await asyncio.wait_for(reader.readexactly(length + 2), timeout)
        else:
            return False
        return True
    except (OSError, asyncio.TimeoutError, ssl.SSLError, asyncio.IncompleteReadError):
        return False
    finally:
        await close_writer(writer)


async def check_proxy(proxy: ProxyEntry, settings: Settings) -> bool:
    if settings.check_mode == "none":
        return True
    if settings.check_mode == "tcp":
        return await check_tcp(proxy, settings.timeout)
    if proxy.scheme in {"http", "https"}:
        return await check_http_proxy(
            proxy, settings.check_host, settings.check_port, settings.timeout
        )
    return await check_socks5_proxy(
        proxy, settings.check_host, settings.check_port, settings.timeout
    )


def build_bypass_list() -> list[dict[str, str]]:
    return [
        {"conditionType": "BypassCondition", "pattern": pattern}
        for pattern in BYPASS_PATTERNS
    ]


def build_proxy_profile(proxy: ProxyEntry, index: int) -> dict[str, object]:
    return {
        "profileType": "FixedProfile",
        "name": f"{PROXY_PREFIX}{index}",
        "color": DEFAULT_PROXY_COLOR,
        "revision": REVISION_ID,
        "bypassList": build_bypass_list(),
        "fallbackProxy": {
            "scheme": proxy.scheme,
            "host": proxy.host,
            "port": proxy.port,
        },
        "auth": {
            "fallbackProxy": {
                "username": proxy.username,
                "password": proxy.password,
            }
        },
    }


def build_config(proxies: Sequence[ProxyEntry]) -> dict[str, object]:
    config: dict[str, object] = {
        AUTO_SWITCH_NAME: {
            "profileType": "SwitchProfile",
            "name": "auto switch",
            "color": "#99dd99",
            "defaultProfileName": "direct",
            "rules": [],
        },
        PROXY_GROUP_NAME: {
            "profileType": "FixedProfile",
            "name": "proxy",
            "color": "#99ccee",
            "revision": DEFAULT_REVISION_ID,
            "bypassList": build_bypass_list(),
            "fallbackProxy": {
                "scheme": DEFAULT_SCHEME,
                "host": "127.0.0.1",
                "port": 80,
            },
        },
        "schemaVersion": SCHEMA_VERSION,
    }
    for index, proxy in enumerate(proxies, 1):
        config[f"{PROXY_PREFIX}{index}"] = build_proxy_profile(proxy, index)
    return config


async def process_one(line_no: int, line: str, resolver: AsyncDNSCache,
                      settings: Settings) -> ResultItem:
    if len(line) > MAX_INPUT_LINE:
        return ResultItem(line_no, line, False, None, "line_too_long")

    proxy = parse_proxy(line)
    if proxy is None:
        return ResultItem(line_no, line, False, None, "parse")

    if settings.resolve and not await resolver.resolve(proxy.host):
        return ResultItem(line_no, line, True, None, "dns")

    if settings.check_mode != "none" and not await check_proxy(proxy, settings):
        reason = "tcp" if settings.check_mode == "tcp" else "proxy"
        return ResultItem(line_no, line, True, None, reason)

    return ResultItem(line_no, line, True, proxy, None)


async def producer(lines: Iterable[tuple[int, str]], queue: asyncio.Queue[WorkItem],
                   workers: int, stats: Stats) -> None:
    try:
        for item in lines:
            stats.total += 1
            await queue.put(item)
    finally:
        # Always release workers even if reading the input fails part-way through.
        for _ in range(workers):
            await queue.put(None)


async def worker(work_queue: asyncio.Queue[WorkItem],
                 result_queue: asyncio.Queue[ResultQueueItem],
                 resolver: AsyncDNSCache, settings: Settings) -> None:
    while True:
        item = await work_queue.get()
        try:
            if item is None:
                return
            result = await process_one(*item, resolver, settings)
            await result_queue.put(result)
        finally:
            work_queue.task_done()


def dedupe_proxies(candidates: list[tuple[int, ProxyEntry]], mode: DedupeMode,
                   preserve_order: bool) -> tuple[list[ProxyEntry], int]:
    seen: set[tuple[object, ...]] = set()
    unique: list[tuple[int, ProxyEntry]] = []
    duplicates = 0

    for line_no, proxy in sorted(candidates, key=lambda item: item[0]):
        key = proxy.dedupe_key(mode)
        if key in seen:
            duplicates += 1
        else:
            seen.add(key)
            unique.append((line_no, proxy))

    if not preserve_order:
        unique.sort(key=lambda item: item[1].sort_key())
    return [proxy for _, proxy in unique], duplicates


async def generate_config(lines: Iterable[tuple[int, str]], logger: logging.Logger, *,
                          settings: Settings, concurrency: int, queue_size: int,
                          dedupe_mode: DedupeMode, preserve_order: bool,
                          progress_every: int) -> tuple[dict[str, object], Stats, list[RejectedLine]]:
    stats = Stats()
    resolver = AsyncDNSCache()
    work_queue: asyncio.Queue[WorkItem] = asyncio.Queue(queue_size)
    result_queue: asyncio.Queue[ResultQueueItem] = asyncio.Queue(queue_size)

    producer_task = asyncio.create_task(
        producer(lines, work_queue, concurrency, stats), name="producer"
    )
    workers = [
        asyncio.create_task(
            worker(work_queue, result_queue, resolver, settings),
            name=f"worker-{index + 1}",
        )
        for index in range(concurrency)
    ]

    candidates: list[tuple[int, ProxyEntry]] = []
    rejected: list[RejectedLine] = []
    processed = 0

    try:
        # Consume results while either input production or workers are still active.
        # A timeout-free asyncio.wait avoids sentinel deadlocks during cancellation.
        while True:
            if producer_task.done() and all(task.done() for task in workers):
                while not result_queue.empty():
                    item = result_queue.get_nowait()
                    try:
                        processed += 1
                        if item.parsed:
                            stats.parsed += 1
                        if item.proxy is not None:
                            candidates.append((item.line_no, item.proxy))
                        else:
                            stats.invalid += 1
                            rejected.append(RejectedLine(item.line_no, item.reason or "unknown", item.line))
                            if item.reason == "dns":
                                stats.dns_failed += 1
                            elif item.reason == "tcp":
                                stats.tcp_failed += 1
                            elif item.reason == "proxy":
                                stats.proxy_failed += 1
                    finally:
                        result_queue.task_done()
                break

            get_task = asyncio.create_task(result_queue.get())
            watched: set[asyncio.Task[object]] = {get_task}
            if not producer_task.done():
                watched.add(producer_task)  # type: ignore[arg-type]
            watched.update(task for task in workers if not task.done())  # type: ignore[arg-type]
            done, _ = await asyncio.wait(watched, return_when=asyncio.FIRST_COMPLETED)

            if get_task in done:
                item = get_task.result()
                try:
                    processed += 1
                    if item.parsed:
                        stats.parsed += 1
                    if item.proxy is not None:
                        candidates.append((item.line_no, item.proxy))
                    else:
                        stats.invalid += 1
                        rejected.append(RejectedLine(item.line_no, item.reason or "unknown", item.line))
                        if item.reason == "dns":
                            stats.dns_failed += 1
                        elif item.reason == "tcp":
                            stats.tcp_failed += 1
                        elif item.reason == "proxy":
                            stats.proxy_failed += 1

                    if progress_every > 0 and processed % progress_every == 0:
                        logger.info(
                            "Processed %d lines (%d passed validation so far)",
                            processed, len(candidates),
                        )
                finally:
                    result_queue.task_done()
            else:
                get_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await get_task

            # Propagate producer/worker exceptions immediately instead of hanging.
            if producer_task.done() and not producer_task.cancelled():
                exc = producer_task.exception()
                if exc is not None:
                    raise exc
            for task in workers:
                if task.done() and not task.cancelled():
                    exc = task.exception()
                    if exc is not None:
                        raise exc

        await producer_task
        await work_queue.join()
        await asyncio.gather(*workers)
        await result_queue.join()
    except BaseException:
        producer_task.cancel()
        for task in workers:
            task.cancel()
        await asyncio.gather(producer_task, *workers, return_exceptions=True)
        raise

    if processed != stats.total:
        raise RuntimeError(
            f"internal pipeline mismatch: produced={stats.total}, processed={processed}"
        )

    proxies, stats.duplicates = dedupe_proxies(candidates, dedupe_mode, preserve_order)
    stats.valid = len(proxies)

    logger.info(
        "Stats → total=%d parsed=%d valid=%d invalid=%d duplicates=%d "
        "dns_failed=%d tcp_failed=%d proxy_failed=%d",
        stats.total, stats.parsed, stats.valid, stats.invalid, stats.duplicates,
        stats.dns_failed, stats.tcp_failed, stats.proxy_failed,
    )
    return build_config(proxies), stats, rejected


def parse_target(value: str) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or not value[end + 1:].startswith(":"):
            raise argparse.ArgumentTypeError("expected [IPv6]:port")
        host, raw_port = value[1:end], value[end + 2:]
    else:
        if value.count(":") != 1:
            raise argparse.ArgumentTypeError("expected host:port")
        host, raw_port = value.rsplit(":", 1)

    normalized = normalize_host(host)
    port = parse_port(raw_port)
    if normalized is None or port is None:
        raise argparse.ArgumentTypeError("invalid check target")
    return normalized, port


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert a raw proxy list into a SwitchyOmega-compatible JSON config."
    )
    parser.add_argument("input", type=Path, help="Input proxy list")
    parser.add_argument("output", type=Path, help="Output JSON config")
    parser.add_argument("--resolve", action="store_true", help="Resolve DNS names")
    parser.add_argument(
        "--check", choices=("none", "tcp", "proxy"), default="none",
        help="Validation: none, TCP port, or real authenticated proxy handshake",
    )
    parser.add_argument(
        "--check-target", type=parse_target, default=parse_target(DEFAULT_CHECK_TARGET),
        metavar="HOST:PORT", help=f"Destination used by proxy check (default: {DEFAULT_CHECK_TARGET})",
    )
    parser.add_argument(
        "--timeout", type=positive_float, default=DEFAULT_TIMEOUT,
        help=f"Timeout per network operation (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--threads", "--concurrency", dest="concurrency", type=positive_int,
        default=DEFAULT_CONCURRENCY,
        help=f"Concurrent workers (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "--queue-size", type=positive_int, default=None,
        help="Bounded input/result queue size (default: concurrency * 4)",
    )
    parser.add_argument(
        "--dedupe", choices=("full", "endpoint"), default="full",
        help="Duplicate mode: complete record or scheme+host+port",
    )
    parser.add_argument(
        "--preserve-order", action="store_true",
        help="Preserve first-occurrence input order instead of sorting",
    )
    parser.add_argument(
        "--rejected", type=Path,
        help="Write rejected lines as: line_number<TAB>reason<TAB>original_line",
    )
    parser.add_argument(
        "--progress-every", type=non_negative_int, default=DEFAULT_PROGRESS_EVERY,
        help=f"Log every N processed lines; 0 disables (default: {DEFAULT_PROGRESS_EVERY})",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


async def async_main() -> int:
    args = build_arg_parser().parse_args()
    logger = setup_logging(args.verbose)
    if not args.input.is_file():
        logger.error("Input file not found or not a regular file: %s", args.input)
        return EXIT_FAILURE
    if args.input.resolve() == args.output.resolve():
        logger.error("Input and output paths must be different")
        return EXIT_FAILURE

    if args.rejected is not None:
        resolved_rejected = args.rejected.resolve()
        if resolved_rejected == args.input.resolve():
            logger.error("Rejected report path must differ from input path")
            return EXIT_FAILURE
        if resolved_rejected == args.output.resolve():
            logger.error("Rejected report path must differ from output path")
            return EXIT_FAILURE

    check_host, check_port = args.check_target
    settings = Settings(
        resolve=args.resolve,
        check_mode=args.check,
        timeout=args.timeout,
        check_host=check_host,
        check_port=check_port,
    )
    queue_size = args.queue_size or args.concurrency * DEFAULT_QUEUE_MULTIPLIER
    started = time.perf_counter()

    try:
        config, stats, rejected = await generate_config(
            iter_proxy_lines(args.input), logger,
            settings=settings,
            concurrency=args.concurrency,
            queue_size=queue_size,
            dedupe_mode=args.dedupe,
            preserve_order=args.preserve_order,
            progress_every=args.progress_every,
        )
        if stats.valid == 0:
            logger.warning("No valid proxies found; writing static profiles only")
        write_json_atomic(config, args.output)
        if args.rejected is not None:
            write_rejected_atomic(rejected, args.rejected)
            logger.info("Rejected report written: %s", args.rejected)
    except asyncio.CancelledError:
        logger.warning("Cancelled by user")
        return 130
    except KeyboardInterrupt:
        logger.warning("Cancelled by user")
        return 130
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        return EXIT_FAILURE

    logger.info("Output written: %s", args.output)
    logger.info("Finished in %.2f sec", time.perf_counter() - started)
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
