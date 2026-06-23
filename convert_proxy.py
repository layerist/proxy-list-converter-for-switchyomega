#!/usr/bin/env python3
"""
Ultra Proxy List Converter
==========================

Converts raw proxy lists into a JSON configuration compatible with proxy
managers such as SwitchyOmega-like profile importers.

Supported input formats
-----------------------
Legacy format:
    host:port:user:pass
    http://host:port:user:pass
    socks5://host:port:user:pass
    http://[2001:db8::1]:8080:user:pass

Standard URL format:
    http://user:pass@host:port
    socks5://user:pass@[2001:db8::1]:1080

Notes
-----
- Passwords may contain ':' in both legacy and URL forms.
- URL-encoded credentials are decoded.
- Processing uses a bounded async window, so huge files do not create one task
  per line.
- DNS resolving and TCP checks are optional.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import signal
import socket
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Literal, Optional, Sequence
from urllib.parse import unquote, urlsplit

# =============================================================================
# Constants
# =============================================================================

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

BYPASS_PATTERNS = (
    "127.0.0.1",
    "::1",
    "localhost",
)

DEFAULT_TIMEOUT = 3.0
DEFAULT_CONCURRENCY = 100
DEFAULT_MAX_PENDING_MULTIPLIER = 4
DEFAULT_PROGRESS_EVERY = 1000

DedupeMode = Literal["full", "host"]


# =============================================================================
# Models
# =============================================================================


@dataclass(frozen=True, slots=True)
class ProxyEntry:
    scheme: str
    host: str
    port: int
    username: str
    password: str

    def dedupe_key(self, mode: DedupeMode) -> tuple[object, ...]:
        if mode == "host":
            return (self.host, self.port)

        return (
            self.scheme,
            self.host,
            self.port,
            self.username,
            self.password,
        )

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.host,
            self.port,
            self.username,
            self.password,
            self.scheme,
        )


@dataclass(slots=True)
class Stats:
    total: int = 0
    parsed: int = 0
    valid: int = 0
    invalid: int = 0
    duplicates: int = 0
    dns_failed: int = 0
    connect_failed: int = 0


# =============================================================================
# Logging
# =============================================================================


def setup_logging(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("proxy_converter")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    logger.addHandler(handler)
    return logger


# =============================================================================
# File helpers
# =============================================================================


def iter_proxy_lines(path: Path) -> Iterator[tuple[int, str]]:
    """Yield non-empty, non-comment lines with their 1-based line numbers."""
    with path.open("r", encoding=ENCODING, errors="ignore") as file:
        for line_no, raw_line in enumerate(file, start=1):
            line = raw_line.strip().lstrip("\ufeff")

            if not line or line.startswith("#"):
                continue

            yield line_no, line


def write_json_atomic(data: dict[str, object], destination: Path) -> None:
    """Write JSON atomically in the destination directory."""
    destination.parent.mkdir(parents=True, exist_ok=True)

    fd: int | None = None
    tmp_path: str | None = None

    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=str(destination.parent),
            text=True,
        )

        with os.fdopen(fd, "w", encoding=ENCODING) as file:
            fd = None
            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False,
            )
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.replace(tmp_path, destination)

    finally:
        if fd is not None:
            os.close(fd)

        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


# =============================================================================
# Host validation / DNS
# =============================================================================


def normalize_host(host: str) -> Optional[str]:
    host = host.strip()

    if not host:
        return None

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    if any(ch.isspace() for ch in host):
        return None

    if any(ch in host for ch in "/:@[]"):
        return None

    host = host.rstrip(".").lower()

    if len(host) > 253 or not host:
        return None

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    labels = ascii_host.split(".")

    for label in labels:
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return None

    return ascii_host


class AsyncDNSCache:
    def __init__(self) -> None:
        self._cache: dict[str, bool] = {}
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

        ok = await asyncio.to_thread(self._resolve_blocking, host)

        async with self._lock:
            self._cache[host] = ok

        return ok

    @staticmethod
    def _resolve_blocking(host: str) -> bool:
        try:
            socket.getaddrinfo(host, None)
            return True
        except socket.gaierror:
            return False


# =============================================================================
# Parser
# =============================================================================


def parse_port(raw_port: str) -> Optional[int]:
    raw_port = raw_port.strip()

    if not raw_port.isdigit():
        return None

    port = int(raw_port)
    if 1 <= port <= 65535:
        return port

    return None


def split_scheme(line: str) -> tuple[str, str] | None:
    if "://" not in line:
        return DEFAULT_SCHEME, line

    scheme, rest = line.split("://", 1)
    scheme = scheme.strip().lower()

    if scheme not in SUPPORTED_SCHEMES:
        return None

    return scheme, rest.strip()


def split_host_port(value: str) -> tuple[str, str] | None:
    """Parse host:port or [IPv6]:port."""
    value = value.strip()

    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return None

        host = value[1:end]
        tail = value[end + 1 :]

        if not tail.startswith(":"):
            return None

        return host, tail[1:]

    if value.count(":") != 1:
        return None

    host, port = value.rsplit(":", 1)
    return host, port


def parse_standard_url(line: str) -> Optional[ProxyEntry]:
    """Parse scheme://user:pass@host:port."""
    if "://" not in line or "@" not in line:
        return None

    try:
        parsed = urlsplit(line)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        return None

    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if not host or port is None:
        return None

    normalized_host = normalize_host(host)
    if normalized_host is None:
        return None

    username = unquote(parsed.username or "").strip()
    password = unquote(parsed.password or "").strip()

    if not username or not password:
        return None

    return ProxyEntry(
        scheme=scheme,
        host=normalized_host,
        port=port,
        username=username,
        password=password,
    )


def parse_legacy_proxy(line: str) -> Optional[ProxyEntry]:
    """Parse host:port:user:pass and scheme://host:port:user:pass."""
    scheme_and_rest = split_scheme(line)
    if scheme_and_rest is None:
        return None

    scheme, rest = scheme_and_rest

    if rest.startswith("["):
        end = rest.find("]")
        if end < 0:
            return None

        host = rest[1:end]
        tail = rest[end + 1 :]

        if not tail.startswith(":"):
            return None

        parts = tail[1:].split(":", 2)
        if len(parts) != 3:
            return None

        raw_port, username, password = parts

    else:
        parts = rest.split(":", 3)
        if len(parts) != 4:
            return None

        host, raw_port, username, password = parts

    normalized_host = normalize_host(host)
    if normalized_host is None:
        return None

    port = parse_port(raw_port)
    if port is None:
        return None

    username = unquote(username.strip())
    password = unquote(password.strip())

    if not username or not password:
        return None

    return ProxyEntry(
        scheme=scheme,
        host=normalized_host,
        port=port,
        username=username,
        password=password,
    )


def parse_proxy(line: str) -> Optional[ProxyEntry]:
    # Try standard URL first because it has unambiguous credentials.
    return parse_standard_url(line) or parse_legacy_proxy(line)


# =============================================================================
# Connectivity Check
# =============================================================================


async def can_connect(host: str, port: int, timeout: float) -> bool:
    writer: asyncio.StreamWriter | None = None

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        return True

    except (OSError, asyncio.TimeoutError):
        return False

    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


# =============================================================================
# Builders
# =============================================================================


def build_bypass_list() -> list[dict[str, str]]:
    return [
        {
            "conditionType": "BypassCondition",
            "pattern": pattern,
        }
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


def build_static_profiles() -> dict[str, object]:
    return {
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


def build_config(proxies: Sequence[ProxyEntry]) -> dict[str, object]:
    config = build_static_profiles()

    for index, proxy in enumerate(proxies, start=1):
        config[f"{PROXY_PREFIX}{index}"] = build_proxy_profile(proxy, index)

    return config


# =============================================================================
# Processing
# =============================================================================


async def process_proxy(
    line_no: int,
    line: str,
    *,
    resolver: AsyncDNSCache,
    resolve: bool,
    check: bool,
    timeout: float,
) -> tuple[int, Optional[ProxyEntry], str | None]:
    proxy = parse_proxy(line)

    if proxy is None:
        return line_no, None, "parse"

    if resolve and not await resolver.resolve(proxy.host):
        return line_no, None, "dns"

    if check and not await can_connect(proxy.host, proxy.port, timeout):
        return line_no, None, "connect"

    return line_no, proxy, None


def dedupe_proxies(
    candidates: list[tuple[int, ProxyEntry]],
    mode: DedupeMode,
    preserve_order: bool,
) -> tuple[list[ProxyEntry], int]:
    seen: set[tuple[object, ...]] = set()
    unique: list[tuple[int, ProxyEntry]] = []
    duplicates = 0

    # First occurrence in the input file wins, even though processing is async.
    for line_no, proxy in sorted(candidates, key=lambda item: item[0]):
        key = proxy.dedupe_key(mode)
        if key in seen:
            duplicates += 1
            continue

        seen.add(key)
        unique.append((line_no, proxy))

    if preserve_order:
        return [proxy for _, proxy in unique], duplicates

    return [proxy for _, proxy in sorted(unique, key=lambda item: item[1].sort_key())], duplicates


async def generate_config(
    lines: Iterable[tuple[int, str]],
    logger: logging.Logger,
    *,
    resolve: bool,
    check: bool,
    timeout: float,
    concurrency: int,
    max_pending: int,
    dedupe_mode: DedupeMode,
    preserve_order: bool,
    progress_every: int,
) -> tuple[dict[str, object], Stats]:
    resolver = AsyncDNSCache()
    stats = Stats()
    candidates: list[tuple[int, ProxyEntry]] = []
    pending: set[asyncio.Task[tuple[int, Optional[ProxyEntry], str | None]]] = set()
    iterator = iter(lines)

    semaphore = asyncio.Semaphore(concurrency)

    async def worker(line_no: int, line: str) -> tuple[int, Optional[ProxyEntry], str | None]:
        async with semaphore:
            return await process_proxy(
                line_no,
                line,
                resolver=resolver,
                resolve=resolve,
                check=check,
                timeout=timeout,
            )

    def schedule_next() -> bool:
        try:
            line_no, line = next(iterator)
        except StopIteration:
            return False

        stats.total += 1
        pending.add(asyncio.create_task(worker(line_no, line)))
        return True

    while len(pending) < max_pending and schedule_next():
        pass

    processed = 0

    while pending:
        done, pending = await asyncio.wait(
            pending,
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in done:
            processed += 1
            line_no, proxy, error_reason = await task

            if proxy is None:
                stats.invalid += 1
                if error_reason == "dns":
                    stats.dns_failed += 1
                elif error_reason == "connect":
                    stats.connect_failed += 1
            else:
                stats.parsed += 1
                candidates.append((line_no, proxy))

            if progress_every > 0 and processed % progress_every == 0:
                logger.info("Processed %d/%d", processed, stats.total)

        while len(pending) < max_pending and schedule_next():
            pass

    proxies, duplicates = dedupe_proxies(
        candidates,
        mode=dedupe_mode,
        preserve_order=preserve_order,
    )

    stats.duplicates = duplicates
    stats.valid = len(proxies)

    logger.info(
        "Stats → total=%d valid=%d invalid=%d duplicates=%d dns_failed=%d connect_failed=%d",
        stats.total,
        stats.valid,
        stats.invalid,
        stats.duplicates,
        stats.dns_failed,
        stats.connect_failed,
    )

    return build_config(proxies), stats


# =============================================================================
# Signals / CLI
# =============================================================================


def install_signal_handlers(logger: logging.Logger) -> None:
    def handler(signum: int, frame: object) -> None:
        logger.warning("Interrupted")
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handler)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert a raw proxy list into JSON proxy-manager configuration."
    )

    parser.add_argument("input", type=Path, help="Input proxy list")
    parser.add_argument("output", type=Path, help="Output JSON config")

    parser.add_argument(
        "--resolve",
        action="store_true",
        help="Resolve DNS names before adding proxies",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check TCP connectivity before adding proxies",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--threads",
        "--concurrency",
        dest="concurrency",
        type=positive_int,
        default=DEFAULT_CONCURRENCY,
        help=f"Concurrent DNS/connect checks (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "--max-pending",
        type=positive_int,
        default=None,
        help="Maximum queued asyncio tasks (default: concurrency * 4)",
    )
    parser.add_argument(
        "--dedupe",
        choices=("full", "host"),
        default="full",
        help="Duplicate detection mode (default: full)",
    )
    parser.add_argument(
        "--preserve-order",
        action="store_true",
        help="Keep input order in generated +mN profiles instead of sorting proxies",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=DEFAULT_PROGRESS_EVERY,
        help=f"Log progress every N processed proxies; 0 disables (default: {DEFAULT_PROGRESS_EVERY})",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    return parser


async def async_main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    logger = setup_logging(args.verbose)
    install_signal_handlers(logger)

    if not args.input.exists():
        logger.error("Input file not found: %s", args.input)
        return EXIT_FAILURE

    if not args.input.is_file():
        logger.error("Input path is not a file: %s", args.input)
        return EXIT_FAILURE

    max_pending = args.max_pending or args.concurrency * DEFAULT_MAX_PENDING_MULTIPLIER
    max_pending = max(max_pending, args.concurrency)

    started = time.perf_counter()

    try:
        config, stats = await generate_config(
            lines=iter_proxy_lines(args.input),
            logger=logger,
            resolve=args.resolve,
            check=args.check,
            timeout=args.timeout,
            concurrency=args.concurrency,
            max_pending=max_pending,
            dedupe_mode=args.dedupe,
            preserve_order=args.preserve_order,
            progress_every=args.progress_every,
        )

        if stats.valid == 0:
            logger.warning("No valid proxies found; writing config with static profiles only")

        write_json_atomic(config, args.output)

    except KeyboardInterrupt:
        logger.warning("Cancelled by user")
        return EXIT_FAILURE

    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        return EXIT_FAILURE

    elapsed = time.perf_counter() - started
    logger.info("Output written: %s", args.output)
    logger.info("Finished in %.2f sec", elapsed)
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
