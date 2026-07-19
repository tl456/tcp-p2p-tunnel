#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stable single-file P2P tunnel node.

Files used by a node:
    node-stable.py
    config.json

The signaling server is semi-trusted and does not know the node shared key.
Every P2P or relay tunnel is authenticated by the nodes themselves. The code
uses only the Python standard library for its network core. Windows tray mode
is enabled when optional packages ``pystray`` and ``Pillow`` are installed.

Python 3.10+ is recommended.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import concurrent.futures
import contextlib
import copy
import ctypes
import hashlib
import hmac
import html
import http.cookies
import http.server
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
import unicodedata
import urllib.parse
import urllib.request
import webbrowser
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable


# =============================================================================
# Protocol constants
# =============================================================================

APPLICATION_VERSION = "2.0-stable"
PROTOCOL_VERSION = 2
MAX_SIGNAL_MESSAGE_HARD = 4 * 1024 * 1024

FRAME_MAGIC = b"PT"
FRAME_HEADER = struct.Struct("!2sBBHQI")

FT_PING = 1
FT_PONG = 2
FT_OPEN_TCP = 10
FT_OPEN_TCP_OK = 11
FT_OPEN_TCP_ERROR = 12
FT_TCP_DATA = 13
FT_TCP_EOF = 14
FT_CLOSE_SESSION = 15
FT_OPEN_UDP = 20
FT_OPEN_UDP_OK = 21
FT_OPEN_UDP_ERROR = 22
FT_UDP_DATA = 23

FLAG_ENCRYPTED = 1

# Only tunnel-wide heartbeat frames may overtake business frames. All session
# frames share the same priority and are ordered by an explicit queue counter.
PRIORITY_HEARTBEAT = 0
PRIORITY_SESSION = 10


# =============================================================================
# Default configuration
# =============================================================================

DEFAULT_CONFIG: dict[str, Any] = {
    "schema_version": 1,
    "node": {
        "id": "A",
        "name": "A-Computer",
        "shared_key": "CHANGE-THIS-NODE-SHARED-KEY-AT-LEAST-16-CHARS",
    },
    "server": {
        "address": "example.com",
        "signal_port": 61009,
        "relay_port": 61010,
        "connect_mode": "AUTO",
        "connect_timeout": 8.0,
        "reconnect_min": 3.0,
        "reconnect_max": 30.0,
        "keepalive_interval": 20.0,
        "keepalive_timeout": 65.0,
    },
    "tunnel": {
        "mode": "AUTO",
        "connection_order": ["IPV6_TCP", "IPV4_TCP", "RELAY"],
        "punch_policy": "PRECONNECT",
        "peer_punch_policies": {},
        "preconnect_retry_interval": 45.0,
        "preconnect_start_delay": 1.0,
        "auto_port": False,
        "p2p_port": 32000,
        "p2p_connect_timeout": 4.0,
        "p2p_handshake_timeout": 6.0,
        "p2p_total_timeout_ipv6": 8.0,
        "p2p_total_timeout_ipv4": 10.0,
        "max_parallel_candidates": 4,
        "candidate_stagger": 0.25,
        "attempt_history_limit": 40,
        "relay_enabled": True,
        "relay_connect_timeout": 10.0,
        "relay_total_timeout": 28.0,
        "relay_retries": 1,
        "relay_upgrade_to_p2p": True,
        "relay_upgrade_interval": 60.0,
        "keep_tunnels_on_signal_loss": True,
        "degraded_keepalive_interval": 5.0,
        "degraded_keepalive_timeout": 45.0,
        "normal_keepalive_interval": 20.0,
        "normal_keepalive_timeout": 65.0,
        "data_frame_size": 16384,
        "max_frame_size": 1048576,
        "max_sessions_per_tunnel": 1024,
        "max_tunnel_queue_frames": 1024,
        "max_tunnel_queue_bytes": 16777216,
        "queue_put_timeout": 15.0,
        "udp_session_timeout": 60.0,
        "max_udp_sessions": 1024,
        "max_udp_datagram": 65507,
    },
    "encryption": {
        "enabled": True,
        "algorithm": "HMAC_STREAM",
    },
    "discovery": {
        "public_ip_enabled": True,
        "timeout": 4.0,
        "refresh_interval": 300.0,
        "ignore_https_certificate_errors": False,
        "ipv6_apis": [
            "https://ipv6.icanhazip.com",
            "https://api64.ipify.org",
            "https://v6.ident.me",
        ],
        "ipv4_apis": [
            "https://ipv4.icanhazip.com",
            "https://v4.ident.me",
        ],
    },
    "recovery": {
        "enabled": True,
        "persistent_memory": True,
        "memory_ttl": 86400.0,
        "total_timeout": 60.0,
        "retry_min": 1.0,
        "retry_max": 8.0,
        "max_candidates": 8,
        "clock_skew": 120.0,
        "accept_after_signal_reconnect_grace": 15.0,
    },
    "web": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 32001,
        "auto_port": True,
        "allow_remote": False,
        "password": "CHANGE-ME",
        "session_ttl": 86400.0,
        "max_sessions": 8,
        "login_failure_window": 60.0,
        "max_login_failures": 5,
        "request_body_limit": 131072,
        "request_timeout": 15.0,
        "status_refresh_ms": 1500,
        "status_snapshot_interval": 0.75,
        "action_timeout": 20.0,
        "theme": "AUTO",
        "open_browser_on_start": False,
    },
    "management": {
        "mode": "AUTO",
        "tray_enabled": True,
        "single_instance": True,
        "tray_refresh_interval": 2.0,
        "open_browser_when_tray_unavailable": False,
        "shutdown_timeout": 25.0,
    },
    "logging": {
        "enabled": True,
        "directory": "./logs",
        "level": "INFO",
        "max_file_size_mb": 50,
        "retention_days": 30,
        "console_mirror": True,
        "candidate_details": True,
        "recent_event_lines": 50,
    },
    "forwards": [],
    "runtime_memory": {"updated_at": 0, "peers": {}},
}


# =============================================================================
# Configuration manager
# =============================================================================


def deep_merge(default: Any, supplied: Any) -> Any:
    if isinstance(default, dict) and isinstance(supplied, dict):
        result = copy.deepcopy(default)
        for key, value in supplied.items():
            result[key] = deep_merge(default[key], value) if key in default else copy.deepcopy(value)
        return result
    return copy.deepcopy(supplied)


def expand_path(value: str, base: Path) -> Path:
    text = os.path.expanduser(str(value))

    def replace_percent(match: re.Match[str]) -> str:
        return os.environ.get(match.group(1), match.group(0))

    text = re.sub(r"%([^%]+)%", replace_percent, text)
    text = os.path.expandvars(text)
    path = Path(text)
    return path if path.is_absolute() else base / path


def read_json_file(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("configuration root must be a JSON object")
    return value


def validate_forward_rule(rule: dict[str, Any], node_id: str) -> dict[str, Any]:
    result = dict(rule)
    rule_id = str(result.get("id", "")).strip()
    if not rule_id or len(rule_id) > 80 or not re.fullmatch(r"[A-Za-z0-9_.-]+", rule_id):
        raise ValueError("forward id must use letters, digits, dot, underscore or dash")
    protocol = str(result.get("protocol", "TCP")).upper()
    if protocol not in {"TCP", "UDP"}:
        raise ValueError(f"forward {rule_id}: unsupported protocol")
    peer = str(result.get("peer", "")).upper()
    if len(peer) != 1 or not ("A" <= peer <= "Z") or peer == node_id:
        raise ValueError(f"forward {rule_id}: invalid peer")
    listen_host = str(result.get("listen_host", "127.0.0.1")).strip()
    target_host = str(result.get("target_host", "127.0.0.1")).strip()
    try:
        listen_port = int(result.get("listen_port", 0))
        target_port = int(result.get("target_port", 0))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"forward {rule_id}: invalid port") from exc
    if not 1 <= listen_port <= 65535 or not 1 <= target_port <= 65535:
        raise ValueError(f"forward {rule_id}: port outside 1-65535")
    if not listen_host or not target_host:
        raise ValueError(f"forward {rule_id}: host cannot be empty")
    result.update(
        {
            "id": rule_id,
            "enabled": bool(result.get("enabled", True)),
            "name": str(result.get("name", rule_id))[:120],
            "protocol": protocol,
            "peer": peer,
            "listen_host": listen_host,
            "listen_port": listen_port,
            "target_host": target_host,
            "target_port": target_port,
        }
    )
    return result


def validate_config(data: dict[str, Any]) -> dict[str, Any]:
    merged = deep_merge(DEFAULT_CONFIG, data)
    node = merged["node"]
    node_id = str(node.get("id", "")).upper()
    node_name = str(node.get("name", "")).strip()
    shared_key = str(node.get("shared_key", ""))
    if len(node_id) != 1 or not ("A" <= node_id <= "Z"):
        raise ValueError("node.id must be one uppercase letter A-Z")
    if not node_name:
        raise ValueError("node.name cannot be empty")
    if len(shared_key.encode("utf-8")) < 16:
        raise ValueError("node.shared_key must contain at least 16 UTF-8 bytes")
    node["id"] = node_id
    node["name"] = node_name

    server = merged["server"]
    if not str(server.get("address", "")).strip():
        raise ValueError("server.address cannot be empty")
    for key in ("signal_port", "relay_port"):
        port = int(server.get(key, 0))
        if not 1 <= port <= 65535:
            raise ValueError(f"server.{key} is invalid")
        server[key] = port
    server["connect_mode"] = str(server.get("connect_mode", "AUTO")).upper()
    if server["connect_mode"] not in {"AUTO", "IPV4_ONLY", "IPV6_ONLY"}:
        raise ValueError("server.connect_mode is invalid")

    tunnel = merged["tunnel"]
    tunnel["mode"] = str(tunnel.get("mode", "AUTO")).upper()
    if tunnel["mode"] not in {"AUTO", "RELAY_ONLY", "IPV4_TCP_ONLY", "IPV6_TCP_ONLY"}:
        raise ValueError("tunnel.mode is invalid")
    tunnel["punch_policy"] = str(tunnel.get("punch_policy", "PRECONNECT")).upper()
    if tunnel["punch_policy"] not in {"PRECONNECT", "ON_DEMAND"}:
        raise ValueError("tunnel.punch_policy is invalid")
    order = [str(item).upper() for item in tunnel.get("connection_order", [])]
    if order != ["IPV6_TCP", "IPV4_TCP", "RELAY"]:
        raise ValueError("tunnel.connection_order must be IPV6_TCP, IPV4_TCP, RELAY")
    tunnel["connection_order"] = order
    if not bool(tunnel.get("auto_port", False)):
        port = int(tunnel.get("p2p_port", 0))
        if not 1 <= port <= 65535:
            raise ValueError("tunnel.p2p_port is invalid")
    policies = tunnel.get("peer_punch_policies", {})
    if not isinstance(policies, dict):
        raise ValueError("tunnel.peer_punch_policies must be an object")
    normalized_policies: dict[str, str] = {}
    for raw_peer, raw_policy in policies.items():
        peer = str(raw_peer).upper()
        policy = str(raw_policy).upper()
        if len(peer) != 1 or not ("A" <= peer <= "Z") or peer == node_id:
            raise ValueError(f"invalid peer policy id: {raw_peer}")
        if policy not in {"PRECONNECT", "ON_DEMAND"}:
            raise ValueError(f"invalid punch policy for {peer}")
        normalized_policies[peer] = policy
    tunnel["peer_punch_policies"] = normalized_policies

    encryption = merged["encryption"]
    encryption["algorithm"] = str(encryption.get("algorithm", "HMAC_STREAM")).upper()
    if encryption["algorithm"] != "HMAC_STREAM":
        raise ValueError("stable build currently supports encryption.algorithm=HMAC_STREAM")

    web = merged["web"]
    if bool(web.get("enabled", True)) and not str(web.get("password", "")):
        raise ValueError("web.password cannot be empty")
    if not 0 <= int(web.get("port", 0)) <= 65535:
        raise ValueError("web.port is invalid")
    web["theme"] = str(web.get("theme", "AUTO")).upper()
    if web["theme"] not in {"AUTO", "LIGHT", "DARK"}:
        raise ValueError("web.theme is invalid")

    management = merged["management"]
    management["mode"] = str(management.get("mode", "AUTO")).upper()
    if management["mode"] not in {"AUTO", "TRAY_WEB", "WEB", "CONSOLE", "HEADLESS"}:
        raise ValueError("management.mode is invalid")

    raw_forwards = merged.get("forwards", [])
    if not isinstance(raw_forwards, list):
        raise ValueError("forwards must be a list")
    forwards: list[dict[str, Any]] = []
    ids: set[str] = set()
    listen_keys: set[tuple[str, str, int]] = set()
    for raw in raw_forwards:
        if not isinstance(raw, dict):
            raise ValueError("every forward must be an object")
        rule = validate_forward_rule(raw, node_id)
        if rule["id"] in ids:
            raise ValueError(f"duplicate forward id: {rule['id']}")
        ids.add(rule["id"])
        if rule["enabled"]:
            key = (rule["protocol"], rule["listen_host"], rule["listen_port"])
            if key in listen_keys:
                raise ValueError(f"duplicate enabled forward listener: {key}")
            listen_keys.add(key)
        forwards.append(rule)
    merged["forwards"] = forwards

    runtime_memory = merged.get("runtime_memory", {})
    if not isinstance(runtime_memory, dict):
        runtime_memory = {"updated_at": 0, "peers": {}}
    if not isinstance(runtime_memory.get("peers"), dict):
        runtime_memory["peers"] = {}
    merged["runtime_memory"] = runtime_memory
    return merged


class ConfigManager:
    def __init__(self, path: Path):
        self.path = path.resolve(strict=False)
        self.base_directory = self.path.parent
        self.backup_path = self.path.with_suffix(self.path.suffix + ".bak")
        self.lock = threading.RLock()
        self.data: dict[str, Any] = {}
        self.loaded_from_backup = False

    def load(self) -> dict[str, Any]:
        with self.lock:
            errors: list[str] = []
            value: dict[str, Any] | None = None
            self.loaded_from_backup = False
            for candidate, backup in ((self.path, False), (self.backup_path, True)):
                try:
                    value = read_json_file(candidate)
                    self.loaded_from_backup = backup
                    break
                except Exception as exc:
                    errors.append(f"{candidate}: {type(exc).__name__}: {exc}")
            if value is None:
                raise FileNotFoundError(
                    "unable to load config.json; copy config-guide.json to config.json first. "
                    + " | ".join(errors)
                )
            self.data = validate_config(value)
            return copy.deepcopy(self.data)

    def reload(self) -> dict[str, Any]:
        return self.load()

    def _atomic_write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        temp = self.path.with_name(self.path.name + f".tmp-{os.getpid()}-{secrets.token_hex(4)}")
        try:
            with temp.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if self.path.exists():
                # Preserve the last known-good backup. A corrupt primary file
                # must never overwrite the valid .bak that allowed recovery.
                try:
                    read_json_file(self.path)
                except Exception:
                    pass
                else:
                    with contextlib.suppress(OSError):
                        shutil.copy2(self.path, self.backup_path)
            os.replace(temp, self.path)
            with contextlib.suppress(OSError):
                directory_fd = os.open(str(self.path.parent), os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            with contextlib.suppress(OSError):
                temp.unlink()

    def save_all(self, value: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            validated = validate_config(value)
            self._atomic_write(validated)
            self.data = validated
            return copy.deepcopy(validated)

    def _fresh_disk_value(self) -> dict[str, Any]:
        try:
            return read_json_file(self.path)
        except Exception:
            return copy.deepcopy(self.data)

    def save_forwards(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        with self.lock:
            value = self._fresh_disk_value()
            value["forwards"] = copy.deepcopy(rules)
            return self.save_all(value)

    def save_runtime_memory(self, memory: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            value = self._fresh_disk_value()
            value["runtime_memory"] = copy.deepcopy(memory)
            return self.save_all(value)

    def save_tunnel_settings(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Atomically update only the Web-editable tunnel settings."""
        with self.lock:
            value = self._fresh_disk_value()
            tunnel = value.setdefault("tunnel", {})
            tunnel.update(copy.deepcopy(updates))
            return self.save_all(value)

    def sanitized(self) -> dict[str, Any]:
        with self.lock:
            value = copy.deepcopy(self.data)
        value.setdefault("node", {})["shared_key"] = "*** hidden ***"
        value.setdefault("web", {})["password"] = "*** hidden ***"
        peers = value.setdefault("runtime_memory", {}).setdefault("peers", {})
        for peer in peers.values():
            if isinstance(peer, dict):
                for generation in peer.get("generations", []) or []:
                    if isinstance(generation, dict) and "secret" in generation:
                        generation["secret"] = "*** hidden ***"
        return value


CONFIG_MANAGER: ConfigManager
CONFIG: dict[str, Any] = {}
CONFIG_PATH: Path
LOCAL_NODE_ID = "A"
LOCAL_NODE_NAME = "Node"
LOCAL_SHARED_KEY = b""


def cfg(path: str, default: Any = None) -> Any:
    value: Any = CONFIG
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def node_id() -> str:
    return LOCAL_NODE_ID


def node_name() -> str:
    return LOCAL_NODE_NAME


def shared_key_bytes() -> bytes:
    return LOCAL_SHARED_KEY


# =============================================================================
# Structured logging and recent events
# =============================================================================

LOG_LEVEL_VALUES = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
EVENTS: deque[str] = deque(maxlen=200)
EVENTS_LOCK = threading.RLock()


class JsonLineLogger:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.directory: Path | None = None
        self.active_path: Path | None = None
        self.active_date = ""
        self.segment = 0
        self.initialized = False

    def initialize(self) -> None:
        with self.lock:
            if self.initialized:
                return
            self.initialized = True
            if not bool(cfg("logging.enabled", True)):
                return
            configured = str(cfg("logging.directory", "./logs"))
            candidates = [
                expand_path(configured, CONFIG_MANAGER.base_directory),
                CONFIG_MANAGER.base_directory / "logs",
                Path(os.environ.get("TEMP") or os.environ.get("TMP") or str(Path.cwd()))
                / "P2PTunnel"
                / "logs",
            ]
            for candidate in candidates:
                try:
                    candidate.mkdir(parents=True, exist_ok=True)
                    probe = candidate / ".write-test"
                    probe.write_text("ok", encoding="utf-8")
                    probe.unlink(missing_ok=True)
                    self.directory = candidate.resolve(strict=False)
                    break
                except OSError:
                    continue
            self.cleanup_old_files()

    def cleanup_old_files(self) -> None:
        days = int(cfg("logging.retention_days", 30))
        if not self.directory or days <= 0:
            return
        cutoff = time.time() - days * 86400
        with contextlib.suppress(OSError):
            for path in self.directory.glob(f"node-{node_id()}-*.jsonl*"):
                with contextlib.suppress(OSError):
                    if path.stat().st_mtime < cutoff:
                        path.unlink(missing_ok=True)

    def _path(self, current: datetime) -> Path | None:
        if not self.directory:
            return None
        date_text = current.strftime("%Y-%m-%d")
        max_bytes = max(1, int(cfg("logging.max_file_size_mb", 50))) * 1024 * 1024
        if date_text != self.active_date:
            self.active_date = date_text
            self.segment = 0
            self.active_path = None
            self.cleanup_old_files()
        while True:
            suffix = "" if self.segment == 0 else f".{self.segment}"
            candidate = self.directory / f"node-{node_id()}-{date_text}.jsonl{suffix}"
            try:
                if not candidate.exists() or candidate.stat().st_size < max_bytes:
                    self.active_path = candidate
                    return candidate
            except OSError:
                return None
            self.segment += 1

    def write(
        self,
        event_name: str,
        *,
        level: str = "INFO",
        message: str = "",
        error: BaseException | None = None,
        include_traceback: bool = False,
        **fields: Any,
    ) -> None:
        level = str(level).upper()
        minimum = LOG_LEVEL_VALUES.get(str(cfg("logging.level", "INFO")).upper(), 20)
        if LOG_LEVEL_VALUES.get(level, 20) < minimum:
            return
        current = datetime.now().astimezone()
        record: dict[str, Any] = {
            "schema": 1,
            "ts": current.isoformat(timespec="milliseconds"),
            "level": level,
            "event": str(event_name),
            "message": str(message),
            "node_id": node_id(),
            "node_name": node_name(),
            "pid": os.getpid(),
            "thread": threading.current_thread().name,
        }
        for key, value in fields.items():
            if isinstance(value, bytes):
                record[key] = f"<bytes:{len(value)}>"
            elif isinstance(value, Path):
                record[key] = str(value)
            else:
                try:
                    json.dumps(value)
                    record[key] = value
                except TypeError:
                    record[key] = str(value)
        if error is not None:
            record["error"] = {"type": type(error).__name__, "message": str(error)}
            if include_traceback:
                record["error"]["traceback"] = "".join(
                    traceback.format_exception(type(error), error, error.__traceback__)
                )
        if bool(cfg("logging.console_mirror", True)) and RUNTIME_HAS_CONSOLE:
            with contextlib.suppress(Exception):
                print(
                    f"{current:%H:%M:%S} {level:<8} {event_name}: {message}",
                    flush=True,
                )
        if not bool(cfg("logging.enabled", True)):
            return
        with self.lock:
            if not self.initialized:
                self.initialize()
            path = self._path(current)
            if not path:
                return
            try:
                with path.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            except OSError:
                pass


JSON_LOGGER = JsonLineLogger()
RUNTIME_HAS_CONSOLE = bool(getattr(sys, "stdout", None)) and Path(sys.executable).name.lower() not in {
    "pythonw.exe",
    "pythonw",
}


def log_event(
    event_name: str,
    *,
    level: str = "INFO",
    message: str = "",
    error: BaseException | None = None,
    include_traceback: bool = False,
    **fields: Any,
) -> None:
    JSON_LOGGER.write(
        event_name,
        level=level,
        message=message,
        error=error,
        include_traceback=include_traceback,
        **fields,
    )


def add_event(text: str, *, level: str = "INFO", event_name: str = "event", **fields: Any) -> None:
    clean = str(text).replace("\r", " ").replace("\n", " ").strip()
    line = f"{time.strftime('%H:%M:%S')} {clean}"
    with EVENTS_LOCK:
        EVENTS.appendleft(line)
    log_event(event_name, level=level, message=clean, **fields)


# =============================================================================
# Packet, socket and text helpers
# =============================================================================


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


async def read_packet(reader: asyncio.StreamReader) -> dict[str, Any]:
    header = await reader.readexactly(4)
    size = struct.unpack("!I", header)[0]
    limit = min(MAX_SIGNAL_MESSAGE_HARD, int(cfg("protocol.max_signal_message", 2 * 1024 * 1024)))
    if size <= 0 or size > limit:
        raise ValueError(f"invalid packet size: {size}")
    payload = await reader.readexactly(size)
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("packet must be a JSON object")
    return value


async def write_packet(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    payload = canonical_json(value)
    if len(payload) > MAX_SIGNAL_MESSAGE_HARD:
        raise ValueError("packet too large")
    writer.write(struct.pack("!I", len(payload)) + payload)
    await writer.drain()


def configure_socket(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if not sock:
        return
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "TCP_KEEPIDLE"):
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    if hasattr(socket, "TCP_KEEPINTVL"):
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    if hasattr(socket, "TCP_KEEPCNT"):
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)


def format_endpoint(endpoint: Any) -> str:
    if not endpoint:
        return "-"
    host, port = str(endpoint[0]), int(endpoint[1])
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def human_bytes(value: int | float) -> str:
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(amount) < 1024 or unit == "TB":
            return f"{amount:.1f}{unit}"
        amount /= 1024
    return f"{value}B"


def format_duration(seconds: float) -> str:
    seconds_i = max(0, int(seconds))
    days, seconds_i = divmod(seconds_i, 86400)
    hours, seconds_i = divmod(seconds_i, 3600)
    minutes, seconds_i = divmod(seconds_i, 60)
    result = []
    if days:
        result.append(f"{days}天")
    if days or hours:
        result.append(f"{hours:02d}小时")
    result.append(f"{minutes:02d}分")
    result.append(f"{seconds_i:02d}秒")
    return " ".join(result)


def display_width(text: str) -> int:
    return sum(
        2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        for char in str(text)
    )


def clip_text(text: str, max_width: int, suffix: str = "...") -> str:
    text = str(text)
    if display_width(text) <= max_width:
        return text
    result: list[str] = []
    used = 0
    limit = max(0, max_width - display_width(suffix))
    for char in text:
        width = 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        if used + width > limit:
            break
        result.append(char)
        used += width
    return "".join(result) + suffix


def is_ip_family(host: str, family: int) -> bool:
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
        return (family == 6 and isinstance(ip, ipaddress.IPv6Address)) or (
            family == 4 and isinstance(ip, ipaddress.IPv4Address)
        )
    except ValueError:
        return False


def candidate_family(host: str) -> int:
    if is_ip_family(host, 6):
        return 6
    if is_ip_family(host, 4):
        return 4
    return 0


def json_payload(value: dict[str, Any]) -> bytes:
    return canonical_json(value)


def parse_json_payload(payload: bytes) -> dict[str, Any]:
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("frame payload must be an object")
    return value


# =============================================================================
# Authentication and lightweight encrypted framing
# =============================================================================


def proof_for(value: dict[str, Any], key: bytes, field: str = "proof") -> str:
    clean = dict(value)
    clean.pop(field, None)
    return hmac.new(key, canonical_json(clean), hashlib.sha256).hexdigest()


def verify_proof(value: dict[str, Any], key: bytes, field: str = "proof") -> bool:
    supplied = str(value.get(field, ""))
    return hmac.compare_digest(supplied, proof_for(value, key, field))


def derive_initial_material(
    peer_id: str,
    attempt_id: str,
    token: str,
    connection_id: str,
    local_nonce: str,
    remote_nonce: str,
) -> tuple[bytes, str, bytes]:
    local_id = node_id()
    low, high = sorted((local_id, peer_id))
    nonce_low = local_nonce if local_id == low else remote_nonce
    nonce_high = remote_nonce if local_id == low else local_nonce
    material = b"|".join(
        [
            b"tunnel-v2",
            low.encode("ascii"),
            high.encode("ascii"),
            attempt_id.encode("utf-8"),
            token.encode("utf-8"),
            connection_id.encode("ascii"),
            nonce_low.encode("ascii"),
            nonce_high.encode("ascii"),
        ]
    )
    master = hmac.new(shared_key_bytes(), material, hashlib.sha256).digest()
    generation_id = attempt_id
    recovery_secret = hmac.new(master, b"recovery-secret-v2", hashlib.sha256).digest()
    return master, generation_id, recovery_secret


def derive_reconnected_material(
    secret: bytes,
    generation_id: str,
    initiator_nonce: str,
    responder_nonce: str,
) -> tuple[bytes, str, bytes]:
    material = b"|".join(
        [
            b"reconnect-v2",
            generation_id.encode("utf-8"),
            initiator_nonce.encode("ascii"),
            responder_nonce.encode("ascii"),
        ]
    )
    master = hmac.new(secret, b"tunnel|" + material, hashlib.sha256).digest()
    next_id = hmac.new(secret, b"generation|" + material, hashlib.sha256).hexdigest()[:32]
    next_secret = hmac.new(secret, b"secret|" + material, hashlib.sha256).digest()
    return master, next_id, next_secret


class FrameCipher:
    """Standard-library HMAC stream cipher with frame authentication.

    This is intentionally retained for zero-dependency compatibility. Every
    tunnel receives a unique master key, independent send/receive keys and a
    strict 64-bit frame sequence. The Web UI labels the algorithm explicitly.
    """

    def __init__(self, master: bytes, peer_id: str):
        local = node_id()
        send_label = f"{local}>{peer_id}".encode("ascii")
        recv_label = f"{peer_id}>{local}".encode("ascii")
        self.send_key = hmac.new(master, b"enc|" + send_label, hashlib.sha256).digest()
        self.send_mac = hmac.new(master, b"mac|" + send_label, hashlib.sha256).digest()
        self.recv_key = hmac.new(master, b"enc|" + recv_label, hashlib.sha256).digest()
        self.recv_mac = hmac.new(master, b"mac|" + recv_label, hashlib.sha256).digest()
        self.send_sequence = 0
        self.recv_sequence = 0

    @staticmethod
    def keystream(key: bytes, sequence: int, size: int) -> bytes:
        output = bytearray()
        block = 0
        while len(output) < size:
            output.extend(
                hmac.new(key, struct.pack("!QI", sequence, block), hashlib.sha256).digest()
            )
            block += 1
        return bytes(output[:size])

    def encrypt(self, frame_type: int, session_id: int, payload: bytes) -> bytes:
        sequence = self.send_sequence
        self.send_sequence += 1
        sequence_bytes = struct.pack("!Q", sequence)
        stream = self.keystream(self.send_key, sequence, len(payload))
        ciphertext = bytes(left ^ right for left, right in zip(payload, stream))
        aad = struct.pack("!BQ", frame_type, session_id)
        tag = hmac.new(
            self.send_mac, aad + sequence_bytes + ciphertext, hashlib.sha256
        ).digest()[:16]
        return sequence_bytes + ciphertext + tag

    def decrypt(self, frame_type: int, session_id: int, payload: bytes) -> bytes:
        if len(payload) < 24:
            raise ValueError("encrypted frame too short")
        sequence = struct.unpack("!Q", payload[:8])[0]
        if sequence != self.recv_sequence:
            raise ValueError(
                f"invalid encrypted frame sequence: got {sequence}, expected {self.recv_sequence}"
            )
        ciphertext = payload[8:-16]
        supplied_tag = payload[-16:]
        aad = struct.pack("!BQ", frame_type, session_id)
        expected = hmac.new(
            self.recv_mac, aad + payload[:8] + ciphertext, hashlib.sha256
        ).digest()[:16]
        if not hmac.compare_digest(supplied_tag, expected):
            raise ValueError("encrypted frame authentication failed")
        self.recv_sequence += 1
        stream = self.keystream(self.recv_key, sequence, len(ciphertext))
        return bytes(left ^ right for left, right in zip(ciphertext, stream))


# =============================================================================
# Runtime state models
# =============================================================================


@dataclass
class PeerInfo:
    node_id: str
    name: str
    p2p_port: int
    mode: str
    encryption: bool
    ipv4: list[dict[str, Any]]
    ipv6: list[dict[str, Any]]
    observed: dict[str, Any]


@dataclass
class Attempt:
    attempt_id: str
    peer_id: str
    token: str
    family: int
    starts_at: float
    expires_at: int
    installed: asyncio.Event = field(default_factory=asyncio.Event)
    created_at: float = field(default_factory=time.time)


@dataclass
class TcpSession:
    session_id: int
    reader: asyncio.StreamReader | None
    writer: asyncio.StreamWriter | None
    open_future: asyncio.Future[bool] | None = None
    rule_id: str = ""
    source: str = ""
    target: str = ""
    created_at: float = field(default_factory=time.time)
    local_eof: bool = False
    remote_eof: bool = False
    closed: bool = False
    upload: int = 0
    download: int = 0
    closed_event: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass
class UdpSession:
    session_id: int
    transport: asyncio.DatagramTransport | None
    source_address: tuple[Any, ...] | None
    listener_transport: asyncio.DatagramTransport | None
    open_future: asyncio.Future[bool] | None = None
    rule_id: str = ""
    target: str = ""
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    upload: int = 0
    download: int = 0
    closed: bool = False


@dataclass
class RecoveryGeneration:
    generation_id: str
    secret: bytes
    created_at: float


@dataclass
class PeerReconnectMemory:
    peer_id: str
    generations: list[RecoveryGeneration]
    preferred_family: int
    preferred_host: str
    preferred_port: int
    candidates: list[dict[str, Any]]
    encrypted: bool
    remembered_at: float
    expires_at: float
    last_result: str = ""


@dataclass
class ForwardRuntime:
    rule: dict[str, Any]
    state: str = "Stopped"
    server: asyncio.AbstractServer | None = None
    transport: asyncio.DatagramTransport | None = None
    protocol_object: Any = None
    last_error: str = ""
    started_at: float = 0.0
    accepted_connections: int = 0
    upload: int = 0
    download: int = 0


# =============================================================================
# Global runtime state
# =============================================================================

APP_STARTED_AT = time.time()
APP_READY = False
APP_SHUTTING_DOWN = False
RESTART_REQUESTED = False
LAST_FATAL_ERROR = ""

ONLINE: dict[str, PeerInfo] = {}
ONLINE_LOCK = threading.RLock()
NODE_LIST_RECEIVED = False
LAST_NODE_LIST_AT = 0.0

SIGNAL_READER: asyncio.StreamReader | None = None
SIGNAL_WRITER: asyncio.StreamWriter | None = None
SIGNAL_SEND_LOCK: asyncio.Lock | None = None
SIGNAL_CONNECTED = False
SIGNAL_ENDPOINT: tuple[Any, ...] | None = None
SIGNAL_RTT: float | None = None
SIGNAL_LAST_PONG = 0.0
SIGNAL_LAST_CONNECT_AT = 0.0
SIGNAL_LAST_DISCONNECT_AT = 0.0
SIGNAL_DEGRADED_MODE = False
SERVER_TIME_OFFSET = 0.0

P2P_SERVERS: list[asyncio.AbstractServer] = []
P2P_LISTEN_PORT = 0
P2P_READY = asyncio.Event()
LOCAL_IPV4: list[str] = []
LOCAL_IPV6: list[str] = []
PUBLIC_IPV4: list[str] = []
PUBLIC_IPV6: list[str] = []
DISCOVERY_STATUS: dict[str, str] = {}

ATTEMPTS: dict[str, Attempt] = {}
ATTEMPT_HISTORY: deque[dict[str, Any]] = deque(maxlen=100)
ATTEMPT_HISTORY_LOCK = threading.RLock()
RELAY_TASKS: dict[str, asyncio.Task[Any]] = {}
RELAY_PEER_EVENTS: dict[str, asyncio.Event] = {}

ACTIVE_TUNNELS: dict[str, "Tunnel"] = {}
DRAINING_TUNNELS: set["Tunnel"] = set()
TUNNEL_LOCKS: dict[str, asyncio.Lock] = {}
CONNECTION_LOCKS: dict[str, asyncio.Lock] = {}
PRECONNECT_TASKS: dict[str, asyncio.Task[Any]] = {}
PRECONNECT_LAST_ATTEMPT: dict[str, float] = {}
PRECONNECT_WAKEUP = asyncio.Event()
DIRECT_RECONNECT_TASKS: dict[str, asyncio.Task[Any]] = {}
RECONNECT_MEMORY: dict[str, PeerReconnectMemory] = {}
RECONNECT_MEMORY_SAVE_TASK: asyncio.Task[Any] | None = None
DIRECT_RECONNECT_NONCES: dict[str, float] = {}

FORWARD_MANAGER: "ForwardManager"
UPLOAD_BYTES = 0
DOWNLOAD_BYTES = 0

CORE_LOOP: asyncio.AbstractEventLoop | None = None
CORE_MAIN_TASK: asyncio.Task[Any] | None = None
CORE_THREAD: threading.Thread | None = None
CORE_STOPPED = threading.Event()
TRAY_ICON: Any = None
INSTANCE_MUTEX_HANDLE: Any = None
TRAY_ACTION_LOCK = threading.Lock()
TRAY_ACTIONS_RUNNING: set[str] = set()
TRAY_CONFIRM_LOCK = threading.Lock()

STATUS_SNAPSHOT_LOCK = threading.RLock()
LATEST_STATUS_SNAPSHOT: dict[str, Any] = {}
LATEST_STATUS_SNAPSHOT_AT = 0.0
RATE_SAMPLE_AT = time.time()
RATE_SAMPLE_UPLOAD = 0
RATE_SAMPLE_DOWNLOAD = 0
RATE_UPLOAD_BPS = 0.0
RATE_DOWNLOAD_BPS = 0.0


# =============================================================================
# Address discovery
# =============================================================================


def collect_local_addresses() -> tuple[list[str], list[str]]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    records: list[Any] = []
    names = {socket.gethostname(), socket.getfqdn(), "localhost"}
    for name in names:
        with contextlib.suppress(OSError):
            records.extend(
                socket.getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            )
    # A UDP connect does not send traffic but often reveals the preferred local
    # interface even when hostname resolution omits it.
    for family, destination in (
        (socket.AF_INET, ("8.8.8.8", 53)),
        (socket.AF_INET6, ("2001:4860:4860::8888", 53, 0, 0)),
    ):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.connect(destination)
            host = str(sock.getsockname()[0])
            records.append((family, socket.SOCK_DGRAM, 0, "", (host, 0)))
        except OSError:
            pass
        finally:
            sock.close()

    for family, _, _, _, address in records:
        host = str(address[0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
            continue
        if isinstance(ip, ipaddress.IPv4Address):
            ipv4.add(str(ip))
        elif not ip.is_link_local and not ip.ipv4_mapped:
            ipv6.add(str(ip))
    return sorted(ipv4), sorted(ipv6)


def query_public_api(url: str, family: int) -> tuple[str, str, str]:
    try:
        context = None
        if bool(cfg("discovery.ignore_https_certificate_errors", False)):
            context = ssl._create_unverified_context()
        request = urllib.request.Request(
            url, headers={"User-Agent": f"P2P-Tunnel/{APPLICATION_VERSION}"}
        )
        with urllib.request.urlopen(
            request,
            timeout=float(cfg("discovery.timeout", 4.0)),
            context=context,
        ) as response:
            text = response.read(4096).decode("utf-8", "ignore").strip()
        candidate = text.split()[0].strip()
        ip = ipaddress.ip_address(candidate)
        if family == 4 and not isinstance(ip, ipaddress.IPv4Address):
            return url, "", "FamilyMismatch"
        if family == 6 and not isinstance(ip, ipaddress.IPv6Address):
            return url, "", "FamilyMismatch"
        return url, str(ip), "Success"
    except Exception as exc:
        return url, "", type(exc).__name__


async def discover_public_addresses() -> None:
    global LOCAL_IPV4, LOCAL_IPV6, PUBLIC_IPV4, PUBLIC_IPV6
    LOCAL_IPV4, LOCAL_IPV6 = collect_local_addresses()
    if not bool(cfg("discovery.public_ip_enabled", True)):
        PUBLIC_IPV4, PUBLIC_IPV6 = [], []
        return
    jobs: list[tuple[str, int]] = []
    jobs.extend((str(url), 6) for url in cfg("discovery.ipv6_apis", []))
    jobs.extend((str(url), 4) for url in cfg("discovery.ipv4_apis", []))
    loop = asyncio.get_running_loop()
    results = await asyncio.gather(
        *(loop.run_in_executor(None, query_public_api, url, family) for url, family in jobs),
        return_exceptions=True,
    )
    found4: set[str] = set()
    found6: set[str] = set()
    for (url, family), result in zip(jobs, results):
        if isinstance(result, BaseException):
            DISCOVERY_STATUS[url] = type(result).__name__
            continue
        _, address, status = result
        DISCOVERY_STATUS[url] = status
        if address:
            (found6 if family == 6 else found4).add(address)
    changed = sorted(found4) != PUBLIC_IPV4 or sorted(found6) != PUBLIC_IPV6
    PUBLIC_IPV4, PUBLIC_IPV6 = sorted(found4), sorted(found6)
    if changed:
        add_event(
            f"公网地址更新：IPv6={len(PUBLIC_IPV6)} IPv4={len(PUBLIC_IPV4)}",
            event_name="address_updated",
        )
        if SIGNAL_CONNECTED:
            with contextlib.suppress(Exception):
                await signal_send(
                    {
                        "type": "ENDPOINT_UPDATE",
                        "ipv4": build_own_candidates(4),
                        "ipv6": build_own_candidates(6),
                        "p2p_port": P2P_LISTEN_PORT,
                    }
                )


async def discovery_loop() -> None:
    while not APP_SHUTTING_DOWN:
        try:
            await discover_public_addresses()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            add_event(
                f"公网地址发现失败：{type(exc).__name__}: {exc}",
                level="WARNING",
                event_name="address_discovery_failed",
            )
        await asyncio.sleep(float(cfg("discovery.refresh_interval", 300.0)))


def build_own_candidates(family: int) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    local = LOCAL_IPV6 if family == 6 else LOCAL_IPV4
    public = PUBLIC_IPV6 if family == 6 else PUBLIC_IPV4
    for address in local:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if family == 4:
            priority = 130 if ip.is_private else 100
        else:
            priority = 120 if ip.is_global else 90
        values.append(
            {
                "host": address,
                "port": P2P_LISTEN_PORT,
                "source": "local",
                "priority": priority,
            }
        )
    for address in public:
        values.append(
            {
                "host": address,
                "port": P2P_LISTEN_PORT,
                "source": "public_api",
                "priority": 100,
            }
        )
    unique: dict[tuple[str, int], dict[str, Any]] = {}
    for value in values:
        key = (value["host"], value["port"])
        if key not in unique or value["priority"] > unique[key]["priority"]:
            unique[key] = value
    return sorted(unique.values(), key=lambda item: int(item["priority"]), reverse=True)


# =============================================================================
# Signaling connection
# =============================================================================


async def open_server_connection(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    address = str(cfg("server.address", ""))
    mode = str(cfg("server.connect_mode", "AUTO")).upper()
    records = await asyncio.get_running_loop().getaddrinfo(
        address, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
    )
    candidates: list[tuple[int, tuple[Any, ...]]] = []
    seen: set[tuple[int, str, int]] = set()
    for family, _, _, _, endpoint in records:
        if mode == "IPV6_ONLY" and family != socket.AF_INET6:
            continue
        if mode == "IPV4_ONLY" and family != socket.AF_INET:
            continue
        key = (family, str(endpoint[0]), int(endpoint[1]))
        if key in seen:
            continue
        seen.add(key)
        candidates.append((family, endpoint))
    if mode == "AUTO":
        candidates.sort(key=lambda item: 0 if item[0] == socket.AF_INET6 else 1)
    if not candidates:
        raise ConnectionError("server address resolved to no usable endpoint")
    last_error: BaseException | None = None
    timeout = float(cfg("server.connect_timeout", 8.0))
    for family, endpoint in candidates:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(endpoint[0]), int(endpoint[1]), family=family),
                timeout=timeout,
            )
            configure_socket(writer)
            return reader, writer
        except Exception as exc:
            last_error = exc
    raise ConnectionError(f"cannot connect to server: {last_error}")


async def signal_send(message: dict[str, Any]) -> None:
    writer = SIGNAL_WRITER
    if not writer or writer.is_closing():
        raise ConnectionError("signal server disconnected")
    if SIGNAL_SEND_LOCK is None:
        raise RuntimeError("signal send lock is unavailable")
    async with SIGNAL_SEND_LOCK:
        await write_packet(writer, message)


def parse_peer(value: dict[str, Any]) -> PeerInfo:
    return PeerInfo(
        node_id=str(value.get("id", value.get("node_id", ""))).upper(),
        name=str(value.get("name", value.get("node_name", ""))),
        p2p_port=int(value.get("p2p_port", 0) or 0),
        mode=str(value.get("mode", value.get("tunnel_mode", "AUTO"))).upper(),
        encryption=bool(value.get("encryption", True)),
        ipv4=[item for item in value.get("ipv4", []) if isinstance(item, dict)],
        ipv6=[item for item in value.get("ipv6", []) if isinstance(item, dict)],
        observed=dict(value.get("observed", {}) or {}),
    )


def extract_node_records(message: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
    containers = [message]
    for key in ("data", "payload", "result"):
        nested = message.get(key)
        if isinstance(nested, dict):
            containers.append(nested)
    for container in containers:
        for key in ("nodes", "node_list", "peers"):
            if key not in container:
                continue
            raw = container.get(key)
            if raw is None:
                return True, []
            if isinstance(raw, list):
                return True, [item for item in raw if isinstance(item, dict)]
            if isinstance(raw, dict):
                records = []
                for peer_id, item in raw.items():
                    if isinstance(item, dict):
                        copied = dict(item)
                        copied.setdefault("id", str(peer_id))
                        records.append(copied)
                return True, records
            return True, []
    return False, []


def clear_online_nodes() -> None:
    global NODE_LIST_RECEIVED, LAST_NODE_LIST_AT
    with ONLINE_LOCK:
        ONLINE.clear()
        NODE_LIST_RECEIVED = False
        LAST_NODE_LIST_AT = 0.0


def apply_online_nodes(message: dict[str, Any], source: str) -> bool:
    global NODE_LIST_RECEIVED, LAST_NODE_LIST_AT
    present, records = extract_node_records(message)
    if not present:
        return False
    updated: dict[str, PeerInfo] = {}
    for value in records:
        try:
            peer = parse_peer(value)
        except (TypeError, ValueError, OverflowError):
            continue
        if (
            len(peer.node_id) == 1
            and "A" <= peer.node_id <= "Z"
            and peer.node_id != node_id()
        ):
            updated[peer.node_id] = peer
    with ONLINE_LOCK:
        previous = set(ONLINE)
        ONLINE.clear()
        ONLINE.update(updated)
        NODE_LIST_RECEIVED = True
        LAST_NODE_LIST_AT = time.time()
        current = set(ONLINE)
    if previous != current or source == "REGISTER_OK":
        add_event(
            f"在线节点更新（{source}）：{', '.join(sorted(current)) or '无'}",
            event_name="online_nodes_updated",
            online_nodes=sorted(current),
        )
    PRECONNECT_WAKEUP.set()
    return True


def update_server_time(server_time: Any) -> None:
    global SERVER_TIME_OFFSET
    try:
        sample = float(server_time) - time.time()
    except (TypeError, ValueError, OverflowError):
        return
    # Smooth clock-offset changes so a single delayed packet cannot move the
    # coordinated punch start time abruptly.
    SERVER_TIME_OFFSET = sample if SERVER_TIME_OFFSET == 0 else SERVER_TIME_OFFSET * 0.8 + sample * 0.2


async def signal_reader_loop(reader: asyncio.StreamReader) -> None:
    global SIGNAL_RTT, SIGNAL_LAST_PONG
    while True:
        message = await read_packet(reader)
        update_server_time(message.get("server_time"))
        message_type = str(message.get("type", ""))
        if message_type == "NODE_LIST":
            apply_online_nodes(message, "NODE_LIST")
        elif message_type == "PING":
            await signal_send(
                {
                    "type": "PONG",
                    "id": message.get("id"),
                    "sent_at": message.get("sent_at"),
                }
            )
        elif message_type == "PONG":
            try:
                sent_at = float(message.get("sent_at", time.time()))
                SIGNAL_RTT = max(0.0, (time.time() - sent_at) * 1000)
            except (TypeError, ValueError):
                pass
            SIGNAL_LAST_PONG = time.time()
        elif message_type == "PUNCH_PREPARE":
            asyncio.create_task(handle_punch_prepare(message), name="punch-prepare")
        elif message_type == "RELAY_OFFER":
            relay_id = str(message.get("relay_id", ""))
            if relay_id and relay_id not in RELAY_TASKS:
                task = asyncio.create_task(handle_relay_offer(message), name=f"relay-offer:{relay_id}")
                RELAY_TASKS[relay_id] = task

                def cleanup(done: asyncio.Task[Any], target: str = relay_id) -> None:
                    if RELAY_TASKS.get(target) is done:
                        RELAY_TASKS.pop(target, None)
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        done.result()

                task.add_done_callback(cleanup)
        elif message_type in {"CONNECT_ERROR", "RELAY_ERROR", "ERROR"}:
            add_event(
                str(message.get("error", message_type)),
                level="WARNING",
                event_name="signal_error",
                message_type=message_type,
            )
        elif message_type == "SESSION_REPLACED":
            raise ConnectionError(str(message.get("reason", "signal session replaced")))


async def signal_ping_loop() -> None:
    global SIGNAL_LAST_PONG
    interval = float(cfg("server.keepalive_interval", 20.0))
    timeout = float(cfg("server.keepalive_timeout", 65.0))
    while SIGNAL_CONNECTED:
        sent_at = time.time()
        await signal_send(
            {"type": "PING", "id": secrets.token_hex(4), "sent_at": sent_at}
        )
        await asyncio.sleep(interval)
        if SIGNAL_LAST_PONG and time.time() - SIGNAL_LAST_PONG > timeout:
            raise ConnectionError("signal heartbeat timeout")


async def signal_connection_loop() -> None:
    global SIGNAL_READER, SIGNAL_WRITER, SIGNAL_CONNECTED, SIGNAL_ENDPOINT
    global SIGNAL_LAST_PONG, SIGNAL_LAST_CONNECT_AT, SIGNAL_LAST_DISCONNECT_AT
    global SIGNAL_DEGRADED_MODE, SIGNAL_SEND_LOCK
    delay = float(cfg("server.reconnect_min", 3.0))
    while not APP_SHUTTING_DOWN:
        connected_session = False
        error: BaseException | None = None
        try:
            reader, writer = await open_server_connection(int(cfg("server.signal_port", 61009)))
            challenge = await asyncio.wait_for(read_packet(reader), timeout=10.0)
            if challenge.get("type") != "SERVER_CHALLENGE":
                raise ConnectionError("server did not send registration challenge")
            if int(challenge.get("version", 0)) != PROTOCOL_VERSION:
                raise ConnectionError("server protocol version mismatch")
            update_server_time(challenge.get("server_time"))
            registration = {
                "type": "REGISTER",
                "version": PROTOCOL_VERSION,
                "challenge": str(challenge.get("challenge", "")),
                "client_nonce": secrets.token_hex(16),
                "node_id": node_id(),
                "node_name": node_name(),
                "p2p_port": P2P_LISTEN_PORT,
                "tunnel_mode": str(cfg("tunnel.mode", "AUTO")).upper(),
                "encryption": bool(cfg("encryption.enabled", True)),
                "ipv4": build_own_candidates(4),
                "ipv6": build_own_candidates(6),
            }
            await write_packet(writer, registration)
            response = await asyncio.wait_for(read_packet(reader), timeout=15.0)
            if response.get("type") != "REGISTER_OK":
                raise ConnectionError(str(response.get("error", "registration failed")))

            SIGNAL_READER, SIGNAL_WRITER = reader, writer
            SIGNAL_SEND_LOCK = asyncio.Lock()
            SIGNAL_ENDPOINT = writer.get_extra_info("peername")
            clear_online_nodes()
            apply_online_nodes(response, "REGISTER_OK")
            update_server_time(response.get("server_time"))
            was_degraded = SIGNAL_DEGRADED_MODE
            SIGNAL_CONNECTED = True
            connected_session = True
            SIGNAL_LAST_CONNECT_AT = time.time()
            SIGNAL_LAST_PONG = time.time()
            SIGNAL_DEGRADED_MODE = False
            PRECONNECT_WAKEUP.set()
            delay = float(cfg("server.reconnect_min", 3.0))
            add_event(
                f"信令已连接：{format_endpoint(SIGNAL_ENDPOINT)}",
                event_name="signal_connected",
            )
            if was_degraded:
                add_event("信令恢复，保留现有隧道", event_name="signal_degraded_exit")
            await asyncio.gather(signal_reader_loop(reader), signal_ping_loop())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = exc
            add_event(
                f"信令{'断开' if connected_session else '连接失败'}：{type(exc).__name__}: {exc}",
                level="WARNING",
                event_name="signal_disconnected" if connected_session else "signal_connect_failed",
            )
        finally:
            was_connected = SIGNAL_CONNECTED or connected_session
            SIGNAL_CONNECTED = False
            clear_online_nodes()
            PRECONNECT_WAKEUP.set()
            writer = SIGNAL_WRITER
            SIGNAL_READER = None
            SIGNAL_WRITER = None
            SIGNAL_SEND_LOCK = None
            if writer:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            if was_connected:
                SIGNAL_LAST_DISCONNECT_AT = time.time()
                active_count = sum(1 for tunnel in ACTIVE_TUNNELS.values() if not tunnel.closed)
                if bool(cfg("tunnel.keep_tunnels_on_signal_loss", True)) and active_count:
                    SIGNAL_DEGRADED_MODE = True
                    add_event(
                        f"进入降级模式，保留 {active_count} 条活动隧道",
                        level="WARNING",
                        event_name="signal_degraded_enter",
                        error=str(error or ""),
                    )
                elif not bool(cfg("tunnel.keep_tunnels_on_signal_loss", True)):
                    for tunnel in list(ACTIVE_TUNNELS.values()):
                        await tunnel.close("signal_loss_policy")
        await asyncio.sleep(delay)
        delay = min(float(cfg("server.reconnect_max", 30.0)), delay * 2)


# =============================================================================
# Tunnel frames and session transport
# =============================================================================


class TunnelHeartbeatTimeout(ConnectionError):
    pass


class RemoteUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, tunnel: "Tunnel", session_id: int):
        self.tunnel = tunnel
        self.session_id = session_id

    def datagram_received(self, data: bytes, addr: Any) -> None:
        asyncio.create_task(
            self.tunnel.send_frame(
                FT_UDP_DATA,
                self.session_id,
                data,
                priority=PRIORITY_SESSION,
            )
        )

    def error_received(self, exc: Exception) -> None:
        log_event(
            "remote_udp_error",
            level="DEBUG",
            message="Remote UDP transport reported an error",
            peer_id=self.tunnel.peer_id,
            session_id=self.session_id,
            error=exc,
        )


class Tunnel:
    def __init__(
        self,
        peer_id: str,
        kind: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        master_key: bytes,
        encrypted: bool,
        *,
        recovery_generation_id: str = "",
        recovery_secret: bytes = b"",
        recovery_candidates: list[dict[str, Any]] | None = None,
        preferred_family: int = 0,
        preferred_host: str = "",
        preferred_port: int = 0,
        connection_id: str = "",
        dialer_id: str = "",
    ) -> None:
        self.peer_id = peer_id
        self.kind = kind
        self.reader = reader
        self.writer = writer
        self.encrypted = encrypted
        self.cipher = FrameCipher(master_key, peer_id) if encrypted else None
        self.recovery_generation_id = recovery_generation_id
        self.recovery_secret = recovery_secret
        self.recovery_candidates = list(recovery_candidates or [])
        self.preferred_family = preferred_family
        self.preferred_host = preferred_host
        self.preferred_port = preferred_port
        self.connection_id = str(connection_id)
        self.dialer_id = str(dialer_id).upper()

        self.queue: asyncio.PriorityQueue[tuple[int, int, int, int, bytes, int]] = (
            asyncio.PriorityQueue(maxsize=int(cfg("tunnel.max_tunnel_queue_frames", 1024)))
        )
        self.queue_sequence = 0
        self.queued_bytes = 0
        self.sessions: dict[int, TcpSession | UdpSession] = {}
        self.closed = False
        self.draining = False
        self.close_reason = ""
        self.upload = 0
        self.download = 0
        self.rtt: float | None = None
        self.last_pong = time.time()
        self.created_at = time.time()
        self.next_session = 1 if node_id() < peer_id else 2
        self.writer_task: asyncio.Task[Any] | None = None
        self.reader_task: asyncio.Task[Any] | None = None
        self.ping_task: asyncio.Task[Any] | None = None
        self.unknown_sessions_warned: dict[int, float] = {}

    def allocate_session_id(self) -> int:
        if len(self.sessions) >= int(cfg("tunnel.max_sessions_per_tunnel", 1024)):
            raise ConnectionError("tunnel session limit reached")
        result = self.next_session
        self.next_session += 2
        if self.next_session > 0xFFFFFFFFFFFFFFFD:
            self.next_session = 1 if node_id() < self.peer_id else 2
        while result in self.sessions:
            result = self.next_session
            self.next_session += 2
        return result

    async def send_frame(
        self,
        frame_type: int,
        session_id: int = 0,
        payload: bytes = b"",
        *,
        priority: int = PRIORITY_SESSION,
    ) -> None:
        if self.closed:
            raise ConnectionError("tunnel closed")
        max_frame = int(cfg("tunnel.max_frame_size", 1048576))
        if len(payload) > max_frame:
            raise ValueError("frame payload too large")
        estimated = FRAME_HEADER.size + len(payload) + (24 if self.cipher else 0)
        if self.queued_bytes + estimated > int(cfg("tunnel.max_tunnel_queue_bytes", 16777216)):
            raise BufferError("tunnel send byte queue limit reached")
        self.queue_sequence += 1
        item = (priority, self.queue_sequence, frame_type, session_id, payload, estimated)
        self.queued_bytes += estimated
        try:
            await asyncio.wait_for(
                self.queue.put(item), timeout=float(cfg("tunnel.queue_put_timeout", 15.0))
            )
        except Exception:
            self.queued_bytes = max(0, self.queued_bytes - estimated)
            raise

    async def writer_loop(self) -> None:
        global UPLOAD_BYTES
        while not self.closed:
            priority, queue_seq, frame_type, session_id, payload, estimated = await self.queue.get()
            del priority, queue_seq
            self.queued_bytes = max(0, self.queued_bytes - estimated)
            flags = 0
            if self.cipher:
                # Encryption and sequence allocation happen only after the final
                # queue order is known. This keeps cipher sequence equal to the
                # actual TCP write order.
                payload = self.cipher.encrypt(frame_type, session_id, payload)
                flags |= FLAG_ENCRYPTED
            header = FRAME_HEADER.pack(
                FRAME_MAGIC,
                PROTOCOL_VERSION,
                frame_type,
                flags,
                session_id,
                len(payload),
            )
            self.writer.write(header + payload)
            await self.writer.drain()
            transferred = len(header) + len(payload)
            self.upload += transferred
            UPLOAD_BYTES += transferred

    async def reader_loop(self) -> None:
        global DOWNLOAD_BYTES
        max_frame = int(cfg("tunnel.max_frame_size", 1048576))
        while not self.closed:
            header = await self.reader.readexactly(FRAME_HEADER.size)
            magic, version, frame_type, flags, session_id, length = FRAME_HEADER.unpack(header)
            if magic != FRAME_MAGIC or version != PROTOCOL_VERSION:
                raise ValueError("invalid tunnel frame header")
            if length > max_frame + 64:
                raise ValueError("tunnel frame too large")
            payload = await self.reader.readexactly(length)
            transferred = len(header) + len(payload)
            self.download += transferred
            DOWNLOAD_BYTES += transferred
            if flags & FLAG_ENCRYPTED:
                if not self.cipher:
                    raise ValueError("unexpected encrypted frame")
                payload = self.cipher.decrypt(frame_type, session_id, payload)
            elif self.cipher:
                raise ValueError("unencrypted frame received on encrypted tunnel")
            await self.handle_frame(frame_type, session_id, payload)

    async def ping_loop(self) -> None:
        while not self.closed:
            degraded = not SIGNAL_CONNECTED and bool(
                cfg("tunnel.keep_tunnels_on_signal_loss", True)
            )
            interval = float(
                cfg(
                    "tunnel.degraded_keepalive_interval"
                    if degraded
                    else "tunnel.normal_keepalive_interval",
                    5.0 if degraded else 20.0,
                )
            )
            timeout = float(
                cfg(
                    "tunnel.degraded_keepalive_timeout"
                    if degraded
                    else "tunnel.normal_keepalive_timeout",
                    45.0 if degraded else 65.0,
                )
            )
            await asyncio.sleep(interval)
            sent_at = time.time()
            await self.send_frame(
                FT_PING,
                payload=struct.pack("!d", sent_at),
                priority=PRIORITY_HEARTBEAT,
            )
            if time.time() - self.last_pong > timeout:
                raise TunnelHeartbeatTimeout(
                    "tunnel heartbeat timeout during signal outage"
                    if degraded
                    else "tunnel heartbeat timeout"
                )

    async def handle_frame(self, frame_type: int, session_id: int, payload: bytes) -> None:
        if frame_type == FT_PING:
            await self.send_frame(
                FT_PONG, payload=payload, priority=PRIORITY_HEARTBEAT
            )
            return
        if frame_type == FT_PONG:
            if len(payload) == 8:
                sent_at = struct.unpack("!d", payload)[0]
                self.rtt = max(0.0, (time.time() - sent_at) * 1000)
            self.last_pong = time.time()
            return
        if frame_type == FT_OPEN_TCP:
            await self.handle_open_tcp(session_id, parse_json_payload(payload))
            return
        if frame_type == FT_OPEN_TCP_OK:
            session = self.sessions.get(session_id)
            if isinstance(session, TcpSession) and session.open_future and not session.open_future.done():
                session.open_future.set_result(True)
            return
        if frame_type == FT_OPEN_TCP_ERROR:
            session = self.sessions.get(session_id)
            if isinstance(session, TcpSession) and session.open_future and not session.open_future.done():
                session.open_future.set_exception(
                    ConnectionError(payload.decode("utf-8", "replace"))
                )
            return
        if frame_type == FT_TCP_DATA:
            session = self.sessions.get(session_id)
            if not isinstance(session, TcpSession) or not session.writer or session.closed:
                await self.notify_unknown_session(session_id)
                return
            if session.remote_eof:
                await self.close_session(session_id, notify=True, reason="data_after_eof")
                return
            try:
                session.writer.write(payload)
                await session.writer.drain()
            except Exception as exc:
                log_event(
                    "tcp_session_write_failed",
                    level="DEBUG",
                    message="Local TCP destination write failed",
                    peer_id=self.peer_id,
                    session_id=session_id,
                    error=exc,
                )
                await self.close_session(session_id, notify=True, reason="local_write_error")
                return
            session.download += len(payload)
            forward_runtime_add_bytes(session.rule_id, download=len(payload))
            return
        if frame_type == FT_TCP_EOF:
            session = self.sessions.get(session_id)
            if not isinstance(session, TcpSession) or session.closed:
                await self.notify_unknown_session(session_id)
                return
            if not session.remote_eof:
                session.remote_eof = True
                if session.writer:
                    try:
                        session.writer.write_eof()
                    except (OSError, AttributeError, NotImplementedError):
                        # TCP transports normally support half-close. If the
                        # platform refuses it, closing is safer than accepting
                        # data after an announced EOF.
                        session.writer.close()
            await self.maybe_finish_tcp_session(session)
            return
        if frame_type == FT_CLOSE_SESSION:
            await self.close_session(session_id, notify=False, reason="peer_close")
            return
        if frame_type == FT_OPEN_UDP:
            await self.handle_open_udp(session_id, parse_json_payload(payload))
            return
        if frame_type == FT_OPEN_UDP_OK:
            session = self.sessions.get(session_id)
            if isinstance(session, UdpSession) and session.open_future and not session.open_future.done():
                session.open_future.set_result(True)
            return
        if frame_type == FT_OPEN_UDP_ERROR:
            session = self.sessions.get(session_id)
            if isinstance(session, UdpSession) and session.open_future and not session.open_future.done():
                session.open_future.set_exception(
                    ConnectionError(payload.decode("utf-8", "replace"))
                )
            return
        if frame_type == FT_UDP_DATA:
            session = self.sessions.get(session_id)
            if not isinstance(session, UdpSession) or session.closed:
                await self.notify_unknown_session(session_id)
                return
            session.last_seen = time.time()
            session.download += len(payload)
            forward_runtime_add_bytes(session.rule_id, download=len(payload))
            if session.source_address and session.listener_transport:
                session.listener_transport.sendto(payload, session.source_address)
            elif session.transport:
                session.transport.sendto(payload)
            return
        raise ValueError(f"unknown frame type: {frame_type}")

    async def notify_unknown_session(self, session_id: int) -> None:
        current = time.time()
        last = self.unknown_sessions_warned.get(session_id, 0.0)
        if current - last > 30:
            self.unknown_sessions_warned[session_id] = current
            log_event(
                "unknown_session_frame",
                level="WARNING",
                message="Frame received for an unknown session",
                peer_id=self.peer_id,
                session_id=session_id,
            )
        with contextlib.suppress(Exception):
            await self.send_frame(
                FT_CLOSE_SESSION,
                session_id,
                priority=PRIORITY_SESSION,
            )

    async def handle_open_tcp(self, session_id: int, value: dict[str, Any]) -> None:
        if len(self.sessions) >= int(cfg("tunnel.max_sessions_per_tunnel", 1024)):
            await self.send_frame(
                FT_OPEN_TCP_ERROR,
                session_id,
                b"session limit reached",
                priority=PRIORITY_SESSION,
            )
            return
        host = str(value.get("host", ""))
        port = int(value.get("port", 0) or 0)
        rule_id = str(value.get("rule_id", ""))[:80]
        if not host or not 1 <= port <= 65535:
            await self.send_frame(
                FT_OPEN_TCP_ERROR,
                session_id,
                b"invalid target",
                priority=PRIORITY_SESSION,
            )
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )
            configure_socket(writer)
            session = TcpSession(
                session_id=session_id,
                reader=reader,
                writer=writer,
                rule_id=rule_id,
                source=f"peer:{self.peer_id}",
                target=format_endpoint((host, port)),
            )
            self.sessions[session_id] = session
            await self.send_frame(
                FT_OPEN_TCP_OK, session_id, priority=PRIORITY_SESSION
            )
            asyncio.create_task(
                self.pump_tcp(session), name=f"tcp-pump:{self.peer_id}:{session_id}"
            )
        except Exception as exc:
            await self.send_frame(
                FT_OPEN_TCP_ERROR,
                session_id,
                str(exc).encode("utf-8")[:1024],
                priority=PRIORITY_SESSION,
            )

    async def handle_open_udp(self, session_id: int, value: dict[str, Any]) -> None:
        if len(self.sessions) >= int(cfg("tunnel.max_sessions_per_tunnel", 1024)):
            await self.send_frame(
                FT_OPEN_UDP_ERROR,
                session_id,
                b"session limit reached",
                priority=PRIORITY_SESSION,
            )
            return
        host = str(value.get("host", ""))
        port = int(value.get("port", 0) or 0)
        rule_id = str(value.get("rule_id", ""))[:80]
        if not host or not 1 <= port <= 65535:
            await self.send_frame(
                FT_OPEN_UDP_ERROR,
                session_id,
                b"invalid target",
                priority=PRIORITY_SESSION,
            )
            return
        try:
            protocol = RemoteUdpProtocol(self, session_id)
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: protocol, remote_addr=(host, port)
            )
            self.sessions[session_id] = UdpSession(
                session_id=session_id,
                transport=transport,
                source_address=None,
                listener_transport=None,
                rule_id=rule_id,
                target=format_endpoint((host, port)),
            )
            await self.send_frame(
                FT_OPEN_UDP_OK, session_id, priority=PRIORITY_SESSION
            )
        except Exception as exc:
            await self.send_frame(
                FT_OPEN_UDP_ERROR,
                session_id,
                str(exc).encode("utf-8")[:1024],
                priority=PRIORITY_SESSION,
            )

    async def pump_tcp(self, session: TcpSession) -> None:
        if not session.reader:
            return
        try:
            while not self.closed and not session.closed:
                data = await session.reader.read(int(cfg("tunnel.data_frame_size", 16384)))
                if not data:
                    if not session.local_eof:
                        session.local_eof = True
                        # EOF has the same priority as DATA. The queue sequence
                        # therefore guarantees all earlier DATA is written first.
                        await self.send_frame(
                            FT_TCP_EOF,
                            session.session_id,
                            priority=PRIORITY_SESSION,
                        )
                    await self.maybe_finish_tcp_session(session)
                    return
                session.upload += len(data)
                forward_runtime_add_bytes(session.rule_id, upload=len(data))
                await self.send_frame(
                    FT_TCP_DATA,
                    session.session_id,
                    data,
                    priority=PRIORITY_SESSION,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log_event(
                "tcp_session_pump_failed",
                level="DEBUG",
                message="TCP session pump ended with an error",
                peer_id=self.peer_id,
                session_id=session.session_id,
                error=exc,
            )
            await self.close_session(session.session_id, notify=True, reason="local_io_error")

    async def maybe_finish_tcp_session(self, session: TcpSession) -> None:
        if session.closed:
            return
        if session.local_eof and session.remote_eof:
            await self.close_session(session.session_id, notify=True, reason="both_eof")

    async def close_session(self, session_id: int, *, notify: bool, reason: str) -> None:
        session = self.sessions.pop(session_id, None)
        if not session:
            return
        if isinstance(session, TcpSession):
            if session.closed:
                return
            session.closed = True
            if session.open_future and not session.open_future.done():
                session.open_future.set_exception(ConnectionError(f"session closed: {reason}"))
            if session.writer:
                session.writer.close()
                with contextlib.suppress(Exception):
                    await session.writer.wait_closed()
            session.closed_event.set()
        else:
            session.closed = True
            if session.open_future and not session.open_future.done():
                session.open_future.set_exception(ConnectionError(f"session closed: {reason}"))
            if session.transport:
                session.transport.close()
        if notify and not self.closed:
            with contextlib.suppress(Exception):
                # CLOSE shares session priority, so it cannot overtake queued
                # DATA or EOF for this session.
                await self.send_frame(
                    FT_CLOSE_SESSION,
                    session_id,
                    priority=PRIORITY_SESSION,
                )
        if self.draining and not self.sessions:
            await self.close("drained")

    async def run(self) -> None:
        self.writer_task = asyncio.create_task(self.writer_loop(), name=f"writer:{self.peer_id}")
        self.reader_task = asyncio.create_task(self.reader_loop(), name=f"reader:{self.peer_id}")
        self.ping_task = asyncio.create_task(self.ping_loop(), name=f"ping:{self.peer_id}")
        reason = "link_failure"
        try:
            done, _ = await asyncio.wait(
                [self.writer_task, self.reader_task, self.ping_task],
                return_when=asyncio.FIRST_EXCEPTION,
            )
            for task in done:
                if task.cancelled():
                    continue
                exception = task.exception()
                if exception:
                    raise exception
            # A normal shutdown closes the tunnel first and cancels its worker
            # tasks. In that case asyncio.wait() returns without an exception;
            # do not misreport the expected cancellation as a link failure.
            if self.closed or APP_SHUTTING_DOWN:
                reason = self.close_reason or ("shutdown" if APP_SHUTTING_DOWN else "closed")
                return
            raise ConnectionError("tunnel task stopped unexpectedly")
        except asyncio.CancelledError:
            reason = "shutdown" if APP_SHUTTING_DOWN else "cancelled"
            raise
        except TunnelHeartbeatTimeout as exc:
            reason = "heartbeat_timeout"
            add_event(
                f"{self.peer_id} {self.kind} 心跳超时",
                level="WARNING",
                event_name="tunnel_heartbeat_timeout",
                error=str(exc),
            )
        except Exception as exc:
            reason = "link_failure"
            add_event(
                f"{self.peer_id} {self.kind} 断开：{type(exc).__name__}: {exc}",
                level="WARNING",
                event_name="tunnel_link_failure",
            )
        finally:
            await self.close(reason)

    async def close(self, reason: str = "normal") -> None:
        if self.closed:
            return
        self.closed = True
        self.close_reason = reason
        was_active = ACTIVE_TUNNELS.get(self.peer_id) is self
        if was_active:
            ACTIVE_TUNNELS.pop(self.peer_id, None)
        DRAINING_TUNNELS.discard(self)
        current = asyncio.current_task()
        for task in (self.writer_task, self.reader_task, self.ping_task):
            if task and task is not current:
                task.cancel()
        for session_id in list(self.sessions):
            await self.close_session(session_id, notify=False, reason="tunnel_close")
        self.writer.close()
        with contextlib.suppress(Exception):
            await self.writer.wait_closed()
        RELAY_PEER_EVENTS.setdefault(self.peer_id, asyncio.Event()).set()
        log_event(
            "tunnel_closed",
            level="WARNING" if reason in {"link_failure", "heartbeat_timeout"} else "INFO",
            message=f"Tunnel to {self.peer_id} closed",
            peer_id=self.peer_id,
            tunnel_kind=self.kind,
            reason=reason,
            upload_bytes=self.upload,
            download_bytes=self.download,
        )
        if (
            was_active
            and bool(cfg("recovery.enabled", True))
            and not SIGNAL_CONNECTED
            and not APP_SHUTTING_DOWN
            and self.kind.startswith("P2P")
            and reason in {"link_failure", "heartbeat_timeout"}
        ):
            schedule_direct_recovery(self.peer_id, reason)


# =============================================================================
# Tunnel handshake, installation and TCP P2P
# =============================================================================


def record_attempt(
    *,
    peer_id: str,
    family: int,
    stage: str,
    state: str,
    address: str = "",
    source: str = "",
    error: str = "",
    attempt_id: str = "",
    started_at: float | None = None,
) -> dict[str, Any]:
    current = time.time()
    item = {
        "time": current,
        "peer_id": peer_id,
        "family": family,
        "stage": stage,
        "state": state,
        "address": address,
        "source": source,
        "error": error,
        "attempt_id": attempt_id[:12],
        "started_at": started_at or current,
        "duration_ms": 0.0,
    }
    with ATTEMPT_HISTORY_LOCK:
        limit = max(10, int(cfg("tunnel.attempt_history_limit", 40)))
        ATTEMPT_HISTORY.appendleft(item)
        while len(ATTEMPT_HISTORY) > limit:
            ATTEMPT_HISTORY.pop()
    return item


def finish_attempt_status(
    item: dict[str, Any], *, state: str, stage: str, error: str = ""
) -> None:
    item["state"] = state
    item["stage"] = stage
    item["error"] = error
    item["duration_ms"] = round((time.time() - float(item["started_at"])) * 1000, 1)


def normalized_candidates(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[int, str, int]] = set()
    for item in values:
        host = str(item.get("host", "")).strip()
        family = int(item.get("family", 0) or candidate_family(host))
        try:
            port = int(item.get("port", 0))
        except (TypeError, ValueError, OverflowError):
            continue
        if not host or family not in (4, 6) or not 1 <= port <= 65535:
            continue
        if not is_ip_family(host, family):
            continue
        key = (family, host, port)
        if key in seen:
            continue
        seen.add(key)
        output.append(
            {
                "host": host,
                "port": port,
                "family": family,
                "source": str(item.get("source", "candidate"))[:32],
                "priority": int(item.get("priority", 50)),
            }
        )
    output.sort(key=lambda item: int(item["priority"]), reverse=True)
    return output


def build_peer_candidates(peer: PeerInfo, family: int) -> list[dict[str, Any]]:
    candidates = peer.ipv6 if family == 6 else peer.ipv4
    values: list[dict[str, Any]] = []
    for candidate in candidates:
        host = str(candidate.get("host", ""))
        try:
            port = int(candidate.get("port", peer.p2p_port))
        except (TypeError, ValueError, OverflowError):
            continue
        if not is_ip_family(host, family) or not 1 <= port <= 65535:
            continue
        priority = int(candidate.get("priority", 50))
        source = str(candidate.get("source", "peer"))
        # Retain the existing direct-connect behavior but make local candidates
        # deterministic and slightly more preferred on a home LAN.
        if source == "local":
            priority += 20
        values.append(
            {
                "host": host,
                "port": port,
                "family": family,
                "source": source,
                "priority": priority,
            }
        )
    observed = peer.observed
    observed_host = str(observed.get("host", ""))
    if (
        int(observed.get("family", 0) or 0) == family
        and peer.p2p_port
        and is_ip_family(observed_host, family)
    ):
        values.append(
            {
                "host": observed_host,
                "port": peer.p2p_port,
                "family": family,
                "source": "server_observed",
                "priority": 110,
            }
        )
    return normalized_candidates(values)


def peer_candidates_for_memory(peer_id: str) -> list[dict[str, Any]]:
    with ONLINE_LOCK:
        peer = ONLINE.get(peer_id)
    if not peer:
        memory = RECONNECT_MEMORY.get(peer_id)
        return list(memory.candidates) if memory else []
    values: list[dict[str, Any]] = []
    for family in (6, 4):
        values.extend(build_peer_candidates(peer, family))
    return normalized_candidates(values)


def validate_remote_hello(
    remote: dict[str, Any],
    peer_id: str,
    attempt_id: str,
    token: str,
    *,
    expected_connection_id: str = "",
    expected_dialer_id: str = "",
) -> None:
    if remote.get("type") != "TUNNEL_HELLO":
        raise ValueError("invalid tunnel hello type")
    if int(remote.get("version", 0)) != PROTOCOL_VERSION:
        raise ValueError("tunnel protocol mismatch")
    if not verify_proof(remote, shared_key_bytes()):
        raise ValueError("node shared-key authentication failed")
    if str(remote.get("node_id", "")).upper() != peer_id:
        raise ValueError("tunnel node ID mismatch")
    if str(remote.get("peer_id", "")).upper() != node_id():
        raise ValueError("tunnel peer ID mismatch")
    if str(remote.get("attempt_id", "")) != attempt_id:
        raise ValueError("tunnel attempt ID mismatch")
    if not hmac.compare_digest(str(remote.get("token", "")), token):
        raise ValueError("tunnel token mismatch")
    skew = max(30.0, float(cfg("recovery.clock_skew", 120.0)))
    if abs(time.time() - int(remote.get("timestamp", 0) or 0)) > skew:
        raise ValueError("tunnel hello timestamp expired")
    if len(str(remote.get("nonce", ""))) < 16:
        raise ValueError("tunnel nonce is invalid")
    connection_id = str(remote.get("connection_id", ""))
    dialer_id = str(remote.get("dialer_id", "")).upper()
    if len(connection_id) < 16:
        raise ValueError("tunnel connection ID is invalid")
    if dialer_id not in {node_id(), peer_id}:
        raise ValueError("tunnel dialer ID is invalid")
    if expected_connection_id and not hmac.compare_digest(connection_id, expected_connection_id):
        raise ValueError("tunnel connection ID mismatch")
    if expected_dialer_id and dialer_id != expected_dialer_id:
        raise ValueError("tunnel dialer ID mismatch")


async def tunnel_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    peer_id: str,
    attempt_id: str,
    token: str,
    kind: str,
    incoming_remote: dict[str, Any] | None = None,
    preferred_host: str = "",
    preferred_port: int = 0,
    preferred_family: int = 0,
) -> Tunnel:
    configure_socket(writer)
    local_nonce = secrets.token_hex(16)
    if incoming_remote is None:
        if kind == "RELAY":
            low, high = sorted((node_id(), peer_id))
            connection_id = hashlib.sha256(
                f"relay|{attempt_id}|{token}|{low}|{high}".encode("utf-8")
            ).hexdigest()[:24]
            dialer_id = low
        else:
            connection_id = secrets.token_hex(12)
            dialer_id = node_id()
    else:
        connection_id = str(incoming_remote.get("connection_id", ""))
        dialer_id = str(incoming_remote.get("dialer_id", "")).upper()
        validate_remote_hello(
            incoming_remote,
            peer_id,
            attempt_id,
            token,
            expected_connection_id=connection_id,
            expected_dialer_id=peer_id,
        )

    hello: dict[str, Any] = {
        "type": "TUNNEL_HELLO",
        "version": PROTOCOL_VERSION,
        "node_id": node_id(),
        "peer_id": peer_id,
        "attempt_id": attempt_id,
        "token": token,
        "connection_id": connection_id,
        "dialer_id": dialer_id,
        "timestamp": int(time.time()),
        "nonce": local_nonce,
        "listen_port": P2P_LISTEN_PORT,
        "encryption": bool(cfg("encryption.enabled", True)),
        "algorithm": str(cfg("encryption.algorithm", "HMAC_STREAM")),
    }
    hello["proof"] = proof_for(hello, shared_key_bytes())
    timeout = float(cfg("tunnel.p2p_handshake_timeout", 6.0))
    if incoming_remote is None:
        await write_packet(writer, hello)
        remote = await asyncio.wait_for(read_packet(reader), timeout=timeout)
    else:
        remote = incoming_remote
        await write_packet(writer, hello)
    validate_remote_hello(
        remote,
        peer_id,
        attempt_id,
        token,
        expected_connection_id=connection_id,
        expected_dialer_id=dialer_id,
    )
    remote_nonce = str(remote.get("nonce", ""))
    master, generation_id, recovery_secret = derive_initial_material(
        peer_id, attempt_id, token, connection_id, local_nonce, remote_nonce
    )
    encrypted = bool(cfg("encryption.enabled", True)) and bool(remote.get("encryption", True))
    if str(remote.get("algorithm", "HMAC_STREAM")).upper() != "HMAC_STREAM":
        raise ValueError("peer encryption algorithm is not supported")
    remote_listen_port = int(remote.get("listen_port", 0) or 0)
    if not preferred_port and 1 <= remote_listen_port <= 65535:
        preferred_port = remote_listen_port
    return Tunnel(
        peer_id,
        kind,
        reader,
        writer,
        master,
        encrypted,
        recovery_generation_id=generation_id,
        recovery_secret=recovery_secret,
        recovery_candidates=peer_candidates_for_memory(peer_id),
        preferred_family=preferred_family,
        preferred_host=preferred_host,
        preferred_port=preferred_port,
        connection_id=connection_id,
        dialer_id=dialer_id,
    )


async def install_tunnel(tunnel: Tunnel) -> bool:
    """Install one tunnel using deterministic duplicate arbitration.

    Both nodes may briefly create two TCP connections during punching. Every
    physical connection carries a shared connection_id and dialer_id. Both
    sides prefer the connection dialed by the lexicographically smaller node,
    then the smaller connection_id, so they converge on the same socket.
    """

    def selection_key(value: Tunnel) -> tuple[int, str]:
        preferred_dialer = min(node_id(), value.peer_id)
        penalty = 0 if value.dialer_id == preferred_dialer else 1
        return penalty, value.connection_id or "~"

    lock = TUNNEL_LOCKS.setdefault(tunnel.peer_id, asyncio.Lock())
    replaced: Tunnel | None = None
    async with lock:
        existing = ACTIVE_TUNNELS.get(tunnel.peer_id)
        if existing and not existing.closed:
            if existing.kind == "RELAY" and tunnel.kind.startswith("P2P"):
                existing.draining = True
                DRAINING_TUNNELS.add(existing)
                ACTIVE_TUNNELS[tunnel.peer_id] = tunnel
                add_event(
                    f"{tunnel.peer_id} 已从 Relay 升级到 {tunnel.kind}",
                    event_name="tunnel_upgraded",
                )
                if not existing.sessions:
                    asyncio.create_task(existing.close("upgraded_empty_relay"))
            elif existing.kind.startswith("P2P") and tunnel.kind.startswith("P2P"):
                if selection_key(tunnel) < selection_key(existing):
                    ACTIVE_TUNNELS[tunnel.peer_id] = tunnel
                    replaced = existing
                    add_event(
                        f"{tunnel.peer_id} P2P重复连接已完成确定性仲裁",
                        event_name="p2p_duplicate_replaced",
                    )
                else:
                    await tunnel.close("duplicate_lost_arbitration")
                    return False
            else:
                await tunnel.close("duplicate")
                return False
        else:
            ACTIVE_TUNNELS[tunnel.peer_id] = tunnel
            add_event(
                f"{tunnel.peer_id} 隧道已建立：{tunnel.kind}",
                event_name="tunnel_established",
            )
        if tunnel.kind.startswith("P2P"):
            remember_p2p_tunnel(tunnel)
        RELAY_PEER_EVENTS.setdefault(tunnel.peer_id, asyncio.Event()).set()
        log_event(
            "tunnel_installed",
            message=f"Tunnel to {tunnel.peer_id} installed",
            peer_id=tunnel.peer_id,
            kind=tunnel.kind,
            encrypted=tunnel.encrypted,
            connection_id=tunnel.connection_id[:12],
            dialer_id=tunnel.dialer_id,
            endpoint=format_endpoint(tunnel.writer.get_extra_info("peername")),
        )
        asyncio.create_task(tunnel.run(), name=f"tunnel:{tunnel.peer_id}:{tunnel.kind}")
    if replaced:
        await replaced.close("duplicate_replaced")
    return True


def make_listener_socket(host: str, port: int, family: int) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    sock.listen(128)
    sock.setblocking(False)
    return sock


async def start_p2p_listeners() -> None:
    global P2P_LISTEN_PORT
    mode = str(cfg("tunnel.mode", "AUTO")).upper()
    if mode == "RELAY_ONLY":
        P2P_LISTEN_PORT = 0
        P2P_READY.set()
        return
    requested = 0 if bool(cfg("tunnel.auto_port", False)) else int(cfg("tunnel.p2p_port", 32000))
    errors: list[str] = []
    # Bind IPv4 first to determine an automatic port, then bind IPv6 to exactly
    # the same port. IPV6_V6ONLY avoids platform-dependent dual-stack conflicts.
    try:
        sock4 = make_listener_socket("0.0.0.0", requested, socket.AF_INET)
        P2P_LISTEN_PORT = int(sock4.getsockname()[1])
        server4 = await asyncio.start_server(p2p_incoming, sock=sock4)
        P2P_SERVERS.append(server4)
    except OSError as exc:
        errors.append(f"IPv4: {exc}")
    try:
        port6 = P2P_LISTEN_PORT or requested
        sock6 = make_listener_socket("::", port6, socket.AF_INET6)
        if not P2P_LISTEN_PORT:
            P2P_LISTEN_PORT = int(sock6.getsockname()[1])
        server6 = await asyncio.start_server(p2p_incoming, sock=sock6)
        P2P_SERVERS.append(server6)
    except OSError as exc:
        errors.append(f"IPv6: {exc}")
    if not P2P_SERVERS:
        if mode in {"IPV6_TCP_ONLY", "IPV4_TCP_ONLY"}:
            raise RuntimeError("P2P listener failed: " + "; ".join(errors))
        add_event(
            "P2P监听失败，AUTO模式将只能使用Relay：" + "; ".join(errors),
            level="WARNING",
            event_name="p2p_listener_failed",
        )
    else:
        add_event(
            f"P2P TCP监听端口：{P2P_LISTEN_PORT}", event_name="p2p_listening"
        )
    P2P_READY.set()


async def p2p_incoming(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peername = writer.get_extra_info("peername")
    try:
        configure_socket(writer)
        remote = await asyncio.wait_for(
            read_packet(reader), timeout=float(cfg("tunnel.p2p_handshake_timeout", 6.0))
        )
        if remote.get("type") == "TUNNEL_RECONNECT":
            await direct_reconnect_incoming(remote, reader, writer)
            return
        if remote.get("type") != "TUNNEL_HELLO":
            raise ValueError("unknown incoming P2P handshake")
        peer_id = str(remote.get("node_id", "")).upper()
        attempt_id = str(remote.get("attempt_id", ""))
        attempt = ATTEMPTS.get(attempt_id)
        if not attempt or attempt.peer_id != peer_id:
            raise ValueError("unknown incoming P2P attempt")
        if time.time() + SERVER_TIME_OFFSET > attempt.expires_at:
            raise ValueError("incoming P2P attempt expired")
        if not hmac.compare_digest(str(remote.get("token", "")), attempt.token):
            raise ValueError("incoming P2P token mismatch")
        host = str(peername[0]) if peername else ""
        with ONLINE_LOCK:
            peer = ONLINE.get(peer_id)
        preferred_port = int(peer.p2p_port) if peer else int(remote.get("listen_port", 0) or 0)
        tunnel = await tunnel_handshake(
            reader,
            writer,
            peer_id=peer_id,
            attempt_id=attempt_id,
            token=attempt.token,
            kind=f"P2P_IPV{attempt.family}",
            incoming_remote=remote,
            preferred_host=host,
            preferred_port=preferred_port,
            preferred_family=attempt.family,
        )
        if await install_tunnel(tunnel):
            attempt.installed.set()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        add_event(
            f"拒绝来自 {format_endpoint(peername)} 的P2P连接：{type(exc).__name__}: {exc}",
            level="WARNING",
            event_name="p2p_incoming_rejected",
        )
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def connect_p2p_candidate(attempt: Attempt, candidate: dict[str, Any]) -> None:
    if attempt.installed.is_set():
        return
    host = str(candidate["host"])
    port = int(candidate["port"])
    family = socket.AF_INET6 if attempt.family == 6 else socket.AF_INET
    display = format_endpoint((host, port))
    status = record_attempt(
        peer_id=attempt.peer_id,
        family=attempt.family,
        stage="CONNECTING",
        state="RUNNING",
        address=display,
        source=str(candidate.get("source", "candidate")),
        attempt_id=attempt.attempt_id,
    )
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, family=family),
            timeout=float(cfg("tunnel.p2p_connect_timeout", 4.0)),
        )
        status["stage"] = "AUTHENTICATING"
        tunnel = await tunnel_handshake(
            reader,
            writer,
            peer_id=attempt.peer_id,
            attempt_id=attempt.attempt_id,
            token=attempt.token,
            kind=f"P2P_IPV{attempt.family}",
            preferred_host=host,
            preferred_port=port,
            preferred_family=attempt.family,
        )
        status["stage"] = "INSTALLING"
        if await install_tunnel(tunnel):
            attempt.installed.set()
            finish_attempt_status(status, state="SUCCESS", stage="ACTIVE")
        else:
            finish_attempt_status(status, state="IGNORED", stage="DUPLICATE")
    except asyncio.CancelledError:
        if writer:
            writer.close()
        raise
    except Exception as exc:
        finish_attempt_status(
            status,
            state="FAILED",
            stage="FAILED",
            error=f"{type(exc).__name__}: {exc}",
        )
        if bool(cfg("logging.candidate_details", True)):
            log_event(
                "p2p_candidate_failed",
                level="DEBUG",
                message=f"Candidate {display} failed",
                peer_id=attempt.peer_id,
                family=attempt.family,
                source=candidate.get("source"),
                error=exc,
            )
        if writer:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def run_punch_attempt(attempt: Attempt, peer: PeerInfo) -> None:
    local_start = attempt.starts_at - SERVER_TIME_OFFSET
    delay = local_start - time.time()
    if delay > 0:
        await asyncio.sleep(delay)
    if time.time() + SERVER_TIME_OFFSET > attempt.expires_at:
        return

    timeout = float(
        cfg(
            "tunnel.p2p_total_timeout_ipv6"
            if attempt.family == 6
            else "tunnel.p2p_total_timeout_ipv4",
            8.0 if attempt.family == 6 else 10.0,
        )
    )
    attempt_started = time.monotonic()

    # To avoid two good TCP connections being installed independently, the
    # lower node ID dials first. The other node remains a listener and starts
    # outbound candidates only after a fallback delay. This preserves reverse
    # direction reachability without creating a routine duplicate race.
    primary_dialer = min(node_id(), attempt.peer_id)
    if node_id() != primary_dialer:
        fallback_delay = min(max(0.8, timeout * 0.55), max(0.0, timeout - 0.8))
        try:
            await asyncio.wait_for(attempt.installed.wait(), timeout=fallback_delay)
            return
        except asyncio.TimeoutError:
            pass

    candidates = build_peer_candidates(peer, attempt.family)
    if not candidates:
        record_attempt(
            peer_id=attempt.peer_id,
            family=attempt.family,
            stage="FAILED",
            state="FAILED",
            error="NO_CANDIDATE",
            attempt_id=attempt.attempt_id,
        )
        return
    semaphore = asyncio.Semaphore(int(cfg("tunnel.max_parallel_candidates", 4)))
    stagger = float(cfg("tunnel.candidate_stagger", 0.25))
    tasks: list[asyncio.Task[Any]] = []

    async def staggered(candidate: dict[str, Any], wait: float) -> None:
        await asyncio.sleep(wait)
        if attempt.installed.is_set():
            return
        async with semaphore:
            await connect_p2p_candidate(attempt, candidate)

    for index, candidate in enumerate(candidates):
        tasks.append(asyncio.create_task(staggered(candidate, index * stagger)))
    remaining = max(0.1, timeout - (time.monotonic() - attempt_started))
    try:
        await asyncio.wait_for(attempt.installed.wait(), timeout=remaining)
    except asyncio.TimeoutError:
        pass
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def handle_punch_prepare(message: dict[str, Any]) -> None:
    try:
        peer = parse_peer(dict(message.get("peer", {}) or {}))
        family = int(message.get("family", 0) or 0)
        attempt_id = str(message.get("attempt_id", ""))
        if not peer.node_id or family not in (4, 6) or not attempt_id:
            return
        mode = str(cfg("tunnel.mode", "AUTO")).upper()
        if mode == "RELAY_ONLY":
            return
        if mode == "IPV6_TCP_ONLY" and family != 6:
            return
        if mode == "IPV4_TCP_ONLY" and family != 4:
            return
        existing = ATTEMPTS.get(attempt_id)
        if existing:
            return
        attempt = Attempt(
            attempt_id=attempt_id,
            peer_id=peer.node_id,
            token=str(message.get("token", "")),
            family=family,
            starts_at=float(message.get("starts_at", time.time())),
            expires_at=int(message.get("expires_at", 0) or 0),
        )
        ATTEMPTS[attempt_id] = attempt
        add_event(
            f"开始 {peer.node_id} IPv{family} TCP连接尝试",
            event_name="p2p_attempt_started",
        )
        await run_punch_attempt(attempt, peer)
    finally:
        attempt_id = str(message.get("attempt_id", ""))
        if attempt_id:
            asyncio.get_running_loop().call_later(60.0, ATTEMPTS.pop, attempt_id, None)


def allowed_families(peer: PeerInfo) -> list[int]:
    local = str(cfg("tunnel.mode", "AUTO")).upper()
    remote = peer.mode
    if local == "RELAY_ONLY" or remote == "RELAY_ONLY":
        return []
    if local == "IPV6_TCP_ONLY":
        return [6] if remote in {"AUTO", "IPV6_TCP_ONLY"} else []
    if local == "IPV4_TCP_ONLY":
        return [4] if remote in {"AUTO", "IPV4_TCP_ONLY"} else []
    result: list[int] = []
    if remote in {"AUTO", "IPV6_TCP_ONLY"}:
        result.append(6)
    if remote in {"AUTO", "IPV4_TCP_ONLY"}:
        result.append(4)
    return result


async def wait_for_tunnel(
    peer_id: str,
    timeout: float,
    *,
    require_kind_prefix: str | None = None,
) -> Tunnel | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        tunnel = ACTIVE_TUNNELS.get(peer_id)
        if tunnel and not tunnel.closed:
            if require_kind_prefix is None or tunnel.kind.startswith(require_kind_prefix):
                return tunnel
        await asyncio.sleep(0.10)
    return None


async def try_p2p_family(peer_id: str, family: int) -> Tunnel | None:
    if not SIGNAL_CONNECTED:
        return None
    with ONLINE_LOCK:
        peer = ONLINE.get(peer_id)
    if not peer or family not in allowed_families(peer):
        return None
    await signal_send({"type": "CONNECT_REQUEST", "peer": peer_id, "family": family})
    timeout = float(
        cfg(
            "tunnel.p2p_total_timeout_ipv6" if family == 6 else "tunnel.p2p_total_timeout_ipv4",
            8.0 if family == 6 else 10.0,
        )
    ) + 2.0
    return await wait_for_tunnel(peer_id, timeout, require_kind_prefix="P2P")


async def try_p2p_tunnel(peer_id: str) -> Tunnel | None:
    with ONLINE_LOCK:
        peer = ONLINE.get(peer_id)
    if not peer:
        return None
    for family in allowed_families(peer):
        tunnel = await try_p2p_family(peer_id, family)
        if tunnel:
            return tunnel
    return None


# =============================================================================
# Relay client and connection selection
# =============================================================================


async def handle_relay_offer(message: dict[str, Any]) -> None:
    peer = parse_peer(dict(message.get("peer", {}) or {}))
    relay_id = str(message.get("relay_id", ""))
    bind_token = str(message.get("token", ""))
    tunnel_token = str(message.get("tunnel_token", ""))
    if not peer.node_id or not relay_id or not bind_token or not tunnel_token:
        return
    active = ACTIVE_TUNNELS.get(peer.node_id)
    if active and not active.closed and active.kind.startswith("P2P"):
        return
    writer: asyncio.StreamWriter | None = None
    status = record_attempt(
        peer_id=peer.node_id,
        family=0,
        stage="RELAY_CONNECTING",
        state="RUNNING",
        attempt_id=relay_id,
    )
    try:
        reader, writer = await open_server_connection(int(cfg("server.relay_port", 61010)))
        await write_packet(
            writer,
            {
                "type": "RELAY_BIND",
                "relay_id": relay_id,
                "node_id": node_id(),
                "token": bind_token,
            },
        )
        deadline = time.monotonic() + float(cfg("tunnel.relay_total_timeout", 28.0))
        paired = False
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            response = await asyncio.wait_for(read_packet(reader), timeout=remaining)
            response_type = str(response.get("type", ""))
            if response_type == "RELAY_BIND_OK":
                status["stage"] = "RELAY_BOUND"
            elif response_type == "RELAY_WAITING":
                status["stage"] = "RELAY_WAITING"
            elif response_type == "RELAY_PAIRED":
                paired = True
                status["stage"] = "AUTHENTICATING"
                break
            elif response_type == "RELAY_ERROR":
                raise ConnectionError(str(response.get("error", "relay rejected")))
            else:
                raise ConnectionError(f"unexpected relay response: {response_type}")
        if not paired:
            raise TimeoutError("relay pairing timed out")
        tunnel = await tunnel_handshake(
            reader,
            writer,
            peer_id=peer.node_id,
            attempt_id=relay_id,
            token=tunnel_token,
            kind="RELAY",
        )
        if await install_tunnel(tunnel):
            finish_attempt_status(status, state="SUCCESS", stage="ACTIVE")
        else:
            finish_attempt_status(status, state="IGNORED", stage="DUPLICATE")
    except asyncio.CancelledError:
        if writer:
            writer.close()
        raise
    except Exception as exc:
        finish_attempt_status(
            status,
            state="FAILED",
            stage="FAILED",
            error=f"{type(exc).__name__}: {exc}",
        )
        add_event(
            f"{peer.node_id} Relay失败：{type(exc).__name__}: {exc}",
            level="WARNING",
            event_name="relay_failed",
        )
        if writer:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    finally:
        RELAY_PEER_EVENTS.setdefault(peer.node_id, asyncio.Event()).set()


async def request_relay_tunnel(peer_id: str) -> Tunnel | None:
    if not bool(cfg("tunnel.relay_enabled", True)) or not SIGNAL_CONNECTED:
        return None
    retries = max(0, int(cfg("tunnel.relay_retries", 1)))
    timeout = float(cfg("tunnel.relay_total_timeout", 28.0))
    for attempt_no in range(retries + 1):
        event = RELAY_PEER_EVENTS.setdefault(peer_id, asyncio.Event())
        event.clear()
        await signal_send(
            {
                "type": "RELAY_REQUEST",
                "peer": peer_id,
                "force_new": attempt_no > 0,
            }
        )
        tunnel = await wait_for_tunnel(peer_id, timeout, require_kind_prefix="RELAY")
        if tunnel:
            return tunnel
        if attempt_no < retries:
            add_event(
                f"{peer_id} Relay首次失败，申请新令牌重试",
                level="WARNING",
                event_name="relay_retry",
            )
            await asyncio.sleep(0.5)
    return None


def configured_peer_ids() -> list[str]:
    peers = {
        str(rule.get("peer", "")).upper()
        for rule in cfg("forwards", [])
        if isinstance(rule, dict) and bool(rule.get("enabled", True))
    }
    return sorted(
        peer for peer in peers if len(peer) == 1 and "A" <= peer <= "Z" and peer != node_id()
    )


def peer_punch_policy(peer_id: str) -> str:
    policies = cfg("tunnel.peer_punch_policies", {})
    return str(policies.get(peer_id, cfg("tunnel.punch_policy", "PRECONNECT"))).upper()


async def ensure_tunnel(peer_id: str) -> Tunnel:
    peer_id = peer_id.upper()
    existing = ACTIVE_TUNNELS.get(peer_id)
    if existing and not existing.closed:
        return existing
    if not SIGNAL_CONNECTED:
        recovered = await reconnect_from_memory(peer_id, trigger="forward_demand")
        if recovered:
            return recovered
        raise ConnectionError(f"信令已断开，且无法从记忆恢复节点 {peer_id}")
    lock = CONNECTION_LOCKS.setdefault(peer_id, asyncio.Lock())
    async with lock:
        existing = ACTIVE_TUNNELS.get(peer_id)
        if existing and not existing.closed:
            return existing
        with ONLINE_LOCK:
            peer = ONLINE.get(peer_id)
        if not peer:
            raise ConnectionError(f"节点 {peer_id} 不在线")
        tunnel = await try_p2p_tunnel(peer_id)
        if tunnel:
            return tunnel
        mode = str(cfg("tunnel.mode", "AUTO")).upper()
        if mode in {"IPV6_TCP_ONLY", "IPV4_TCP_ONLY"}:
            raise ConnectionError("P2P连接失败，当前ONLY模式不允许Relay")
        tunnel = await request_relay_tunnel(peer_id)
        if tunnel:
            return tunnel
        raise ConnectionError("IPv6 TCP、IPv4 TCP和Relay均未建立")


async def preconnect_peer(peer_id: str) -> None:
    lock = CONNECTION_LOCKS.setdefault(peer_id, asyncio.Lock())
    async with lock:
        existing = ACTIVE_TUNNELS.get(peer_id)
        if existing and not existing.closed:
            return
        if not SIGNAL_CONNECTED:
            return
        with ONLINE_LOCK:
            if peer_id not in ONLINE:
                return
        add_event(f"{peer_id} 预连接开始", event_name="preconnect_started")
        tunnel = await try_p2p_tunnel(peer_id)
        if not tunnel and bool(cfg("tunnel.relay_enabled", True)):
            tunnel = await request_relay_tunnel(peer_id)
        if not tunnel:
            add_event(
                f"{peer_id} 预连接暂不可用，等待下次重试",
                level="WARNING",
                event_name="preconnect_unavailable",
            )


async def preconnect_loop() -> None:
    while not APP_SHUTTING_DOWN:
        try:
            await asyncio.wait_for(
                PRECONNECT_WAKEUP.wait(),
                timeout=float(cfg("tunnel.preconnect_retry_interval", 45.0)),
            )
        except asyncio.TimeoutError:
            pass
        PRECONNECT_WAKEUP.clear()
        if not SIGNAL_CONNECTED:
            continue
        await asyncio.sleep(float(cfg("tunnel.preconnect_start_delay", 1.0)))
        current = time.time()
        for peer_id in configured_peer_ids():
            if peer_punch_policy(peer_id) != "PRECONNECT":
                continue
            with ONLINE_LOCK:
                online = peer_id in ONLINE
            if not online:
                continue
            tunnel = ACTIVE_TUNNELS.get(peer_id)
            if tunnel and not tunnel.closed:
                continue
            running = PRECONNECT_TASKS.get(peer_id)
            if running and not running.done():
                continue
            last = PRECONNECT_LAST_ATTEMPT.get(peer_id, 0.0)
            retry = float(cfg("tunnel.preconnect_retry_interval", 45.0))
            if current - last < retry:
                continue
            PRECONNECT_LAST_ATTEMPT[peer_id] = current
            task = asyncio.create_task(preconnect_peer(peer_id), name=f"preconnect:{peer_id}")
            PRECONNECT_TASKS[peer_id] = task

            def cleanup(done: asyncio.Task[Any], target: str = peer_id) -> None:
                if PRECONNECT_TASKS.get(target) is done:
                    PRECONNECT_TASKS.pop(target, None)
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    done.result()

            task.add_done_callback(cleanup)


async def relay_upgrade_loop() -> None:
    while not APP_SHUTTING_DOWN:
        interval = float(cfg("tunnel.relay_upgrade_interval", 60.0))
        await asyncio.sleep(interval * (0.85 + secrets.randbelow(31) / 100))
        if (
            not SIGNAL_CONNECTED
            or not bool(cfg("tunnel.relay_upgrade_to_p2p", True))
            or str(cfg("tunnel.mode", "AUTO")).upper() != "AUTO"
        ):
            continue
        for peer_id, tunnel in list(ACTIVE_TUNNELS.items()):
            if tunnel.closed or tunnel.kind != "RELAY":
                continue
            with contextlib.suppress(Exception):
                await try_p2p_tunnel(peer_id)


# =============================================================================
# Persistent direct-reconnect memory
# =============================================================================


def load_reconnect_memory() -> None:
    RECONNECT_MEMORY.clear()
    if not bool(cfg("recovery.enabled", True)):
        return
    peers = cfg("runtime_memory.peers", {})
    if not isinstance(peers, dict):
        return
    current = time.time()
    for raw_peer, raw_value in peers.items():
        peer_id = str(raw_peer).upper()
        if (
            len(peer_id) != 1
            or not ("A" <= peer_id <= "Z")
            or peer_id == node_id()
            or not isinstance(raw_value, dict)
        ):
            continue
        try:
            generations: list[RecoveryGeneration] = []
            for item in raw_value.get("generations", [])[:2]:
                if not isinstance(item, dict):
                    continue
                generation_id = str(item.get("id", ""))
                secret_text = str(item.get("secret", ""))
                if not generation_id or not secret_text:
                    continue
                try:
                    secret = base64.b64decode(secret_text.encode("ascii"), validate=True)
                except Exception:
                    continue
                if len(secret) < 16:
                    continue
                generations.append(
                    RecoveryGeneration(
                        generation_id=generation_id,
                        secret=secret,
                        created_at=float(item.get("created_at", 0.0) or 0.0),
                    )
                )
            candidates = normalized_candidates(
                [item for item in raw_value.get("candidates", []) if isinstance(item, dict)]
            )[: int(cfg("recovery.max_candidates", 8))]
            memory = PeerReconnectMemory(
                peer_id=peer_id,
                generations=generations,
                preferred_family=int(raw_value.get("preferred_family", 0) or 0),
                preferred_host=str(raw_value.get("preferred_host", "")),
                preferred_port=int(raw_value.get("preferred_port", 0) or 0),
                candidates=candidates,
                encrypted=bool(raw_value.get("encrypted", True)),
                remembered_at=float(raw_value.get("remembered_at", 0.0) or 0.0),
                expires_at=float(raw_value.get("expires_at", 0.0) or 0.0),
                last_result=str(raw_value.get("last_result", "")),
            )
            if memory.generations and memory.candidates and memory.expires_at > current:
                RECONNECT_MEMORY[peer_id] = memory
        except (TypeError, ValueError, OverflowError):
            continue
    if RECONNECT_MEMORY:
        add_event(
            f"已加载 {len(RECONNECT_MEMORY)} 个节点的持久恢复记忆",
            event_name="recovery_memory_loaded",
        )


def serialize_reconnect_memory() -> dict[str, Any]:
    current = time.time()
    peers: dict[str, Any] = {}
    for peer_id, memory in list(RECONNECT_MEMORY.items()):
        if memory.expires_at <= current or not memory.generations or not memory.candidates:
            continue
        peers[peer_id] = {
            "remembered_at": memory.remembered_at,
            "expires_at": memory.expires_at,
            "preferred_family": memory.preferred_family,
            "preferred_host": memory.preferred_host,
            "preferred_port": memory.preferred_port,
            "encrypted": memory.encrypted,
            "last_result": memory.last_result,
            "candidates": memory.candidates[: int(cfg("recovery.max_candidates", 8))],
            "generations": [
                {
                    "id": generation.generation_id,
                    "secret": base64.b64encode(generation.secret).decode("ascii"),
                    "created_at": generation.created_at,
                }
                for generation in memory.generations[:2]
            ],
        }
    return {"updated_at": time.time(), "peers": peers}


async def persist_reconnect_memory() -> None:
    global CONFIG
    if not bool(cfg("recovery.persistent_memory", True)):
        return
    memory = serialize_reconnect_memory()
    loop = asyncio.get_running_loop()
    try:
        saved = await loop.run_in_executor(None, CONFIG_MANAGER.save_runtime_memory, memory)
        CONFIG = saved
        log_event(
            "recovery_memory_saved",
            message="Persistent reconnect memory saved",
            peer_count=len(memory["peers"]),
        )
    except Exception as exc:
        add_event(
            f"保存恢复记忆失败：{type(exc).__name__}: {exc}",
            level="ERROR",
            event_name="recovery_memory_save_failed",
        )


def schedule_memory_save() -> None:
    global RECONNECT_MEMORY_SAVE_TASK
    if not bool(cfg("recovery.persistent_memory", True)) or APP_SHUTTING_DOWN:
        return
    if RECONNECT_MEMORY_SAVE_TASK and not RECONNECT_MEMORY_SAVE_TASK.done():
        return

    async def delayed() -> None:
        await asyncio.sleep(0.5)
        await persist_reconnect_memory()

    RECONNECT_MEMORY_SAVE_TASK = asyncio.create_task(delayed(), name="memory-save")


def remember_p2p_tunnel(tunnel: Tunnel) -> None:
    if (
        not bool(cfg("recovery.enabled", True))
        or not tunnel.recovery_generation_id
        or not tunnel.recovery_secret
    ):
        return
    candidates = list(tunnel.recovery_candidates) or peer_candidates_for_memory(tunnel.peer_id)
    if tunnel.preferred_host and tunnel.preferred_port:
        candidates.insert(
            0,
            {
                "host": tunnel.preferred_host,
                "port": tunnel.preferred_port,
                "family": tunnel.preferred_family or candidate_family(tunnel.preferred_host),
                "source": "last_success",
                "priority": 1000,
            },
        )
    candidates = normalized_candidates(candidates)[: int(cfg("recovery.max_candidates", 8))]
    if not candidates:
        return
    current = time.time()
    old = RECONNECT_MEMORY.get(tunnel.peer_id)
    generations = [
        RecoveryGeneration(
            generation_id=tunnel.recovery_generation_id,
            secret=tunnel.recovery_secret,
            created_at=current,
        )
    ]
    if old:
        generations.extend(
            item
            for item in old.generations
            if item.generation_id != tunnel.recovery_generation_id
        )
    generations = generations[:2]
    RECONNECT_MEMORY[tunnel.peer_id] = PeerReconnectMemory(
        peer_id=tunnel.peer_id,
        generations=generations,
        preferred_family=tunnel.preferred_family or int(candidates[0]["family"]),
        preferred_host=tunnel.preferred_host or str(candidates[0]["host"]),
        preferred_port=tunnel.preferred_port or int(candidates[0]["port"]),
        candidates=candidates,
        encrypted=tunnel.encrypted,
        remembered_at=current,
        expires_at=current + float(cfg("recovery.memory_ttl", 86400.0)),
        last_result="stored",
    )
    schedule_memory_save()
    log_event(
        "recovery_memory_refreshed" if old else "recovery_memory_created",
        message=f"Recovery memory stored for {tunnel.peer_id}",
        peer_id=tunnel.peer_id,
        candidate_count=len(candidates),
        generations=len(generations),
    )


def get_valid_reconnect_memory(peer_id: str) -> PeerReconnectMemory | None:
    memory = RECONNECT_MEMORY.get(peer_id)
    if not memory:
        return None
    if memory.expires_at <= time.time() or not memory.generations or not memory.candidates:
        RECONNECT_MEMORY.pop(peer_id, None)
        schedule_memory_save()
        return None
    return memory


def find_recovery_generation(
    memory: PeerReconnectMemory, generation_id: str
) -> RecoveryGeneration | None:
    return next(
        (item for item in memory.generations if item.generation_id == generation_id), None
    )


def remember_direct_nonce(peer_id: str, nonce: str) -> bool:
    skew = float(cfg("recovery.clock_skew", 120.0))
    cutoff = time.time() - skew * 2
    for key, timestamp in list(DIRECT_RECONNECT_NONCES.items()):
        if timestamp < cutoff:
            DIRECT_RECONNECT_NONCES.pop(key, None)
    key = f"{peer_id}:{nonce}"
    if key in DIRECT_RECONNECT_NONCES:
        return False
    DIRECT_RECONNECT_NONCES[key] = time.time()
    return True


def direct_reconnect_allowed() -> bool:
    if APP_SHUTTING_DOWN or not bool(cfg("recovery.enabled", True)):
        return False
    if not SIGNAL_CONNECTED:
        return True
    grace = float(cfg("recovery.accept_after_signal_reconnect_grace", 15.0))
    return bool(SIGNAL_LAST_CONNECT_AT and time.time() - SIGNAL_LAST_CONNECT_AT <= grace)


async def direct_reconnect_incoming(
    remote: dict[str, Any], reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    if not direct_reconnect_allowed():
        raise ConnectionError("direct reconnect is not currently allowed")
    if int(remote.get("version", 0)) != PROTOCOL_VERSION:
        raise ValueError("direct reconnect protocol mismatch")
    peer_id = str(remote.get("node_id", "")).upper()
    if str(remote.get("peer_id", "")).upper() != node_id():
        raise ValueError("direct reconnect peer mismatch")
    memory = get_valid_reconnect_memory(peer_id)
    if not memory:
        raise ValueError("no valid direct reconnect memory")
    generation_id = str(remote.get("generation", ""))
    generation = find_recovery_generation(memory, generation_id)
    if not generation:
        raise ValueError("direct reconnect generation mismatch")
    skew = float(cfg("recovery.clock_skew", 120.0))
    if abs(time.time() - int(remote.get("timestamp", 0) or 0)) > skew:
        raise ValueError("direct reconnect timestamp expired")
    initiator_nonce = str(remote.get("nonce", ""))
    connection_id = str(remote.get("connection_id", initiator_nonce))
    dialer_id = str(remote.get("dialer_id", peer_id)).upper()
    if connection_id != initiator_nonce or dialer_id != peer_id:
        raise ValueError("direct reconnect connection identity mismatch")
    if len(initiator_nonce) < 16 or not remember_direct_nonce(peer_id, initiator_nonce):
        raise ValueError("direct reconnect nonce rejected")
    if not verify_proof(remote, generation.secret):
        raise ValueError("direct reconnect authentication failed")
    responder_nonce = secrets.token_hex(16)
    response: dict[str, Any] = {
        "type": "TUNNEL_RECONNECT_OK",
        "version": PROTOCOL_VERSION,
        "node_id": node_id(),
        "peer_id": peer_id,
        "generation": generation_id,
        "request_nonce": initiator_nonce,
        "connection_id": connection_id,
        "dialer_id": dialer_id,
        "nonce": responder_nonce,
        "timestamp": int(time.time()),
        "listen_port": P2P_LISTEN_PORT,
        "encryption": bool(cfg("encryption.enabled", True)),
        "algorithm": str(cfg("encryption.algorithm", "HMAC_STREAM")),
    }
    response["proof"] = proof_for(response, generation.secret)
    await write_packet(writer, response)
    master, next_id, next_secret = derive_reconnected_material(
        generation.secret, generation_id, initiator_nonce, responder_nonce
    )
    peername = writer.get_extra_info("peername")
    host = str(peername[0]) if peername else memory.preferred_host
    family = candidate_family(host) or memory.preferred_family
    remote_port = int(remote.get("listen_port", 0) or memory.preferred_port)
    tunnel = Tunnel(
        peer_id,
        f"P2P_RECONNECT_IPV{family}",
        reader,
        writer,
        master,
        bool(cfg("encryption.enabled", True)) and bool(remote.get("encryption", True)),
        recovery_generation_id=next_id,
        recovery_secret=next_secret,
        recovery_candidates=memory.candidates,
        preferred_family=family,
        preferred_host=host,
        preferred_port=remote_port,
        connection_id=connection_id,
        dialer_id=dialer_id,
    )
    if await install_tunnel(tunnel):
        memory.last_result = "incoming_success"
        add_event(
            f"接受 {peer_id} 的直接恢复连接",
            event_name="direct_recovery_succeeded",
        )


async def try_direct_candidate(
    memory: PeerReconnectMemory,
    candidate: dict[str, Any],
    generation: RecoveryGeneration,
) -> Tunnel | None:
    host = str(candidate["host"])
    port = int(candidate["port"])
    family_number = int(candidate["family"])
    family = socket.AF_INET6 if family_number == 6 else socket.AF_INET
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, family=family),
            timeout=float(cfg("tunnel.p2p_connect_timeout", 4.0)),
        )
        configure_socket(writer)
        initiator_nonce = secrets.token_hex(16)
        request: dict[str, Any] = {
            "type": "TUNNEL_RECONNECT",
            "version": PROTOCOL_VERSION,
            "node_id": node_id(),
            "peer_id": memory.peer_id,
            "generation": generation.generation_id,
            "timestamp": int(time.time()),
            "nonce": initiator_nonce,
            "connection_id": initiator_nonce,
            "dialer_id": node_id(),
            "listen_port": P2P_LISTEN_PORT,
            "encryption": bool(cfg("encryption.enabled", True)),
            "algorithm": str(cfg("encryption.algorithm", "HMAC_STREAM")),
        }
        request["proof"] = proof_for(request, generation.secret)
        await write_packet(writer, request)
        response = await asyncio.wait_for(
            read_packet(reader), timeout=float(cfg("tunnel.p2p_handshake_timeout", 6.0))
        )
        if response.get("type") != "TUNNEL_RECONNECT_OK":
            raise ValueError("direct reconnect rejected")
        if str(response.get("node_id", "")).upper() != memory.peer_id:
            raise ValueError("direct reconnect response node mismatch")
        if str(response.get("peer_id", "")).upper() != node_id():
            raise ValueError("direct reconnect response peer mismatch")
        if str(response.get("generation", "")) != generation.generation_id:
            raise ValueError("direct reconnect response generation mismatch")
        if str(response.get("request_nonce", "")) != initiator_nonce:
            raise ValueError("direct reconnect response nonce mismatch")
        if str(response.get("connection_id", "")) != initiator_nonce:
            raise ValueError("direct reconnect response connection ID mismatch")
        if str(response.get("dialer_id", "")).upper() != node_id():
            raise ValueError("direct reconnect response dialer ID mismatch")
        responder_nonce = str(response.get("nonce", ""))
        if len(responder_nonce) < 16:
            raise ValueError("direct reconnect responder nonce invalid")
        skew = float(cfg("recovery.clock_skew", 120.0))
        if abs(time.time() - int(response.get("timestamp", 0) or 0)) > skew:
            raise ValueError("direct reconnect response expired")
        if not verify_proof(response, generation.secret):
            raise ValueError("direct reconnect response authentication failed")
        master, next_id, next_secret = derive_reconnected_material(
            generation.secret,
            generation.generation_id,
            initiator_nonce,
            responder_nonce,
        )
        tunnel = Tunnel(
            memory.peer_id,
            f"P2P_RECONNECT_IPV{family_number}",
            reader,
            writer,
            master,
            bool(cfg("encryption.enabled", True)) and bool(response.get("encryption", True)),
            recovery_generation_id=next_id,
            recovery_secret=next_secret,
            recovery_candidates=memory.candidates,
            preferred_family=family_number,
            preferred_host=host,
            preferred_port=port,
            connection_id=initiator_nonce,
            dialer_id=node_id(),
        )
        if await install_tunnel(tunnel):
            memory.last_result = "outgoing_success"
            return tunnel
        return ACTIVE_TUNNELS.get(memory.peer_id)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if bool(cfg("logging.candidate_details", True)):
            log_event(
                "direct_recovery_candidate_failed",
                level="DEBUG",
                message=f"Remembered candidate {format_endpoint((host, port))} failed",
                peer_id=memory.peer_id,
                generation=generation.generation_id[:8],
                error=exc,
            )
        if writer:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        return None


async def reconnect_from_memory(peer_id: str, trigger: str = "manual") -> Tunnel | None:
    memory = get_valid_reconnect_memory(peer_id)
    if not memory or APP_SHUTTING_DOWN:
        return None
    existing = ACTIVE_TUNNELS.get(peer_id)
    if existing and not existing.closed:
        return existing
    lock = CONNECTION_LOCKS.setdefault(peer_id, asyncio.Lock())
    async with lock:
        existing = ACTIVE_TUNNELS.get(peer_id)
        if existing and not existing.closed:
            return existing
        memory = get_valid_reconnect_memory(peer_id)
        if not memory:
            return None
        deadline = time.monotonic() + float(cfg("recovery.total_timeout", 60.0))
        delay = 0.2 if node_id() < peer_id else 1.5
        add_event(
            f"{peer_id} 开始使用本地记忆直接恢复",
            level="WARNING",
            event_name="direct_recovery_started",
            trigger=trigger,
        )
        await asyncio.sleep(delay)
        rounds = 0
        while time.monotonic() < deadline and not APP_SHUTTING_DOWN:
            if SIGNAL_CONNECTED and trigger != "startup":
                break
            current = get_valid_reconnect_memory(peer_id)
            if not current:
                break
            rounds += 1
            # Try the current generation first and retain the previous one as a
            # recovery path after an interrupted JSON write or asymmetric exit.
            for generation in list(current.generations):
                for candidate in list(current.candidates):
                    tunnel = await try_direct_candidate(current, candidate, generation)
                    if tunnel:
                        add_event(
                            f"{peer_id} 直接恢复成功",
                            event_name="direct_recovery_succeeded",
                        )
                        return tunnel
                    if APP_SHUTTING_DOWN or (SIGNAL_CONNECTED and trigger != "startup"):
                        break
                if APP_SHUTTING_DOWN or (SIGNAL_CONNECTED and trigger != "startup"):
                    break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(delay, remaining))
            delay = min(
                float(cfg("recovery.retry_max", 8.0)),
                max(float(cfg("recovery.retry_min", 1.0)), delay * 2),
            )
        memory.last_result = f"failed:{trigger}:{rounds}"
        schedule_memory_save()
        add_event(
            f"{peer_id} 直接恢复未成功",
            level="WARNING",
            event_name="direct_recovery_failed",
        )
        return None


def schedule_direct_recovery(peer_id: str, reason: str) -> None:
    if (
        APP_SHUTTING_DOWN
        or SIGNAL_CONNECTED
        or not get_valid_reconnect_memory(peer_id)
    ):
        return
    running = DIRECT_RECONNECT_TASKS.get(peer_id)
    if running and not running.done():
        return
    task = asyncio.create_task(
        reconnect_from_memory(peer_id, trigger=reason), name=f"direct-recovery:{peer_id}"
    )
    DIRECT_RECONNECT_TASKS[peer_id] = task

    def cleanup(done: asyncio.Task[Any], target: str = peer_id) -> None:
        if DIRECT_RECONNECT_TASKS.get(target) is done:
            DIRECT_RECONNECT_TASKS.pop(target, None)
        with contextlib.suppress(asyncio.CancelledError, Exception):
            done.result()

    task.add_done_callback(cleanup)


async def startup_recovery_loop() -> None:
    await P2P_READY.wait()
    await asyncio.sleep(1.0)
    if SIGNAL_CONNECTED or APP_SHUTTING_DOWN:
        return
    for peer_id in sorted(RECONNECT_MEMORY):
        if peer_id not in configured_peer_ids():
            continue
        running = DIRECT_RECONNECT_TASKS.get(peer_id)
        if running and not running.done():
            continue
        schedule_direct_recovery(peer_id, "startup")


async def recovery_cleanup_loop() -> None:
    while not APP_SHUTTING_DOWN:
        await asyncio.sleep(10.0)
        changed = False
        for peer_id in list(RECONNECT_MEMORY):
            if not get_valid_reconnect_memory(peer_id):
                changed = True
        skew = float(cfg("recovery.clock_skew", 120.0))
        cutoff = time.time() - skew * 2
        for key, timestamp in list(DIRECT_RECONNECT_NONCES.items()):
            if timestamp < cutoff:
                DIRECT_RECONNECT_NONCES.pop(key, None)
        if changed:
            schedule_memory_save()


# =============================================================================
# Dynamic TCP / UDP forwarding
# =============================================================================


def forward_runtime_add_bytes(rule_id: str, *, upload: int = 0, download: int = 0) -> None:
    manager = globals().get("FORWARD_MANAGER")
    if not manager or not rule_id:
        return
    runtime = manager.runtimes.get(rule_id)
    if runtime:
        runtime.upload += int(upload)
        runtime.download += int(download)


async def local_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    runtime: ForwardRuntime,
) -> None:
    rule = runtime.rule
    tunnel: Tunnel | None = None
    session: TcpSession | None = None
    runtime.accepted_connections += 1
    peername = writer.get_extra_info("peername")
    try:
        configure_socket(writer)
        peer_id = str(rule["peer"]).upper()
        tunnel = await ensure_tunnel(peer_id)
        session_id = tunnel.allocate_session_id()
        future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
        session = TcpSession(
            session_id=session_id,
            reader=reader,
            writer=writer,
            open_future=future,
            rule_id=str(rule["id"]),
            source=format_endpoint(peername),
            target=format_endpoint((rule["target_host"], rule["target_port"])),
        )
        tunnel.sessions[session_id] = session
        await tunnel.send_frame(
            FT_OPEN_TCP,
            session_id,
            json_payload(
                {
                    "host": str(rule["target_host"]),
                    "port": int(rule["target_port"]),
                    "rule_id": str(rule["id"]),
                }
            ),
            priority=PRIORITY_SESSION,
        )
        await asyncio.wait_for(future, timeout=15.0)
        await tunnel.pump_tcp(session)
        # A local half-close may still receive data from the remote service.
        # Keep the socket alive until the peer also sends EOF/CLOSE.
        if not session.closed:
            await session.closed_event.wait()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        runtime.last_error = f"{type(exc).__name__}: {exc}"
        add_event(
            f"TCP转发 {rule.get('name', rule.get('id'))}：{runtime.last_error}",
            level="WARNING",
            event_name="tcp_forward_error",
        )
    finally:
        if tunnel and session and not session.closed:
            await tunnel.close_session(
                session.session_id, notify=True, reason="local_forward_finished"
            )
        elif not writer.is_closing():
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


class LocalUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, runtime: ForwardRuntime):
        self.runtime = runtime
        self.transport: asyncio.DatagramTransport | None = None
        self.sessions: dict[tuple[int, str, int], UdpSession] = {}

    @property
    def rule(self) -> dict[str, Any]:
        return self.runtime.rule

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        if len(data) > int(cfg("tunnel.max_udp_datagram", 65507)):
            return
        asyncio.create_task(self.handle_datagram(data, addr))

    async def handle_datagram(self, data: bytes, addr: tuple[Any, ...]) -> None:
        rule = self.rule
        try:
            tunnel = await ensure_tunnel(str(rule["peer"]).upper())
            key = (id(tunnel), str(addr[0]), int(addr[1]))
            session = self.sessions.get(key)
            if not session or session.session_id not in tunnel.sessions or session.closed:
                if len(self.sessions) >= int(cfg("tunnel.max_udp_sessions", 1024)):
                    return
                session_id = tunnel.allocate_session_id()
                future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
                session = UdpSession(
                    session_id=session_id,
                    transport=None,
                    source_address=addr,
                    listener_transport=self.transport,
                    open_future=future,
                    rule_id=str(rule["id"]),
                    target=format_endpoint((rule["target_host"], rule["target_port"])),
                )
                tunnel.sessions[session_id] = session
                self.sessions[key] = session
                await tunnel.send_frame(
                    FT_OPEN_UDP,
                    session_id,
                    json_payload(
                        {
                            "host": str(rule["target_host"]),
                            "port": int(rule["target_port"]),
                            "rule_id": str(rule["id"]),
                        }
                    ),
                    priority=PRIORITY_SESSION,
                )
                await asyncio.wait_for(future, timeout=10.0)
            session.last_seen = time.time()
            session.upload += len(data)
            forward_runtime_add_bytes(str(rule["id"]), upload=len(data))
            await tunnel.send_frame(
                FT_UDP_DATA,
                session.session_id,
                data,
                priority=PRIORITY_SESSION,
            )
        except Exception as exc:
            self.runtime.last_error = f"{type(exc).__name__}: {exc}"
            log_event(
                "udp_forward_error",
                level="DEBUG",
                message=f"UDP forward {rule.get('id')} failed",
                error=exc,
            )

    def error_received(self, exc: Exception) -> None:
        self.runtime.last_error = f"{type(exc).__name__}: {exc}"


class ForwardManager:
    def __init__(self) -> None:
        self.runtimes: dict[str, ForwardRuntime] = {}
        self.lock = asyncio.Lock()

    async def create_runtime(self, rule: dict[str, Any]) -> ForwardRuntime:
        runtime = ForwardRuntime(rule=copy.deepcopy(rule))
        if not bool(rule.get("enabled", True)):
            runtime.state = "Disabled"
            return runtime
        protocol = str(rule["protocol"]).upper()
        try:
            if protocol == "TCP":
                runtime.server = await asyncio.start_server(
                    lambda reader, writer: asyncio.create_task(
                        local_tcp_client(reader, writer, runtime)
                    ),
                    host=str(rule["listen_host"]),
                    port=int(rule["listen_port"]),
                    reuse_address=True,
                )
            else:
                protocol_object = LocalUdpProtocol(runtime)
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: protocol_object,
                    local_addr=(str(rule["listen_host"]), int(rule["listen_port"])),
                )
                runtime.transport = transport
                runtime.protocol_object = protocol_object
            runtime.state = "Listening"
            runtime.started_at = time.time()
            add_event(
                f"{protocol} {rule['listen_host']}:{rule['listen_port']} -> "
                f"{rule['peer']} {rule['target_host']}:{rule['target_port']}",
                event_name="forward_started",
                rule_id=rule["id"],
            )
            return runtime
        except Exception as exc:
            runtime.state = "Error"
            runtime.last_error = f"{type(exc).__name__}: {exc}"
            await self.stop_runtime(runtime, force=True)
            raise

    async def stop_runtime(self, runtime: ForwardRuntime, *, force: bool) -> None:
        if runtime.server:
            runtime.server.close()
            with contextlib.suppress(Exception):
                await runtime.server.wait_closed()
            runtime.server = None
        if runtime.transport:
            runtime.transport.close()
            runtime.transport = None
        runtime.state = "Stopped"
        if force:
            await self.close_rule_sessions(str(runtime.rule.get("id", "")))

    async def start_all(self, rules: list[dict[str, Any]]) -> None:
        async with self.lock:
            for rule in rules:
                try:
                    runtime = await self.create_runtime(rule)
                except Exception as exc:
                    runtime = ForwardRuntime(
                        rule=copy.deepcopy(rule),
                        state="Error",
                        last_error=f"{type(exc).__name__}: {exc}",
                    )
                    add_event(
                        f"转发 {rule.get('id')} 启动失败：{runtime.last_error}",
                        level="ERROR",
                        event_name="forward_start_failed",
                    )
                self.runtimes[str(rule["id"])] = runtime

    async def shutdown(self) -> None:
        async with self.lock:
            for runtime in list(self.runtimes.values()):
                await self.stop_runtime(runtime, force=True)
            self.runtimes.clear()

    async def apply_rules(self, rules: list[dict[str, Any]]) -> None:
        async with self.lock:
            wanted = {str(rule["id"]): copy.deepcopy(rule) for rule in rules}
            for rule_id in list(self.runtimes):
                if rule_id not in wanted:
                    runtime = self.runtimes.pop(rule_id)
                    await self.stop_runtime(runtime, force=False)
            for rule_id, rule in wanted.items():
                old = self.runtimes.get(rule_id)
                if old and old.rule == rule:
                    continue
                if old and self.listener_key(old.rule) == self.listener_key(rule):
                    old.rule = copy.deepcopy(rule)
                    if bool(rule.get("enabled", True)) and old.state == "Disabled":
                        self.runtimes[rule_id] = await self.create_runtime(rule)
                    elif not bool(rule.get("enabled", True)) and old.state != "Disabled":
                        await self.stop_runtime(old, force=False)
                        old.state = "Disabled"
                    continue
                new_runtime: ForwardRuntime
                try:
                    new_runtime = await self.create_runtime(rule)
                except Exception as exc:
                    add_event(
                        f"重载转发 {rule_id} 失败：{type(exc).__name__}: {exc}",
                        level="ERROR",
                        event_name="forward_reload_failed",
                    )
                    continue
                if old:
                    await self.stop_runtime(old, force=False)
                self.runtimes[rule_id] = new_runtime

    @staticmethod
    def listener_key(rule: dict[str, Any]) -> tuple[str, str, int, bool]:
        return (
            str(rule.get("protocol", "TCP")).upper(),
            str(rule.get("listen_host", "")),
            int(rule.get("listen_port", 0) or 0),
            bool(rule.get("enabled", True)),
        )

    async def save_rule(self, raw_rule: dict[str, Any]) -> None:
        global CONFIG
        rule = validate_forward_rule(raw_rule, node_id())
        async with self.lock:
            current_rules = [copy.deepcopy(item) for item in cfg("forwards", [])]
            index = next(
                (i for i, item in enumerate(current_rules) if item["id"] == rule["id"]),
                None,
            )
            old_runtime = self.runtimes.get(rule["id"])
            staged: ForwardRuntime | None = None
            same_listener = bool(
                old_runtime and self.listener_key(old_runtime.rule) == self.listener_key(rule)
            )
            if bool(rule["enabled"]) and not same_listener:
                staged = await self.create_runtime(rule)
            if index is None:
                current_rules.append(rule)
            else:
                current_rules[index] = rule
            try:
                saved = await asyncio.get_running_loop().run_in_executor(
                    None, CONFIG_MANAGER.save_forwards, current_rules
                )
            except Exception:
                if staged:
                    await self.stop_runtime(staged, force=True)
                raise
            CONFIG = saved
            if same_listener and old_runtime:
                old_runtime.rule = copy.deepcopy(rule)
                if not bool(rule["enabled"]) and old_runtime.state != "Disabled":
                    await self.stop_runtime(old_runtime, force=False)
                    old_runtime.state = "Disabled"
                elif bool(rule["enabled"]) and old_runtime.state == "Disabled":
                    self.runtimes[rule["id"]] = await self.create_runtime(rule)
            else:
                if old_runtime:
                    await self.stop_runtime(old_runtime, force=False)
                self.runtimes[rule["id"]] = staged or ForwardRuntime(
                    rule=copy.deepcopy(rule), state="Disabled"
                )
        PRECONNECT_WAKEUP.set()

    async def delete_rule(self, rule_id: str, *, force: bool) -> None:
        global CONFIG
        async with self.lock:
            current_rules = [
                copy.deepcopy(item)
                for item in cfg("forwards", [])
                if str(item.get("id")) != rule_id
            ]
            runtime = self.runtimes.get(rule_id)
            if not runtime and len(current_rules) == len(cfg("forwards", [])):
                raise KeyError("forward rule not found")
            if runtime:
                await self.stop_runtime(runtime, force=force)
            try:
                saved = await asyncio.get_running_loop().run_in_executor(
                    None, CONFIG_MANAGER.save_forwards, current_rules
                )
            except Exception:
                if runtime:
                    with contextlib.suppress(Exception):
                        self.runtimes[rule_id] = await self.create_runtime(runtime.rule)
                raise
            CONFIG = saved
            self.runtimes.pop(rule_id, None)
        PRECONNECT_WAKEUP.set()

    async def toggle_rule(self, rule_id: str, enabled: bool) -> None:
        rule = next(
            (copy.deepcopy(item) for item in cfg("forwards", []) if item["id"] == rule_id),
            None,
        )
        if not rule:
            raise KeyError("forward rule not found")
        rule["enabled"] = bool(enabled)
        await self.save_rule(rule)

    async def restart_rule(self, rule_id: str) -> None:
        async with self.lock:
            runtime = self.runtimes.get(rule_id)
            if not runtime:
                raise KeyError("forward rule not found")
            rule = copy.deepcopy(runtime.rule)
            await self.stop_runtime(runtime, force=False)
            self.runtimes[rule_id] = await self.create_runtime(rule)

    async def close_rule_sessions(self, rule_id: str) -> None:
        for tunnel in list(ACTIVE_TUNNELS.values()) + list(DRAINING_TUNNELS):
            for session_id, session in list(tunnel.sessions.items()):
                if getattr(session, "rule_id", "") == rule_id:
                    await tunnel.close_session(
                        session_id, notify=True, reason="forward_force_stop"
                    )

    def snapshot(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for rule_id, runtime in sorted(self.runtimes.items()):
            rule = runtime.rule
            sessions = 0
            for tunnel in list(ACTIVE_TUNNELS.values()) + list(DRAINING_TUNNELS):
                sessions += sum(
                    1
                    for session in tunnel.sessions.values()
                    if getattr(session, "rule_id", "") == rule_id
                )
            output.append(
                {
                    **copy.deepcopy(rule),
                    "state": runtime.state,
                    "last_error": runtime.last_error,
                    "started_at": runtime.started_at,
                    "accepted_connections": runtime.accepted_connections,
                    "sessions": sessions,
                    "upload": runtime.upload,
                    "download": runtime.download,
                }
            )
        return output


async def udp_cleanup_loop() -> None:
    while not APP_SHUTTING_DOWN:
        await asyncio.sleep(10.0)
        cutoff = time.time() - float(cfg("tunnel.udp_session_timeout", 60.0))
        for runtime in list(FORWARD_MANAGER.runtimes.values()):
            protocol_object = runtime.protocol_object
            if not isinstance(protocol_object, LocalUdpProtocol):
                continue
            for key, session in list(protocol_object.sessions.items()):
                if session.last_seen >= cutoff:
                    continue
                protocol_object.sessions.pop(key, None)
                for tunnel in list(ACTIVE_TUNNELS.values()) + list(DRAINING_TUNNELS):
                    if tunnel.sessions.get(session.session_id) is session:
                        await tunnel.close_session(
                            session.session_id, notify=True, reason="udp_timeout"
                        )
                        break
        for tunnel in list(ACTIVE_TUNNELS.values()) + list(DRAINING_TUNNELS):
            for session_id, session in list(tunnel.sessions.items()):
                if isinstance(session, UdpSession) and session.last_seen < cutoff:
                    await tunnel.close_session(session_id, notify=True, reason="udp_timeout")


# =============================================================================
# Status snapshots, diagnostics and management actions
# =============================================================================

CONFIG_RESTART_REQUIRED: list[str] = []


def tunnel_kind_text(tunnel: Tunnel | None) -> str:
    if not tunnel:
        return "仅信令在线"
    mapping = {
        "P2P_IPV6": "IPv6 TCP",
        "P2P_IPV4": "IPv4 TCP",
        "P2P_RECONNECT_IPV6": "IPv6 TCP（恢复）",
        "P2P_RECONNECT_IPV4": "IPv4 TCP（恢复）",
        "RELAY": "Relay",
    }
    return mapping.get(tunnel.kind, tunnel.kind.replace("_", " "))


def build_status_snapshot() -> dict[str, Any]:
    global RATE_SAMPLE_AT, RATE_SAMPLE_UPLOAD, RATE_SAMPLE_DOWNLOAD
    global RATE_UPLOAD_BPS, RATE_DOWNLOAD_BPS
    current = time.time()
    elapsed = current - RATE_SAMPLE_AT
    if elapsed >= 0.5:
        RATE_UPLOAD_BPS = max(0.0, (UPLOAD_BYTES - RATE_SAMPLE_UPLOAD) / elapsed)
        RATE_DOWNLOAD_BPS = max(0.0, (DOWNLOAD_BYTES - RATE_SAMPLE_DOWNLOAD) / elapsed)
        RATE_SAMPLE_AT = current
        RATE_SAMPLE_UPLOAD = UPLOAD_BYTES
        RATE_SAMPLE_DOWNLOAD = DOWNLOAD_BYTES

    active_items = [
        (peer_id, tunnel)
        for peer_id, tunnel in list(ACTIVE_TUNNELS.items())
        if not tunnel.closed
    ]
    tunnels = [
        {
            "peer_id": peer_id,
            "kind": tunnel.kind,
            "kind_text": tunnel_kind_text(tunnel),
            "verified": True,
            "encrypted": tunnel.encrypted,
            "algorithm": str(cfg("encryption.algorithm", "HMAC_STREAM"))
            if tunnel.encrypted
            else "NONE",
            "rtt_ms": tunnel.rtt,
            "sessions": len(tunnel.sessions),
            "upload": tunnel.upload,
            "download": tunnel.download,
            "created_at": tunnel.created_at,
            "draining": tunnel.draining,
            "queue_frames": tunnel.queue.qsize(),
            "queue_bytes": tunnel.queued_bytes,
        }
        for peer_id, tunnel in sorted(active_items)
    ]
    active_by_peer = {peer_id: tunnel for peer_id, tunnel in active_items}
    with ONLINE_LOCK:
        online_items = list(ONLINE.items())
        node_list_received = NODE_LIST_RECEIVED
        last_node_list_at = LAST_NODE_LIST_AT
    online_nodes = []
    for peer_id, peer in sorted(online_items):
        tunnel = active_by_peer.get(peer_id)
        online_nodes.append(
            {
                "peer_id": peer_id,
                "name": peer.name,
                "mode": peer.mode,
                "p2p_port": peer.p2p_port,
                "signal_online": True,
                "verified": bool(tunnel),
                "encryption_advertised": peer.encryption,
                "connection": tunnel_kind_text(tunnel),
                "tunnel_kind": tunnel.kind if tunnel else None,
                "rtt_ms": tunnel.rtt if tunnel else None,
                "sessions": len(tunnel.sessions) if tunnel else 0,
                "ipv4_count": len(peer.ipv4),
                "ipv6_count": len(peer.ipv6),
            }
        )
    preserved_nodes = [
        {
            "peer_id": peer_id,
            "connection": tunnel_kind_text(tunnel),
            "verified": True,
            "rtt_ms": tunnel.rtt,
            "sessions": len(tunnel.sessions),
        }
        for peer_id, tunnel in sorted(active_items)
        if peer_id not in {item[0] for item in online_items}
    ]
    sessions: list[dict[str, Any]] = []
    for peer_id, tunnel in sorted(active_items):
        for session_id, session in sorted(tunnel.sessions.items()):
            if isinstance(session, TcpSession):
                sessions.append(
                    {
                        "peer_id": peer_id,
                        "session_id": session_id,
                        "protocol": "TCP",
                        "rule_id": session.rule_id,
                        "source": session.source,
                        "target": session.target,
                        "created_at": session.created_at,
                        "upload": session.upload,
                        "download": session.download,
                        "local_eof": session.local_eof,
                        "remote_eof": session.remote_eof,
                    }
                )
            else:
                sessions.append(
                    {
                        "peer_id": peer_id,
                        "session_id": session_id,
                        "protocol": "UDP",
                        "rule_id": session.rule_id,
                        "source": format_endpoint(session.source_address),
                        "target": session.target,
                        "created_at": session.created_at,
                        "upload": session.upload,
                        "download": session.download,
                        "local_eof": False,
                        "remote_eof": False,
                    }
                )
    with ATTEMPT_HISTORY_LOCK:
        attempts = copy.deepcopy(list(ATTEMPT_HISTORY))
    memories = [
        {
            "peer_id": peer_id,
            "preferred_family": memory.preferred_family,
            "preferred_host": memory.preferred_host,
            "preferred_port": memory.preferred_port,
            "candidate_count": len(memory.candidates),
            "generation_count": len(memory.generations),
            "remembered_at": memory.remembered_at,
            "expires_at": memory.expires_at,
            "last_result": memory.last_result,
        }
        for peer_id, memory in sorted(RECONNECT_MEMORY.items())
        if memory.expires_at > current
    ]
    recovering = sorted(
        peer_id
        for peer_id, task in list(DIRECT_RECONNECT_TASKS.items())
        if not task.done()
    )
    if APP_SHUTTING_DOWN:
        state = "STOPPING"
    elif not APP_READY:
        state = "ERROR" if LAST_FATAL_ERROR else "STARTING"
    elif recovering:
        state = "RECOVERING"
    elif SIGNAL_CONNECTED:
        if any(tunnel.kind == "RELAY" for _, tunnel in active_items):
            state = "RELAY"
        else:
            state = "NORMAL"
    elif active_items:
        state = "DEGRADED"
    else:
        state = "OFFLINE"
    outage = current - SIGNAL_LAST_DISCONNECT_AT if SIGNAL_LAST_DISCONNECT_AT and not SIGNAL_CONNECTED else 0
    connected_for = current - SIGNAL_LAST_CONNECT_AT if SIGNAL_LAST_CONNECT_AT and SIGNAL_CONNECTED else 0
    with EVENTS_LOCK:
        recent_events = list(EVENTS)[: int(cfg("logging.recent_event_lines", 50))]
    return {
        "version": APPLICATION_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "current_time": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "state": state,
        "node_id": node_id(),
        "node_name": node_name(),
        "uptime_seconds": current - APP_STARTED_AT,
        "uptime_text": format_duration(current - APP_STARTED_AT),
        "signal_connected": SIGNAL_CONNECTED,
        "signal_endpoint": format_endpoint(SIGNAL_ENDPOINT),
        "signal_rtt_ms": SIGNAL_RTT,
        "signal_outage_seconds": outage,
        "signal_outage_text": format_duration(outage),
        "signal_connected_seconds": connected_for,
        "signal_connected_text": format_duration(connected_for),
        "node_list_received": node_list_received,
        "node_list_age_seconds": current - last_node_list_at if last_node_list_at else None,
        "p2p_port": P2P_LISTEN_PORT,
        "tunnel_mode": str(cfg("tunnel.mode", "AUTO")),
        "punch_policy": str(cfg("tunnel.punch_policy", "PRECONNECT")),
        "relay_enabled": bool(cfg("tunnel.relay_enabled", True)),
        "relay_upgrade_enabled": bool(cfg("tunnel.relay_upgrade_to_p2p", True)),
        "relay_upgrade_interval": float(cfg("tunnel.relay_upgrade_interval", 60.0)),
        "preconnect_retry_interval": float(cfg("tunnel.preconnect_retry_interval", 45.0)),
        "relay_retries": int(cfg("tunnel.relay_retries", 1)),
        "encryption_enabled": bool(cfg("encryption.enabled", True)),
        "encryption_algorithm": str(cfg("encryption.algorithm", "HMAC_STREAM")),
        "server_has_shared_key": False,
        "public_ipv4": list(PUBLIC_IPV4),
        "public_ipv6": list(PUBLIC_IPV6),
        "local_ipv4": list(LOCAL_IPV4),
        "local_ipv6": list(LOCAL_IPV6),
        "online_nodes": online_nodes,
        "online_count": len(online_nodes),
        "preserved_nodes": preserved_nodes,
        "tunnels": tunnels,
        "sessions": sessions,
        "forwards": FORWARD_MANAGER.snapshot() if globals().get("FORWARD_MANAGER") else [],
        "attempts": attempts,
        "memories": memories,
        "recovering": recovering,
        "upload_bytes": UPLOAD_BYTES,
        "download_bytes": DOWNLOAD_BYTES,
        "upload_bps": RATE_UPLOAD_BPS,
        "download_bps": RATE_DOWNLOAD_BPS,
        "recent_events": recent_events,
        "log_directory": str(JSON_LOGGER.directory or ""),
        "log_file": str(JSON_LOGGER.active_path or ""),
        "config_path": str(CONFIG_MANAGER.path),
        "config_loaded_from_backup": CONFIG_MANAGER.loaded_from_backup,
        "restart_required": list(CONFIG_RESTART_REQUIRED),
        "last_fatal_error": LAST_FATAL_ERROR,
        "management_endpoint": WEB_ENDPOINT,
    }


def publish_status_snapshot() -> None:
    global LATEST_STATUS_SNAPSHOT, LATEST_STATUS_SNAPSHOT_AT
    try:
        snapshot = build_status_snapshot()
    except Exception as exc:
        log_event(
            "status_snapshot_failed",
            level="ERROR",
            message="Unable to build status snapshot",
            error=exc,
            include_traceback=True,
        )
        snapshot = {
            "version": APPLICATION_VERSION,
            "state": "ERROR",
            "node_id": node_id(),
            "node_name": node_name(),
            "last_fatal_error": f"{type(exc).__name__}: {exc}",
            "recent_events": [],
        }
    snapshot["snapshot_published_at"] = time.time()
    with STATUS_SNAPSHOT_LOCK:
        LATEST_STATUS_SNAPSHOT = snapshot
        LATEST_STATUS_SNAPSHOT_AT = time.time()


def get_cached_status_snapshot() -> dict[str, Any]:
    with STATUS_SNAPSHOT_LOCK:
        snapshot = copy.deepcopy(LATEST_STATUS_SNAPSHOT)
        published = LATEST_STATUS_SNAPSHOT_AT
    if not snapshot:
        snapshot = {
            "version": APPLICATION_VERSION,
            "state": "STARTING",
            "node_id": node_id(),
            "node_name": node_name(),
            "recent_events": [],
        }
    snapshot["current_time"] = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    snapshot["management_endpoint"] = WEB_ENDPOINT
    snapshot["snapshot_age_seconds"] = (
        round(max(0.0, time.time() - published), 3) if published else None
    )
    return snapshot


async def status_snapshot_loop() -> None:
    while not APP_SHUTTING_DOWN:
        publish_status_snapshot()
        await asyncio.sleep(float(cfg("web.status_snapshot_interval", 0.75)))
    publish_status_snapshot()


def diagnostic_text() -> str:
    snapshot = get_cached_status_snapshot()
    lines = [
        f"Version: {snapshot.get('version', '-')}",
        f"Protocol: {snapshot.get('protocol_version', '-')}",
        f"Time: {snapshot.get('current_time', '-')}",
        f"Node: {snapshot.get('node_id', '-')} / {snapshot.get('node_name', '-')}",
        f"State: {snapshot.get('state', '-')}",
        f"Uptime: {snapshot.get('uptime_text', '-')}",
        f"Signal: {'connected' if snapshot.get('signal_connected') else 'disconnected'}",
        f"Signal endpoint: {snapshot.get('signal_endpoint', '-')}",
        f"Signal RTT: {snapshot.get('signal_rtt_ms', '-')}",
        f"P2P port: {snapshot.get('p2p_port', '-')}",
        f"Mode: {snapshot.get('tunnel_mode', '-')} / {snapshot.get('punch_policy', '-')}",
        f"Encryption: {snapshot.get('encryption_enabled')} / {snapshot.get('encryption_algorithm')}",
        f"Online peers: {snapshot.get('online_count', 0)}",
        f"Active tunnels: {len(snapshot.get('tunnels', []))}",
        f"Active sessions: {len(snapshot.get('sessions', []))}",
        f"Forwards: {len(snapshot.get('forwards', []))}",
        f"Traffic: up={human_bytes(snapshot.get('upload_bytes', 0))}, down={human_bytes(snapshot.get('download_bytes', 0))}",
        f"Config: {snapshot.get('config_path', '-')}",
        f"Log: {snapshot.get('log_file', '-')}",
        f"Restart required: {', '.join(snapshot.get('restart_required', [])) or '-'}",
        f"Last fatal error: {snapshot.get('last_fatal_error') or '-'}",
    ]
    for tunnel in snapshot.get("tunnels", []):
        lines.append(
            f"Tunnel {tunnel['peer_id']}: {tunnel['kind_text']}, verified={tunnel['verified']}, "
            f"encrypted={tunnel['encrypted']}, sessions={tunnel['sessions']}"
        )
    return "\n".join(lines)


async def force_signal_reconnect() -> None:
    writer = SIGNAL_WRITER
    if writer:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    add_event("已请求重新连接信令", event_name="signal_reconnect_requested")


async def recover_all_peers() -> None:
    peers = sorted(set(configured_peer_ids()) | set(RECONNECT_MEMORY))
    for peer_id in peers:
        existing = ACTIVE_TUNNELS.get(peer_id)
        if existing and not existing.closed:
            continue
        if SIGNAL_CONNECTED:
            asyncio.create_task(ensure_tunnel(peer_id), name=f"manual-connect:{peer_id}")
        else:
            schedule_direct_recovery(peer_id, "manual")


async def reload_configuration() -> list[str]:
    global CONFIG, CONFIG_RESTART_REQUIRED
    old = copy.deepcopy(CONFIG)
    new = await asyncio.get_running_loop().run_in_executor(None, CONFIG_MANAGER.reload)
    restart_fields: list[str] = []
    comparisons = {
        "node.id": (old.get("node", {}).get("id"), new.get("node", {}).get("id")),
        "node.shared_key": (
            old.get("node", {}).get("shared_key"),
            new.get("node", {}).get("shared_key"),
        ),
        "tunnel.p2p_port": (
            old.get("tunnel", {}).get("p2p_port"),
            new.get("tunnel", {}).get("p2p_port"),
        ),
        "tunnel.auto_port": (
            old.get("tunnel", {}).get("auto_port"),
            new.get("tunnel", {}).get("auto_port"),
        ),
        "web.host": (old.get("web", {}).get("host"), new.get("web", {}).get("host")),
        "web.port": (old.get("web", {}).get("port"), new.get("web", {}).get("port")),
        "management.mode": (
            old.get("management", {}).get("mode"),
            new.get("management", {}).get("mode"),
        ),
    }
    for name, (before, after) in comparisons.items():
        if before != after:
            restart_fields.append(name)
    CONFIG = new
    CONFIG_RESTART_REQUIRED = restart_fields
    await FORWARD_MANAGER.apply_rules(cfg("forwards", []))
    PRECONNECT_WAKEUP.set()
    add_event(
        "配置已重载" + (f"；需重启：{', '.join(restart_fields)}" if restart_fields else ""),
        event_name="configuration_reloaded",
    )
    return restart_fields


async def reload_forwards_only() -> None:
    global CONFIG
    new = await asyncio.get_running_loop().run_in_executor(None, CONFIG_MANAGER.reload)
    CONFIG["forwards"] = copy.deepcopy(new["forwards"])
    await FORWARD_MANAGER.apply_rules(CONFIG["forwards"])
    PRECONNECT_WAKEUP.set()
    add_event("转发规则已重载", event_name="forwards_reloaded")


async def peer_action(peer_id: str, action: str) -> str:
    peer_id = str(peer_id).upper()
    if len(peer_id) != 1 or not ("A" <= peer_id <= "Z") or peer_id == node_id():
        raise ValueError("invalid peer ID")
    action = str(action).lower()
    if action == "connect":
        await ensure_tunnel(peer_id)
        return "连接已建立"
    if action == "ipv6":
        if not await try_p2p_family(peer_id, 6):
            raise ConnectionError("IPv6 TCP未建立")
        return "IPv6 TCP已建立"
    if action == "ipv4":
        if not await try_p2p_family(peer_id, 4):
            raise ConnectionError("IPv4 TCP未建立")
        return "IPv4 TCP已建立"
    if action == "relay":
        existing = ACTIVE_TUNNELS.get(peer_id)
        if existing and not existing.closed:
            await existing.close("manual_relay_switch")
        if not await request_relay_tunnel(peer_id):
            raise ConnectionError("Relay未建立")
        return "Relay已建立"
    if action == "upgrade":
        if not await try_p2p_tunnel(peer_id):
            raise ConnectionError("Relay升级P2P未成功")
        return "已升级到P2P"
    if action == "disconnect":
        tunnel = ACTIVE_TUNNELS.get(peer_id)
        if tunnel:
            await tunnel.close("manual_disconnect")
        return "隧道已断开"
    if action == "recover":
        if not await reconnect_from_memory(peer_id, trigger="web"):
            raise ConnectionError("本地记忆恢复未成功")
        return "恢复成功"
    if action == "clear-memory":
        RECONNECT_MEMORY.pop(peer_id, None)
        await persist_reconnect_memory()
        return "恢复记忆已清除"
    raise ValueError("unknown peer action")


async def update_hot_tunnel_settings(values: dict[str, Any]) -> str:
    """Validate, persist and apply the small set of Web-editable settings."""
    global CONFIG
    policy = str(values.get("punch_policy", cfg("tunnel.punch_policy", "PRECONNECT"))).upper()
    if policy not in {"PRECONNECT", "ON_DEMAND"}:
        raise ValueError("punch_policy must be PRECONNECT or ON_DEMAND")
    interval = float(values.get("relay_upgrade_interval", cfg("tunnel.relay_upgrade_interval", 60.0)))
    if not 10.0 <= interval <= 86400.0:
        raise ValueError("relay_upgrade_interval must be between 10 and 86400 seconds")
    retry_interval = float(values.get("preconnect_retry_interval", cfg("tunnel.preconnect_retry_interval", 45.0)))
    if not 1.0 <= retry_interval <= 86400.0:
        raise ValueError("preconnect_retry_interval must be between 1 and 86400 seconds")
    relay_retries = int(values.get("relay_retries", cfg("tunnel.relay_retries", 1)))
    if not 0 <= relay_retries <= 5:
        raise ValueError("relay_retries must be between 0 and 5")
    updates = {
        "punch_policy": policy,
        "relay_enabled": bool(values.get("relay_enabled", cfg("tunnel.relay_enabled", True))),
        "relay_upgrade_to_p2p": bool(
            values.get("relay_upgrade_to_p2p", cfg("tunnel.relay_upgrade_to_p2p", True))
        ),
        "relay_upgrade_interval": interval,
        "preconnect_retry_interval": retry_interval,
        "relay_retries": relay_retries,
    }
    new_config = await asyncio.get_running_loop().run_in_executor(
        None, CONFIG_MANAGER.save_tunnel_settings, updates
    )
    CONFIG = new_config
    PRECONNECT_WAKEUP.set()
    add_event("连接设置已保存并热更新", event_name="hot_tunnel_settings_updated")
    return "连接设置已保存并立即生效"


async def close_business_session(peer_id: str, session_id: int) -> None:
    tunnel = ACTIVE_TUNNELS.get(peer_id)
    if not tunnel:
        raise KeyError("tunnel not found")
    if session_id not in tunnel.sessions:
        raise KeyError("session not found")
    await tunnel.close_session(session_id, notify=True, reason="web_close")


# =============================================================================
# Local Web management
# =============================================================================

WEB_SESSION_LOCK = threading.RLock()
WEB_LOGIN_LOCK = threading.RLock()
WEB_ACTION_LOCK = threading.RLock()
WEB_SESSIONS: dict[str, dict[str, Any]] = {}
WEB_LOGIN_FAILURES: dict[str, deque[float]] = {}
WEB_ACTION_FUTURES: dict[str, concurrent.futures.Future[Any]] = {}
WEB_SERVER: http.server.ThreadingHTTPServer | None = None
WEB_THREAD: threading.Thread | None = None
WEB_ENDPOINT = ""
WEB_BOUND_HOST = ""
WEB_BOUND_PORT = 0
WEB_COOKIE_NAME = "P2PADMIN"


def cleanup_web_sessions() -> None:
    current = time.time()
    with WEB_SESSION_LOCK:
        for token, session in list(WEB_SESSIONS.items()):
            if float(session.get("expires", 0)) <= current:
                WEB_SESSIONS.pop(token, None)
        max_sessions = int(cfg("web.max_sessions", 8))
        if len(WEB_SESSIONS) > max_sessions:
            ordered = sorted(
                WEB_SESSIONS.items(),
                key=lambda item: float(item[1].get("last_seen", item[1].get("created", 0))),
            )
            for token, _ in ordered[: len(WEB_SESSIONS) - max_sessions]:
                WEB_SESSIONS.pop(token, None)


def new_web_session() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    current = time.time()
    ttl = float(cfg("web.session_ttl", 86400.0))
    with WEB_SESSION_LOCK:
        WEB_SESSIONS[token] = {
            "created": current,
            "last_seen": current,
            "expires": current + ttl,
            "csrf": csrf,
        }
    cleanup_web_sessions()
    return token, csrf


def get_web_session(cookie_header: str) -> tuple[str | None, dict[str, Any] | None]:
    cleanup_web_sessions()
    try:
        cookie = http.cookies.SimpleCookie()
        cookie.load(cookie_header or "")
        morsel = cookie.get(WEB_COOKIE_NAME)
        token = morsel.value if morsel else ""
    except Exception:
        token = ""
    if not token:
        return None, None
    current = time.time()
    ttl = float(cfg("web.session_ttl", 86400.0))
    with WEB_SESSION_LOCK:
        session = WEB_SESSIONS.get(token)
        if not session or float(session.get("expires", 0)) <= current:
            WEB_SESSIONS.pop(token, None)
            return None, None
        session["last_seen"] = current
        session["expires"] = current + ttl
        return token, dict(session)


def web_login_rate_limited(client: str) -> bool:
    current = time.time()
    window = float(cfg("web.login_failure_window", 60.0))
    maximum = int(cfg("web.max_login_failures", 5))
    with WEB_LOGIN_LOCK:
        attempts = WEB_LOGIN_FAILURES.setdefault(client, deque())
        while attempts and attempts[0] < current - window:
            attempts.popleft()
        return len(attempts) >= maximum


def record_web_login_failure(client: str) -> None:
    current = time.time()
    window = float(cfg("web.login_failure_window", 60.0))
    with WEB_LOGIN_LOCK:
        attempts = WEB_LOGIN_FAILURES.setdefault(client, deque())
        while attempts and attempts[0] < current - window:
            attempts.popleft()
        attempts.append(current)


def login_page(error_message: str = "") -> bytes:
    error = (
        f'<div class="error">{html.escape(error_message)}</div>' if error_message else ""
    )
    theme = json.dumps(str(cfg("web.theme", "AUTO")).lower())
    page = f'''<!doctype html><html lang="zh-CN" data-theme="auto"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>P2P Tunnel 登录</title>
<style>
:root{{--bg:#eef2f7;--panel:#fff;--text:#182230;--muted:#68778a;--line:#d8e0ea;--accent:#256fe5;--bad:#c43f50;--shadow:0 22px 70px rgba(20,40,70,.14)}}
html[data-theme=dark]{{--bg:#0d141d;--panel:#17212c;--text:#eef4fa;--muted:#96a7b9;--line:#2c3c4d;--accent:#5798ff;--bad:#ff7c89;--shadow:0 24px 80px rgba(0,0,0,.42)}}
@media(prefers-color-scheme:dark){{html[data-theme=auto]{{--bg:#0d141d;--panel:#17212c;--text:#eef4fa;--muted:#96a7b9;--line:#2c3c4d;--accent:#5798ff;--bad:#ff7c89;--shadow:0 24px 80px rgba(0,0,0,.42)}}}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:22px;background:radial-gradient(circle at 20% 8%,color-mix(in srgb,var(--accent) 16%,transparent),transparent 35%),var(--bg);font-family:Segoe UI,Microsoft YaHei UI,system-ui,sans-serif;color:var(--text)}}
.card{{width:min(430px,100%);padding:28px;background:var(--panel);border:1px solid var(--line);border-radius:20px;box-shadow:var(--shadow)}}.brand{{display:flex;gap:13px;align-items:center}}.logo{{width:50px;height:50px;border-radius:15px;display:grid;place-items:center;background:linear-gradient(145deg,var(--accent),#7456e9);color:#fff;font-weight:900}}h1{{font-size:23px;margin:0}}p{{margin:5px 0;color:var(--muted);font-size:13px}}label{{display:block;margin:23px 0 8px;font-weight:700;font-size:14px}}input{{width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:11px;background:color-mix(in srgb,var(--panel) 92%,var(--bg));color:var(--text);font:inherit;outline:none}}input:focus{{border-color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent) 18%,transparent)}}button{{width:100%;margin-top:16px;padding:12px;border:0;border-radius:11px;background:var(--accent);color:#fff;font:inherit;font-weight:800;cursor:pointer}}.note{{margin-top:20px;padding:11px 12px;border:1px solid var(--line);border-radius:10px;color:var(--muted);font-size:12px;line-height:1.6}}.error{{margin-top:18px;padding:10px 12px;border:1px solid color-mix(in srgb,var(--bad) 45%,var(--line));border-radius:10px;color:var(--bad)}}
</style></head><body><main class="card"><div class="brand"><div class="logo">P2P</div><div><h1>节点管理登录</h1><p>{html.escape(node_id())} · {html.escape(node_name())}</p></div></div>{error}
<form method="post" action="/login" autocomplete="off"><label for="password">管理密码</label><input id="password" type="password" name="password" required autofocus maxlength="256"><button type="submit">登录</button></form><div class="note">简易认证：单密码、会话 Cookie、CSRF 与失败限速。节点共享密钥不会显示在网页或日志中。</div></main>
<script>(()=>{{let t={theme};try{{t=localStorage.getItem('p2p-theme')||t}}catch(_e){{}}document.documentElement.dataset.theme=['light','dark'].includes(t)?t:'auto'}})()</script></body></html>'''
    return page.encode("utf-8")


def dashboard_page(csrf: str) -> bytes:
    refresh = max(500, int(cfg("web.status_refresh_ms", 1500)))
    theme = json.dumps(str(cfg("web.theme", "AUTO")).lower())
    page = r'''<!doctype html><html lang="zh-CN" data-theme="auto"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light dark"><title>P2P Tunnel 管理</title>
<style>
:root{--bg:#eef2f6;--surface:#fff;--surface2:#f7f9fc;--text:#172230;--muted:#69798b;--line:#d9e1e9;--accent:#286fd9;--accent2:#7558e8;--good:#13824c;--good-bg:#e5f7ed;--warn:#a66a08;--warn-bg:#fff3d8;--bad:#c23e4d;--bad-bg:#fdebed;--blue-bg:#e8f1ff;--shadow:0 10px 32px rgba(23,43,68,.08);--top:rgba(238,242,246,.9)}
html[data-theme=dark]{--bg:#0c131c;--surface:#16212c;--surface2:#111a24;--text:#eef4f9;--muted:#98a9ba;--line:#2b3c4c;--accent:#5798ff;--accent2:#947cff;--good:#70e3a4;--good-bg:#173b2a;--warn:#ffd176;--warn-bg:#493916;--bad:#ff929c;--bad-bg:#4b2027;--blue-bg:#172e4d;--shadow:0 14px 40px rgba(0,0,0,.25);--top:rgba(12,19,28,.9)}
@media(prefers-color-scheme:dark){html[data-theme=auto]{--bg:#0c131c;--surface:#16212c;--surface2:#111a24;--text:#eef4f9;--muted:#98a9ba;--line:#2b3c4c;--accent:#5798ff;--accent2:#947cff;--good:#70e3a4;--good-bg:#173b2a;--warn:#ffd176;--warn-bg:#493916;--bad:#ff929c;--bad-bg:#4b2027;--blue-bg:#172e4d;--shadow:0 14px 40px rgba(0,0,0,.25);--top:rgba(12,19,28,.9)}}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font-family:Segoe UI,Microsoft YaHei UI,system-ui,sans-serif;line-height:1.45}.top{position:sticky;top:0;z-index:20;background:var(--top);backdrop-filter:blur(18px);border-bottom:1px solid var(--line)}.topin{width:min(1500px,95vw);min-height:68px;margin:auto;display:flex;align-items:center;justify-content:space-between;gap:14px}.brand{display:flex;align-items:center;gap:11px;min-width:0}.logo{width:39px;height:39px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(145deg,var(--accent),var(--accent2));color:#fff;font-size:12px;font-weight:900}h1{font-size:18px;margin:0}.sub{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:58vw}.toolbar,.actions{display:flex;gap:7px;flex-wrap:wrap;align-items:center}button,.button{appearance:none;border:1px solid var(--line);background:var(--surface2);color:var(--text);border-radius:9px;padding:8px 10px;font:inherit;font-size:12px;font-weight:750;cursor:pointer;text-decoration:none;transition:.15s}button:hover,.button:hover{border-color:var(--accent);transform:translateY(-1px)}button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.warn{color:var(--warn);background:var(--warn-bg)}button.danger{color:var(--bad);background:var(--bad-bg)}button:disabled{opacity:.55;cursor:wait;transform:none}main{width:min(1500px,95vw);margin:16px auto 48px}.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:12px}.card{grid-column:span 3;background:var(--surface);border:1px solid var(--line);border-radius:15px;padding:15px;box-shadow:var(--shadow);min-width:0}.wide{grid-column:1/-1}.half{grid-column:span 6}.title{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:11px}.title h2{font-size:14px;margin:0;color:var(--muted)}.metric{font-size:24px;font-weight:800;letter-spacing:-.025em}.detail{font-size:12px;color:var(--muted);margin-top:5px;overflow-wrap:anywhere}.badge{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border-radius:999px;border:1px solid var(--line);background:var(--surface2);font-size:11px;font-weight:850}.badge:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}.NORMAL{color:var(--good);background:var(--good-bg)}.RELAY,.DEGRADED,.RECOVERING{color:var(--warn);background:var(--warn-bg)}.OFFLINE,.ERROR,.STOPPING{color:var(--bad);background:var(--bad-bg)}.STARTING{color:var(--accent);background:var(--blue-bg)}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:11px}table{width:100%;border-collapse:collapse;min-width:720px}th,td{text-align:left;padding:8px 9px;border-bottom:1px solid var(--line);font-size:12px;white-space:nowrap}th{position:sticky;top:0;background:var(--surface2);color:var(--muted);font-weight:800}tr:last-child td{border-bottom:0}.empty{padding:16px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:10px}.mini{padding:5px 7px;font-size:11px}.good{color:var(--good)}.bad{color:var(--bad)}.muted{color:var(--muted)}pre{margin:0;padding:11px;border:1px solid var(--line);border-radius:10px;background:var(--surface2);font:12px/1.55 Consolas,Microsoft YaHei UI,monospace;white-space:pre-wrap;word-break:break-word;max-height:330px;overflow:auto}.tags{display:flex;gap:6px;flex-wrap:wrap}.tag{padding:4px 7px;border:1px solid var(--line);border-radius:7px;background:var(--surface2);font:11px Consolas,monospace}.notice{padding:10px 11px;border:1px solid color-mix(in srgb,var(--accent) 25%,var(--line));border-radius:10px;background:var(--blue-bg);font-size:12px;color:var(--muted)}dialog{width:min(570px,94vw);border:1px solid var(--line);border-radius:16px;background:var(--surface);color:var(--text);box-shadow:0 30px 100px rgba(0,0,0,.35);padding:0}dialog::backdrop{background:rgba(5,12,20,.55);backdrop-filter:blur(3px)}.dialoghead,.dialogfoot{padding:15px 17px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}.dialogfoot{border-top:1px solid var(--line);border-bottom:0;justify-content:flex-end}.dialogbody{padding:17px}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field.full{grid-column:1/-1}.field label{display:block;font-size:12px;font-weight:750;margin-bottom:6px;color:var(--muted)}input,select{width:100%;padding:10px 11px;border:1px solid var(--line);border-radius:9px;background:var(--surface2);color:var(--text);font:inherit;outline:none}input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 17%,transparent)}#toast{display:none;position:fixed;right:16px;bottom:16px;z-index:60;max-width:min(430px,90vw);padding:11px 14px;background:var(--surface);border:1px solid var(--line);border-radius:11px;box-shadow:var(--shadow);font-size:13px}
@media(max-width:1080px){.card{grid-column:span 6}.wide{grid-column:1/-1}}@media(max-width:720px){.topin{padding:10px 0;align-items:flex-start}.topin,.toolbar{flex-direction:column}.toolbar{align-items:stretch;width:100%}.toolbar button{flex:1}.card,.half{grid-column:1/-1}.metric{font-size:21px}.formgrid{grid-template-columns:1fr}.field.full{grid-column:auto}.sub{max-width:88vw}}
</style></head><body><header class="top"><div class="topin"><div class="brand"><div class="logo">P2P</div><div><h1>P2P Tunnel 管理</h1><div id="subtitle" class="sub">正在读取状态…</div></div></div><div class="toolbar"><button onclick="load(true)">刷新</button><button onclick="toggleTheme()">主题</button><button onclick="copyDiagnostics()">复制诊断</button><button onclick="logout()">退出登录</button></div></div></header>
<main><section class="grid">
<article class="card"><div class="title"><h2>总体状态</h2><span id="state" class="badge STARTING">STARTING</span></div><div id="node" class="metric">-</div><div id="uptime" class="detail">-</div></article>
<article class="card"><div class="title"><h2>信令</h2><span id="signalBadge" class="badge OFFLINE">OFFLINE</span></div><div id="signal" class="metric">-</div><div id="signalDetail" class="detail">-</div></article>
<article class="card"><div class="title"><h2>实时流量</h2></div><div id="traffic" class="metric">-</div><div id="trafficDetail" class="detail">-</div></article>
<article class="card"><div class="title"><h2>常用操作</h2></div><div class="actions"><button class="primary" onclick="action('reconnect-signal',this)">重连信令</button><button onclick="action('recover-all',this)">恢复隧道</button><button onclick="action('reload-config',this)">重载配置</button><button onclick="action('save-state',this)">保存状态</button><button class="warn" onclick="action('restart',this,true)">重启</button><button class="danger" onclick="action('shutdown',this,true)">退出</button></div></article>
<article class="card wide"><div class="title"><h2>在线节点</h2><span id="nodeCount" class="detail">0</span></div><div id="nodes"></div></article>
<article class="card wide"><div class="title"><h2>活动隧道</h2><span id="tunnelCount" class="detail">0</span></div><div id="tunnels"></div></article>
<article class="card wide"><div class="title"><h2>端口转发</h2><div class="actions"><span id="forwardCount" class="detail">0</span><button class="primary" onclick="newForward()">新增转发</button><button onclick="action('reload-forwards',this)">重载规则</button></div></div><div id="forwards"></div></article>
<article class="card wide"><div class="title"><h2>最近连接尝试</h2></div><div id="attempts"></div></article>
<article class="card half"><div class="title"><h2>恢复记忆</h2></div><div id="memories"></div></article>
<article class="card half"><div class="title"><h2>活动会话</h2></div><div id="sessions"></div></article>
<article class="card half"><div class="title"><h2>网络地址</h2></div><div id="addresses"></div></article>
<article class="card half" id="connectionSettings"><div class="title"><h2>连接设置</h2><span class="detail">保存后热更新</span></div><div class="formgrid">
<div class="field"><label>打孔策略</label><select id="s_punch_policy"><option value="PRECONNECT">PRECONNECT</option><option value="ON_DEMAND">ON_DEMAND</option></select></div>
<div class="field"><label>Relay升级周期（秒）</label><input id="s_relay_upgrade_interval" type="number" min="10" max="86400"></div>
<div class="field"><label>预连接重试周期（秒）</label><input id="s_preconnect_retry_interval" type="number" min="1" max="86400"></div>
<div class="field"><label>Relay重新申请次数</label><input id="s_relay_retries" type="number" min="0" max="5"></div>
<div class="field full"><label><input id="s_relay_enabled" type="checkbox" style="width:auto"> 允许Relay兜底</label> <label style="display:inline-block;margin-left:18px"><input id="s_relay_upgrade" type="checkbox" style="width:auto"> Relay后台升级P2P</label></div>
<div class="field full"><button class="primary" onclick="saveConnectionSettings(this)">保存连接设置</button></div></div></article>
<article class="card half"><div class="title"><h2>安全与运行</h2></div><div id="runtime"></div></article>
<article class="card wide"><div class="title"><h2>最近事件</h2><div class="actions"><a class="button" href="/api/log" target="_blank">下载日志</a><span id="updated" class="detail">-</span></div></div><pre id="events">-</pre></article>
</section></main><div id="toast"></div>
<dialog id="forwardDialog"><form method="dialog" onsubmit="return false"><div class="dialoghead"><strong id="dialogTitle">新增转发</strong><button onclick="closeForward()">关闭</button></div><div class="dialogbody"><div class="formgrid">
<div class="field"><label>规则ID</label><input id="f_id" required pattern="[A-Za-z0-9_.-]+"></div><div class="field"><label>名称</label><input id="f_name"></div>
<div class="field"><label>协议</label><select id="f_protocol"><option>TCP</option><option>UDP</option></select></div><div class="field"><label>目标节点</label><input id="f_peer" maxlength="1" required></div>
<div class="field"><label>本地监听地址</label><input id="f_listen_host" value="127.0.0.1" required></div><div class="field"><label>本地监听端口</label><input id="f_listen_port" type="number" min="1" max="65535" required></div>
<div class="field"><label>远端目标地址</label><input id="f_target_host" value="127.0.0.1" required></div><div class="field"><label>远端目标端口</label><input id="f_target_port" type="number" min="1" max="65535" required></div>
<div class="field full"><label><input id="f_enabled" type="checkbox" checked style="width:auto"> 启用此规则</label></div></div></div><div class="dialogfoot"><button onclick="closeForward()">取消</button><button class="primary" onclick="saveForward(this)">保存</button></div></form></dialog>
<script>
const CSRF=__CSRF__,REFRESH=__REFRESH__,CONFIG_THEME=__THEME__;let timer=null,loading=false,last=null;
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const bytes=n=>{n=Number(n||0);const u=['B','KB','MB','GB','TB'];let i=0;while(Math.abs(n)>=1024&&i<u.length-1){n/=1024;i++}return n.toFixed(i?1:0)+u[i]};
const rtt=n=>n==null?'-':Number(n).toFixed(Number(n)<1?3:1)+' ms';const age=t=>t?Math.max(0,Math.round(Date.now()/1000-Number(t)))+'秒':'-';
function theme(v){v=['light','dark'].includes(v)?v:'auto';document.documentElement.dataset.theme=v;try{localStorage.setItem('p2p-theme',v)}catch(_e){}}
function toggleTheme(){const v=document.documentElement.dataset.theme||'auto';theme(v==='auto'?'dark':v==='dark'?'light':'auto')}
(()=>{let t='';try{t=localStorage.getItem('p2p-theme')||''}catch(_e){}theme(t||CONFIG_THEME)})();
function toast(m,bad=false){const e=document.getElementById('toast');e.textContent=m;e.style.display='block';e.style.borderColor=bad?'var(--bad)':'var(--line)';clearTimeout(e._t);e._t=setTimeout(()=>e.style.display='none',3600)}
function table(headers,rows){if(!rows.length)return '<div class="empty">暂无数据</div>';return '<div class="tablewrap"><table><thead><tr>'+headers.map(x=>'<th>'+esc(x)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(x=>'<td>'+x+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>'}
const b=(text,fn,cls='')=>'<button class="mini '+cls+'" onclick="'+fn+'">'+esc(text)+'</button>';
async function api(path,body){const r=await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body||{})});const v=await r.json().catch(()=>({message:'HTTP '+r.status}));if(r.status===401){location.href='/';throw new Error('需要登录')}if(!r.ok)throw new Error(v.message||'操作失败');return v}
async function load(manual=false){if(loading)return;loading=true;try{const r=await fetch('/api/status',{cache:'no-store',credentials:'same-origin'});if(r.status===401){location.href='/';return}if(!r.ok)throw new Error('HTTP '+r.status);last=await r.json();render(last)}catch(e){toast('状态读取失败：'+e.message,true)}finally{loading=false;clearTimeout(timer);if(!document.hidden)timer=setTimeout(()=>load(false),REFRESH)}}
document.addEventListener('visibilitychange',()=>document.hidden?clearTimeout(timer):load(false));
function render(s){const st=String(s.state||'STARTING');document.getElementById('subtitle').textContent=(s.current_time||'-')+' · '+(s.management_endpoint||'本机管理');const se=document.getElementById('state');se.textContent=st;se.className='badge '+st;document.getElementById('node').textContent=(s.node_id||'-')+' · '+(s.node_name||'-');document.getElementById('uptime').textContent='运行 '+(s.uptime_text||'-')+' · 版本 '+(s.version||'-');
const connected=!!s.signal_connected,sb=document.getElementById('signalBadge');sb.textContent=connected?'CONNECTED':'OFFLINE';sb.className='badge '+(connected?'NORMAL':'OFFLINE');document.getElementById('signal').textContent=connected?'已连接':'已断开';document.getElementById('signalDetail').textContent=(s.signal_endpoint||'-')+' · RTT '+rtt(s.signal_rtt_ms)+(connected?' · '+(s.signal_connected_text||'-'):' · '+(s.signal_outage_text||'-'));
document.getElementById('traffic').textContent=bytes(s.upload_bps)+'/s ↑ · '+bytes(s.download_bps)+'/s ↓';document.getElementById('trafficDetail').textContent='累计 '+bytes(s.upload_bytes)+' ↑ / '+bytes(s.download_bytes)+' ↓';
const nodes=s.online_nodes||[];document.getElementById('nodeCount').textContent=nodes.length+' 个';document.getElementById('nodes').innerHTML=table(['节点','名称','身份','连接','RTT','会话','候选','操作'],nodes.map(n=>['<b>'+esc(n.peer_id)+'</b>',esc(n.name||'-'),n.verified?'<span class="good">已验证</span>':'<span class="muted">待隧道验证</span>',esc(n.connection||'-'),esc(rtt(n.rtt_ms)),esc(n.sessions),'IPv6 '+esc(n.ipv6_count)+' / IPv4 '+esc(n.ipv4_count),b('连接',`peer('${n.peer_id}','connect')`,'primary')+b('IPv6',`peer('${n.peer_id}','ipv6')`)+b('IPv4',`peer('${n.peer_id}','ipv4')`)+b('Relay',`peer('${n.peer_id}','relay')`,'warn')+b('升级',`peer('${n.peer_id}','upgrade')`)+b('断开',`peer('${n.peer_id}','disconnect')`,'danger')]));
const ts=s.tunnels||[];document.getElementById('tunnelCount').textContent=ts.length+' 条';document.getElementById('tunnels').innerHTML=table(['节点','类型','身份','加密','RTT','会话','队列','上传','下载'],ts.map(t=>[esc(t.peer_id),esc(t.kind_text),'<span class="good">共享密钥已验证</span>',t.encrypted?esc(t.algorithm):'<span class="bad">未加密</span>',esc(rtt(t.rtt_ms)),esc(t.sessions),esc(t.queue_frames)+' / '+bytes(t.queue_bytes),bytes(t.upload),bytes(t.download)]));
const fs=s.forwards||[];document.getElementById('forwardCount').textContent=fs.length+' 条';document.getElementById('forwards').innerHTML=table(['状态','协议','本地监听','节点','远端目标','会话','流量','名称','操作'],fs.map(f=>[f.state==='Listening'?'<span class="good">监听中</span>':f.state==='Disabled'?'<span class="muted">已停用</span>':'<span class="bad">'+esc(f.state)+'</span>',esc(f.protocol),esc(f.listen_host)+':'+esc(f.listen_port),esc(f.peer),esc(f.target_host)+':'+esc(f.target_port),esc(f.sessions),bytes(f.upload)+' ↑ / '+bytes(f.download)+' ↓',esc(f.name||f.id),b('编辑',`editForward('${f.id}')`)+b(f.enabled?'停用':'启用',`toggleForward('${f.id}',${!f.enabled})`)+b('重启',`forwardAction('restart','${f.id}')`)+b('删除',`deleteForward('${f.id}')`,'danger')]));
const at=(s.attempts||[]).slice(0,30);document.getElementById('attempts').innerHTML=table(['时间','节点','类型','阶段','候选','来源','结果','耗时/错误'],at.map(a=>[new Date(Number(a.time)*1000).toLocaleTimeString(),esc(a.peer_id),a.family?('IPv'+a.family):'Relay',esc(a.stage),esc(a.address||'-'),esc(a.source||'-'),a.state==='SUCCESS'?'<span class="good">成功</span>':a.state==='FAILED'?'<span class="bad">失败</span>':esc(a.state),esc(a.error||((a.duration_ms||0)+' ms'))]));
const ms=s.memories||[];document.getElementById('memories').innerHTML=table(['节点','首选地址','候选','代次','剩余','结果','操作'],ms.map(m=>[esc(m.peer_id),esc((m.preferred_host||'-')+':'+m.preferred_port),esc(m.candidate_count),esc(m.generation_count),Math.max(0,Math.round(m.expires_at-Date.now()/1000))+'秒',esc(m.last_result||'-'),b('恢复',`peer('${m.peer_id}','recover')`)+b('清除',`peer('${m.peer_id}','clear-memory')`,'danger')]));
const ss=s.sessions||[];document.getElementById('sessions').innerHTML=table(['节点','ID','协议','规则','来源','目标','运行','流量','EOF','操作'],ss.map(x=>[esc(x.peer_id),esc(x.session_id),esc(x.protocol),esc(x.rule_id||'-'),esc(x.source||'-'),esc(x.target||'-'),age(x.created_at),bytes(x.upload)+' ↑ / '+bytes(x.download)+' ↓',(x.local_eof?'L✓ ':'')+(x.remote_eof?'R✓':''),b('关闭',`closeSession('${x.peer_id}',${x.session_id})`,'danger')]));
const tags=v=>(v&&v.length)?'<div class="tags">'+v.map(x=>'<span class="tag">'+esc(x)+'</span>').join('')+'</div>':'-';document.getElementById('addresses').innerHTML='<div class="detail">公网IPv6</div>'+tags(s.public_ipv6)+'<div class="detail">公网IPv4</div>'+tags(s.public_ipv4)+'<div class="detail">本地IPv6</div>'+tags(s.local_ipv6)+'<div class="detail">本地IPv4</div>'+tags(s.local_ipv4);
const settings=document.getElementById('connectionSettings');if(settings&&!settings.contains(document.activeElement)){document.getElementById('s_punch_policy').value=s.punch_policy||'PRECONNECT';document.getElementById('s_relay_enabled').checked=!!s.relay_enabled;document.getElementById('s_relay_upgrade').checked=!!s.relay_upgrade_enabled;document.getElementById('s_relay_upgrade_interval').value=Number(s.relay_upgrade_interval||60);document.getElementById('s_preconnect_retry_interval').value=Number(s.preconnect_retry_interval||45);document.getElementById('s_relay_retries').value=Number(s.relay_retries||0)}const restart=(s.restart_required||[]);document.getElementById('runtime').innerHTML='<div class="notice">服务器不持有节点共享密钥。身份在P2P或Relay隧道内由节点之间验证。</div><p class="detail">连接顺序：IPv6 TCP → IPv4 TCP → Relay</p><p class="detail">加密：'+esc(s.encryption_algorithm)+' · Relay升级：'+(s.relay_upgrade_enabled?'开启':'关闭')+'</p><p class="detail">配置：'+esc(s.config_path||'-')+'</p><p class="detail">日志：'+esc(s.log_file||'-')+'</p>'+(restart.length?'<p class="bad">以下修改需重启：'+esc(restart.join(', '))+'</p>':'');document.getElementById('events').textContent=(s.recent_events||[]).join('\n')||'-';document.getElementById('updated').textContent='更新 '+new Date().toLocaleTimeString()}
async function action(name,btn,confirmIt=false){if(confirmIt&&!confirm(name==='shutdown'?'确定退出程序？':'确定安全重启程序？'))return;btn.disabled=true;try{const v=await api('/api/actions/'+name,{});toast(v.message||'操作已提交');if(!['shutdown','restart'].includes(name))setTimeout(()=>load(true),500)}catch(e){toast(e.message,true)}finally{if(!['shutdown','restart'].includes(name))btn.disabled=false}}
async function peer(id,a){try{const v=await api('/api/peer-action',{peer_id:id,action:a});toast(v.message||'操作已提交');setTimeout(()=>load(true),500)}catch(e){toast(e.message,true)}}
async function closeSession(p,id){if(!confirm('关闭此业务会话？'))return;try{await api('/api/session-close',{peer_id:p,session_id:id});toast('会话已关闭');load(true)}catch(e){toast(e.message,true)}}
function newForward(){document.getElementById('dialogTitle').textContent='新增转发';for(const id of ['f_id','f_name','f_listen_port','f_target_port'])document.getElementById(id).value='';document.getElementById('f_protocol').value='TCP';document.getElementById('f_peer').value='';document.getElementById('f_listen_host').value='127.0.0.1';document.getElementById('f_target_host').value='127.0.0.1';document.getElementById('f_enabled').checked=true;document.getElementById('f_id').disabled=false;document.getElementById('forwardDialog').showModal()}
function editForward(id){const f=(last.forwards||[]).find(x=>x.id===id);if(!f)return;document.getElementById('dialogTitle').textContent='编辑转发';for(const k of ['id','name','protocol','peer','listen_host','listen_port','target_host','target_port'])document.getElementById('f_'+k).value=f[k]??'';document.getElementById('f_enabled').checked=!!f.enabled;document.getElementById('f_id').disabled=true;document.getElementById('forwardDialog').showModal()}
function closeForward(){document.getElementById('forwardDialog').close()}
async function saveForward(btn){const rule={id:document.getElementById('f_id').value.trim(),name:document.getElementById('f_name').value.trim(),protocol:document.getElementById('f_protocol').value,peer:document.getElementById('f_peer').value.trim().toUpperCase(),listen_host:document.getElementById('f_listen_host').value.trim(),listen_port:Number(document.getElementById('f_listen_port').value),target_host:document.getElementById('f_target_host').value.trim(),target_port:Number(document.getElementById('f_target_port').value),enabled:document.getElementById('f_enabled').checked};btn.disabled=true;try{await api('/api/forwards/save',{rule});closeForward();toast('转发规则已保存并应用');load(true)}catch(e){toast(e.message,true)}finally{btn.disabled=false}}
async function toggleForward(id,en){try{await api('/api/forwards/toggle',{id,enabled:en});toast('规则状态已更新');load(true)}catch(e){toast(e.message,true)}}
async function forwardAction(a,id){try{await api('/api/forwards/'+a,{id});toast('操作完成');load(true)}catch(e){toast(e.message,true)}}
async function deleteForward(id){if(!confirm('删除转发 '+id+'？现有会话默认继续到自然结束。'))return;try{await api('/api/forwards/delete',{id,force:false});toast('规则已删除');load(true)}catch(e){toast(e.message,true)}}
async function saveConnectionSettings(btn){btn.disabled=true;try{const body={punch_policy:document.getElementById('s_punch_policy').value,relay_enabled:document.getElementById('s_relay_enabled').checked,relay_upgrade_to_p2p:document.getElementById('s_relay_upgrade').checked,relay_upgrade_interval:Number(document.getElementById('s_relay_upgrade_interval').value),preconnect_retry_interval:Number(document.getElementById('s_preconnect_retry_interval').value),relay_retries:Number(document.getElementById('s_relay_retries').value)};const v=await api('/api/settings',body);toast(v.message||'连接设置已保存');load(true)}catch(e){toast(e.message,true)}finally{btn.disabled=false}}
async function copyDiagnostics(){try{const r=await fetch('/api/diagnostics',{credentials:'same-origin'});const t=await r.text();await navigator.clipboard.writeText(t);toast('诊断信息已复制')}catch(e){toast('复制失败：'+e.message,true)}}
async function logout(){try{await api('/logout',{})}finally{location.href='/'}}
load(false);
</script></body></html>'''
    page = (
        page.replace("__CSRF__", json.dumps(csrf))
        .replace("__REFRESH__", str(refresh))
        .replace("__THEME__", theme)
    )
    return page.encode("utf-8")


class LocalAdminServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False
    request_queue_size = 64

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(float(cfg("web.request_timeout", 15.0)))
        return request, address


class LocalAdminServerV6(LocalAdminServer):
    address_family = socket.AF_INET6


class LocalAdminHandler(http.server.BaseHTTPRequestHandler):
    server_version = "P2PTunnelAdmin/2.0"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def client_allowed(self) -> bool:
        if bool(cfg("web.allow_remote", False)):
            return True
        try:
            return ipaddress.ip_address(str(self.client_address[0])).is_loopback
        except ValueError:
            return False

    def send_headers(
        self,
        status: int,
        content_type: str,
        length: int,
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()

    def send_bytes(
        self,
        status: int,
        payload: bytes,
        content_type: str,
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_headers(status, content_type, len(payload), extra)
        with contextlib.suppress(
            BrokenPipeError,
            ConnectionResetError,
            ConnectionAbortedError,
            socket.timeout,
            OSError,
        ):
            self.wfile.write(payload)

    def send_json(self, status: int, value: Any) -> None:
        self.send_bytes(
            status,
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def redirect(self, location: str, cookie: str | None = None) -> None:
        headers = {"Location": location}
        if cookie:
            headers["Set-Cookie"] = cookie
        self.send_bytes(303, b"", "text/plain; charset=utf-8", headers)

    def read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length < 0 or length > int(cfg("web.request_body_limit", 131072)):
            raise ValueError("request body too large")
        return self.rfile.read(length) if length else b""

    def read_json(self) -> dict[str, Any]:
        body = self.read_body()
        if not body:
            return {}
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def session(self) -> tuple[str | None, dict[str, Any] | None]:
        return get_web_session(str(self.headers.get("Cookie", "")))

    def require_auth(self, *, csrf: bool) -> tuple[str | None, dict[str, Any] | None]:
        token, session = self.session()
        if not session:
            self.send_json(401, {"ok": False, "message": "需要登录"})
            return None, None
        if csrf:
            supplied = str(self.headers.get("X-CSRF-Token", ""))
            if not supplied or not hmac.compare_digest(supplied, str(session.get("csrf", ""))):
                self.send_json(403, {"ok": False, "message": "CSRF校验失败"})
                return None, None
        return token, session

    def do_GET(self) -> None:
        if not self.client_allowed():
            self.send_bytes(403, b"Forbidden", "text/plain; charset=utf-8")
            return
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/health":
            self.send_json(200, {"ok": True, "auth_required": True, "state": get_cached_status_snapshot().get("state")})
            return
        token, session = self.session()
        if path == "/":
            page = dashboard_page(str(session.get("csrf"))) if session else login_page()
            self.send_bytes(200, page, "text/html; charset=utf-8")
            return
        if not session:
            self.send_json(401, {"ok": False, "message": "需要登录"})
            return
        if path == "/api/status":
            self.send_json(200, get_cached_status_snapshot())
            return
        if path == "/api/diagnostics":
            self.send_bytes(200, diagnostic_text().encode("utf-8"), "text/plain; charset=utf-8")
            return
        if path == "/api/config":
            self.send_json(200, CONFIG_MANAGER.sanitized())
            return
        if path == "/api/log":
            log_path = JSON_LOGGER.active_path
            if not log_path or not log_path.exists():
                self.send_json(404, {"ok": False, "message": "当前日志文件不存在"})
                return
            try:
                payload = log_path.read_bytes()
            except OSError as exc:
                self.send_json(500, {"ok": False, "message": str(exc)})
                return
            self.send_bytes(
                200,
                payload,
                "application/x-ndjson; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="{log_path.name}"'},
            )
            return
        self.send_json(404, {"ok": False, "message": "Not found"})

    def do_POST(self) -> None:
        if not self.client_allowed():
            self.send_json(403, {"ok": False, "message": "客户端不允许访问"})
            return
        path = urllib.parse.urlsplit(self.path).path
        client = str(self.client_address[0])
        if path == "/login":
            if web_login_rate_limited(client):
                self.send_bytes(429, login_page("登录失败次数过多，请稍后再试。"), "text/html; charset=utf-8")
                return
            try:
                form = urllib.parse.parse_qs(
                    self.read_body().decode("utf-8", "replace"), keep_blank_values=True
                )
                supplied = (form.get("password") or [""])[0]
            except Exception as exc:
                self.send_bytes(400, login_page(str(exc)), "text/html; charset=utf-8")
                return
            if not hmac.compare_digest(
                str(supplied).encode("utf-8"), str(cfg("web.password", "")).encode("utf-8")
            ):
                record_web_login_failure(client)
                log_event("web_login_failed", level="WARNING", message="Web login failed", client=client)
                self.send_bytes(401, login_page("密码错误。"), "text/html; charset=utf-8")
                return
            with WEB_LOGIN_LOCK:
                WEB_LOGIN_FAILURES.pop(client, None)
            token, _ = new_web_session()
            cookie = (
                f"{WEB_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; "
                f"Max-Age={int(float(cfg('web.session_ttl', 86400.0)))}"
            )
            self.redirect("/", cookie)
            return
        token, session = self.require_auth(csrf=True)
        if not session:
            return
        if path == "/logout":
            with WEB_SESSION_LOCK:
                if token:
                    WEB_SESSIONS.pop(token, None)
            cookie = f"{WEB_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            self.redirect("/", cookie)
            return
        try:
            body = self.read_json()
        except Exception as exc:
            self.send_json(400, {"ok": False, "message": str(exc)})
            return
        try:
            if path.startswith("/api/actions/"):
                self.handle_general_action(path.rsplit("/", 1)[-1])
                return
            if path == "/api/peer-action":
                self.run_coroutine(
                    f"peer:{body.get('peer_id')}:{body.get('action')}",
                    peer_action(str(body.get("peer_id", "")), str(body.get("action", ""))),
                    success="节点操作完成",
                )
                return
            if path == "/api/session-close":
                self.run_coroutine(
                    "session-close",
                    close_business_session(
                        str(body.get("peer_id", "")).upper(), int(body.get("session_id", 0))
                    ),
                    success="会话已关闭",
                )
                return
            if path == "/api/forwards/save":
                self.run_coroutine(
                    "forward-save",
                    FORWARD_MANAGER.save_rule(dict(body.get("rule", {}) or {})),
                    success="转发规则已保存并应用",
                )
                return
            if path == "/api/forwards/delete":
                self.run_coroutine(
                    "forward-delete",
                    FORWARD_MANAGER.delete_rule(
                        str(body.get("id", "")), force=bool(body.get("force", False))
                    ),
                    success="转发规则已删除",
                )
                return
            if path == "/api/forwards/toggle":
                self.run_coroutine(
                    "forward-toggle",
                    FORWARD_MANAGER.toggle_rule(
                        str(body.get("id", "")), bool(body.get("enabled", True))
                    ),
                    success="转发规则状态已更新",
                )
                return
            if path == "/api/forwards/restart":
                self.run_coroutine(
                    "forward-restart",
                    FORWARD_MANAGER.restart_rule(str(body.get("id", ""))),
                    success="转发监听已重启",
                )
                return
            if path == "/api/settings":
                self.run_coroutine(
                    "hot-settings",
                    update_hot_tunnel_settings(body),
                    success="连接设置已保存并立即生效",
                )
                return
            self.send_json(404, {"ok": False, "message": "Not found"})
        except Exception as exc:
            self.send_json(400, {"ok": False, "message": f"{type(exc).__name__}: {exc}"})

    def handle_general_action(self, action: str) -> None:
        if action == "shutdown":
            request_application_shutdown("web", restart=False)
            self.send_json(200, {"ok": True, "message": "程序正在安全退出"})
            return
        if action == "restart":
            request_application_shutdown("web", restart=True)
            self.send_json(200, {"ok": True, "message": "程序正在安全重启"})
            return
        actions: dict[str, tuple[Awaitable[Any], str]] = {
            "reconnect-signal": (force_signal_reconnect(), "已请求重连信令"),
            "rediscover": (discover_public_addresses(), "公网地址发现已完成"),
            "recover-all": (recover_all_peers(), "隧道恢复任务已提交"),
            "reload-config": (reload_configuration(), "配置已重载"),
            "reload-forwards": (reload_forwards_only(), "转发规则已重载"),
            "save-state": (persist_reconnect_memory(), "恢复状态已保存"),
        }
        item = actions.get(action)
        if not item:
            self.send_json(404, {"ok": False, "message": "未知管理操作"})
            return
        self.run_coroutine(action, item[0], success=item[1])

    def run_coroutine(self, name: str, coroutine: Awaitable[Any], *, success: str) -> None:
        if not CORE_LOOP or CORE_LOOP.is_closed() or not CORE_MAIN_TASK or CORE_MAIN_TASK.done():
            if hasattr(coroutine, "close"):
                coroutine.close()  # type: ignore[attr-defined]
            self.send_json(503, {"ok": False, "message": "网络核心未运行"})
            return
        with WEB_ACTION_LOCK:
            previous = WEB_ACTION_FUTURES.get(name)
            if previous and not previous.done():
                if hasattr(coroutine, "close"):
                    coroutine.close()  # type: ignore[attr-defined]
                self.send_json(409, {"ok": False, "message": "相同操作正在执行"})
                return
            future = asyncio.run_coroutine_threadsafe(coroutine, CORE_LOOP)
            WEB_ACTION_FUTURES[name] = future

            def cleanup(done: concurrent.futures.Future[Any], target: str = name) -> None:
                with WEB_ACTION_LOCK:
                    if WEB_ACTION_FUTURES.get(target) is done:
                        WEB_ACTION_FUTURES.pop(target, None)
                with contextlib.suppress(Exception):
                    done.result()

            future.add_done_callback(cleanup)
        try:
            result = future.result(timeout=float(cfg("web.action_timeout", 20.0)))
            response: dict[str, Any] = {"ok": True, "message": success}
            if isinstance(result, list) and result:
                response["message"] += "；部分修改需重启"
                response["restart_required"] = result
            elif isinstance(result, str) and result:
                response["message"] = result
            self.send_json(200, response)
        except concurrent.futures.TimeoutError:
            self.send_json(202, {"ok": True, "message": "操作已提交，仍在网络核心中执行"})
        except Exception as exc:
            self.send_json(500, {"ok": False, "message": f"{type(exc).__name__}: {exc}"})


def start_web_server() -> bool:
    global WEB_SERVER, WEB_THREAD, WEB_ENDPOINT, WEB_BOUND_HOST, WEB_BOUND_PORT
    if not bool(cfg("web.enabled", True)):
        return False
    host = str(cfg("web.host", "127.0.0.1"))
    ports = [int(cfg("web.port", 32001))]
    if bool(cfg("web.auto_port", True)) and ports[0] != 0:
        ports.append(0)
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None
    server_class = LocalAdminServerV6 if host_ip and host_ip.version == 6 else LocalAdminServer
    last_error: BaseException | None = None
    for port in ports:
        try:
            WEB_SERVER = server_class((host, port), LocalAdminHandler)
            WEB_BOUND_HOST = str(WEB_SERVER.server_address[0])
            WEB_BOUND_PORT = int(WEB_SERVER.server_address[1])
            display_host = "127.0.0.1" if host in {"0.0.0.0", "localhost"} else host
            if ":" in display_host and not display_host.startswith("["):
                display_host = f"[{display_host}]"
            WEB_ENDPOINT = f"http://{display_host}:{WEB_BOUND_PORT}/"
            break
        except OSError as exc:
            last_error = exc
            WEB_SERVER = None
    if not WEB_SERVER:
        add_event(
            f"Web管理服务启动失败：{last_error}",
            level="ERROR",
            event_name="web_start_failed",
        )
        return False
    server = WEB_SERVER

    def worker() -> None:
        try:
            add_event(f"Web管理地址：{WEB_ENDPOINT}", event_name="web_started")
            server.serve_forever(poll_interval=0.4)
        except Exception as exc:
            if not APP_SHUTTING_DOWN:
                log_event(
                    "web_server_crashed",
                    level="ERROR",
                    message="Web management server crashed",
                    error=exc,
                    include_traceback=True,
                )

    WEB_THREAD = threading.Thread(target=worker, name="local-web-admin", daemon=False)
    WEB_THREAD.start()
    publish_status_snapshot()
    return True


def stop_web_server() -> None:
    global WEB_SERVER, WEB_THREAD
    server, thread = WEB_SERVER, WEB_THREAD
    WEB_SERVER = None
    if server:
        with contextlib.suppress(Exception):
            server.shutdown()
        with contextlib.suppress(Exception):
            server.server_close()
    if thread and thread is not threading.current_thread():
        thread.join(timeout=5.0)
    WEB_THREAD = None


def open_management_page() -> None:
    if not WEB_ENDPOINT:
        return
    try:
        webbrowser.open(WEB_ENDPOINT, new=2)
    except Exception as exc:
        log_event("web_open_failed", level="ERROR", message="Cannot open management page", error=exc)


# =============================================================================
# Windows tray, platform integration and process lifecycle
# =============================================================================

SHUTDOWN_LOCK = threading.Lock()
ORIGINAL_CLI_ARGS: list[str] = []


@dataclass(frozen=True)
class RuntimeEnvironment:
    platform: str
    is_windows: bool
    has_console: bool
    has_display: bool
    browser_available: bool
    tray_available: bool
    selected_mode: str


RUNTIME_ENVIRONMENT: RuntimeEnvironment | None = None


def module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def detect_runtime_environment() -> RuntimeEnvironment:
    requested = str(cfg("management.mode", "AUTO")).upper()
    is_windows = os.name == "nt"
    has_display = bool(
        is_windows
        or sys.platform == "darwin"
        or os.environ.get("DISPLAY")
        or os.environ.get("WAYLAND_DISPLAY")
    )
    try:
        webbrowser.get()
        browser_available = True
    except Exception:
        browser_available = False
    tray_available = bool(
        is_windows
        and bool(cfg("management.tray_enabled", True))
        and module_available("pystray")
        and module_available("PIL")
    )
    if requested == "AUTO":
        selected = "TRAY_WEB" if tray_available else "WEB"
    elif requested == "TRAY_WEB":
        selected = "TRAY_WEB" if tray_available else "WEB"
    else:
        selected = requested
    return RuntimeEnvironment(
        platform=sys.platform,
        is_windows=is_windows,
        has_console=RUNTIME_HAS_CONSOLE,
        has_display=has_display,
        browser_available=browser_available,
        tray_available=tray_available,
        selected_mode=selected,
    )


def acquire_single_instance() -> bool:
    global INSTANCE_MUTEX_HANDLE
    if os.name != "nt" or not bool(cfg("management.single_instance", True)):
        return True
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.CreateMutexW(None, False, f"Local\\P2PTunnelStable_{node_id()}")
    if not handle:
        raise ctypes.WinError()
    if kernel32.GetLastError() == 183:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        return False
    INSTANCE_MUTEX_HANDLE = handle
    return True


def release_single_instance() -> None:
    global INSTANCE_MUTEX_HANDLE
    if INSTANCE_MUTEX_HANDLE and os.name == "nt":
        with contextlib.suppress(Exception):
            ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(INSTANCE_MUTEX_HANDLE))
        INSTANCE_MUTEX_HANDLE = None


def windows_launch_command() -> str:
    if getattr(sys, "frozen", False):
        args = [str(Path(sys.executable).resolve()), "--config", str(CONFIG_MANAGER.path)]
    else:
        executable = Path(sys.executable).resolve()
        pythonw = executable.with_name("pythonw.exe")
        if pythonw.exists():
            executable = pythonw
        args = [str(executable), str(Path(__file__).resolve()), "--config", str(CONFIG_MANAGER.path)]
    return subprocess.list2cmdline(args)


def autostart_task_name() -> str:
    return f"P2PTunnel_Stable_{node_id()}"


def no_window_flag() -> int:
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


def is_autostart_enabled() -> bool:
    if os.name != "nt":
        return False
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", autostart_task_name()],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=no_window_flag(),
        check=False,
    )
    return result.returncode == 0


def set_autostart_enabled(enabled: bool) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "仅支持 Windows"
    command = (
        [
            "schtasks",
            "/Create",
            "/TN",
            autostart_task_name(),
            "/TR",
            windows_launch_command(),
            "/SC",
            "ONLOGON",
            "/DELAY",
            "0000:15",
            "/RL",
            "LIMITED",
            "/F",
        ]
        if enabled
        else ["schtasks", "/Delete", "/TN", autostart_task_name(), "/F"]
    )
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=no_window_flag(),
            check=False,
        )
        message = (result.stdout or result.stderr or "").strip()
        return result.returncode == 0, message
    except Exception as exc:
        return False, str(exc)


def set_windows_clipboard_text(text: str) -> None:
    if os.name != "nt":
        raise RuntimeError("native clipboard is only available on Windows")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002
    data = (str(text) + "\0").encode("utf-16-le")
    opened = False
    for _ in range(8):
        if user32.OpenClipboard(None):
            opened = True
            break
        time.sleep(0.04)
    if not opened:
        raise ctypes.WinError(ctypes.get_last_error())
    handle = None
    transferred = False
    try:
        if not user32.EmptyClipboard():
            raise ctypes.WinError(ctypes.get_last_error())
        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
        if not handle:
            raise MemoryError("GlobalAlloc failed")
        kernel32.GlobalLock.restype = ctypes.c_void_p
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            ctypes.memmove(pointer, data, len(data))
        finally:
            kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(CF_UNICODETEXT, handle):
            raise ctypes.WinError(ctypes.get_last_error())
        transferred = True
    finally:
        user32.CloseClipboard()
        if handle and not transferred:
            kernel32.GlobalFree(handle)


def copy_management_address() -> None:
    with contextlib.suppress(Exception):
        set_windows_clipboard_text(WEB_ENDPOINT)


def copy_diagnostics_native() -> None:
    with contextlib.suppress(Exception):
        set_windows_clipboard_text(diagnostic_text())


def open_log_directory() -> None:
    JSON_LOGGER.initialize()
    directory = JSON_LOGGER.directory
    if not directory:
        return
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        os.startfile(str(directory))  # type: ignore[attr-defined]
    else:
        webbrowser.open(directory.as_uri())


def native_message_box(
    title: str, message: str, *, yes_no: bool = False, error: bool = False
) -> bool:
    if os.name != "nt":
        return False if yes_no else True
    flags = 0x00000004 if yes_no else 0x00000000
    flags |= 0x00000010 if error else 0x00000030
    if yes_no:
        flags |= 0x00000100
    flags |= 0x00010000 | 0x00040000
    try:
        result = ctypes.windll.user32.MessageBoxW(None, str(message), str(title), flags)
        return result == 6 if yes_no else result != 0
    except Exception:
        return False if yes_no else True


def request_application_shutdown(source: str, *, restart: bool) -> bool:
    global APP_SHUTTING_DOWN, RESTART_REQUESTED
    with SHUTDOWN_LOCK:
        if APP_SHUTTING_DOWN:
            if restart:
                RESTART_REQUESTED = True
            return False
        APP_SHUTTING_DOWN = True
        RESTART_REQUESTED = restart
    log_event(
        "application_shutdown_requested",
        message="Application restart requested" if restart else "Application shutdown requested",
        source=source,
    )
    if CORE_LOOP and CORE_MAIN_TASK and not CORE_MAIN_TASK.done():
        with contextlib.suppress(Exception):
            CORE_LOOP.call_soon_threadsafe(CORE_MAIN_TASK.cancel)
    icon = TRAY_ICON
    if icon:
        with contextlib.suppress(Exception):
            icon.stop()
    return True


def tray_image(state: str):
    from PIL import Image, ImageDraw

    colors = {
        "NORMAL": "#24b36b",
        "RELAY": "#e3a72f",
        "DEGRADED": "#e3a72f",
        "RECOVERING": "#3f8cff",
        "STARTING": "#3f8cff",
        "OFFLINE": "#e0525e",
        "ERROR": "#e0525e",
        "STOPPING": "#8c96a5",
    }
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((5, 5, 59, 59), radius=15, fill="#17222e")
    draw.ellipse((17, 17, 47, 47), fill=colors.get(state, "#8c96a5"))
    draw.ellipse((25, 25, 39, 39), fill="#ffffff")
    return image


def tray_state_label(_item: Any = None) -> str:
    snapshot = get_cached_status_snapshot()
    return (
        f"{datetime.now():%H:%M:%S} · {snapshot.get('state', '-')} · "
        f"在线 {snapshot.get('online_count', 0)} · 隧道 {len(snapshot.get('tunnels', []))}"
    )


def tray_signal_label(_item: Any = None) -> str:
    snapshot = get_cached_status_snapshot()
    return (
        f"信令：{snapshot.get('signal_endpoint', '-')}"
        if snapshot.get("signal_connected")
        else f"信令：已断开 {float(snapshot.get('signal_outage_seconds', 0)):.0f}s"
    )


def tray_tunnel_label(_item: Any = None) -> str:
    snapshot = get_cached_status_snapshot()
    tunnels = snapshot.get("tunnels", [])
    if not tunnels:
        return "隧道：无"
    return "隧道：" + ", ".join(
        f"{item['peer_id']} {item['kind_text']}" for item in tunnels[:4]
    )


def tray_submit(coroutine_factory: Callable[[], Awaitable[Any]], name: str) -> None:
    """Submit a tray action once; rapid repeated clicks are ignored."""
    with TRAY_ACTION_LOCK:
        if name in TRAY_ACTIONS_RUNNING:
            return
        TRAY_ACTIONS_RUNNING.add(name)

    def worker() -> None:
        coroutine: Awaitable[Any] | None = None
        try:
            if not CORE_LOOP or CORE_LOOP.is_closed():
                return
            coroutine = coroutine_factory()
            future = asyncio.run_coroutine_threadsafe(coroutine, CORE_LOOP)
            coroutine = None
            try:
                future.result(timeout=float(cfg("web.action_timeout", 20.0)))
            except concurrent.futures.TimeoutError:
                # The operation remains in the network core; the running flag
                # is cleared only when this tray worker returns.
                pass
        except Exception as exc:
            if coroutine is not None and hasattr(coroutine, "close"):
                with contextlib.suppress(Exception):
                    coroutine.close()  # type: ignore[attr-defined]
            log_event(
                "tray_action_failed",
                level="WARNING",
                message=f"Tray action {name} failed",
                error=exc,
            )
        finally:
            with TRAY_ACTION_LOCK:
                TRAY_ACTIONS_RUNNING.discard(name)

    threading.Thread(target=worker, name=f"tray-{name}", daemon=True).start()


def tray_toggle_autostart(_icon: Any = None, _item: Any = None) -> None:
    ok, message = set_autostart_enabled(not is_autostart_enabled())
    if not ok:
        threading.Thread(
            target=native_message_box,
            args=("开机自动启动", message or "设置失败"),
            kwargs={"error": True},
            daemon=True,
        ).start()


def tray_request_exit(icon: Any = None, _item: Any = None) -> None:
    if not TRAY_CONFIRM_LOCK.acquire(blocking=False):
        return

    def worker() -> None:
        try:
            if native_message_box(
                "退出 P2P Tunnel",
                "退出后，本地转发和活动隧道都会断开。\n确定退出吗？",
                yes_no=True,
            ):
                request_application_shutdown("tray", restart=False)
        finally:
            TRAY_CONFIRM_LOCK.release()

    threading.Thread(target=worker, name="tray-exit-confirm", daemon=False).start()


def tray_request_restart(icon: Any = None, _item: Any = None) -> None:
    if not TRAY_CONFIRM_LOCK.acquire(blocking=False):
        return

    def worker() -> None:
        try:
            if native_message_box(
                "重启 P2P Tunnel", "确定安全重启程序并重新加载全部配置吗？", yes_no=True
            ):
                request_application_shutdown("tray", restart=True)
        finally:
            TRAY_CONFIRM_LOCK.release()

    threading.Thread(target=worker, name="tray-restart-confirm", daemon=False).start()


def build_tray_icon():
    import pystray

    menu = pystray.Menu(
        pystray.MenuItem(tray_state_label, None, enabled=False),
        pystray.MenuItem(tray_signal_label, None, enabled=False),
        pystray.MenuItem(tray_tunnel_label, None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("打开管理页面", lambda icon, item: open_management_page(), default=True),
        pystray.MenuItem("复制管理地址", lambda icon, item: copy_management_address()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "重新连接信令",
            lambda icon, item: tray_submit(force_signal_reconnect, "reconnect-signal"),
        ),
        pystray.MenuItem(
            "重新发现公网地址",
            lambda icon, item: tray_submit(discover_public_addresses, "rediscover"),
        ),
        pystray.MenuItem(
            "恢复全部断开隧道",
            lambda icon, item: tray_submit(recover_all_peers, "recover-all"),
        ),
        pystray.MenuItem(
            "重载配置",
            lambda icon, item: tray_submit(reload_configuration, "reload-config"),
        ),
        pystray.MenuItem(
            "重载转发规则",
            lambda icon, item: tray_submit(reload_forwards_only, "reload-forwards"),
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("打开日志目录", lambda icon, item: open_log_directory()),
        pystray.MenuItem("复制诊断信息", lambda icon, item: copy_diagnostics_native()),
        pystray.MenuItem(
            "开机自动启动", tray_toggle_autostart, checked=lambda item: is_autostart_enabled()
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("安全重启", tray_request_restart),
        pystray.MenuItem("退出程序", tray_request_exit),
    )
    return pystray.Icon(
        f"p2p_stable_{node_id()}",
        tray_image("STARTING"),
        f"P2P Tunnel {node_id()}",
        menu,
    )


def tray_monitor(icon: Any) -> None:
    last_state = ""
    while not APP_SHUTTING_DOWN:
        snapshot = get_cached_status_snapshot()
        try:
            state = str(snapshot.get("state", "STARTING"))
            if state != last_state:
                icon.icon = tray_image(state)
                last_state = state
            tunnels = snapshot.get("tunnels", [])
            kind = tunnels[0]["kind_text"] if len(tunnels) == 1 else f"{len(tunnels)}条隧道"
            icon.title = (
                f"P2P {node_id()} · {state} · 在线 {snapshot.get('online_count', 0)} · {kind}"
            )
            icon.update_menu()
        except Exception:
            pass
        time.sleep(float(cfg("management.tray_refresh_interval", 2.0)))


# =============================================================================
# Async supervision, startup and shutdown
# =============================================================================


async def supervise_task(name: str, factory: Callable[[], Awaitable[Any]]) -> None:
    failures = 0
    while not APP_SHUTTING_DOWN:
        try:
            await factory()
            if APP_SHUTTING_DOWN:
                return
            raise RuntimeError(f"background task {name} returned unexpectedly")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failures += 1
            delay = min(60.0, 3.0 * (2 ** min(failures - 1, 4)))
            add_event(
                f"后台任务 {name} 异常，将在 {delay:.0f}s 后重启：{type(exc).__name__}: {exc}",
                level="ERROR",
                event_name="background_task_crashed",
            )
            await asyncio.sleep(delay)


async def terminal_status_loop() -> None:
    first = True
    while not APP_SHUTTING_DOWN:
        await asyncio.sleep(3.0)
        if not RUNTIME_HAS_CONSOLE:
            continue
        snapshot = build_status_snapshot()
        width = max(72, min(100, shutil.get_terminal_size((88, 24)).columns))
        lines = [
            "=" * width,
            clip_text(
                f"P2P Tunnel {node_id()} · {snapshot['state']} · {snapshot['current_time']}",
                width,
            ),
            "=" * width,
            f"Signal: {'connected' if snapshot['signal_connected'] else 'offline'} "
            f"{snapshot['signal_endpoint']}  RTT={snapshot['signal_rtt_ms'] or '-'}",
            "Tunnels: " + (", ".join(str(t["peer_id"]) + ":" + str(t["kind_text"]) for t in snapshot["tunnels"]) or "-"),
            f"Forwards: {len(snapshot['forwards'])}  Sessions: {len(snapshot['sessions'])}",
            f"Traffic: {human_bytes(snapshot['upload_bps'])}/s up  {human_bytes(snapshot['download_bps'])}/s down",
            f"Web: {WEB_ENDPOINT or '-'}",
            "-" * width,
        ]
        lines.extend(snapshot["recent_events"][:8])
        output = "\n".join(clip_text(line, width) for line in lines)
        if first:
            print("\x1b[2J", end="")
            first = False
        print("\x1b[H" + output + "\x1b[J", end="", flush=True)


async def async_main() -> None:
    global APP_READY, APP_SHUTTING_DOWN, FORWARD_MANAGER
    APP_SHUTTING_DOWN = False
    add_event(
        f"节点启动：{node_id()} {node_name()}，模式={cfg('tunnel.mode')}，策略={cfg('tunnel.punch_policy')}",
        event_name="application_start",
    )
    await start_p2p_listeners()
    await discover_public_addresses()
    FORWARD_MANAGER = ForwardManager()
    await FORWARD_MANAGER.start_all(cfg("forwards", []))
    APP_READY = True
    publish_status_snapshot()

    task_specs: list[tuple[str, Callable[[], Awaitable[Any]]]] = [
        ("signal", signal_connection_loop),
        ("discovery", discovery_loop),
        ("preconnect", preconnect_loop),
        ("relay-upgrade", relay_upgrade_loop),
        ("udp-cleanup", udp_cleanup_loop),
        ("recovery-cleanup", recovery_cleanup_loop),
        ("status-snapshot", status_snapshot_loop),
    ]
    if RUNTIME_ENVIRONMENT and RUNTIME_ENVIRONMENT.selected_mode == "CONSOLE":
        task_specs.append(("terminal-ui", terminal_status_loop))
    tasks = [
        asyncio.create_task(supervise_task(name, factory), name=f"supervisor:{name}")
        for name, factory in task_specs
    ]
    tasks.append(asyncio.create_task(startup_recovery_loop(), name="startup-recovery"))
    try:
        await asyncio.gather(*tasks)
    finally:
        APP_SHUTTING_DOWN = True
        APP_READY = False
        add_event("开始安全关闭网络核心", event_name="application_shutdown_started")
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for task in list(PRECONNECT_TASKS.values()) + list(DIRECT_RECONNECT_TASKS.values()) + list(RELAY_TASKS.values()):
            task.cancel()
        await asyncio.gather(
            *list(PRECONNECT_TASKS.values()),
            *list(DIRECT_RECONNECT_TASKS.values()),
            *list(RELAY_TASKS.values()),
            return_exceptions=True,
        )
        if RECONNECT_MEMORY_SAVE_TASK and not RECONNECT_MEMORY_SAVE_TASK.done():
            RECONNECT_MEMORY_SAVE_TASK.cancel()
            await asyncio.gather(RECONNECT_MEMORY_SAVE_TASK, return_exceptions=True)
        with contextlib.suppress(Exception):
            await persist_reconnect_memory()
        if globals().get("FORWARD_MANAGER"):
            await FORWARD_MANAGER.shutdown()
        for tunnel in list(ACTIVE_TUNNELS.values()) + list(DRAINING_TUNNELS):
            await tunnel.close("shutdown")
        for server in P2P_SERVERS:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in P2P_SERVERS), return_exceptions=True)
        P2P_SERVERS.clear()
        writer = SIGNAL_WRITER
        if writer:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        publish_status_snapshot()
        add_event("网络核心已安全关闭", event_name="application_shutdown_complete")


def asyncio_exception_handler(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
    error = context.get("exception")
    log_event(
        "asyncio_unhandled_exception",
        level="ERROR",
        message=str(context.get("message") or "Unhandled asyncio exception"),
        error=error if isinstance(error, BaseException) else None,
        include_traceback=bool(error),
        task=str(context.get("task") or context.get("future") or ""),
    )


def core_thread_main() -> None:
    global CORE_LOOP, CORE_MAIN_TASK, LAST_FATAL_ERROR, APP_SHUTTING_DOWN
    loop: asyncio.AbstractEventLoop | None = None
    try:
        loop = asyncio.new_event_loop()
        CORE_LOOP = loop
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(asyncio_exception_handler)
        CORE_MAIN_TASK = loop.create_task(async_main(), name="node-main")
        loop.run_until_complete(CORE_MAIN_TASK)
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        LAST_FATAL_ERROR = f"{type(exc).__name__}: {exc}"
        log_event(
            "application_fatal_error",
            level="CRITICAL",
            message="Network core stopped unexpectedly",
            error=exc,
            include_traceback=True,
        )
    finally:
        APP_SHUTTING_DOWN = True
        if loop and not loop.is_closed():
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
                with contextlib.suppress(Exception):
                    loop.run_until_complete(loop.shutdown_default_executor())
            finally:
                loop.close()
        CORE_STOPPED.set()
        if TRAY_ICON:
            with contextlib.suppress(Exception):
                TRAY_ICON.stop()


def install_exception_hooks() -> None:
    previous_sys = sys.excepthook

    def sys_hook(exc_type: Any, exc: BaseException, tb: Any) -> None:
        log_event(
            "uncaught_main_exception",
            level="CRITICAL",
            message="Unhandled main-thread exception",
            error=exc,
            include_traceback=True,
        )
        previous_sys(exc_type, exc, tb)

    sys.excepthook = sys_hook
    if hasattr(threading, "excepthook"):
        previous_thread = threading.excepthook

        def thread_hook(args: Any) -> None:
            log_event(
                "uncaught_thread_exception",
                level="CRITICAL",
                message=f"Unhandled exception in thread {getattr(args.thread, 'name', '-')}",
                error=args.exc_value,
                include_traceback=True,
            )
            previous_thread(args)

        threading.excepthook = thread_hook


def wait_for_core_thread() -> None:
    shutdown_started: float | None = None
    timeout = float(cfg("management.shutdown_timeout", 25.0))
    try:
        while CORE_THREAD and CORE_THREAD.is_alive():
            CORE_THREAD.join(timeout=0.5)
            if APP_SHUTTING_DOWN:
                shutdown_started = shutdown_started or time.monotonic()
                if time.monotonic() - shutdown_started > timeout:
                    log_event(
                        "forced_process_exit",
                        level="CRITICAL",
                        message="Safe shutdown timed out; forcing process termination",
                        timeout=timeout,
                    )
                    os._exit(2)
    except KeyboardInterrupt:
        request_application_shutdown("keyboard", restart=False)
        if CORE_THREAD:
            CORE_THREAD.join(timeout=timeout)


def restart_process() -> None:
    args = list(ORIGINAL_CLI_ARGS)
    if not args:
        args = ["--config", str(CONFIG_MANAGER.path)]
    if getattr(sys, "frozen", False):
        os.execv(sys.executable, [sys.executable, *args])
    os.execv(
        sys.executable,
        [sys.executable, str(Path(__file__).resolve()), *args],
    )


def run_application() -> None:
    global CORE_THREAD, TRAY_ICON, RUNTIME_ENVIRONMENT
    install_exception_hooks()
    JSON_LOGGER.initialize()
    RUNTIME_ENVIRONMENT = detect_runtime_environment()
    if not acquire_single_instance():
        log_event(
            "duplicate_instance",
            level="WARNING",
            message=f"Node {node_id()} is already running",
        )
        if os.name == "nt":
            native_message_box("P2P Tunnel", f"节点 {node_id()} 已经在运行。", error=True)
        return
    try:
        CORE_STOPPED.clear()
        CORE_THREAD = threading.Thread(target=core_thread_main, name="node-asyncio", daemon=False)
        CORE_THREAD.start()
        web_started = start_web_server()
        if web_started and RUNTIME_ENVIRONMENT.has_console:
            print(f"P2P Tunnel Web: {WEB_ENDPOINT}", flush=True)
        should_open = bool(cfg("web.open_browser_on_start", False))
        if (
            not RUNTIME_ENVIRONMENT.tray_available
            and bool(cfg("management.open_browser_when_tray_unavailable", False))
        ):
            should_open = True
        if (
            web_started
            and should_open
            and RUNTIME_ENVIRONMENT.selected_mode != "HEADLESS"
            and RUNTIME_ENVIRONMENT.has_display
            and RUNTIME_ENVIRONMENT.browser_available
        ):
            timer = threading.Timer(0.8, open_management_page)
            timer.daemon = True
            timer.start()
        if RUNTIME_ENVIRONMENT.selected_mode == "TRAY_WEB":
            try:
                TRAY_ICON = build_tray_icon()
                threading.Thread(
                    target=tray_monitor,
                    args=(TRAY_ICON,),
                    name="tray-monitor",
                    daemon=True,
                ).start()
                TRAY_ICON.run()
            except Exception as exc:
                log_event(
                    "tray_runtime_failed",
                    level="ERROR",
                    message="Windows tray failed; continuing in Web mode",
                    error=exc,
                    include_traceback=True,
                )
                TRAY_ICON = None
                if web_started:
                    threading.Thread(target=open_management_page, daemon=True).start()
                wait_for_core_thread()
            else:
                if CORE_THREAD and CORE_THREAD.is_alive() and not APP_SHUTTING_DOWN:
                    request_application_shutdown("tray_loop_ended", restart=False)
                wait_for_core_thread()
        else:
            wait_for_core_thread()
    finally:
        if CORE_THREAD and CORE_THREAD.is_alive():
            request_application_shutdown("runtime_finalizer", restart=False)
            wait_for_core_thread()
        stop_web_server()
        release_single_instance()
    if RESTART_REQUESTED:
        restart_process()


# =============================================================================
# CLI bootstrap and self-test
# =============================================================================


def resolve_config_path(args: argparse.Namespace) -> Path:
    if args.config:
        return Path(args.config).expanduser()
    if args.config_dir:
        return Path(args.config_dir).expanduser() / "config.json"
    base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    return base / "config.json"


def warn_config_permissions(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            print(
                f"Warning: {path} permissions are {oct(mode)}; 0o600 is recommended because it contains keys.",
                file=sys.stderr,
            )
    except OSError:
        pass


def run_self_test() -> None:
    global LOCAL_NODE_ID
    sample = {"type": "HELLO", "value": 123}
    sample["proof"] = proof_for(sample, shared_key_bytes())
    assert verify_proof(sample, shared_key_bytes())
    master = hashlib.sha256(b"self-test-master").digest()
    original = LOCAL_NODE_ID
    try:
        LOCAL_NODE_ID = "A"
        side_a = FrameCipher(master, "B")
        LOCAL_NODE_ID = "B"
        side_b = FrameCipher(master, "A")
        LOCAL_NODE_ID = "A"
        encrypted = side_a.encrypt(FT_TCP_DATA, 1, b"hello stable tunnel")
        LOCAL_NODE_ID = "B"
        assert side_b.decrypt(FT_TCP_DATA, 1, encrypted) == b"hello stable tunnel"
    finally:
        LOCAL_NODE_ID = original
    packed = FRAME_HEADER.pack(FRAME_MAGIC, PROTOCOL_VERSION, FT_PING, 0, 0, 8)
    assert FRAME_HEADER.unpack(packed)[0] == FRAME_MAGIC
    print("node-stable.py self-test: OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stable single-file P2P tunnel node")
    parser.add_argument("--config", help="path to config.json")
    parser.add_argument("--config-dir", help="directory containing config.json")
    parser.add_argument("--check-config", action="store_true", help="validate configuration and exit")
    parser.add_argument("--self-test", action="store_true", help="run local protocol self-tests and exit")
    parser.add_argument("--headless", action="store_true", help="force HEADLESS management mode")
    parser.add_argument("--no-tray", action="store_true", help="disable Windows tray for this run")
    parser.add_argument("--no-browser", action="store_true", help="do not automatically open a browser")
    parser.add_argument("--version", action="version", version=APPLICATION_VERSION)
    return parser.parse_args()


def bootstrap() -> int:
    global CONFIG_MANAGER, CONFIG, CONFIG_PATH
    global LOCAL_NODE_ID, LOCAL_NODE_NAME, LOCAL_SHARED_KEY, ORIGINAL_CLI_ARGS
    args = parse_args()
    ORIGINAL_CLI_ARGS = list(sys.argv[1:])
    CONFIG_PATH = resolve_config_path(args).resolve(strict=False)
    CONFIG_MANAGER = ConfigManager(CONFIG_PATH)
    try:
        CONFIG = CONFIG_MANAGER.load()
    except Exception as exc:
        print(f"Configuration error: {type(exc).__name__}: {exc}", file=sys.stderr)
        if os.name == "nt":
            native_message_box(
                "P2P Tunnel 配置错误",
                f"无法加载配置文件：\n{CONFIG_PATH}\n\n{type(exc).__name__}: {exc}",
                error=True,
            )
        return 2
    LOCAL_NODE_ID = str(CONFIG["node"]["id"])
    LOCAL_NODE_NAME = str(CONFIG["node"]["name"])
    LOCAL_SHARED_KEY = str(CONFIG["node"]["shared_key"]).encode("utf-8")
    if args.headless:
        CONFIG["management"]["mode"] = "HEADLESS"
    if args.no_tray:
        CONFIG["management"]["tray_enabled"] = False
        if CONFIG["management"]["mode"] == "TRAY_WEB":
            CONFIG["management"]["mode"] = "WEB"
    if args.no_browser:
        CONFIG["web"]["open_browser_on_start"] = False
        CONFIG["management"]["open_browser_when_tray_unavailable"] = False
    warn_config_permissions(CONFIG_PATH)
    if CONFIG_MANAGER.loaded_from_backup:
        print(f"Warning: primary config failed; loaded backup {CONFIG_MANAGER.backup_path}", file=sys.stderr)
    load_reconnect_memory()
    if args.check_config:
        print(f"Configuration OK: {CONFIG_PATH}")
        print(json.dumps(CONFIG_MANAGER.sanitized(), ensure_ascii=False, indent=2))
        return 0
    if args.self_test:
        run_self_test()
        return 0
    try:
        run_application()
        return 0
    except Exception as exc:
        log_event(
            "bootstrap_fatal_error",
            level="CRITICAL",
            message="Application bootstrap failed",
            error=exc,
            include_traceback=True,
        )
        print(f"Fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        if os.name == "nt":
            native_message_box(
                "P2P Tunnel 致命错误", f"{type(exc).__name__}: {exc}", error=True
            )
        return 1


if __name__ == "__main__":
    raise SystemExit(bootstrap())
