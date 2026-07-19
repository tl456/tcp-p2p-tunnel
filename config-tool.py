#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small helper for node-stable.py config.json files.

Examples:
    python config-tool.py init config.json --node-id A --node-name "A-Laptop" --server example.com
    python config-tool.py validate config.json
    python config-tool.py show config.json
    python config-tool.py set config.json web.password '"new-password"'
    python config-tool.py rotate-key config.json

The tool intentionally has no third-party dependencies.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import secrets
import shutil
import sys
from pathlib import Path
from typing import Any


TEMPLATE: dict[str, Any] = {
    "schema_version": 1,
    "node": {
        "id": "A",
        "name": "A-Computer",
        "shared_key": "CHANGE-THIS-FAMILY-SHARED-KEY-AT-LEAST-16-CHARS",
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
    "encryption": {"enabled": True, "algorithm": "HMAC_STREAM"},
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


def read_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("configuration root must be a JSON object")
    return value


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".tmp-{os.getpid()}-{secrets.token_hex(4)}")
    backup = path.with_suffix(path.suffix + ".bak")
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists():
            try:
                read_config(path)
            except Exception:
                pass
            else:
                shutil.copy2(path, backup)
        os.replace(temp, path)
        try:
            directory_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        try:
            temp.unlink()
        except OSError:
            pass


def validate(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    warnings: list[str] = []
    node = data.get("node", {})
    node_id = str(node.get("id", "")).upper()
    if len(node_id) != 1 or not ("A" <= node_id <= "Z"):
        errors.append("node.id must be one letter A-Z")
    if not str(node.get("name", "")).strip():
        errors.append("node.name cannot be empty")
    shared_key = str(node.get("shared_key", ""))
    if len(shared_key.encode("utf-8")) < 16:
        errors.append("node.shared_key must contain at least 16 UTF-8 bytes")
    if shared_key.startswith("CHANGE-"):
        warnings.append("node.shared_key is still a template value")

    server = data.get("server", {})
    if not str(server.get("address", "")).strip():
        errors.append("server.address cannot be empty")
    for key in ("signal_port", "relay_port"):
        try:
            port = int(server.get(key, 0))
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"server.{key} must be a port from 1 to 65535")

    tunnel = data.get("tunnel", {})
    if [str(x).upper() for x in tunnel.get("connection_order", [])] != [
        "IPV6_TCP",
        "IPV4_TCP",
        "RELAY",
    ]:
        errors.append("tunnel.connection_order must be IPv6 TCP, IPv4 TCP, Relay")
    if str(tunnel.get("mode", "AUTO")).upper() not in {
        "AUTO",
        "RELAY_ONLY",
        "IPV4_TCP_ONLY",
        "IPV6_TCP_ONLY",
    }:
        errors.append("tunnel.mode is invalid")

    web = data.get("web", {})
    if bool(web.get("enabled", True)) and not str(web.get("password", "")):
        errors.append("web.password cannot be empty")
    if str(web.get("password", "")) in {"CHANGE-ME", "10086"}:
        warnings.append("web.password is still simple/default")
    if str(web.get("host", "127.0.0.1")) not in {"127.0.0.1", "::1", "localhost"} and not bool(
        web.get("allow_remote", False)
    ):
        warnings.append("web.host is non-loopback but web.allow_remote is false")

    forwards = data.get("forwards", [])
    if not isinstance(forwards, list):
        errors.append("forwards must be a list")
    else:
        seen_ids: set[str] = set()
        seen_listeners: set[tuple[str, str, int]] = set()
        for index, rule in enumerate(forwards):
            prefix = f"forwards[{index}]"
            if not isinstance(rule, dict):
                errors.append(f"{prefix} must be an object")
                continue
            rule_id = str(rule.get("id", ""))
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", rule_id):
                errors.append(f"{prefix}.id is invalid")
            elif rule_id in seen_ids:
                errors.append(f"duplicate forward id: {rule_id}")
            seen_ids.add(rule_id)
            protocol = str(rule.get("protocol", "TCP")).upper()
            if protocol not in {"TCP", "UDP"}:
                errors.append(f"{prefix}.protocol is invalid")
            peer = str(rule.get("peer", "")).upper()
            if len(peer) != 1 or not ("A" <= peer <= "Z") or peer == node_id:
                errors.append(f"{prefix}.peer is invalid")
            try:
                listen_port = int(rule.get("listen_port", 0))
                target_port = int(rule.get("target_port", 0))
                if not 1 <= listen_port <= 65535 or not 1 <= target_port <= 65535:
                    raise ValueError
            except (TypeError, ValueError):
                errors.append(f"{prefix} contains an invalid port")
                continue
            if bool(rule.get("enabled", True)):
                listener = (protocol, str(rule.get("listen_host", "")), listen_port)
                if listener in seen_listeners:
                    errors.append(f"duplicate enabled listener: {listener}")
                seen_listeners.add(listener)

    if errors:
        raise ValueError("; ".join(errors))
    return warnings


def parse_json_value(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def set_dotted(data: dict[str, Any], key: str, value: Any) -> None:
    parts = key.split(".")
    target: dict[str, Any] = data
    for part in parts[:-1]:
        child = target.get(part)
        if not isinstance(child, dict):
            child = {}
            target[part] = child
        target = child
    target[parts[-1]] = value


def sanitize(data: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(data)
    value.setdefault("node", {})["shared_key"] = "*** hidden ***"
    value.setdefault("web", {})["password"] = "*** hidden ***"
    for peer in value.setdefault("runtime_memory", {}).setdefault("peers", {}).values():
        if isinstance(peer, dict):
            for generation in peer.get("generations", []) or []:
                if isinstance(generation, dict) and "secret" in generation:
                    generation["secret"] = "*** hidden ***"
    return value


def command_init(args: argparse.Namespace) -> None:
    path = Path(args.path)
    if path.exists() and not args.force:
        raise FileExistsError(f"{path} already exists; use --force to replace it")
    value = copy.deepcopy(TEMPLATE)
    value["node"]["id"] = args.node_id.upper()
    value["node"]["name"] = args.node_name
    value["server"]["address"] = args.server
    value["node"]["shared_key"] = args.shared_key or secrets.token_urlsafe(32)
    value["web"]["password"] = args.web_password or secrets.token_urlsafe(18)
    validate(value)
    atomic_write(path, value)
    print(f"Created: {path.resolve()}")
    print(f"Node shared key: {value['node']['shared_key']}")
    print(f"Web password: {value['web']['password']}")
    print("Use the same node shared key on every trusted node.")


def command_validate(args: argparse.Namespace) -> None:
    path = Path(args.path)
    warnings = validate(read_config(path))
    print(f"Configuration OK: {path.resolve()}")
    for warning in warnings:
        print(f"Warning: {warning}")


def command_show(args: argparse.Namespace) -> None:
    value = read_config(Path(args.path))
    print(json.dumps(value if args.full else sanitize(value), ensure_ascii=False, indent=2))


def command_set(args: argparse.Namespace) -> None:
    path = Path(args.path)
    value = read_config(path)
    set_dotted(value, args.key, parse_json_value(args.value))
    warnings = validate(value)
    atomic_write(path, value)
    print(f"Updated {args.key} in {path.resolve()}")
    for warning in warnings:
        print(f"Warning: {warning}")


def command_rotate_key(args: argparse.Namespace) -> None:
    path = Path(args.path)
    value = read_config(path)
    key = secrets.token_urlsafe(max(24, int(args.bytes)))
    value.setdefault("node", {})["shared_key"] = key
    # Existing reconnect generations are invalid after a key rotation.
    value["runtime_memory"] = {"updated_at": 0, "peers": {}}
    validate(value)
    atomic_write(path, value)
    print(f"Node shared key rotated in {path.resolve()}")
    print(key)
    print("Apply the same key to every trusted node, then restart all nodes.")


def command_password(args: argparse.Namespace) -> None:
    path = Path(args.path)
    value = read_config(path)
    password = args.password or secrets.token_urlsafe(18)
    value.setdefault("web", {})["password"] = password
    validate(value)
    atomic_write(path, value)
    print(f"Web password updated in {path.resolve()}")
    print(password)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create and maintain node-stable config.json")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a new config.json")
    init.add_argument("path")
    init.add_argument("--node-id", default="A")
    init.add_argument("--node-name", default="A-Computer")
    init.add_argument("--server", default="example.com")
    init.add_argument("--shared-key")
    init.add_argument("--web-password")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=command_init)

    validate_parser = sub.add_parser("validate", help="validate an existing config")
    validate_parser.add_argument("path")
    validate_parser.set_defaults(func=command_validate)

    show = sub.add_parser("show", help="show a config; secrets are hidden by default")
    show.add_argument("path")
    show.add_argument("--full", action="store_true")
    show.set_defaults(func=command_show)

    set_parser = sub.add_parser("set", help="set a dotted config key")
    set_parser.add_argument("path")
    set_parser.add_argument("key")
    set_parser.add_argument("value", help="JSON value or plain string")
    set_parser.set_defaults(func=command_set)

    rotate = sub.add_parser("rotate-key", help="generate a new shared node key")
    rotate.add_argument("path")
    rotate.add_argument("--bytes", type=int, default=32)
    rotate.set_defaults(func=command_rotate_key)

    password = sub.add_parser("set-web-password", help="set or generate a Web password")
    password.add_argument("path")
    password.add_argument("password", nargs="?")
    password.set_defaults(func=command_password)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        args.func(args)
        return 0
    except Exception as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
