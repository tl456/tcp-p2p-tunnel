#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P2P Tunnel stable signaling/relay server.

Security model
--------------
The server is a controlled but semi-trusted public coordinator. It does not
store the node shared key and cannot authenticate or decrypt node-to-node
traffic. Node identity is finally verified by the nodes during the tunnel
handshake.

Deployment
----------
Open TCP SIGNAL_PORT and RELAY_PORT on the cloud firewall/security group.
Python 3.10+ is recommended on Windows and Linux.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import logging
import logging.handlers
import os
import secrets
import signal
import socket
import struct
import sys
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# =============================================================================
# Server tuning area
# =============================================================================

APPLICATION_VERSION = "2.0-stable"
LISTEN_HOST_V6 = "::"
LISTEN_HOST_V4 = "0.0.0.0"
SIGNAL_PORT = 61009
RELAY_PORT = 61010

# Empty set means every A-Z node ID is accepted. Example: {"A", "B", "C"}.
ALLOWED_NODE_IDS: set[str] = set()
REPLACE_OLD_NODE = True
MAX_NODES = 26
MAX_RELAY_TUNNELS = 100
MAX_SIGNAL_MESSAGE = 2 * 1024 * 1024

PROTOCOL_VERSION = 2
REGISTER_TIMEOUT = 15.0
KEEPALIVE_INTERVAL = 20.0
KEEPALIVE_TIMEOUT = 65.0

PUNCH_START_DELAY = 1.20
PUNCH_TOKEN_TTL = 45
RELAY_TOKEN_TTL = 90
RELAY_BIND_TIMEOUT = 30.0
RELAY_REBIND_GRACE = 8.0

# Lightweight public-service abuse limits. These are not identity checks.
MAX_CONNECTIONS_PER_IP = 12
MAX_NEW_CONNECTIONS_PER_MINUTE = 60
MAX_REGISTRATIONS_PER_MINUTE = 30
MAX_MESSAGES_PER_SECOND = 30
MAX_CANDIDATES_PER_FAMILY = 32
MAX_NODE_NAME_LENGTH = 80

SOCKET_BACKLOG = 256
RELAY_COPY_CHUNK = 128 * 1024

UI_ENABLED = True
UI_REFRESH_INTERVAL = 2.0
UI_WIDTH = 88
UI_EVENT_LINES = 10
CONSOLE_DETAIL_LOG_ENABLED = True

LOG_ENABLED = True
LOG_DIRECTORY = "./logs"
LOG_LEVEL = "INFO"
LOG_MAX_FILE_SIZE_MB = 20
LOG_BACKUP_COUNT = 5


# =============================================================================
# Logging and helpers
# =============================================================================

STARTED_AT = time.time()
EVENTS: deque[str] = deque(maxlen=max(UI_EVENT_LINES, 50))
LOGGER = logging.getLogger("p2p-server")


def configure_logging() -> None:
    level = getattr(logging, str(LOG_LEVEL).upper(), logging.INFO)
    LOGGER.setLevel(level)
    LOGGER.handlers.clear()
    LOGGER.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    if LOG_ENABLED:
        try:
            directory = Path(os.path.expandvars(os.path.expanduser(LOG_DIRECTORY)))
            directory.mkdir(parents=True, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                directory / "server-stable.log",
                maxBytes=max(1, int(LOG_MAX_FILE_SIZE_MB)) * 1024 * 1024,
                backupCount=max(1, int(LOG_BACKUP_COUNT)),
                encoding="utf-8",
            )
            handler.setFormatter(formatter)
            handler.setLevel(level)
            LOGGER.addHandler(handler)
        except OSError as exc:
            print(f"Warning: cannot initialize server log file: {exc}", file=sys.stderr)

    if not UI_ENABLED:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        console.setLevel(level)
        LOGGER.addHandler(console)


def event(text: str, *, level: int = logging.INFO, **fields: Any) -> None:
    clean = str(text).replace("\r", " ").replace("\n", " ").strip()
    clock = time.strftime("%H:%M:%S")
    EVENTS.appendleft(f"{clock} {clean}")
    if fields:
        suffix = " ".join(f"{key}={value!r}" for key, value in fields.items())
        LOGGER.log(level, "%s | %s", clean, suffix)
    else:
        LOGGER.log(level, "%s", clean)
    if CONSOLE_DETAIL_LOG_ENABLED and not UI_ENABLED and not LOGGER.handlers:
        print(f"{clock} {clean}", flush=True)


def now() -> int:
    return int(time.time())


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


async def read_packet(reader: asyncio.StreamReader) -> dict[str, Any]:
    header = await reader.readexactly(4)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_SIGNAL_MESSAGE:
        raise ValueError(f"invalid packet size: {size}")
    payload = await reader.readexactly(size)
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("packet must be a JSON object")
    return value


async def write_packet(writer: asyncio.StreamWriter, value: dict[str, Any]) -> None:
    payload = canonical_json(value)
    if len(payload) > MAX_SIGNAL_MESSAGE:
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


def endpoint_host(endpoint: Any) -> str:
    if not endpoint:
        return ""
    return str(endpoint[0])


def format_endpoint(endpoint: Any) -> str:
    if not endpoint:
        return "-"
    host, port = str(endpoint[0]), int(endpoint[1])
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def normalized_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ip)
    except ValueError:
        return value


def valid_node_id(node_id: str) -> bool:
    return (
        len(node_id) == 1
        and "A" <= node_id <= "Z"
        and (not ALLOWED_NODE_IDS or node_id in ALLOWED_NODE_IDS)
    )


def sanitize_candidates(raw: Any, family: int) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for item in raw[:MAX_CANDIDATES_PER_FAMILY * 2]:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host", "")).strip()
        try:
            port = int(item.get("port", 0))
            ip = ipaddress.ip_address(host.split("%", 1)[0])
        except (TypeError, ValueError, OverflowError):
            continue
        if family == 4 and not isinstance(ip, ipaddress.IPv4Address):
            continue
        if family == 6 and not isinstance(ip, ipaddress.IPv6Address):
            continue
        if not 1 <= port <= 65535:
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        output.append(
            {
                "host": host,
                "port": port,
                "source": str(item.get("source", "node"))[:32],
                "priority": max(-10000, min(10000, int(item.get("priority", 50)))),
            }
        )
        if len(output) >= MAX_CANDIDATES_PER_FAMILY:
            break
    return output


# =============================================================================
# Rate limiting
# =============================================================================


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def allow(self, category: str, key: str, limit: int, window: float) -> bool:
        current = time.monotonic()
        records = self._records[(category, key)]
        cutoff = current - window
        while records and records[0] < cutoff:
            records.popleft()
        if len(records) >= limit:
            return False
        records.append(current)
        return True

    def cleanup(self) -> None:
        current = time.monotonic()
        for key, records in list(self._records.items()):
            while records and records[0] < current - 300:
                records.popleft()
            if not records:
                self._records.pop(key, None)


LIMITER = SlidingWindowLimiter()
IP_CONNECTION_COUNTS: dict[str, int] = defaultdict(int)


# =============================================================================
# Runtime state
# =============================================================================


@dataclass
class Node:
    node_id: str
    name: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    endpoint: tuple[Any, ...]
    session_id: str
    candidates4: list[dict[str, Any]]
    candidates6: list[dict[str, Any]]
    p2p_port: int
    tunnel_mode: str
    encryption: bool
    connected_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    message_times: deque[float] = field(default_factory=deque)

    async def send(self, message: dict[str, Any]) -> None:
        async with self.send_lock:
            await write_packet(self.writer, message)


@dataclass
class PunchAttempt:
    attempt_id: str
    node_a: str
    node_b: str
    family: int
    token: str
    starts_at: float
    expires_at: int


@dataclass
class RelaySlot:
    relay_id: str
    node_a: str
    node_b: str
    tokens: dict[str, str]
    tunnel_token: str
    expires_at: int
    requested_by: str
    endpoints: dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = field(
        default_factory=dict
    )
    endpoint_bound_at: dict[str, float] = field(default_factory=dict)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    close_reason: str = ""

    @property
    def pair_key(self) -> tuple[str, str]:
        return tuple(sorted((self.node_a, self.node_b)))  # type: ignore[return-value]


NODES: dict[str, Node] = {}
PUNCH_ATTEMPTS: dict[str, PunchAttempt] = {}
PUNCH_BY_PAIR: dict[tuple[str, str, int], str] = {}
RELAYS: dict[str, RelaySlot] = {}
RELAYS_BY_PAIR: dict[tuple[str, str], str] = {}
STATE_LOCK = asyncio.Lock()
SHUTDOWN_EVENT = asyncio.Event()
TOTAL_RELAY_UPLOAD = 0
TOTAL_RELAY_DOWNLOAD = 0


def public_node(node: Node) -> dict[str, Any]:
    return {
        "id": node.node_id,
        "name": node.name,
        "p2p_port": node.p2p_port,
        "mode": node.tunnel_mode,
        "encryption": node.encryption,
        "ipv4": list(node.candidates4),
        "ipv6": list(node.candidates6),
        "observed": {
            "host": normalized_ip(str(node.endpoint[0])),
            "port": int(node.endpoint[1]),
            "family": 6 if ":" in str(node.endpoint[0]) else 4,
        },
    }


async def broadcast_nodes() -> None:
    nodes = [public_node(node) for node in sorted(NODES.values(), key=lambda n: n.node_id)]
    message = {"type": "NODE_LIST", "nodes": nodes, "server_time": time.time()}
    stale: list[Node] = []
    for node in list(NODES.values()):
        try:
            await node.send(message)
        except Exception:
            stale.append(node)
    for node in stale:
        node.writer.close()


def node_message_allowed(node: Node) -> bool:
    current = time.monotonic()
    cutoff = current - 1.0
    while node.message_times and node.message_times[0] < cutoff:
        node.message_times.popleft()
    if len(node.message_times) >= MAX_MESSAGES_PER_SECOND:
        return False
    node.message_times.append(current)
    return True


# =============================================================================
# Signaling
# =============================================================================


async def register_node(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    message: dict[str, Any],
    *,
    challenge: str,
    session_id: str,
) -> Node:
    if message.get("type") != "REGISTER":
        raise ValueError("first client packet must be REGISTER")
    if int(message.get("version", 0)) != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if not secrets.compare_digest(str(message.get("challenge", "")), challenge):
        raise ValueError("registration challenge mismatch")

    node_id = str(message.get("node_id", "")).strip().upper()
    node_name = str(message.get("node_name", "")).strip()[:MAX_NODE_NAME_LENGTH]
    client_nonce = str(message.get("client_nonce", ""))
    p2p_port = int(message.get("p2p_port", 0) or 0)
    tunnel_mode = str(message.get("tunnel_mode", "AUTO")).upper()

    if not valid_node_id(node_id):
        raise ValueError("node ID is not allowed")
    if not node_name:
        raise ValueError("node name is empty")
    if len(client_nonce) < 16:
        raise ValueError("invalid client nonce")
    if not 0 <= p2p_port <= 65535:
        raise ValueError("invalid P2P port")
    if tunnel_mode not in {"AUTO", "RELAY_ONLY", "IPV6_TCP_ONLY", "IPV4_TCP_ONLY"}:
        raise ValueError("invalid tunnel mode")

    peername = writer.get_extra_info("peername")
    if not peername:
        raise ValueError("cannot determine signal endpoint")
    remote_ip = normalized_ip(str(peername[0]))
    if not LIMITER.allow("register", remote_ip, MAX_REGISTRATIONS_PER_MINUTE, 60.0):
        raise ConnectionError("registration rate limit exceeded")

    node = Node(
        node_id=node_id,
        name=node_name,
        reader=reader,
        writer=writer,
        endpoint=peername,
        session_id=session_id,
        candidates4=sanitize_candidates(message.get("ipv4", []), 4),
        candidates6=sanitize_candidates(message.get("ipv6", []), 6),
        p2p_port=p2p_port,
        tunnel_mode=tunnel_mode,
        encryption=bool(message.get("encryption", True)),
    )

    old_node: Node | None = None
    async with STATE_LOCK:
        if node_id in NODES:
            if not REPLACE_OLD_NODE:
                raise ValueError("NODE_ID_ALREADY_ONLINE")
            old_node = NODES[node_id]
        elif len(NODES) >= MAX_NODES:
            raise ValueError("maximum node count reached")
        NODES[node_id] = node

    if old_node:
        with contextlib.suppress(Exception):
            await old_node.send(
                {
                    "type": "SESSION_REPLACED",
                    "reason": "a newer connection registered with the same node ID",
                }
            )
        old_node.writer.close()
        event(f"{node_id} replaced an older signal session", level=logging.WARNING)

    initial_nodes = [
        public_node(item) for item in sorted(NODES.values(), key=lambda n: n.node_id)
    ]
    await node.send(
        {
            "type": "REGISTER_OK",
            "version": PROTOCOL_VERSION,
            "session_id": session_id,
            "server_time": time.time(),
            "observed": {
                "host": remote_ip,
                "port": int(peername[1]),
                "family": 6 if ":" in str(peername[0]) else 4,
            },
            "nodes": initial_nodes,
        }
    )
    event(f"{node_id} {node_name} online from {format_endpoint(peername)}")
    await broadcast_nodes()
    return node


async def send_connect_error(node: Node, peer_id: str, family: int, error: str) -> None:
    await node.send(
        {"type": "CONNECT_ERROR", "peer": peer_id, "family": family, "error": error}
    )


def family_compatible(node: Node, peer: Node, family: int) -> bool:
    if node.tunnel_mode == "RELAY_ONLY" or peer.tunnel_mode == "RELAY_ONLY":
        return False
    if family == 6:
        return node.tunnel_mode in {"AUTO", "IPV6_TCP_ONLY"} and peer.tunnel_mode in {
            "AUTO",
            "IPV6_TCP_ONLY",
        }
    return node.tunnel_mode in {"AUTO", "IPV4_TCP_ONLY"} and peer.tunnel_mode in {
        "AUTO",
        "IPV4_TCP_ONLY",
    }


async def handle_connect_request(node: Node, message: dict[str, Any]) -> None:
    peer_id = str(message.get("peer", "")).upper()
    family = int(message.get("family", 0) or 0)
    if peer_id == node.node_id or family not in (4, 6):
        return
    peer = NODES.get(peer_id)
    if not peer:
        await send_connect_error(node, peer_id, family, "peer offline")
        return
    if not family_compatible(node, peer, family):
        await send_connect_error(node, peer_id, family, "address family is disabled")
        return

    pair = tuple(sorted((node.node_id, peer_id)))
    pair_key = (pair[0], pair[1], family)
    existing_id = PUNCH_BY_PAIR.get(pair_key)
    existing = PUNCH_ATTEMPTS.get(existing_id or "")
    if existing and existing.expires_at >= now():
        # A simultaneous request from the other node reuses the same attempt.
        attempt = existing
    else:
        attempt = PunchAttempt(
            attempt_id=secrets.token_hex(12),
            node_a=pair[0],
            node_b=pair[1],
            family=family,
            token=secrets.token_hex(32),
            starts_at=time.time() + PUNCH_START_DELAY,
            expires_at=now() + PUNCH_TOKEN_TTL,
        )
        PUNCH_ATTEMPTS[attempt.attempt_id] = attempt
        PUNCH_BY_PAIR[pair_key] = attempt.attempt_id

    common = {
        "type": "PUNCH_PREPARE",
        "attempt_id": attempt.attempt_id,
        "token": attempt.token,
        "family": family,
        "starts_at": attempt.starts_at,
        "expires_at": attempt.expires_at,
        "server_time": time.time(),
        "requested_by": node.node_id,
    }
    await node.send({**common, "peer": public_node(peer)})
    await peer.send({**common, "peer": public_node(node)})
    event(f"{node.node_id}-{peer_id} IPv{family} TCP attempt prepared")


async def close_relay_slot(slot: RelaySlot, reason: str) -> None:
    if slot.done.is_set():
        return
    slot.close_reason = reason
    for _, writer in list(slot.endpoints.values()):
        writer.close()
    RELAYS.pop(slot.relay_id, None)
    if RELAYS_BY_PAIR.get(slot.pair_key) == slot.relay_id:
        RELAYS_BY_PAIR.pop(slot.pair_key, None)
    slot.done.set()


async def offer_relay(slot: RelaySlot) -> None:
    node_a = NODES.get(slot.node_a)
    node_b = NODES.get(slot.node_b)
    if not node_a or not node_b:
        await close_relay_slot(slot, "peer offline before relay offer")
        return
    await node_a.send(
        {
            "type": "RELAY_OFFER",
            "relay_id": slot.relay_id,
            "token": slot.tokens[slot.node_a],
            "tunnel_token": slot.tunnel_token,
            "expires_at": slot.expires_at,
            "peer": public_node(node_b),
            "requested_by": slot.requested_by,
        }
    )
    await node_b.send(
        {
            "type": "RELAY_OFFER",
            "relay_id": slot.relay_id,
            "token": slot.tokens[slot.node_b],
            "tunnel_token": slot.tunnel_token,
            "expires_at": slot.expires_at,
            "peer": public_node(node_a),
            "requested_by": slot.requested_by,
        }
    )


async def handle_relay_request(node: Node, message: dict[str, Any]) -> None:
    peer_id = str(message.get("peer", "")).upper()
    force_new = bool(message.get("force_new", False))
    if peer_id == node.node_id:
        return
    peer = NODES.get(peer_id)
    if not peer:
        await node.send({"type": "RELAY_ERROR", "peer": peer_id, "error": "peer offline"})
        return

    pair = tuple(sorted((node.node_id, peer_id)))
    existing_id = RELAYS_BY_PAIR.get(pair)
    existing = RELAYS.get(existing_id or "")
    if existing and not existing.done.is_set() and existing.expires_at >= now() and not force_new:
        await offer_relay(existing)
        event(f"{node.node_id}-{peer_id} existing relay offer repeated")
        return
    if existing and not existing.done.is_set():
        await close_relay_slot(existing, "replaced by a new relay request")

    if len(RELAYS) >= MAX_RELAY_TUNNELS:
        await node.send(
            {"type": "RELAY_ERROR", "peer": peer_id, "error": "relay capacity reached"}
        )
        return

    slot = RelaySlot(
        relay_id=secrets.token_hex(12),
        node_a=pair[0],
        node_b=pair[1],
        tokens={pair[0]: secrets.token_hex(32), pair[1]: secrets.token_hex(32)},
        tunnel_token=secrets.token_hex(32),
        expires_at=now() + RELAY_TOKEN_TTL,
        requested_by=node.node_id,
    )
    RELAYS[slot.relay_id] = slot
    RELAYS_BY_PAIR[pair] = slot.relay_id
    await offer_relay(slot)
    event(f"{node.node_id}-{peer_id} relay offered id={slot.relay_id[:8]}")


async def handle_signal_message(node: Node, message: dict[str, Any]) -> None:
    if not node_message_allowed(node):
        raise ConnectionError("signal message rate limit exceeded")
    message_type = str(message.get("type", ""))
    node.last_seen = time.time()

    if message_type == "PONG":
        return
    if message_type == "PING":
        await node.send(
            {
                "type": "PONG",
                "id": message.get("id"),
                "sent_at": message.get("sent_at"),
                "server_time": time.time(),
            }
        )
        return
    if message_type == "ENDPOINT_UPDATE":
        node.candidates4 = sanitize_candidates(message.get("ipv4", []), 4)
        node.candidates6 = sanitize_candidates(message.get("ipv6", []), 6)
        p2p_port = int(message.get("p2p_port", node.p2p_port) or 0)
        if not 0 <= p2p_port <= 65535:
            raise ValueError("invalid updated P2P port")
        node.p2p_port = p2p_port
        await broadcast_nodes()
        return
    if message_type == "CONNECT_REQUEST":
        await handle_connect_request(node, message)
        return
    if message_type == "RELAY_REQUEST":
        await handle_relay_request(node, message)
        return
    if message_type == "CLIENT_EVENT":
        # Optional short diagnostic supplied by a trusted local node. It is not
        # displayed as an authentication fact.
        text = str(message.get("message", ""))[:300]
        if text:
            event(f"{node.node_id} client event: {text}", level=logging.DEBUG)
        return


async def signal_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    configure_socket(writer)
    peername = writer.get_extra_info("peername")
    remote_ip = normalized_ip(endpoint_host(peername))
    node: Node | None = None
    challenge = secrets.token_hex(16)
    session_id = secrets.token_hex(12)

    try:
        if IP_CONNECTION_COUNTS[remote_ip] > MAX_CONNECTIONS_PER_IP:
            raise ConnectionError("too many connections from this IP")
        await write_packet(
            writer,
            {
                "type": "SERVER_CHALLENGE",
                "version": PROTOCOL_VERSION,
                "challenge": challenge,
                "session_id": session_id,
                "server_time": time.time(),
            },
        )
        first = await asyncio.wait_for(read_packet(reader), timeout=REGISTER_TIMEOUT)
        node = await register_node(
            reader, writer, first, challenge=challenge, session_id=session_id
        )
        while True:
            message = await read_packet(reader)
            await handle_signal_message(node, message)
    except asyncio.IncompleteReadError:
        pass
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        event(
            f"Signal client {format_endpoint(peername)} error: {type(exc).__name__}: {exc}",
            level=logging.WARNING,
        )
        with contextlib.suppress(Exception):
            await write_packet(
                writer,
                {
                    "type": "REGISTER_ERROR" if node is None else "ERROR",
                    "error": str(exc),
                },
            )
    finally:
        if node:
            async with STATE_LOCK:
                if NODES.get(node.node_id) is node:
                    NODES.pop(node.node_id, None)
            event(f"{node.node_id} offline")
            with contextlib.suppress(Exception):
                await broadcast_nodes()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


# =============================================================================
# Relay transport
# =============================================================================


async def relay_copy(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    slot: RelaySlot,
    direction: str,
) -> None:
    global TOTAL_RELAY_UPLOAD, TOTAL_RELAY_DOWNLOAD
    try:
        while True:
            data = await reader.read(RELAY_COPY_CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            if direction == "a_to_b":
                slot.bytes_a_to_b += len(data)
                TOTAL_RELAY_UPLOAD += len(data)
            else:
                slot.bytes_b_to_a += len(data)
                TOTAL_RELAY_DOWNLOAD += len(data)
    except (ConnectionError, OSError, asyncio.IncompleteReadError):
        pass
    finally:
        with contextlib.suppress(OSError, AttributeError):
            writer.write_eof()


async def run_relay(slot: RelaySlot) -> None:
    try:
        a_reader, a_writer = slot.endpoints[slot.node_a]
        b_reader, b_writer = slot.endpoints[slot.node_b]
        event(f"{slot.node_a}-{slot.node_b} relay paired id={slot.relay_id[:8]}")

        # RELAY_PAIRED is the final framed server packet. After both writes have
        # completed, the connection becomes a transparent node-to-node stream.
        await write_packet(
            a_writer,
            {"type": "RELAY_PAIRED", "relay_id": slot.relay_id, "peer": slot.node_b},
        )
        await write_packet(
            b_writer,
            {"type": "RELAY_PAIRED", "relay_id": slot.relay_id, "peer": slot.node_a},
        )
        slot.ready.set()
        await asyncio.gather(
            relay_copy(a_reader, b_writer, slot, "a_to_b"),
            relay_copy(b_reader, a_writer, slot, "b_to_a"),
        )
    except Exception as exc:
        slot.close_reason = f"relay failure: {type(exc).__name__}: {exc}"
        event(
            f"{slot.node_a}-{slot.node_b} relay failed: {type(exc).__name__}: {exc}",
            level=logging.WARNING,
        )
    finally:
        for _, writer in list(slot.endpoints.values()):
            writer.close()
        for _, writer in list(slot.endpoints.values()):
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        RELAYS.pop(slot.relay_id, None)
        if RELAYS_BY_PAIR.get(slot.pair_key) == slot.relay_id:
            RELAYS_BY_PAIR.pop(slot.pair_key, None)
        slot.done.set()
        event(
            f"{slot.node_a}-{slot.node_b} relay closed "
            f"A>B={human_bytes(slot.bytes_a_to_b)} B>A={human_bytes(slot.bytes_b_to_a)}"
        )


async def relay_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    configure_socket(writer)
    peername = writer.get_extra_info("peername")
    slot: RelaySlot | None = None
    node_id = ""
    try:
        bind = await asyncio.wait_for(read_packet(reader), timeout=RELAY_BIND_TIMEOUT)
        if bind.get("type") != "RELAY_BIND":
            raise ValueError("first relay packet must be RELAY_BIND")
        relay_id = str(bind.get("relay_id", ""))
        node_id = str(bind.get("node_id", "")).upper()
        token = str(bind.get("token", ""))
        slot = RELAYS.get(relay_id)
        if not slot:
            raise ValueError("relay not found")
        if now() > slot.expires_at:
            raise ValueError("relay offer expired")
        if node_id not in (slot.node_a, slot.node_b):
            raise ValueError("node is not part of this relay")
        if not secrets.compare_digest(token, slot.tokens.get(node_id, "")):
            raise ValueError("relay token mismatch")

        async with slot.lock:
            old = slot.endpoints.get(node_id)
            if old:
                _, old_writer = old
                old_age = time.time() - slot.endpoint_bound_at.get(node_id, 0)
                if not old_writer.is_closing() and old_age < RELAY_REBIND_GRACE:
                    raise ValueError("duplicate relay bind")
                old_writer.close()
            slot.endpoints[node_id] = (reader, writer)
            slot.endpoint_bound_at[node_id] = time.time()
            await write_packet(
                writer,
                {
                    "type": "RELAY_BIND_OK",
                    "relay_id": relay_id,
                    "peer": slot.node_b if node_id == slot.node_a else slot.node_a,
                    "expires_at": slot.expires_at,
                },
            )
            if len(slot.endpoints) < 2:
                await write_packet(
                    writer,
                    {
                        "type": "RELAY_WAITING",
                        "relay_id": relay_id,
                        "expires_at": slot.expires_at,
                    },
                )
            elif not slot.ready.is_set():
                # Only one handler creates the transparent copy task.
                asyncio.create_task(run_relay(slot), name=f"relay:{relay_id}")

        await slot.done.wait()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        event(
            f"Relay client {format_endpoint(peername)} error: {type(exc).__name__}: {exc}",
            level=logging.WARNING,
        )
        with contextlib.suppress(Exception):
            await write_packet(writer, {"type": "RELAY_ERROR", "error": str(exc)})
        if slot and not slot.ready.is_set():
            async with slot.lock:
                current = slot.endpoints.get(node_id)
                if current and current[1] is writer:
                    slot.endpoints.pop(node_id, None)
                    slot.endpoint_bound_at.pop(node_id, None)
    finally:
        if not slot or not slot.ready.is_set():
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


# =============================================================================
# Maintenance and UI
# =============================================================================


async def maintenance_loop() -> None:
    while not SHUTDOWN_EVENT.is_set():
        await asyncio.sleep(KEEPALIVE_INTERVAL)
        LIMITER.cleanup()
        current = time.time()

        stale: list[Node] = []
        for node in list(NODES.values()):
            if current - node.last_seen > KEEPALIVE_TIMEOUT:
                stale.append(node)
                continue
            try:
                await node.send(
                    {
                        "type": "PING",
                        "id": secrets.token_hex(4),
                        "sent_at": current,
                        "server_time": current,
                    }
                )
            except Exception:
                stale.append(node)
        for node in stale:
            node.writer.close()

        for attempt_id, attempt in list(PUNCH_ATTEMPTS.items()):
            if attempt.expires_at < now():
                PUNCH_ATTEMPTS.pop(attempt_id, None)
                key = (*tuple(sorted((attempt.node_a, attempt.node_b))), attempt.family)
                if PUNCH_BY_PAIR.get(key) == attempt_id:
                    PUNCH_BY_PAIR.pop(key, None)

        for relay_id, slot in list(RELAYS.items()):
            if not slot.ready.is_set() and slot.expires_at < now():
                await close_relay_slot(slot, "relay offer expired")


def human_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            return f"{amount:.1f}{unit}"
        amount /= 1024
    return f"{value}B"


def uptime_text() -> str:
    seconds = int(time.time() - STARTED_AT)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    prefix = f"{days}d " if days else ""
    return f"{prefix}{hours:02d}:{minutes:02d}:{seconds:02d}"


def display_width(text: str) -> int:
    return sum(
        2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        for char in str(text)
    )


def clip_text(text: str, max_width: int, suffix: str = "...") -> str:
    text = str(text)
    if display_width(text) <= max_width:
        return text
    if max_width <= 0:
        return ""
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


def pad_text(text: str, width: int) -> str:
    clipped = clip_text(text, width)
    return clipped + " " * max(0, width - display_width(clipped))


async def ui_loop() -> None:
    first = True
    while not SHUTDOWN_EVENT.is_set():
        await asyncio.sleep(UI_REFRESH_INTERVAL)
        if not UI_ENABLED:
            continue
        terminal_width = os.get_terminal_size().columns if sys.stdout.isatty() else UI_WIDTH
        width = max(64, min(UI_WIDTH, terminal_width))
        major = "=" * width
        minor = "-" * width
        lines = [
            major,
            clip_text(
                f"P2P Stable Signal / Relay Server   {time.strftime('%Y-%m-%d %H:%M:%S')}",
                width,
            ),
            major,
            f"Signal TCP : {SIGNAL_PORT}    Relay TCP : {RELAY_PORT}",
            f"Uptime     : {uptime_text()}    Nodes: {len(NODES)}/{MAX_NODES}    "
            f"Relays: {len(RELAYS)}/{MAX_RELAY_TUNNELS}",
            f"Model      : Semi-trusted coordinator; node shared key is not stored here",
            "",
            minor,
            "Online nodes",
            minor,
        ]
        if NODES:
            lines.append(
                f"{pad_text('ID', 4)}{pad_text('Name', 26)}{pad_text('Signal endpoint', 25)}Mode"
            )
            for node in sorted(NODES.values(), key=lambda item: item.node_id):
                age = int(max(0, time.time() - node.last_seen))
                lines.append(
                    clip_text(
                        f"{pad_text(node.node_id, 4)}{pad_text(node.name, 26)}"
                        f"{pad_text(format_endpoint(node.endpoint), 25)}"
                        f"{node.tunnel_mode}  seen {age}s",
                        width,
                    )
                )
        else:
            lines.append("- No client nodes online")

        lines.extend(["", minor, "Active relays", minor])
        if RELAYS:
            for slot in list(RELAYS.values()):
                state = "ACTIVE" if slot.ready.is_set() else f"WAIT {len(slot.endpoints)}/2"
                lines.append(
                    clip_text(
                        f"{slot.node_a}<->{slot.node_b} {state} id={slot.relay_id[:8]} "
                        f"A>B {human_bytes(slot.bytes_a_to_b)} B>A {human_bytes(slot.bytes_b_to_a)}",
                        width,
                    )
                )
        else:
            lines.append("- No active relays")

        lines.extend(
            [
                "",
                minor,
                "Traffic",
                minor,
                f"Relay upload {human_bytes(TOTAL_RELAY_UPLOAD)}    "
                f"Relay download {human_bytes(TOTAL_RELAY_DOWNLOAD)}",
            ]
        )
        if CONSOLE_DETAIL_LOG_ENABLED:
            lines.extend(["", minor, "Recent events", minor])
            lines.extend(clip_text(item, width) for item in list(EVENTS)[:UI_EVENT_LINES])
            if not EVENTS:
                lines.append("- No recent events")

        output = "\n".join(lines)
        if first:
            print("\x1b[2J", end="")
            first = False
        print("\x1b[H" + output + "\x1b[J", end="", flush=True)


async def connection_counted_client(
    callback: Any, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    peername = writer.get_extra_info("peername")
    remote_ip = normalized_ip(endpoint_host(peername))
    if not LIMITER.allow(
        "connection", remote_ip, MAX_NEW_CONNECTIONS_PER_MINUTE, 60.0
    ):
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return
    if IP_CONNECTION_COUNTS[remote_ip] >= MAX_CONNECTIONS_PER_IP:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return
    IP_CONNECTION_COUNTS[remote_ip] += 1
    try:
        await callback(reader, writer)
    finally:
        IP_CONNECTION_COUNTS[remote_ip] = max(0, IP_CONNECTION_COUNTS[remote_ip] - 1)
        if not IP_CONNECTION_COUNTS[remote_ip]:
            IP_CONNECTION_COUNTS.pop(remote_ip, None)


def listener_socket(host: str, port: int, family: int) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    sock.listen(SOCKET_BACKLOG)
    sock.setblocking(False)
    return sock


async def start_listener(callback: Any, host: str, port: int, family: int):
    try:
        sock = listener_socket(host, port, family)
        server = await asyncio.start_server(
            lambda reader, writer: connection_counted_client(callback, reader, writer),
            sock=sock,
            start_serving=True,
        )
        event(f"Listening on {format_endpoint((host, port))}")
        return server
    except OSError as exc:
        event(
            f"Cannot listen on {format_endpoint((host, port))}: {exc}",
            level=logging.ERROR,
        )
        return None


def validate_server_configuration() -> None:
    if not 1 <= SIGNAL_PORT <= 65535 or not 1 <= RELAY_PORT <= 65535:
        raise ValueError("invalid signal or relay port")
    if SIGNAL_PORT == RELAY_PORT:
        raise ValueError("signal and relay ports must be different")
    if MAX_NODES <= 0 or MAX_RELAY_TUNNELS <= 0:
        raise ValueError("invalid capacity limit")
    if KEEPALIVE_TIMEOUT <= KEEPALIVE_INTERVAL:
        raise ValueError("KEEPALIVE_TIMEOUT must exceed KEEPALIVE_INTERVAL")
    for node_id in ALLOWED_NODE_IDS:
        if len(node_id) != 1 or not ("A" <= node_id <= "Z"):
            raise ValueError(f"invalid allowed node ID: {node_id!r}")


async def async_main() -> None:
    validate_server_configuration()
    configure_logging()
    event(
        f"Server starting protocol={PROTOCOL_VERSION} signal={SIGNAL_PORT} relay={RELAY_PORT}"
    )

    servers: list[asyncio.AbstractServer] = []
    for callback, port in ((signal_client, SIGNAL_PORT), (relay_client, RELAY_PORT)):
        ipv6 = await start_listener(callback, LISTEN_HOST_V6, port, socket.AF_INET6)
        if ipv6:
            servers.append(ipv6)
        ipv4 = await start_listener(callback, LISTEN_HOST_V4, port, socket.AF_INET)
        if ipv4:
            servers.append(ipv4)

    if not servers:
        raise RuntimeError("no server listener could be started")

    loop = asyncio.get_running_loop()
    for signame in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, signame, None)
        if sig is not None:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(sig, SHUTDOWN_EVENT.set)

    tasks = [
        asyncio.create_task(maintenance_loop(), name="maintenance"),
        asyncio.create_task(ui_loop(), name="ui"),
    ]
    try:
        await SHUTDOWN_EVENT.wait()
    finally:
        event("Server shutdown requested")
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers), return_exceptions=True)
        for node in list(NODES.values()):
            node.writer.close()
        for slot in list(RELAYS.values()):
            await close_relay_slot(slot, "server shutdown")
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        event("Server stopped")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stable P2P signaling and relay server")
    parser.add_argument("--check", action="store_true", help="validate built-in settings and exit")
    parser.add_argument("--no-ui", action="store_true", help="disable terminal dashboard")
    parser.add_argument("--version", action="version", version=APPLICATION_VERSION)
    return parser.parse_args()


def main() -> int:
    global UI_ENABLED
    args = parse_args()
    if args.no_ui:
        UI_ENABLED = False
    if args.check:
        validate_server_configuration()
        print("server-stable.py configuration: OK")
        return 0
    try:
        asyncio.run(async_main())
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        configure_logging()
        event(f"Fatal server error: {type(exc).__name__}: {exc}", level=logging.CRITICAL)
        print(f"Fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
