# TCP P2P Tunnel

A lightweight personal TCP P2P tunneling and encrypted port-forwarding tool with a signaling server, TCP relay fallback, local Web management, persistent recovery, and an optional Windows tray.

## Connection order

1. IPv6 TCP direct connection
2. IPv4 TCP direct connection
3. TCP Relay fallback

When configured, an active Relay tunnel periodically retries IPv6 and IPv4 P2P. New sessions switch to a successful P2P tunnel while existing Relay sessions drain normally.

## Trust model

- The signaling server coordinates peers and Relay slots but does **not** possess the node shared key.
- Controlled nodes use the same shared key to authenticate one another and derive per-tunnel encryption material.
- A compromised signaling server may disrupt coordination or observe metadata, but it should not be able to authenticate as a node or decrypt tunnel payloads without the node key.

## Features

- IPv6 TCP → IPv4 TCP → Relay connection policy
- Preconnect and on-demand connection modes
- Peer-to-peer authentication with a shared node key
- Dependency-free lightweight encrypted framing
- TCP and UDP port forwarding over the established tunnel
- Runtime creation, editing, enabling, disabling, and deletion of forwards
- Signal-loss degraded mode and persistent direct-recovery memory
- Local Web dashboard with simple password authentication
- Windows tray, single-instance protection, and scheduled-task autostart
- Windows and Linux support
- Structured JSONL logging and diagnostics

## Files

- `server-stable.py` — signaling and TCP Relay server
- `node-stable.py` — node, tunnel, forwarding, recovery, Web UI, and tray runtime
- `node-stable-windows.pyw` — Windows no-console launcher
- `config-tool.py` — initialize, validate, and update node configuration
- `config.example.json` — safe public example; copy it to `config.json`
- `server-tuning-guide.txt` — server deployment and tuning notes

## Requirements

- Python 3.10 or newer is recommended.
- The core network and Web functions use the Python standard library.
- Optional Windows tray dependencies:

```powershell
py -m pip install pystray pillow
```

## Quick start

### 1. Start the public server

Open the configured TCP signal and Relay ports in the cloud firewall and operating-system firewall.

```bash
python3 server-stable.py --check
python3 server-stable.py --no-ui
```

### 2. Create a node configuration

```bash
cp config.example.json config.json
python config-tool.py validate config.json
```

Or generate one:

```bash
python config-tool.py init config.json \
  --node-id A \
  --node-name "Laptop" \
  --server your-server.example.com
```

All controlled nodes must use the same `node.shared_key`, but each node must use a different `node.id` and normally a different P2P listening port when multiple nodes run behind the same host.

### 3. Start a node

```bash
python node-stable.py --config config.json --check-config
python node-stable.py --config config.json --self-test
python node-stable.py --config config.json
```

The default Web interface is:

```text
http://127.0.0.1:32001/
```

On Windows, install the optional tray dependencies and launch `node-stable-windows.pyw`.

## Configuration safety

Never commit your real `config.json`. It contains the shared node key, Web password, private topology, and persistent recovery material. The included `.gitignore` excludes it by default.

Before publishing a screenshot, redact:

- Public and private IP addresses
- Device names
- Windows user paths
- Server domain names
- Attempt identifiers and recovery data when relevant

## Security limitations

This is a personal experimental project, not an audited VPN product. The built-in lightweight cipher is designed for controlled home devices and ease of deployment. For high-risk environments, use an independently audited protocol such as WireGuard or TLS.

The project does not guarantee traversal of every NAT, firewall, or carrier network. An interrupted TCP application session cannot be resumed transparently even when the tunnel itself reconnects.

## License

MIT. See `LICENSE`.
