# Security Policy

## Scope

This project is intended for controlled personal devices, home labs, and experimental networking. The signaling server does not possess the node shared key. Peer identity and tunnel encryption are verified between nodes.

The built-in `HMAC_STREAM` mode is a lightweight, dependency-free design and has not received an independent cryptographic audit. Do not treat it as a replacement for WireGuard, TLS, or another audited protocol in high-risk or enterprise environments.

## Protect local files

Never publish:

- `config.json`
- Node shared keys or Web passwords
- `runtime_memory` recovery secrets
- JSONL logs containing private addresses or device names
- Screenshots containing public IP addresses, internal topology, or personal paths

The repository includes `config.example.json`; copy it to `config.json` locally.

## Reporting vulnerabilities

Please use a private GitHub security advisory when available. Do not include active credentials, private configuration files, or working server addresses in public issues.

Only the latest release is supported.
