# NetRecon

A beginner-friendly network security and penetration testing tools suite.

## Features

NetRecon provides 15+ security tools organized into reconnaissance and penetration testing capabilities:

### Reconnaissance Tools
- **Port Scanner** - Find open ports and services on network hosts
- **Ping Sweep** - Discover live hosts on a network range
- **DNS Lookup** - Query DNS records for domains
- **Traceroute** - Trace network paths to destinations
- **Banner Grabbing** - Read service banners to identify software versions
- **SSL/TLS Checker** - Inspect SSL certificates and configurations
- **WHOIS Lookup** - Query domain registration information
- **HTTP Headers Inspector** - Analyze HTTP security headers
- **Subnet Calculator** - Calculate subnet ranges and host counts

### Penetration Testing Tools (New in v0.2.0)
- **HTTP Fuzzer** - Discover hidden directories and files on web servers
- **Service Fingerprinting** - Identify OS and service versions
- **Vulnerability Scanner** - Check for common security vulnerabilities
- **Network Sniffer** - Capture and analyze live network traffic

### Analysis Tools
- **PCAP Viewer** - Read and summarize packet capture files
- **Log Parser** - Parse security logs for suspicious activity

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

### Command Line Interface

```bash
# View all available commands
netrecon --help

# View networking glossary
netrecon glossary

# Port scanning
netrecon scan example.com -p 1-1024

# HTTP fuzzing
netrecon fuzz https://example.com

# Service fingerprinting
netrecon fingerprint example.com

# Vulnerability scanning
netrecon vulnscan https://example.com

# Network sniffing (requires root/admin)
sudo netrecon sniff --count 100

# Get explanations for any tool
netrecon scan --explain
```

### GUI Application

```bash
netrecon-gui
```

## Building DMG (macOS)

To package NetRecon as a macOS application:

```bash
./packaging/build_dmg.sh
```

The DMG file will be created in the `dist/` directory.

## Educational Focus

NetRecon is designed for learning. Every tool includes:
- Beginner-friendly explanations (`--explain` flag)
- Built-in glossary of networking terms
- Rich, formatted output
- Authorization confirmations for active scans

## Requirements

- Python 3.9+
- Root/administrator privileges for some tools (network sniffing, raw sockets)

## License

MIT
