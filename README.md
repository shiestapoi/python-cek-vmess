# Proxy Checker - VMess & VLESS Config Analyzer

A comprehensive Python tool to decode, analyze, and generate interactive reports for VMess and VLESS proxy configurations with IP geolocation and connectivity testing capabilities.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Multi-Protocol Support**: Decode and analyze both VMess and VLESS configurations
- **Flexible Runtime Modes**: 
  - VMess only mode
  - VLESS only mode
  - Combined mode (both protocols)
- **Dual Geolocation APIs**:
  - ipgeolocation.io (with API key support)
  - ipapi.co (free, no API key required)
- **Connectivity Testing**: Real proxy connectivity verification using Xray core
- **Interactive HTML Reports**: Beautiful, filterable web-based reports
- **Parallel Processing**: Multi-threaded connectivity checks for faster results
- **Smart Fallbacks**: Automatically fetches configs from remote sources when local files are unavailable

## Table of Contents

- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [API Keys](#api-keys)
- [Examples](#examples)
- [Output Format](#output-format)
- [Troubleshooting](#troubleshooting)

## Installation

1. Clone or download the script:
```bash
git clone <repository-url>
cd proxy-checker
```

2. Ensure you have Python 3.8 or higher installed:
```bash
python3 --version
```

3. No additional Python packages required - uses only standard library!

## Prerequisites

### Required
- Python 3.8+
- `curl` command-line tool

### Optional (for connectivity testing)
- [Xray-core](https://github.com/XTLS/Xray-core) installed and available in PATH

To install Xray-core:
```bash
# macOS with Homebrew
brew install xray

# Linux - download from releases
wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
unzip Xray-linux-64.zip -d /usr/local/bin/
chmod +x /usr/local/bin/xray

# Verify installation
xray version
```

## Quick Start

### Basic Usage

```bash
# Check all configs (VMess + VLESS) from default remote sources
python3 proxy_checker.py

# Check only VMess configs
python3 proxy_checker.py --mode vmess

# Check only VLESS configs
python3 proxy_checker.py --mode vless

# Use local config file
python3 proxy_checker.py --mode vmess -i my_configs.txt
```

## Usage

```
python3 proxy_checker.py [OPTIONS]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --input` | Input config file path | Remote URL based on mode |
| `-o, --output` | Output HTML report file | `report.html` |
| `--json` | Output JSON data file | `report.json` |
| `--mode` | Runtime mode: `vmess`, `vless`, or `all` | `all` |
| `--report-only` | Generate report from existing JSON | `False` |
| `--report-json` | Input JSON for report-only mode | `report.json` |
| `--check-connectivity` | Enable/disable connectivity checks | `True` |
| `--no-check-connectivity` | Skip connectivity testing | - |
| `--connect-timeout` | Timeout per connectivity check (seconds) | `10.0` |
| `--connect-workers` | Parallel workers for connectivity | `80` |
| `--timeout` | HTTP timeout for IP lookup (seconds) | `6.0` |
| `--max-entries` | Maximum entries to process | `0` (all) |
| `--all` | Process all entries | `False` |
| `--no-progress` | Disable progress bars | `False` |
| `--no-free-api` | Disable ipapi.co fallback | `False` |
| `-h, --help` | Show help message | - |

## Configuration

### Environment File (.env)

Create a `.env` file in the same directory to configure API keys:

```bash
# .env file
IPGEOLOCATION_API_KEYS=["your-api-key-1", "your-api-key-2"]
```

Or in simpler format:
```bash
IPGEOLOCATION_API_KEYS=your-api-key-1,your-api-key-2
```

### Default Remote Sources

When no local file is specified, the tool automatically fetches from:

| Mode | URL |
|------|-----|
| VMess | `https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt` |
| VLESS | `https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt` |

## API Keys

### Built-in API Keys

The script includes default API keys for ipgeolocation.io. These are shared and may have usage limits.

### Getting Your Own API Key

1. Visit [ipgeolocation.io](https://ipgeolocation.io/)
2. Sign up for a free account (1000 requests/day)
3. Get your API key from the dashboard
4. Add it to your `.env` file

### Free Alternative (ipapi.co)

The script automatically falls back to ipapi.co when ipgeolocation.io keys are exhausted or unavailable:

- **Free tier**: 30,000 requests/month (1,000/day)
- **No API key required**
- **Rate limit**: 1 request per second

To disable the free API fallback:
```bash
python3 proxy_checker.py --no-free-api
```

## Examples

### Example 1: Basic Check with Default Sources

```bash
python3 proxy_checker.py
```
Output:
```
VMess source: https://raw.githubusercontent.com/...
VLESS source: https://raw.githubusercontent.com/...
Parse VMess        [========================]   150/150   100.00% ETA       0.0s  done in 2.34s
IP Lookup          [========================]    45/45    100.00% ETA       0.0s  done in 8.92s
Merge Results      [========================]   150/150   100.00% ETA       0.0s  done in 0.01s
Parse VLESS        [========================]    89/89    100.00% ETA       0.0s  done in 1.56s
IP Lookup          [========================]    32/32    100.00% ETA       0.0s  done in 6.45s
Merge Results      [========================]    89/89    100.00% ETA       0.0s  done in 0.01s
Connectivity       [========================]   239/239   100.00% ETA       0.0s  done in 45.23s

==================================================
Processing complete!
==================================================
Total entries processed: 239
  - VMess: 150
  - VLESS: 89
HTML report generated: report.html
JSON data generated: report.json
```

### Example 2: VMess Only from Local File

```bash
python3 proxy_checker.py --mode vmess -i vmess_configs.txt -o vmess_report.html
```

### Example 3: VLESS Only with Custom Output

```bash
python3 proxy_checker.py --mode vless -i vless_configs.txt --json vless_data.json
```

### Example 4: Skip Connectivity Check

```bash
python3 proxy_checker.py --mode vmess --no-check-connectivity
```

### Example 5: Process Limited Entries

```bash
# Process only first 50 entries
python3 proxy_checker.py --mode vmess --max-entries 50

# Process all entries
python3 proxy_checker.py --mode vmess --all
```

### Example 6: Generate Report from Existing JSON

```bash
# First run to generate JSON
python3 proxy_checker.py --mode vmess --no-check-connectivity

# Later, generate HTML report from JSON
python3 proxy_checker.py --report-only --report-json report.json -o updated_report.html
```

### Example 7: Adjust Performance

```bash
# More workers for faster connectivity checks
python3 proxy_checker.py --connect-workers 100

# Longer timeout for slow connections
python3 proxy_checker.py --connect-timeout 15

# Faster IP lookup (may be less reliable)
python3 proxy_checker.py --timeout 3
```

### Example 8: Combined Local Files

```bash
# Create combined file
cat vmess.txt vless.txt > combined.txt

# Process combined file
python3 proxy_checker.py --mode all -i combined.txt
```

## Output Format

### JSON Structure

```json
[
  {
    "type": "vmess",
    "original": "vmess://eyJhZGQiOi...",
    "format": "base64-json",
    "add": "example.com",
    "endpoint_port": 443,
    "tls_enabled": true,
    "resolved_ip": "192.168.1.1",
    "country": "United States",
    "city": "Los Angeles",
    "isp": "Cloudflare Inc",
    "services": "AS13335 | America/Los_Angeles",
    "lookup_source": "ipgeolocation.io",
    "connectivity": "ok",
    "connectivity_detail": "Matched via xray socks 127.0.0.1:54321: 192.168.1.1",
    "status": "ok",
    "error": "",
    "decoded": "{...}"
  }
]
```

### HTML Report Features

- **Search**: Filter by any field (config, IP, ISP, host, etc.)
- **Country Filter**: Dropdown to filter by country
- **ISP Filter**: Dropdown to filter by ISP
- **Connectivity Filter**: Filter by connection status (ok, failed, not matched, skipped)
- **TLS Filter**: Filter by TLS enabled status
- **Type Filter**: Filter by proxy type (VMess/VLESS)
- **Detail View**: Click "View Detail" to see full config information
- **Copy Config**: One-click copy of original config URL

### Connectivity Status

| Status | Description |
|--------|-------------|
| `ok` | Proxy is working correctly |
| `failed` | Connection failed or timed out |
| `not matched` | Connected but IP mismatch |
| `skipped` | Skipped due to previous errors |
| `unknown` | Not tested |

## Troubleshooting

### Issue: "xray core not found in PATH"

**Solution**: Install Xray-core and ensure it's in your PATH:
```bash
which xray  # Should return path to xray
```

### Issue: All connectivity checks fail

**Possible causes**:
1. Xray-core not installed
2. Network restrictions (firewall)
3. Invalid proxy configs

**Debug**:
```bash
# Test without connectivity check first
python3 proxy_checker.py --no-check-connectivity

# Check if configs are valid in the HTML report
```

### Issue: IP geolocation returns "Unknown"

**Possible causes**:
1. All API keys exhausted
2. Rate limiting
3. Network issues

**Solutions**:
- Wait and retry
- Add your own API keys to `.env`
- Check network connectivity

### Issue: Script runs slowly

**Solutions**:
```bash
# Reduce workers if system is overloaded
python3 proxy_checker.py --connect-workers 20

# Reduce timeout
python3 proxy_checker.py --timeout 3 --connect-timeout 5

# Disable connectivity check for faster parsing
python3 proxy_checker.py --no-check-connectivity

# Process fewer entries
python3 proxy_checker.py --max-entries 50
```

### Issue: "DNS lookup failed"

**Cause**: Cannot resolve hostname in config

**Solution**: Check your DNS settings or try a different network

## Geolocation API Response Format

### ipgeolocation.io (with API key)

```json
{
  "ip": "91.128.103.196",
  "location": {
    "country_name": "Sweden",
    "city": "Stockholm",
    ...
  },
  "asn": {
    "as_number": "AS1257",
    "organization": "Tele2 Sverige AB"
  },
  "time_zone": {
    "name": "Europe/Stockholm"
  }
}
```

### ipapi.co (free)

```json
{
  "ip": "91.128.103.196",
  "country_name": "Sweden",
  "city": "Kista",
  "org": "Tele2 SWIPnet",
  "asn": "AS1257"
}
```

## Security Notes

- API keys in `.env` file are only used locally
- No data is sent to external servers except for geolocation queries
- Connectivity tests use local Xray instance only
- Config URLs are processed locally

## License

MIT License - Feel free to use, modify, and distribute.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Acknowledgments

- [ipgeolocation.io](https://ipgeolocation.io/) for geolocation API
- [ipapi.co](https://ipapi.co/) for free geolocation service
- [Xray-core](https://github.com/XTLS/Xray-core) for proxy testing
- [free-v2ray-public-list](https://github.com/ebrasha/free-v2ray-public-list) for default config sources
