import argparse
import base64
import concurrent.futures
import datetime
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


VMESS_PATTERN = re.compile(r"vmess://\S+")
BASE64_CHARS = re.compile(r"^[A-Za-z0-9_\-+/=]+")

IPGEOLOCATION_KEYS = [
    "efb9d83c2d2245f4abd557e68a8500d3",
    "e4f30a7389bc482f9782e1fd8a3f520c",
    "3091c2b2648b4b87b9a3e6a380b7b062",
]

IFCONFIG_URL = "https://ifconfig.me/ip"
DEFAULT_VMESS_URL = "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt"


def parse_bool_like(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return text not in {"0", "false", "none", "off", "no", "null", ""}


def load_api_keys_from_env(
    env_path: str = ".env", env_var: str = "IPGEOLOCATION_API_KEYS"
) -> List[str]:
    if not os.path.exists(env_path):
        return []

    try:
        with open(env_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []

    raw_value: Optional[str] = None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() == env_var:
            raw_value = value.strip()
            break

    if not raw_value:
        return []

    if (raw_value.startswith('"') and raw_value.endswith('"')) or (
        raw_value.startswith("'") and raw_value.endswith("'")
    ):
        raw_value = raw_value[1:-1]

    try:
        parsed = json.loads(raw_value)
        if isinstance(parsed, list):
            keys = [str(v).strip() for v in parsed if str(v).strip()]
            return keys
    except Exception:
        pass

    value = raw_value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    keys = [part.strip().strip('"').strip("'") for part in value.split(",")]
    return [k for k in keys if k]


def read_input_source(input_file: Optional[str], input_url: str) -> Tuple[str, str]:
    if input_file and os.path.exists(input_file):
        with open(input_file, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), input_file

    if input_file:
        print(
            f"Input file not found: {input_file}. Falling back to URL source: {input_url}",
            file=sys.stderr,
        )

    with urllib.request.urlopen(input_url, timeout=20) as response:
        content = response.read().decode("utf-8", errors="replace")
    return content, input_url


class ApiKeyPool:
    def __init__(self, keys: List[str]):
        self._lock = threading.Lock()
        self._state = {key: True for key in keys}

    def ordered_keys(self) -> List[str]:
        with self._lock:
            return [k for k, ok in self._state.items() if ok]

    def disable(self, key: str) -> None:
        with self._lock:
            if key in self._state:
                self._state[key] = False

    def has_active(self) -> bool:
        with self._lock:
            return any(self._state.values())


class CliProgress:
    def __init__(self, label: str, total: int, width: int = 28, enabled: bool = True):
        self.label = label
        self.total = max(total, 0)
        self.width = max(width, 10)
        self.enabled = enabled
        self.current = 0
        self.start = time.perf_counter()
        self.last_draw = 0.0
        self.min_interval = 0.05

    @staticmethod
    def _format_duration(seconds: float) -> str:
        sec = max(0.0, float(seconds))
        if sec < 60:
            return f"{sec:0.1f}s"
        total_sec = int(round(sec))
        mins, rem = divmod(total_sec, 60)
        if mins < 60:
            return f"{mins}m {rem}s"
        hrs, mins = divmod(mins, 60)
        return f"{hrs}h {mins}m {rem}s"

    def update(self, current: int) -> None:
        if not self.enabled:
            return
        self.current = min(max(current, 0), self.total)
        now = time.perf_counter()
        if self.current < self.total and (now - self.last_draw) < self.min_interval:
            return
        self.last_draw = now

        ratio = (self.current / self.total) if self.total else 1.0
        filled = int(self.width * ratio)
        bar = "=" * filled + "." * (self.width - filled)
        elapsed = now - self.start
        speed = (self.current / elapsed) if elapsed > 0 else 0.0
        remain = (self.total - self.current) / speed if speed > 0 else 0.0

        line = (
            f"\r\x1b[36m{self.label:<18}\x1b[0m "
            f"[{bar}] {self.current:>5}/{self.total:<5} "
            f"{ratio * 100:6.2f}% "
            f"ETA {self._format_duration(remain):>9}"
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self) -> None:
        if not self.enabled:
            return
        self.update(self.total)
        elapsed = time.perf_counter() - self.start
        sys.stdout.write(f"  done in {elapsed:.2f}s\n")
        sys.stdout.flush()


def extract_vmess_tokens(text: str) -> List[str]:
    tokens: List[str] = []
    for match in VMESS_PATTERN.finditer(text):
        raw = match.group(0)
        clean = sanitize_token(raw)
        if clean:
            tokens.append(clean)
    return tokens


def sanitize_token(token: str) -> str:
    if not token.startswith("vmess://"):
        return ""

    body = token[len("vmess://") :]
    if not body:
        return ""

    # If it looks like URI-style vmess, keep URL-safe characters.
    if "@" in body or body.startswith("http"):
        url_chars = re.match(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", body)
        if url_chars:
            return "vmess://" + url_chars.group(0)
        return ""

    # Otherwise treat it as base64 payload and trim non-base64 suffix chars.
    b64_match = BASE64_CHARS.match(body)
    if not b64_match:
        return ""
    return "vmess://" + b64_match.group(0)


def decode_b64_json(payload: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    raw = payload.strip()
    if not raw:
        return None, "Empty payload"

    # vmess payloads can be standard or urlsafe base64 and may miss padding.
    candidates = [raw, raw.replace("-", "+").replace("_", "/")]

    for candidate in candidates:
        padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False)
        except Exception:
            continue

        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                text = decoded.decode(encoding)
            except UnicodeDecodeError:
                continue

            text = text.strip()
            if not text:
                continue
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    return obj, None
            except json.JSONDecodeError:
                continue

    return None, "Base64 decode or JSON parse failed"


def parse_vmess(token: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "vmess_original": token,
        "format": "unknown",
        "add": "",
        "endpoint_port": 0,
        "tls_enabled": False,
        "resolved_ip": "",
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "services": "Unknown",
        "lookup_source": "none",
        "connectivity": "unknown",
        "connectivity_detail": "",
        "status": "ok",
        "error": "",
        "decoded": None,
    }

    body = token[len("vmess://") :]

    # Try base64-json first.
    decoded_obj, decode_err = decode_b64_json(body)
    if decoded_obj is not None:
        result["format"] = "base64-json"
        result["decoded"] = decoded_obj
        add_val = str(decoded_obj.get("add", "")).strip()
        result["add"] = add_val
        port_val = decoded_obj.get("port", 0)
        try:
            result["endpoint_port"] = int(str(port_val).strip())
        except Exception:
            result["endpoint_port"] = 0
        result["tls_enabled"] = parse_bool_like(decoded_obj.get("tls", ""))
        return result

    # Fallback to URI-style vmess://uuid@host:port?...
    try:
        parsed = urllib.parse.urlsplit(token)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = f"Unable to parse vmess URI: {exc}"
        return result

    if parsed.hostname:
        result["format"] = "uri-style"
        result["add"] = parsed.hostname.strip()
        result["endpoint_port"] = int(parsed.port or 0)
        query = urllib.parse.parse_qs(parsed.query)
        tls_query = ""
        if "security" in query and query["security"]:
            tls_query = str(query["security"][0])
        if not tls_query and "tls" in query and query["tls"]:
            tls_query = str(query["tls"][0])
        result["tls_enabled"] = str(tls_query).strip().lower() in {"tls", "true", "1"}
        return result

    result["status"] = "error"
    result["error"] = decode_err or "Unsupported vmess format"
    return result


def derive_endpoint_fields(row: Dict[str, Any]) -> None:
    if row.get("endpoint_port") and row.get("add") and ("tls_enabled" in row):
        return

    token = str(row.get("vmess_original", "")).strip()
    if not token:
        return

    parsed = parse_vmess(token)
    if not row.get("add"):
        row["add"] = parsed.get("add", "")

    if not row.get("endpoint_port"):
        port_val = parsed.get("endpoint_port", 0)
        try:
            row["endpoint_port"] = int(port_val)
        except Exception:
            row["endpoint_port"] = 0

    if "tls_enabled" not in row:
        row["tls_enabled"] = bool(parsed.get("tls_enabled", False))


def resolve_all_ipv4(host_or_ip: str) -> List[str]:
    try:
        ipaddress.ip_address(host_or_ip)
        return [host_or_ip]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host_or_ip, None, socket.AF_INET, socket.SOCK_STREAM)
    except Exception:
        return []

    ips: List[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in ips:
            ips.append(ip)
    return ips


def find_free_local_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def check_vmess_connectivity_endpoint(
    add: str, resolved_ip: str, port: int, timeout: float
) -> Tuple[str, str]:
    if not add and not resolved_ip:
        return "failed", "Missing endpoint host/IP"
    if not port or port <= 0 or port > 65535:
        return "failed", "Invalid or missing port"

    total_budget = max(3.0, min(10.0, timeout))
    start_time = time.perf_counter()
    target_url = IFCONFIG_URL

    expected_ips: List[str] = []
    base_host = add.strip() or resolved_ip.strip()
    for ip in resolve_all_ipv4(base_host):
        if ip not in expected_ips:
            expected_ips.append(ip)
    if resolved_ip and resolved_ip not in expected_ips:
        expected_ips.append(resolved_ip)

    proxy_hosts: List[str] = []
    if add:
        proxy_hosts.append(add.strip())
    if resolved_ip and resolved_ip not in proxy_hosts:
        proxy_hosts.append(resolved_ip)
    for ip in expected_ips:
        if ip not in proxy_hosts:
            proxy_hosts.append(ip)

    proxy_candidates: List[str] = []
    for host in proxy_hosts:
        proxy_candidates.append(f"socks5h://{host}:{port}")
        proxy_candidates.append(f"http://{host}:{port}")

    reachable = False
    tcp_targets = expected_ips if expected_ips else [resolved_ip or add]
    for target in tcp_targets:
        if not target:
            continue
        try:
            with socket.create_connection(
                (target, port), timeout=min(3.0, total_budget)
            ):
                reachable = True
                break
        except Exception:
            continue

    errors: List[str] = []
    mismatches: List[str] = []
    attempts = 0

    while (time.perf_counter() - start_time) < total_budget:
        for proxy in proxy_candidates:
            remaining = total_budget - (time.perf_counter() - start_time)
            if remaining <= 0:
                break

            per_try = max(1.5, min(4.0, remaining))
            attempts += 1
            ok, body, err = run_curl_text(target_url, per_try, proxy=proxy)
            if not ok:
                if err:
                    errors.append(f"{proxy} -> {err}")
                continue

            match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body)
            if not match:
                errors.append(f"{proxy} -> no IP in response")
                continue

            outbound_ip = match.group(0)
            if outbound_ip in expected_ips:
                return "ok", f"Matched via {proxy}: {outbound_ip}"

            mismatches.append(
                f"{proxy} -> expected one of {', '.join(expected_ips) or '-'}, got {outbound_ip}"
            )

        if (time.perf_counter() - start_time) < total_budget:
            time.sleep(0.25)

    if mismatches:
        return "not matched", mismatches[-1]

    if reachable:
        return "failed", (
            f"Endpoint reachable but proxy test failed after {attempts} attempts / {total_budget:.1f}s"
        )
    return (
        "failed",
        f"Connection failed after {attempts} attempts / {total_budget:.1f}s",
    )


def resolve_ip(add: str, dns_cache: Dict[str, str]) -> Tuple[str, str]:
    if not add:
        return "", "Missing add field"

    if add in dns_cache:
        return dns_cache[add], ""

    try:
        ipaddress.ip_address(add)
        dns_cache[add] = add
        return add, ""
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(add, None, socket.AF_INET, socket.SOCK_STREAM)
        if not infos:
            return "", "DNS lookup returned no IPv4 result"
        ip = str(infos[0][4][0])
        dns_cache[add] = ip
        return ip, ""
    except Exception as exc:
        return "", f"DNS lookup failed: {exc}"


def unknown_info(source: str = "none") -> Dict[str, str]:
    return {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "services": "Unknown",
        "lookup_source": source,
    }


def run_curl_text(
    url: str, timeout: float, proxy: Optional[str] = None
) -> Tuple[bool, str, str]:
    max_time = max(1.0, timeout)
    cmd = [
        "curl",
        "-sS",
        "-L",
        "-X",
        "GET",
        "--max-time",
        f"{max_time}",
        "--connect-timeout",
        f"{max(1.0, min(8.0, timeout))}",
    ]
    if proxy:
        cmd.extend(["--proxy", proxy])
    cmd.append(url)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as exc:
        return False, "", str(exc)

    if proc.returncode != 0:
        return False, "", (proc.stderr or "curl failed").strip()

    text = (proc.stdout or "").strip()
    if not text:
        return False, "", "Empty response"
    return True, text, ""


def check_vmess_connectivity_via_xray(
    token: str, add: str, resolved_ip: str, port: int, timeout: float
) -> Tuple[str, str]:
    xray_bin = shutil.which("xray")
    if not xray_bin:
        return "failed", "xray core not found in PATH (need 'xray')"

    parsed = parse_vmess(token)
    decoded = parsed.get("decoded")
    if not isinstance(decoded, dict):
        return "failed", "Decoded VMess JSON required for xray mode"

    vmess_id = str(decoded.get("id", "")).strip()
    if not vmess_id:
        return "failed", "Missing vmess id"

    net = str(decoded.get("net", "tcp") or "tcp").strip().lower()
    security = str(decoded.get("tls", "") or "").strip().lower()
    host = str(decoded.get("host", "") or "").strip()
    path = str(decoded.get("path", "") or "").strip() or "/"
    sni = str(decoded.get("sni", "") or "").strip()
    scy = str(decoded.get("scy", "auto") or "auto").strip()
    aid_raw = decoded.get("aid", 0)
    try:
        aid = int(str(aid_raw).strip() or "0")
    except Exception:
        aid = 0

    stream_settings: Dict[str, Any] = {"network": net}
    if security == "tls":
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {
            "serverName": sni or host or add,
            "allowInsecure": True,
        }

    if net == "ws":
        headers = {}
        if host:
            headers["Host"] = host
        stream_settings["wsSettings"] = {"path": path, "headers": headers}

    expected_ips: List[str] = []
    for ip in resolve_all_ipv4(add):
        if ip not in expected_ips:
            expected_ips.append(ip)
    if resolved_ip and resolved_ip not in expected_ips:
        expected_ips.append(resolved_ip)

    last_error = ""
    for _ in range(3):
        socks_port = find_free_local_port()
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {"udp": False},
                }
            ],
            "outbounds": [
                {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": add,
                                "port": port,
                                "users": [
                                    {"id": vmess_id, "alterId": aid, "security": scy}
                                ],
                            }
                        ]
                    },
                    "streamSettings": stream_settings,
                }
            ],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", delete=False
        ) as tf:
            config_path = tf.name
            json.dump(config, tf, ensure_ascii=False)

        proc: Optional[subprocess.Popen[str]] = None
        try:
            proc = subprocess.Popen(
                [xray_bin, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            time.sleep(1.2)

            if proc.poll() is not None:
                last_error = "xray exited early"
                continue

            ok, body, err = run_curl_text(
                IFCONFIG_URL,
                timeout=max(2.0, min(10.0, timeout)),
                proxy=f"socks5h://127.0.0.1:{socks_port}",
            )
            if not ok:
                last_error = f"xray proxy curl failed: {err}"
                continue

            match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body)
            if not match:
                last_error = "ifconfig response has no IP"
                continue

            outbound_ip = match.group(0)
            if outbound_ip in expected_ips:
                return (
                    "ok",
                    f"Matched via xray socks 127.0.0.1:{socks_port}: {outbound_ip}",
                )
            return (
                "not matched",
                f"Expected one of {', '.join(expected_ips) or '-'}, got {outbound_ip} via xray",
            )
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                os.remove(config_path)
            except Exception:
                pass

    return "failed", (last_error or "xray connection failed")


def check_vmess_connectivity(
    token: str, add: str, resolved_ip: str, port: int, timeout: float
) -> Tuple[str, str]:
    return check_vmess_connectivity_via_xray(token, add, resolved_ip, port, timeout)


def run_curl_json(url: str, timeout: float) -> Optional[Dict[str, Any]]:
    max_time = max(1.0, timeout)
    cmd = [
        "curl",
        "-sS",
        "-X",
        "GET",
        "--max-time",
        f"{max_time}",
        url,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    text = (proc.stdout or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def should_disable_key(data: Dict[str, Any]) -> bool:
    message_parts: List[str] = []
    for key in ("message", "error", "reason"):
        value = data.get(key)
        if value:
            message_parts.append(str(value).lower())
    merged = " ".join(message_parts)
    checks = ["quota", "limit", "credit", "exceed", "invalid api", "unauthorized"]
    return any(word in merged for word in checks)


def parse_ipgeolocation_response(data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    location = data.get("location")
    asn = data.get("asn")
    if not isinstance(location, dict):
        return None
    if not isinstance(asn, dict):
        asn = {}

    country = str(location.get("country_name") or "Unknown")
    city = str(location.get("city") or "Unknown")
    isp = str(asn.get("organization") or "Unknown")
    as_number = str(asn.get("as_number") or "")
    timezone_obj = data.get("time_zone")
    tz_name = ""
    if isinstance(timezone_obj, dict):
        tz_name = str(timezone_obj.get("name") or "")
    parts = [p for p in [as_number, tz_name] if p]
    services = " | ".join(parts) if parts else "Unknown"
    return {
        "country": country,
        "city": city,
        "isp": isp,
        "services": services,
        "lookup_source": "ipgeolocation.io",
    }


def parse_ip_api_response(data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    if str(data.get("status", "")).lower() != "success":
        return None
    country = str(data.get("country") or "Unknown")
    city = str(data.get("city") or "Unknown")
    isp = str(data.get("isp") or data.get("org") or "Unknown")
    asn = str(data.get("as") or "")
    flags = []
    for key in ("proxy", "hosting", "mobile"):
        if key in data:
            flags.append(f"{key}:{str(bool(data[key])).lower()}")
    parts = [p for p in [asn, " ".join(flags)] if p]
    services = " | ".join(parts) if parts else "Unknown"
    return {
        "country": country,
        "city": city,
        "isp": isp,
        "services": services,
        "lookup_source": "demo.ip-api.com",
    }


def lookup_ip_info(ip: str, key_pool: ApiKeyPool, timeout: float) -> Dict[str, str]:
    if not ip:
        return unknown_info("none")

    for api_key in key_pool.ordered_keys():
        base = "https://api.ipgeolocation.io/v3/ipgeo"
        url = f"{base}?apiKey={urllib.parse.quote(api_key)}&ip={urllib.parse.quote(ip)}"
        data = run_curl_json(url, timeout)
        if not data:
            continue
        parsed = parse_ipgeolocation_response(data)
        if parsed:
            return parsed
        if should_disable_key(data):
            key_pool.disable(api_key)

    fallback_url = (
        f"https://demo.ip-api.com/json/{urllib.parse.quote(ip)}?fields=66842623&lang=en"
    )
    fallback_data = run_curl_json(fallback_url, timeout)
    if fallback_data:
        parsed = parse_ip_api_response(fallback_data)
        if parsed:
            return parsed

    return unknown_info("unavailable")


def generate_html(rows: List[Dict[str, Any]], source_file: str) -> str:
    countries = sorted({row.get("country", "Unknown") for row in rows})
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows_json = json.dumps(rows, ensure_ascii=False)
    countries_json = json.dumps(countries, ensure_ascii=False)

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>VMess Report</title>
  <style>
    :root {{
      --bg: #0b111b;
      --bg-alt: #121b2a;
      --panel: #111827;
      --line: #273247;
      --text: #e5ecf5;
      --muted: #95a2b7;
      --accent: #19c8b4;
      --accent-2: #28a8ff;
      --good: #16c47f;
      --bad: #ef5350;
      --chip: #1b2638;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
      color: var(--text);
      background: radial-gradient(1200px 700px at 10% 0%, #132138 0%, var(--bg) 50%),
                  linear-gradient(180deg, #0b111b 0%, #09101a 100%);
      min-height: 100vh;
    }}
    .wrap {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 28px 18px 40px;
    }}
    .hero {{
      background: linear-gradient(130deg, rgba(25,200,180,0.15), rgba(40,168,255,0.15));
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 18px;
      backdrop-filter: blur(8px);
    }}
    h1 {{
      margin: 0 0 6px;
      font-size: 24px;
      letter-spacing: 0.3px;
    }}
    .meta {{ color: var(--muted); font-size: 13px; }}
    .controls {{
      display: grid;
      grid-template-columns: 1.6fr 1fr 1fr 1fr 1fr;
      gap: 10px;
      margin: 14px 0 14px;
    }}
    @media (max-width: 760px) {{
      .controls {{ grid-template-columns: 1fr; }}
    }}
    input, select {{
      width: 100%;
      background: var(--panel);
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: 10px;
      height: 42px;
      padding: 0 12px;
      outline: none;
    }}
    input:focus, select:focus {{
      border-color: var(--accent-2);
      box-shadow: 0 0 0 3px rgba(40,168,255,0.18);
    }}
    .table-wrap {{
      border: 1px solid var(--line);
      border-radius: 14px;
      overflow: hidden;
      background: rgba(17, 24, 39, 0.95);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }}
    thead th {{
      position: sticky;
      top: 0;
      z-index: 1;
      background: #182235;
      color: #d3dff0;
      text-align: left;
      font-size: 12px;
      letter-spacing: 0.3px;
      padding: 12px 10px;
      border-bottom: 1px solid var(--line);
    }}
    tbody td {{
      padding: 10px;
      border-bottom: 1px solid rgba(39, 50, 71, 0.65);
      vertical-align: top;
      font-size: 13px;
      line-height: 1.4;
    }}
    tbody tr:hover {{ background: rgba(40,168,255,0.08); }}
    .mono {{
      font-family: Consolas, "Courier New", monospace;
      word-break: break-all;
      color: #d7e3f3;
    }}
    .tag {{
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 11px;
      background: var(--chip);
      border: 1px solid var(--line);
      color: #cfe2ff;
    }}
    .ok {{ color: var(--good); }}
    .err {{ color: var(--bad); }}
    .stats {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 10px;
    }}
    .chip {{
      background: var(--chip);
      border: 1px solid var(--line);
      color: #c6d4e8;
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 12px;
    }}
    .vmess-cell {{
      display: flex;
      gap: 8px;
      align-items: center;
      justify-content: center;
    }}
    .copy-btn {{
      border: 1px solid #365177;
      background: #1b2b45;
      color: #d7e8ff;
      border-radius: 8px;
      padding: 6px 10px;
      font-size: 12px;
      cursor: pointer;
      white-space: nowrap;
    }}
    .copy-btn:hover {{ background: #23406d; }}
    .copy-btn.copied {{
      border-color: #219e78;
      background: #164e3f;
      color: #d5ffe8;
    }}
    .conn-pill {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      border: 1px solid var(--line);
      background: var(--chip);
    }}
    .conn-ok {{
      color: #baf5d8;
      border-color: #2c8c67;
      background: #123f31;
    }}
    .conn-failed {{
      color: #ffd1d1;
      border-color: #a84747;
      background: #4d1f1f;
    }}
    .conn-not-matched {{
      color: #ffe7bf;
      border-color: #a16b2f;
      background: #4a3114;
    }}
    .conn-skipped {{
      color: #c4d0df;
      border-color: #4c5f7a;
      background: #1f2b3e;
    }}
    .modal {{
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(8, 12, 22, 0.75);
      backdrop-filter: blur(3px);
      z-index: 25;
      padding: 16px;
    }}
    .modal.open {{ display: flex; }}
    .modal-card {{
      width: min(860px, 100%);
      max-height: 90vh;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: #0f1727;
      box-shadow: 0 20px 40px rgba(0,0,0,0.35);
    }}
    .modal-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px;
      border-bottom: 1px solid var(--line);
    }}
    .modal-title {{ font-weight: 600; }}
    .modal-body {{ padding: 14px; display: grid; gap: 8px; }}
    .kv {{ display: grid; grid-template-columns: 140px 1fr; gap: 10px; font-size: 13px; }}
    .k {{ color: var(--muted); }}
    .v {{ word-break: break-all; }}
    @media (max-width: 980px) {{
      .table-wrap {{ border: 0; background: transparent; }}
      table, thead, tbody, th, td, tr {{ display: block; width: 100%; }}
      thead {{ display: none; }}
      tbody tr {{
        background: rgba(17, 24, 39, 0.95);
        border: 1px solid var(--line);
        border-radius: 12px;
        margin-bottom: 12px;
        padding: 8px;
      }}
      tbody td {{
        border-bottom: 0;
        display: grid;
        grid-template-columns: 118px 1fr;
        gap: 10px;
        padding: 8px;
      }}
      tbody td::before {{
        content: attr(data-label);
        color: var(--muted);
        font-size: 12px;
      }}
      .copy-btn {{
        width: 100%;
      }}
      .kv {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <section class=\"hero\">
      <h1>VMess Decode + IP Intelligence Report</h1>
      <div class=\"meta\">Source: {html.escape(source_file)} | Generated: {html.escape(now)}</div>
      <div class=\"stats\">
        <div class=\"chip\" id=\"countAll\">Total: 0</div>
        <div class=\"chip\" id=\"countShown\">Shown: 0</div>
        <div class=\"chip\" id=\"countCountries\">Countries: 0</div>
      </div>
    </section>

    <section class=\"controls\">
      <input id=\"search\" type=\"text\" placeholder=\"Search vmess / IP / ISP / host...\" />
      <select id=\"country\"></select>
      <select id=\"isp\"></select>
      <select id=\"conn\"></select>
      <select id=\"tls\"></select>
    </section>

    <section class=\"table-wrap\">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Country</th>
            <th>ISP</th>
            <th>Connectivity</th>
            <th>Status</th>
            <th>TLS</th>
            <th>Aksi</th>
          </tr>
        </thead>
        <tbody id=\"rows\"></tbody>
      </table>
    </section>
  </div>

  <div id=\"detailModal\" class=\"modal\" onclick=\"closeModal()\">
    <div class=\"modal-card\" onclick=\"event.stopPropagation()\">
      <div class=\"modal-head\">
        <div class=\"modal-title\">VMess Detail</div>
        <button type=\"button\" class=\"copy-btn\" onclick=\"closeModal()\">Close</button>
      </div>
      <div class=\"modal-body\" id=\"modalBody\"></div>
    </div>
  </div>

  <script>
    const data = {rows_json};
    const countries = {countries_json};

    const rowsEl = document.getElementById('rows');
    const searchEl = document.getElementById('search');
    const countryEl = document.getElementById('country');
    const ispEl = document.getElementById('isp');
    const connEl = document.getElementById('conn');
    const tlsEl = document.getElementById('tls');
    const countAllEl = document.getElementById('countAll');
    const countShownEl = document.getElementById('countShown');
    const countCountriesEl = document.getElementById('countCountries');

    function esc(v) {{
      return String(v ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }}

    function enc(v) {{
      return encodeURIComponent(String(v ?? ''));
    }}

    function connClass(state) {{
      const s = String(state || 'unknown').toLowerCase();
      if (s === 'ok') return 'conn-pill conn-ok';
      if (s === 'not matched') return 'conn-pill conn-not-matched';
      if (s === 'failed') return 'conn-pill conn-failed';
      return 'conn-pill conn-skipped';
    }}

    async function copyVmess(btn) {{
      const raw = btn.getAttribute('data-vmess') || '';
      const decoded = decodeURIComponent(raw);
      try {{
        await navigator.clipboard.writeText(decoded);
        const old = btn.textContent;
        btn.textContent = 'Copied';
        btn.classList.add('copied');
        setTimeout(() => {{
          btn.textContent = old;
          btn.classList.remove('copied');
        }}, 1200);
      }} catch (err) {{
        btn.textContent = 'Failed';
        setTimeout(() => {{ btn.textContent = 'Copy'; }}, 1200);
      }}
    }}

    function buildCountryOptions() {{
      countryEl.innerHTML = '';
      const all = document.createElement('option');
      all.value = 'ALL';
      all.textContent = 'All Countries';
      countryEl.appendChild(all);

      countries.forEach((country) => {{
        const opt = document.createElement('option');
        opt.value = country;
        opt.textContent = country;
        countryEl.appendChild(opt);
      }});
    }}

    function buildIspOptions(country) {{
      const prevValue = ispEl.value || 'ALL';
      const list = data
        .filter((row) => country === 'ALL' || row.country === country)
        .map((row) => (row.isp || 'Unknown'));

      const uniqueIsps = Array.from(new Set(list)).sort((a, b) => a.localeCompare(b));

      ispEl.innerHTML = '';
      const allIsp = document.createElement('option');
      allIsp.value = 'ALL';
      allIsp.textContent = country === 'ALL' ? 'All ISP' : `All ISP (${{country}})`;
      ispEl.appendChild(allIsp);

      uniqueIsps.forEach((isp) => {{
        const opt = document.createElement('option');
        opt.value = isp;
        opt.textContent = isp;
        ispEl.appendChild(opt);
      }});

      const hasPrev = uniqueIsps.includes(prevValue);
      ispEl.value = hasPrev ? prevValue : 'ALL';
    }}

    function buildConnOptions(country, isp) {{
      const prevValue = connEl.value || 'ALL';
      const list = data
        .filter((row) => (country === 'ALL' || row.country === country) && (isp === 'ALL' || row.isp === isp))
        .map((row) => (row.connectivity || 'unknown'));

      const uniqueStates = Array.from(new Set(list)).sort((a, b) => a.localeCompare(b));

      connEl.innerHTML = '';
      const allConn = document.createElement('option');
      allConn.value = 'ALL';
      allConn.textContent = 'All Connectivity';
      connEl.appendChild(allConn);

      uniqueStates.forEach((state) => {{
        const opt = document.createElement('option');
        opt.value = state;
        opt.textContent = state;
        connEl.appendChild(opt);
      }});

      const hasPrev = uniqueStates.includes(prevValue);
      connEl.value = hasPrev ? prevValue : 'ALL';
    }}

    function buildTlsOptions() {{
      const prevValue = tlsEl.value || 'ALL';
      const options = ['true', 'false'];
      tlsEl.innerHTML = '';
      const allTls = document.createElement('option');
      allTls.value = 'ALL';
      allTls.textContent = 'All TLS';
      tlsEl.appendChild(allTls);
      options.forEach((item) => {{
        const opt = document.createElement('option');
        opt.value = item;
        opt.textContent = item;
        tlsEl.appendChild(opt);
      }});
      tlsEl.value = options.includes(prevValue) ? prevValue : 'ALL';
    }}

    function rowMatches(row, q, country, isp, conn, tls) {{
      if (country !== 'ALL' && row.country !== country) return false;
      if (isp !== 'ALL' && row.isp !== isp) return false;
      if (conn !== 'ALL' && (row.connectivity || 'unknown') !== conn) return false;
      const rowTls = row.tls_enabled ? 'true' : 'false';
      if (tls !== 'ALL' && rowTls !== tls) return false;
      if (!q) return true;

      const hay = [
        row.vmess_original,
        row.add,
        row.resolved_ip,
        row.country,
        row.city,
        row.isp,
        row.services,
        row.lookup_source,
        row.connectivity,
        row.connectivity_detail,
        row.format,
        row.status,
        row.error,
      ].join(' ').toLowerCase();

      return hay.includes(q);
    }}

    function openDetail(index) {{
      const row = data[index];
      if (!row) return;
      const modal = document.getElementById('detailModal');
      const body = document.getElementById('modalBody');
      body.innerHTML = `
        <div class=\"kv\"><div class=\"k\">Country</div><div class=\"v\">${{esc(row.country || '-')}}</div></div>
        <div class=\"kv\"><div class=\"k\">City</div><div class=\"v\">${{esc(row.city || '-')}}</div></div>
        <div class=\"kv\"><div class=\"k\">ISP</div><div class=\"v\">${{esc(row.isp || '-')}}</div></div>
        <div class=\"kv\"><div class=\"k\">Services</div><div class=\"v\">${{esc(row.services || '-')}}</div></div>
        <div class=\"kv\"><div class=\"k\">Host</div><div class=\"v mono\">${{esc(row.add || '-')}}</div></div>
        <div class=\"kv\"><div class=\"k\">Resolved IP</div><div class=\"v mono\">${{esc(row.resolved_ip || '-')}}</div></div>
        <div class=\"kv\"><div class=\"k\">Port</div><div class=\"v\">${{esc(row.endpoint_port || 0)}}</div></div>
        <div class=\"kv\"><div class=\"k\">TLS</div><div class=\"v\">${{row.tls_enabled ? 'true' : 'false'}}</div></div>
        <div class=\"kv\"><div class=\"k\">Connectivity</div><div class=\"v\">${{esc(row.connectivity || 'unknown')}} - ${{esc(row.connectivity_detail || '-')}}</div></div>
        <div class=\"kv\"><div class=\"k\">Status</div><div class=\"v\">${{esc(row.status)}}${{row.error ? ' - ' + esc(row.error) : ''}}</div></div>
        <div class=\"kv\"><div class=\"k\">Original VMess</div><div class=\"v mono\">${{esc(row.vmess_original || '')}}</div></div>
        <button type=\"button\" class=\"copy-btn\" data-vmess=\"${{enc(row.vmess_original)}}\" onclick=\"copyVmess(this)\">Copy VMess</button>
      `;
      modal.classList.add('open');
    }}

    function closeModal() {{
      const modal = document.getElementById('detailModal');
      modal.classList.remove('open');
    }}

    function render() {{
      const q = searchEl.value.trim().toLowerCase();
      const c = countryEl.value || 'ALL';
      const i = ispEl.value || 'ALL';
      const k = connEl.value || 'ALL';
      const t = tlsEl.value || 'ALL';

      const filtered = data.filter((row) => rowMatches(row, q, c, i, k, t));
      rowsEl.innerHTML = filtered.map((row, idx) => `
        <tr>
          <td data-label=\"#\">${{idx + 1}}</td>
          <td data-label=\"Country\"><span class=\"tag\">${{esc(row.country)}}</span></td>
          <td data-label=\"ISP\">${{esc(row.isp)}}</td>
          <td data-label=\"Connectivity\"><span class=\"${{connClass(row.connectivity)}}\" title=\"${{esc(row.connectivity_detail || '')}}\">${{esc(row.connectivity || 'unknown')}}</span></td>
          <td data-label=\"Status\" class=\"${{row.status === 'ok' ? 'ok' : 'err'}}\">${{esc(row.status)}}${{row.error ? ' - ' + esc(row.error) : ''}}</td>
          <td data-label=\"TLS\"><span class=\"tag\">${{row.tls_enabled ? 'true' : 'false'}}</span></td>
          <td data-label=\"Aksi\"><button type=\"button\" class=\"copy-btn\" onclick=\"openDetail(${{data.indexOf(row)}})\">View Detail</button></td>
        </tr>
      `).join('');

      countAllEl.textContent = `Total: ${{data.length}}`;
      countShownEl.textContent = `Shown: ${{filtered.length}}`;
      countCountriesEl.textContent = `Countries: ${{countries.length}}`;
    }}

    buildCountryOptions();
    buildIspOptions('ALL');
    buildConnOptions('ALL', 'ALL');
    buildTlsOptions();
    render();

    searchEl.addEventListener('input', render);
    countryEl.addEventListener('change', () => {{
      buildIspOptions(countryEl.value || 'ALL');
      buildConnOptions(countryEl.value || 'ALL', ispEl.value || 'ALL');
      render();
    }});
    ispEl.addEventListener('change', () => {{
      buildConnOptions(countryEl.value || 'ALL', ispEl.value || 'ALL');
      render();
    }});
    connEl.addEventListener('change', render);
    tlsEl.addEventListener('change', render);
  </script>
</body>
</html>
"""


def process_file(
    content: str,
    timeout: float,
    api_keys: List[str],
    show_progress: bool = True,
    max_entries: int = 0,
) -> List[Dict[str, Any]]:
    tokens = extract_vmess_tokens(content)
    if max_entries > 0:
        tokens = tokens[:max_entries]

    dns_cache: Dict[str, str] = {}
    ip_cache: Dict[str, Dict[str, str]] = {}
    results: List[Dict[str, Any]] = []

    parse_progress = CliProgress("Parse + Resolve", len(tokens), enabled=show_progress)
    for idx, token in enumerate(tokens, start=1):
        item = parse_vmess(token)

        ip, dns_error = resolve_ip(item.get("add", ""), dns_cache)
        item["resolved_ip"] = ip

        if dns_error:
            item["status"] = "error"
            item["error"] = dns_error if not item.get("error") else item["error"]
        # Convert decoded object to compact json string for optional future use.
        if isinstance(item.get("decoded"), dict):
            item["decoded"] = json.dumps(
                item["decoded"], ensure_ascii=False, separators=(",", ":")
            )

        results.append(item)
        parse_progress.update(idx)

    parse_progress.finish()

    key_pool = ApiKeyPool(api_keys)
    unique_ips = sorted({r["resolved_ip"] for r in results if r.get("resolved_ip")})
    lookup_progress = CliProgress("IP Lookup", len(unique_ips), enabled=show_progress)
    for idx, ip in enumerate(unique_ips, start=1):
        ip_cache[ip] = lookup_ip_info(ip, key_pool, timeout)
        lookup_progress.update(idx)

    lookup_progress.finish()

    merge_progress = CliProgress("Merge Results", len(results), enabled=show_progress)
    for idx, item in enumerate(results, start=1):
        ip = item.get("resolved_ip", "")
        if ip:
            info = ip_cache.get(ip)
            if info:
                item.update(info)
        merge_progress.update(idx)

    merge_progress.finish()

    return results


def update_connectivity_status(
    rows: List[Dict[str, Any]],
    timeout: float,
    workers: int,
    show_progress: bool,
) -> None:
    candidates: List[Tuple[int, str, str, str, int]] = []
    for idx, row in enumerate(rows):
        derive_endpoint_fields(row)
        if str(row.get("status", "")).lower() != "ok":
            row["connectivity"] = "skipped"
            row["connectivity_detail"] = "Skipped because geolocation/status is not ok"
            continue

        token = str(row.get("vmess_original", "")).strip()
        add = str(row.get("add", "")).strip()
        ip = str(row.get("resolved_ip", "")).strip()
        try:
            port = int(row.get("endpoint_port", 0) or 0)
        except Exception:
            port = 0
        candidates.append((idx, token, add, ip, port))

    progress = CliProgress("Connectivity", len(candidates), enabled=show_progress)

    if not candidates:
        progress.finish()
        return

    max_workers = max(1, workers)
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        fut_map = {
            executor.submit(
                check_vmess_connectivity, token, add, ip, port, timeout
            ): idx
            for idx, token, add, ip, port in candidates
        }

        for future in concurrent.futures.as_completed(fut_map):
            row_idx = fut_map[future]
            try:
                state, detail = future.result()
            except Exception as exc:
                state, detail = "failed", f"Connectivity check error: {exc}"

            rows[row_idx]["connectivity"] = state
            rows[row_idx]["connectivity_detail"] = detail
            completed += 1
            progress.update(completed)

    progress.finish()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decode VMess configs and generate HTML report"
    )
    parser.add_argument(
        "-i", "--input", default="vmess_configs.txt", help="Input VMess text file"
    )
    parser.add_argument(
        "-o", "--output", default="report.html", help="Output HTML report file"
    )
    parser.add_argument("--json", default="report.json", help="Output JSON data file")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Generate HTML report from existing JSON without re-processing VMess",
    )
    parser.add_argument(
        "--report-json",
        default="report.json",
        help="Input JSON file when using --report-only",
    )
    parser.add_argument(
        "--check-connectivity",
        action="store_true",
        help="Check VMess TCP connectivity and update JSON/HTML",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=10.0,
        help="Max seconds per VMess connectivity check (recommended: 10)",
    )
    parser.add_argument(
        "--connect-workers",
        type=int,
        default=80,
        help="Parallel workers for connectivity checks",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=6.0,
        help="HTTP timeout for IP lookup (seconds)",
    )
    parser.add_argument(
        "--max-entries",
        type=int,
        default=0,
        help="How many VMess entries to process (0 = all entries)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Process all VMess entries in file",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable CLI progress bars",
    )
    args = parser.parse_args()

    env_keys = load_api_keys_from_env()
    api_keys = env_keys if env_keys else list(IPGEOLOCATION_KEYS)

    if args.report_only:
        if not os.path.exists(args.report_json):
            raise FileNotFoundError(
                f"Report JSON not found: {args.report_json}. "
                "Generate it first or pass a valid --report-json path."
            )
        with open(args.report_json, "r", encoding="utf-8") as jf:
            rows = json.load(jf)
        if not isinstance(rows, list):
            raise ValueError("Invalid report JSON format: expected a list of objects")
        rows = [r for r in rows if isinstance(r, dict)]
        source_label = args.report_json
    else:
        max_entries = 0 if args.all else max(0, args.max_entries)
        content, source_label = read_input_source(args.input, DEFAULT_VMESS_URL)
        rows = process_file(
            content,
            args.timeout,
            api_keys,
            show_progress=not args.no_progress,
            max_entries=max_entries,
        )

    if args.check_connectivity:
        update_connectivity_status(
            rows,
            timeout=max(1.0, min(10.0, args.connect_timeout)),
            workers=max(1, args.connect_workers),
            show_progress=not args.no_progress,
        )

    if args.report_only:
        with open(args.report_json, "w", encoding="utf-8") as jf:
            json.dump(rows, jf, ensure_ascii=False, indent=2)
    else:
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(rows, jf, ensure_ascii=False, indent=2)

    html_text = generate_html(rows, source_label)
    with open(args.output, "w", encoding="utf-8") as hf:
        hf.write(html_text)

    print(f"Processed VMess entries: {len(rows)}")
    print(f"HTML report generated: {args.output}")
    if args.report_only:
        print(f"JSON data updated: {args.report_json}")
    else:
        print(f"JSON data generated: {args.json}")


if __name__ == "__main__":
    main()
