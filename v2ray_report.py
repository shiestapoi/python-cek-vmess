"""
v2ray_report.py — VMess + VLess Decode & IP Intelligence Report
================================================================
Supports:
  • VMess (base64-JSON and URI-style)
  • VLess (URI-style: vless://UUID@host:port?...)
  • Dual geolocation: ipgeolocation.io (API-key) + ipapi.co (free)
  • Runtime mode: vmess | vless | all (default: all)
  • Separate or combined input files; auto-fetch from GitHub if no local file
  • Rich filterable HTML report + JSON output
"""

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


def _cpu_count() -> int:
    """Return logical CPU count, fallback to 4."""
    try:
        return max(1, os.cpu_count() or 4)
    except Exception:
        return 4


# Sensible default worker counts derived from CPU count.
# These can all be overridden via CLI flags.
_CPUS = _cpu_count()

# ── Default worker counts — NO artificial caps, scales with hardware ──────────
# All values are multiplied from CPU count; Python's ThreadPoolExecutor handles
# I/O-bound threads efficiently well beyond CPU count.
# Users can always reduce these via CLI flags if needed.
#
# Thread type   │ Why high?
# ──────────────┼──────────────────────────────────────────────────────────────
# PARSE/DNS     │ Pure I/O (getaddrinfo blocks), GIL released during syscall
# GEO HTTP      │ Pure I/O (curl subprocess), no GIL contention
# TCP pre-filter│ Pure I/O (socket.connect), hundreds are fine
# CONNECT       │ Thread pool wrapper for xray procs; actual procs capped by SEM
# XRAY_SEM      │ Actual live xray processes; each uses ~30-50 MB RAM

DEFAULT_PARSE_WORKERS   = _CPUS * 32   # DNS + parse: pure I/O
DEFAULT_GEO_WORKERS     = _CPUS * 32   # HTTP geo calls: pure I/O
DEFAULT_TCP_WORKERS     = _CPUS * 128  # socket.connect stage-1: pure I/O
DEFAULT_CONNECT_WORKERS = _CPUS * 128  # thread pool for stage-2 xray
DEFAULT_XRAY_SEMAPHORE  = _CPUS * 16   # live xray procs (~40 MB RAM each)


# ── Regex patterns ──────────────────────────────────────────────────────────
VMESS_PATTERN = re.compile(r"vmess://\S+")
VLESS_PATTERN = re.compile(r"vless://\S+")
BASE64_CHARS = re.compile(r"^[A-Za-z0-9_\-+/=]+")

# ── Default API keys (override via .env IPGEOLOCATION_API_KEYS) ─────────────
IPGEOLOCATION_KEYS: List[str] = [
    "efb9d83c2d2245f4abd557e68a8500d3",
    "e4f30a7389bc482f9782e1fd8a3f520c",
    "3091c2b2648b4b87b9a3e6a380b7b062",
    "42db810ae34c412e9e8f184cb47116a0",
]

# ── ISO 3166-1 alpha-2 country code → localized name (Indonesian/English mix) ─
# Used to translate mmdb country_code (e.g. "ID", "JP") to readable names
COUNTRY_NAMES: Dict[str, str] = {
    "AD": "Andorra", "AE": "Uni Emirat Arab", "AF": "Afghanistan",
    "AG": "Antigua dan Barbuda", "AI": "Anguilla", "AL": "Albania",
    "AM": "Armenia", "AO": "Angola", "AQ": "Antartika",
    "AR": "Argentina", "AS": "Samoa Amerika", "AT": "Austria",
    "AU": "Australia", "AW": "Aruba", "AX": "Kepulauan Aland",
    "AZ": "Azerbaijan", "BA": "Bosnia dan Herzegovina", "BB": "Barbados",
    "BD": "Bangladesh", "BE": "Belgia", "BF": "Burkina Faso",
    "BG": "Bulgaria", "BH": "Bahrain", "BI": "Burundi",
    "BJ": "Benin", "BL": "Saint Barthelemy", "BM": "Bermuda",
    "BN": "Brunei", "BO": "Bolivia", "BQ": "Karibia Belanda",
    "BR": "Brasil", "BS": "Bahama", "BT": "Bhutan",
    "BV": "Pulau Bouvet", "BW": "Botswana", "BY": "Belarus",
    "BZ": "Belize", "CA": "Kanada", "CC": "Kepulauan Cocos",
    "CD": "Kongo (RDK)", "CF": "Afrika Tengah", "CG": "Kongo",
    "CH": "Swiss", "CI": "Pantai Gading", "CK": "Kepulauan Cook",
    "CL": "Chili", "CM": "Kamerun", "CN": "China",
    "CO": "Kolombia", "CR": "Kosta Rika", "CU": "Kuba",
    "CV": "Tanjung Verde", "CW": "Curacao", "CX": "Pulau Christmas",
    "CY": "Siprus", "CZ": "Ceko", "DE": "Jerman",
    "DJ": "Djibouti", "DK": "Denmark", "DM": "Dominika",
    "DO": "Dominika (Rep)", "DZ": "Aljazair", "EC": "Ekuador",
    "EE": "Estonia", "EG": "Mesir", "EH": "Sahara Barat",
    "ER": "Eritrea", "ES": "Spanyol", "ET": "Etiopia",
    "FI": "Finlandia", "FJ": "Fiji", "FK": "Kepulauan Falkland",
    "FM": "Mikronesia", "FO": "Kepulauan Faroe", "FR": "Prancis",
    "GA": "Gabon", "GB": "Inggris", "GD": "Grenada",
    "GE": "Georgia", "GF": "Guyana Prancis", "GG": "Guernsey",
    "GH": "Ghana", "GI": "Gibraltar", "GL": "Greenland",
    "GM": "Gambia", "GN": "Guinea", "GP": "Guadeloupe",
    "GQ": "Guinea Ekuatorial", "GR": "Yunani", "GS": "Georgia Selatan",
    "GT": "Guatemala", "GU": "Guam", "GW": "Guinea-Bissau",
    "GY": "Guyana", "HK": "Hong Kong", "HM": "Heard & McDonald",
    "HN": "Honduras", "HR": "Kroasia", "HT": "Haiti",
    "HU": "Hungaria", "ID": "Indonesia", "IE": "Irlandia",
    "IL": "Israel", "IM": "Isle of Man", "IN": "India",
    "IO": "Teritorial Samudra Hindia", "IQ": "Irak", "IR": "Iran",
    "IS": "Islandia", "IT": "Italia", "JE": "Jersey",
    "JM": "Jamaika", "JO": "Yordania", "JP": "Jepang",
    "KE": "Kenya", "KG": "Kirgistan", "KH": "Kamboja",
    "KI": "Kiribati", "KM": "Komoro", "KN": "Saint Kitts dan Nevis",
    "KP": "Korea Utara", "KR": "Korea Selatan", "KW": "Kuwait",
    "KY": "Kepulauan Cayman", "KZ": "Kazakhstan", "LA": "Laos",
    "LB": "Lebanon", "LC": "Saint Lucia", "LI": "Liechtenstein",
    "LK": "Sri Lanka", "LR": "Liberia", "LS": "Lesotho",
    "LT": "Lituania", "LU": "Luksemburg", "LV": "Latvia",
    "LY": "Libya", "MA": "Maroko", "MC": "Monako",
    "MD": "Moldova", "ME": "Montenegro", "MF": "Saint Martin",
    "MG": "Madagaskar", "MH": "Kepulauan Marshall", "MK": "Makedonia Utara",
    "ML": "Mali", "MM": "Myanmar", "MN": "Mongolia",
    "MO": "Makau", "MP": "Kepulauan Mariana Utara", "MQ": "Martinik",
    "MR": "Mauritania", "MS": "Montserrat", "MT": "Malta",
    "MU": "Mauritius", "MV": "Maladewa", "MW": "Malawi",
    "MX": "Meksiko", "MY": "Malaysia", "MZ": "Mozambik",
    "NA": "Namibia", "NC": "Kaledonia Baru", "NE": "Niger",
    "NF": "Pulau Norfolk", "NG": "Nigeria", "NI": "Nikaragua",
    "NL": "Belanda", "NO": "Norwegia", "NP": "Nepal",
    "NR": "Nauru", "NU": "Niue", "NZ": "Selandia Baru",
    "OM": "Oman", "PA": "Panama", "PE": "Peru",
    "PF": "Polinesia Prancis", "PG": "Papua Nugini", "PH": "Filipina",
    "PK": "Pakistan", "PL": "Polandia", "PM": "Saint Pierre",
    "PN": "Kepulauan Pitcairn", "PR": "Puerto Riko", "PS": "Palestina",
    "PT": "Portugal", "PW": "Palau", "PY": "Paraguay",
    "QA": "Qatar", "RE": "Reunion", "RO": "Rumania",
    "RS": "Serbia", "RU": "Rusia", "RW": "Rwanda",
    "SA": "Arab Saudi", "SB": "Kepulauan Solomon", "SC": "Seychelles",
    "SD": "Sudan", "SE": "Swedia", "SG": "Singapura",
    "SH": "Saint Helena", "SI": "Slovenia", "SJ": "Svalbard",
    "SK": "Slovakia", "SL": "Sierra Leone", "SM": "San Marino",
    "SN": "Senegal", "SO": "Somalia", "SR": "Suriname",
    "SS": "Sudan Selatan", "ST": "Sao Tome", "SV": "El Salvador",
    "SX": "Sint Maarten", "SY": "Suriah", "SZ": "Eswatini",
    "TC": "Turks dan Caicos", "TD": "Chad", "TF": "Teritorial Selatan Prancis",
    "TG": "Togo", "TH": "Thailand", "TJ": "Tajikistan",
    "TK": "Tokelau", "TL": "Timor-Leste", "TM": "Turkmenistan",
    "TN": "Tunisia", "TO": "Tonga", "TR": "Turki",
    "TT": "Trinidad dan Tobago", "TV": "Tuvalu", "TW": "Taiwan",
    "TZ": "Tanzania", "UA": "Ukraina", "UG": "Uganda",
    "UM": "Outlying Islands AS", "US": "Amerika Serikat", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VA": "Vatikan", "VC": "Saint Vincent",
    "VE": "Venezuela", "VG": "Virgin Islands (UK)", "VI": "Virgin Islands (AS)",
    "VN": "Vietnam", "VU": "Vanuatu", "WF": "Wallis dan Futuna",
    "WS": "Samoa", "XK": "Kosovo", "YE": "Yaman",
    "YT": "Mayotte", "ZA": "Afrika Selatan", "ZM": "Zambia",
    "ZW": "Zimbabwe",
}


# ── ISO 3166-1 alpha-3 → alpha-2 (for mmdb sources that return 3-letter codes) ─
_ALPHA3_TO_ALPHA2: Dict[str, str] = {
    "AFG":"AF","ALB":"AL","DZA":"DZ","ASM":"AS","AND":"AD","AGO":"AO","AIA":"AI",
    "ATA":"AQ","ATG":"AG","ARG":"AR","ARM":"AM","ABW":"AW","AUS":"AU","AUT":"AT",
    "AZE":"AZ","BHS":"BS","BHR":"BH","BGD":"BD","BRB":"BB","BLR":"BY","BEL":"BE",
    "BLZ":"BZ","BEN":"BJ","BMU":"BM","BTN":"BT","BOL":"BO","BIH":"BA","BWA":"BW",
    "BVT":"BV","BRA":"BR","IOT":"IO","BRN":"BN","BGR":"BG","BFA":"BF","BDI":"BI",
    "CPV":"CV","KHM":"KH","CMR":"CM","CAN":"CA","CYM":"KY","CAF":"CF","TCD":"TD",
    "CHL":"CL","CHN":"CN","CXR":"CX","CCK":"CC","COL":"CO","COM":"KM","COD":"CD",
    "COG":"CG","COK":"CK","CRI":"CR","HRV":"HR","CUB":"CU","CUW":"CW","CYP":"CY",
    "CZE":"CZ","DNK":"DK","DJI":"DJ","DMA":"DM","DOM":"DO","ECU":"EC","EGY":"EG",
    "SLV":"SV","GNQ":"GQ","ERI":"ER","EST":"EE","SWZ":"SZ","ETH":"ET","FLK":"FK",
    "FRO":"FO","FJI":"FJ","FIN":"FI","FRA":"FR","GUF":"GF","PYF":"PF","ATF":"TF",
    "GAB":"GA","GMB":"GM","GEO":"GE","DEU":"DE","GHA":"GH","GIB":"GI","GRC":"GR",
    "GRL":"GL","GRD":"GD","GLP":"GP","GUM":"GU","GTM":"GT","GGY":"GG","GIN":"GN",
    "GNB":"GW","GUY":"GY","HTI":"HT","HMD":"HM","VAT":"VA","HND":"HN","HKG":"HK",
    "HUN":"HU","ISL":"IS","IND":"IN","IDN":"ID","IRN":"IR","IRQ":"IQ","IRL":"IE",
    "IMN":"IM","ISR":"IL","ITA":"IT","JAM":"JM","JPN":"JP","JEY":"JE","JOR":"JO",
    "KAZ":"KZ","KEN":"KE","KIR":"KI","PRK":"KP","KOR":"KR","KWT":"KW","KGZ":"KG",
    "LAO":"LA","LVA":"LV","LBN":"LB","LSO":"LS","LBR":"LR","LBY":"LY","LIE":"LI",
    "LTU":"LT","LUX":"LU","MAC":"MO","MDG":"MG","MWI":"MW","MYS":"MY","MDV":"MV",
    "MLI":"ML","MLT":"MT","MHL":"MH","MTQ":"MQ","MRT":"MR","MUS":"MU","MYT":"YT",
    "MEX":"MX","FSM":"FM","MDA":"MD","MCO":"MC","MNG":"MN","MNE":"ME","MSR":"MS",
    "MAR":"MA","MOZ":"MZ","MMR":"MM","NAM":"NA","NRU":"NR","NPL":"NP","NLD":"NL",
    "NCL":"NC","NZL":"NZ","NIC":"NI","NER":"NE","NGA":"NG","NIU":"NU","NFK":"NF",
    "MKD":"MK","MNP":"MP","NOR":"NO","OMN":"OM","PAK":"PK","PLW":"PW","PSE":"PS",
    "PAN":"PA","PNG":"PG","PRY":"PY","PER":"PE","PHL":"PH","PCN":"PN","POL":"PL",
    "PRT":"PT","PRI":"PR","QAT":"QA","REU":"RE","ROU":"RO","RUS":"RU","RWA":"RW",
    "BLM":"BL","SHN":"SH","KNA":"KN","LCA":"LC","MAF":"MF","SPM":"PM","VCT":"VC",
    "WSM":"WS","SMR":"SM","STP":"ST","SAU":"SA","SEN":"SN","SRB":"RS","SYC":"SC",
    "SLE":"SL","SGP":"SG","SXM":"SX","SVK":"SK","SVN":"SI","SLB":"SB","SOM":"SO",
    "ZAF":"ZA","SGS":"GS","SSD":"SS","ESP":"ES","LKA":"LK","SDN":"SD","SUR":"SR",
    "SJM":"SJ","SWE":"SE","CHE":"CH","SYR":"SY","TWN":"TW","TJK":"TJ","TZA":"TZ",
    "THA":"TH","TLS":"TL","TGO":"TG","TKL":"TK","TON":"TO","TTO":"TT","TUN":"TN",
    "TUR":"TR","TKM":"TM","TCA":"TC","TUV":"TV","UGA":"UG","UKR":"UA","ARE":"AE",
    "GBR":"GB","UMI":"UM","USA":"US","URY":"UY","UZB":"UZ","VUT":"VU","VEN":"VE",
    "VNM":"VN","VGB":"VG","VIR":"VI","WLF":"WF","ESH":"EH","YEM":"YE","ZMB":"ZM",
    "ZWE":"ZW","ALA":"AX","BES":"BQ","XKX":"XK",
}


def resolve_country_name(code_or_name: str) -> str:
    """Translate any country identifier to a human-readable name.

    Handles:
      - ISO 3166-1 alpha-2 (2-letter):  "JP"  → "Jepang"
      - ISO 3166-1 alpha-3 (3-letter):  "JPN" → "Jepang"
      - Already a full name:             "Japan" → "Japan" (passthrough)
      - Empty / dash:                    "—" → "—"
    """
    if not code_or_name:
        return code_or_name   # preserve empty string / None as-is; _s() handles it
    if code_or_name == "—":
        return "—"
    v = code_or_name.strip()
    if not v:
        return code_or_name
    # alpha-2: 2 uppercase letters
    if len(v) == 2 and v.isupper():
        return COUNTRY_NAMES.get(v, v)
    # alpha-3: 3 uppercase letters → convert to alpha-2 first
    if len(v) == 3 and v.isupper():
        alpha2 = _ALPHA3_TO_ALPHA2.get(v)
        if alpha2:
            return COUNTRY_NAMES.get(alpha2, v)
        return v
    # Already a full name — passthrough
    return v


# ── Remote default sources ───────────────────────────────────────────────────
IFCONFIG_URL = "https://ifconfig.me/ip"
DEFAULT_VMESS_URL = (
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list"
    "/refs/heads/main/vmess_configs.txt"
)
DEFAULT_VLESS_URL = (
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list"
    "/refs/heads/main/vless_configs.txt"
)

# ── Geo provider constants ───────────────────────────────────────────────────
# Fallback chain (auto):
#   ipgeolocation.io → ipapi.co → abstractapi.com → ipinfo.io/lite → mmdb (offline)
GEO_AUTO     = "auto"      # full chain above
GEO_APIKEY   = "apikey"    # only ipgeolocation.io (requires key)
GEO_FREE     = "free"      # ipapi.co → abstractapi → ipinfo.io → mmdb (no paid key)
GEO_IPINFO   = "ipinfo"    # only ipinfo.io/lite (requires token)
GEO_ABSTRACT = "abstract"  # only abstractapi.com (requires api key)
GEO_OFFLINE  = "offline"   # only local ipinfo_lite.mmdb (no network at all)

GEO_CHOICES = [GEO_AUTO, GEO_APIKEY, GEO_FREE, GEO_ABSTRACT, GEO_IPINFO, GEO_OFFLINE]

# ── Tokens / keys ────────────────────────────────────────────────────────────
IPINFO_DEFAULT_TOKEN    = "afa96d3d510513"       # ipinfo.io free demo token
ABSTRACTAPI_DEFAULT_KEY = "c7e6df44d71747a5928d71f0bbafca60"  # abstractapi free key
# ── Local MMDB filenames (auto-downloaded if missing) ────────────────────────
DEFAULT_MMDB_CITY_V4 = "geolite2-city-ipv4.mmdb"
DEFAULT_MMDB_CITY_V6 = "geolite2-city-ipv6.mmdb"
DEFAULT_MMDB_ASN_V4  = "geolite2-asn-ipv4.mmdb"
DEFAULT_MMDB_ASN_V6  = "geolite2-asn-ipv6.mmdb"

# ── Remote download URLs (sapics/ip-location-db) ─────────────────────────────
_MMDB_BASE = (
    "https://raw.githubusercontent.com/sapics/ip-location-db"
    "/refs/heads/main"
)
MMDB_REMOTE: Dict[str, str] = {
    DEFAULT_MMDB_CITY_V4: f"{_MMDB_BASE}/geolite2-city-mmdb/geolite2-city-ipv4.mmdb",
    DEFAULT_MMDB_CITY_V6: f"{_MMDB_BASE}/geolite2-city-mmdb/geolite2-city-ipv6.mmdb",
    DEFAULT_MMDB_ASN_V4 : f"{_MMDB_BASE}/geolite2-asn-mmdb/geolite2-asn-ipv4.mmdb",
    DEFAULT_MMDB_ASN_V6 : f"{_MMDB_BASE}/geolite2-asn-mmdb/geolite2-asn-ipv6.mmdb",
}

# ── Runtime mode constants ───────────────────────────────────────────────────
MODE_VMESS = "vmess"
MODE_VLESS = "vless"
MODE_ALL = "all"


# ════════════════════════════════════════════════════════════════════════════
# Utility helpers
# ════════════════════════════════════════════════════════════════════════════

def parse_bool_like(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text not in {"0", "false", "none", "off", "no", "null"}


def load_api_keys_from_env(
    env_path: str = ".env",
    env_var: str = "IPGEOLOCATION_API_KEYS",
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
        k, v = stripped.split("=", 1)
        if k.strip() == env_var:
            raw_value = v.strip()
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
            return [str(v).strip() for v in parsed if str(v).strip()]
    except Exception:
        pass

    value = raw_value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return [p.strip().strip('"').strip("'") for p in value.split(",") if p.strip()]


def _load_env_value(env_path: str, key: str) -> str:
    """Read a single key=value from an .env file.  Returns '' if missing."""
    if not os.path.exists(env_path):
        return ""
    try:
        with open(env_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                k, v = stripped.split("=", 1)
                if k.strip() == key:
                    v = v.strip().strip('"').strip("'")
                    return v
    except Exception:
        pass
    return ""


def _fetch_url(url: str, label: str = "") -> Tuple[str, str]:
    """Fetch text content from a URL.  Returns (content, url) or ("", url) on error."""
    name = label or url
    print(f"  [fetch] {name}", file=sys.stderr)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "v2ray-report/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        print(f"  [fetch] OK ({len(content)//1024} KB)", file=sys.stderr)
        return content, url
    except Exception as exc:
        print(f"  [fetch] FAILED {url}: {exc}", file=sys.stderr)
        return "", url


def read_source(file_path: Optional[str], fallback_url: str) -> Tuple[str, str]:
    """Read configs from *file_path* (local file or URL), or fall back to *fallback_url*.

    Priority:
      1. If file_path starts with http(s)://  → fetch as URL directly
      2. If file_path is a local path that exists → read from disk
      3. If file_path is set but not found → warn, fall back to fallback_url
      4. If file_path is empty/None → fetch fallback_url (script default)
    """
    if not file_path:
        # No input specified → use script default URL
        return _fetch_url(fallback_url, f"default: {fallback_url}")

    if file_path.startswith(("http://", "https://")):
        # Explicit URL passed as input
        return _fetch_url(file_path)

    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), file_path

    # Local file not found → fall back to default URL
    print(
        f"[warn] File not found: {file_path!r}. "
        f"Fetching from default URL: {fallback_url}",
        file=sys.stderr,
    )
    return _fetch_url(fallback_url, fallback_url)


# ════════════════════════════════════════════════════════════════════════════
# API-key pool + CLI progress bar
# ════════════════════════════════════════════════════════════════════════════

class ApiKeyPool:
    def __init__(self, keys: List[str]):
        self._lock = threading.Lock()
        self._state: Dict[str, bool] = {k: True for k in keys}

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
    def _fmt(sec: float) -> str:
        sec = max(0.0, sec)
        if sec < 60:
            return f"{sec:.1f}s"
        m, s = divmod(int(round(sec)), 60)
        if m < 60:
            return f"{m}m {s}s"
        h, m = divmod(m, 60)
        return f"{h}h {m}m {s}s"

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
            f"\r\x1b[36m{self.label:<20}\x1b[0m "
            f"[{bar}] {self.current:>5}/{self.total:<5} "
            f"{ratio * 100:6.2f}% "
            f"ETA {self._fmt(remain):>9}"
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


# ════════════════════════════════════════════════════════════════════════════
# Token extraction
# ════════════════════════════════════════════════════════════════════════════

def _sanitize_vmess(token: str) -> str:
    if not token.startswith("vmess://"):
        return ""
    body = token[len("vmess://"):]
    if not body:
        return ""
    if "@" in body or body.startswith("http"):
        m = re.match(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", body)
        return ("vmess://" + m.group(0)) if m else ""
    m = BASE64_CHARS.match(body)
    return ("vmess://" + m.group(0)) if m else ""


def _sanitize_vless(token: str) -> str:
    if not token.startswith("vless://"):
        return ""
    body = token[len("vless://"):]
    if not body:
        return ""
    m = re.match(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", body)
    return ("vless://" + m.group(0)) if m else ""


def extract_vmess_tokens(text: str) -> List[str]:
    return [c for raw in VMESS_PATTERN.findall(text) if (c := _sanitize_vmess(raw))]


def extract_vless_tokens(text: str) -> List[str]:
    return [c for raw in VLESS_PATTERN.findall(text) if (c := _sanitize_vless(raw))]


def extract_tokens(text: str, mode: str = MODE_ALL) -> List[str]:
    tokens: List[str] = []
    if mode in (MODE_VMESS, MODE_ALL):
        tokens.extend(extract_vmess_tokens(text))
    if mode in (MODE_VLESS, MODE_ALL):
        tokens.extend(extract_vless_tokens(text))
    return tokens


# ════════════════════════════════════════════════════════════════════════════
# Protocol parsers
# ════════════════════════════════════════════════════════════════════════════

def _base_row(protocol: str, original: str) -> Dict[str, Any]:
    return {
        "protocol": protocol,
        "original": original,
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


def decode_b64_json(payload: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    raw = payload.strip()
    if not raw:
        return None, "Empty payload"
    for candidate in (raw, raw.replace("-", "+").replace("_", "/")):
        padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False)
        except Exception:
            continue
        for enc in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                text = decoded.decode(enc).strip()
            except UnicodeDecodeError:
                continue
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
    result = _base_row("vmess", token)
    result["vmess_original"] = token  # backward compat

    body = token[len("vmess://"):]

    decoded_obj, decode_err = decode_b64_json(body)
    if decoded_obj is not None:
        result["format"] = "base64-json"
        result["decoded"] = decoded_obj
        result["add"] = str(decoded_obj.get("add", "")).strip()
        try:
            result["endpoint_port"] = int(str(decoded_obj.get("port", 0)).strip())
        except Exception:
            result["endpoint_port"] = 0
        result["tls_enabled"] = parse_bool_like(decoded_obj.get("tls", ""))
        return result

    # URI-style fallback
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
        q = urllib.parse.parse_qs(parsed.query)
        tls_q = str((q.get("security") or q.get("tls") or [""])[0])
        result["tls_enabled"] = tls_q.strip().lower() in {"tls", "true", "1"}
        return result

    result["status"] = "error"
    result["error"] = decode_err or "Unsupported vmess format"
    return result


def parse_vless(token: str) -> Dict[str, Any]:
    result = _base_row("vless", token)
    result["vless_original"] = token  # backward compat

    try:
        parsed = urllib.parse.urlsplit(token)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = f"Unable to parse vless URI: {exc}"
        return result

    if not parsed.hostname:
        result["status"] = "error"
        result["error"] = "Unsupported vless format or missing host"
        return result

    result["format"] = "uri-style"
    result["add"] = parsed.hostname.strip()
    result["endpoint_port"] = int(parsed.port or 0)

    q = urllib.parse.parse_qs(parsed.query)

    def _q(key: str, default: str = "") -> str:
        return str((q.get(key) or [default])[0])

    security = _q("security")
    result["tls_enabled"] = security.lower() in {"tls", "xtls", "reality"}
    result["uuid"] = parsed.username or ""
    result["name"] = urllib.parse.unquote(parsed.fragment or "")
    result["network"] = _q("type", "tcp")
    result["security_type"] = security or "none"
    result["sni"] = _q("sni")
    result["host"] = _q("host")
    result["path"] = _q("path", "/")
    result["fp"] = _q("fp")
    result["pbk"] = _q("pbk")   # Reality public key
    result["sid"] = _q("sid")   # Reality short ID
    result["flow"] = _q("flow")
    return result


def parse_token(token: str) -> Dict[str, Any]:
    if token.startswith("vmess://"):
        return parse_vmess(token)
    if token.startswith("vless://"):
        return parse_vless(token)
    return {
        "protocol": "unknown",
        "original": token,
        "status": "error",
        "error": "Unknown protocol prefix",
        "add": "",
        "endpoint_port": 0,
        "tls_enabled": False,
        "resolved_ip": "",
    }


# ════════════════════════════════════════════════════════════════════════════
# DNS / endpoint helpers
# ════════════════════════════════════════════════════════════════════════════

def derive_endpoint_fields(row: Dict[str, Any]) -> None:
    if row.get("endpoint_port") and row.get("add") and "tls_enabled" in row:
        return
    token = str(row.get("original", row.get("vmess_original", row.get("vless_original", "")))).strip()
    if not token:
        return
    protocol = str(row.get("protocol", "vmess"))
    parsed = parse_vmess(token) if protocol == "vmess" else parse_vless(token)

    if not row.get("add"):
        row["add"] = parsed.get("add", "")
    if not row.get("endpoint_port"):
        try:
            row["endpoint_port"] = int(parsed.get("endpoint_port", 0))
        except Exception:
            row["endpoint_port"] = 0
    if "tls_enabled" not in row:
        row["tls_enabled"] = bool(parsed.get("tls_enabled", False))


def resolve_ip(
    add: str,
    dns_cache: Dict[str, str],
    dns_lock: "Optional[threading.Lock]" = None,
) -> Tuple[str, str]:
    """Resolve *add* to IPv4.  Thread-safe when *dns_lock* is provided."""
    if not add:
        return "", "Missing add field"

    if add in dns_cache:
        return dns_cache[add], ""

    result_ip = ""
    error = ""
    try:
        ipaddress.ip_address(add)
        result_ip = add
    except ValueError:
        try:
            infos = socket.getaddrinfo(add, None, socket.AF_INET, socket.SOCK_STREAM)
            if infos:
                result_ip = str(infos[0][4][0])
            else:
                error = "DNS lookup returned no IPv4 result"
        except Exception as exc:
            error = f"DNS lookup failed: {exc}"

    if result_ip:
        if dns_lock:
            with dns_lock:
                dns_cache.setdefault(add, result_ip)
                result_ip = dns_cache[add]
        else:
            dns_cache[add] = result_ip

    return result_ip, error


def resolve_all_ipv4(host_or_ip: str) -> List[str]:
    try:
        ipaddress.ip_address(host_or_ip)
        return [host_or_ip]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host_or_ip, None, socket.AF_INET, socket.SOCK_STREAM)
        ips: List[str] = []
        for info in infos:
            ip = str(info[4][0])
            if ip not in ips:
                ips.append(ip)
        return ips
    except Exception:
        return []


def find_free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ════════════════════════════════════════════════════════════════════════════
# curl helpers
# ════════════════════════════════════════════════════════════════════════════

def run_curl_json(url: str, timeout: float) -> Optional[Dict[str, Any]]:
    cmd = [
        "curl", "-sS", "-X", "GET",
        "--max-time", f"{max(1.0, timeout)}",
        "--connect-timeout", f"{max(0.5, timeout)}",
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
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def run_curl_text(
    url: str, timeout: float, proxy: Optional[str] = None
) -> Tuple[bool, str, str]:
    cmd = [
        "curl", "-sS", "-L", "-X", "GET",
        "--max-time", f"{max(1.0, timeout)}",
        "--connect-timeout", f"{max(0.5, timeout)}",
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
    return (True, text, "") if text else (False, "", "Empty response")


# ════════════════════════════════════════════════════════════════════════════
# Connectivity checks (xray-based + TCP endpoint fallback)
# ════════════════════════════════════════════════════════════════════════════

def _xray_check(
    xray_config: Dict[str, Any],
    add: str,
    resolved_ip: str,
    timeout: float,
    label: str,
) -> Tuple[str, str]:
    """Shared xray runner used by both VMess and VLess checkers."""
    xray_bin = shutil.which("xray")
    if not xray_bin:
        return "failed", "xray binary not found in PATH"

    expected_ips: List[str] = []
    for ip in resolve_all_ipv4(add):
        if ip not in expected_ips:
            expected_ips.append(ip)
    if resolved_ip and resolved_ip not in expected_ips:
        expected_ips.append(resolved_ip)

    last_error = ""
    for _ in range(1):  # single attempt; caller retries via workers
        socks_port = find_free_local_port()
        xray_config["inbounds"][0]["port"] = socks_port

        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", delete=False
        ) as tf:
            cfg_path = tf.name
            json.dump(xray_config, tf, ensure_ascii=False)

        proc: Optional[subprocess.Popen[str]] = None
        try:
            proc = subprocess.Popen(
                [xray_bin, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            time.sleep(0.5)  # reduced from 1.2s; xray starts fast on modern hw
            if proc.poll() is not None:
                last_error = "xray exited early"
                continue

            ok, body, err = run_curl_text(
                IFCONFIG_URL,
                timeout=max(0.5, timeout),
                proxy=f"socks5h://127.0.0.1:{socks_port}",
            )
            if not ok:
                last_error = f"xray proxy curl failed: {err}"
                continue

            m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body)
            if not m:
                last_error = "ifconfig response has no IP"
                continue

            outbound_ip = m.group(0)
            if outbound_ip in expected_ips:
                return "ok", f"Matched via xray {label} socks :{socks_port}: {outbound_ip}"
            return (
                "not matched",
                f"Expected one of {', '.join(expected_ips) or '-'}, got {outbound_ip} via xray",
            )
        finally:
            if proc is not None:
                try:
                    proc.terminate(); proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                os.remove(cfg_path)
            except Exception:
                pass

    return "failed", (last_error or f"xray {label} connection failed")


def check_vmess_connectivity_via_xray(
    token: str, add: str, resolved_ip: str, port: int, timeout: float
) -> Tuple[str, str]:
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
    try:
        aid = int(str(decoded.get("aid", 0)).strip() or "0")
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
        headers = {"Host": host} if host else {}
        stream_settings["wsSettings"] = {"path": path, "headers": headers}

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": 0, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [{
            "protocol": "vmess",
            "settings": {"vnext": [{"address": add, "port": port,
                                     "users": [{"id": vmess_id, "alterId": aid, "security": scy}]}]},
            "streamSettings": stream_settings,
        }],
    }
    return _xray_check(config, add, resolved_ip, timeout, "vmess")


def check_vless_connectivity_via_xray(
    token: str, add: str, resolved_ip: str, port: int, timeout: float
) -> Tuple[str, str]:
    parsed = parse_vless(token)
    uuid = str(parsed.get("uuid", "")).strip()
    if not uuid:
        return "failed", "Missing vless UUID"

    net = str(parsed.get("network", "tcp") or "tcp").strip().lower()
    security = str(parsed.get("security_type", "") or "").strip().lower()
    sni = str(parsed.get("sni", "") or "").strip()
    host = str(parsed.get("host", "") or "").strip()
    path = str(parsed.get("path", "/") or "/").strip() or "/"
    fp = str(parsed.get("fp", "") or "").strip()
    pbk = str(parsed.get("pbk", "") or "").strip()
    sid = str(parsed.get("sid", "") or "").strip()
    flow = str(parsed.get("flow", "") or "").strip()

    user: Dict[str, Any] = {"id": uuid, "encryption": "none"}
    if flow:
        user["flow"] = flow

    stream_settings: Dict[str, Any] = {"network": net}
    if security in ("tls", "xtls"):
        stream_settings["security"] = "tls"
        tls_cfg: Dict[str, Any] = {"serverName": sni or host or add, "allowInsecure": True}
        if fp:
            tls_cfg["fingerprint"] = fp
        stream_settings["tlsSettings"] = tls_cfg
    elif security == "reality":
        stream_settings["security"] = "reality"
        stream_settings["realitySettings"] = {
            "serverName": sni or add,
            "publicKey": pbk,
            "shortId": sid,
            "fingerprint": fp or "chrome",
        }

    if net == "ws":
        headers = {"Host": host} if host else {}
        stream_settings["wsSettings"] = {"path": path, "headers": headers}
    elif net == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": path.lstrip("/")}

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": 0, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": add, "port": port, "users": [user]}]},
            "streamSettings": stream_settings,
        }],
    }
    return _xray_check(config, add, resolved_ip, timeout, "vless")


def check_proxy_connectivity(
    token: str, add: str, resolved_ip: str, port: int, timeout: float, protocol: str
) -> Tuple[str, str]:
    if protocol == "vless":
        return check_vless_connectivity_via_xray(token, add, resolved_ip, port, timeout)
    return check_vmess_connectivity_via_xray(token, add, resolved_ip, port, timeout)


# ════════════════════════════════════════════════════════════════════════════
# Geolocation / IP lookup
# ════════════════════════════════════════════════════════════════════════════

# ── Optional: maxminddb for offline mmdb ─────────────────────────────────────
try:
    import maxminddb as _maxminddb          # pip install maxminddb
    _MMDB_AVAILABLE = True
except ImportError:
    _maxminddb = None                       # type: ignore[assignment]
    _MMDB_AVAILABLE = False


def _download_mmdb(path: str, url: str) -> bool:
    """Download *url* → *path* using urllib.  Returns True on success."""
    print(f"  [mmdb] Downloading {os.path.basename(path)} ...", file=sys.stderr, end=" ", flush=True)
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            data = resp.read()
        with open(path, "wb") as f:
            f.write(data)
        size_kb = len(data) // 1024
        print(f"OK ({size_kb} KB)", file=sys.stderr)
        return True
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return False


def _ensure_mmdb(path: str, auto_download: bool = True) -> bool:
    """Return True if *path* exists locally.
    If not found and *auto_download* is True, attempt download from MMDB_REMOTE.
    """
    if os.path.exists(path):
        return True
    if not auto_download:
        return False
    url = MMDB_REMOTE.get(path) or MMDB_REMOTE.get(os.path.basename(path))
    if not url:
        return False
    return _download_mmdb(path, url)


def _load_mmdb(path: str, auto_download: bool = True) -> Any:
    """Ensure *path* exists (downloading if needed), then open and return reader."""
    if not _MMDB_AVAILABLE:
        print(
            f"[warn] maxminddb not installed; cannot load {path!r}.\n"
            "       Run: pip install maxminddb",
            file=sys.stderr,
        )
        return None
    if not _ensure_mmdb(path, auto_download):
        if not os.path.exists(path):
            print(f"[warn] mmdb file not found and could not be downloaded: {path!r}",
                  file=sys.stderr)
        return None
    try:
        return _maxminddb.open_database(path)
    except Exception as exc:
        print(f"[warn] Failed to open mmdb {path!r}: {exc}", file=sys.stderr)
        return None


class MmdbPair:
    """Holds IPv4 and IPv6 mmdb readers; routes .get(ip) to the correct one.

    Wraps two maxminddb readers so callers never need to check IP version
    manually.  Either reader can be None (e.g. only v4 file available).
    """

    def __init__(self, v4: Any, v6: Any) -> None:
        self.v4 = v4
        self.v6 = v6

    @property
    def loaded(self) -> bool:
        return self.v4 is not None or self.v6 is not None

    def get(self, ip: str) -> Any:
        """Query the correct reader based on IP version; return record or None."""
        try:
            ver = ipaddress.ip_address(ip).version
        except ValueError:
            ver = 4  # treat unparseable as IPv4
        reader = self.v6 if ver == 6 else self.v4
        if reader is None:
            # fall back to the other reader as best-effort
            reader = self.v4 if ver == 6 else self.v6
        if reader is None:
            return None
        try:
            return reader.get(ip)
        except Exception:
            return None

    def close(self) -> None:
        for r in (self.v4, self.v6):
            if r is not None:
                try:
                    r.close()
                except Exception:
                    pass

    def status(self, v4_path: str = "", v6_path: str = "") -> str:
        """Human-readable load status for summary output."""
        parts = []
        if v4_path:
            parts.append(f"v4:{os.path.basename(v4_path)}({'OK' if self.v4 else 'missing'})")
        if v6_path:
            parts.append(f"v6:{os.path.basename(v6_path)}({'OK' if self.v6 else 'missing'})")
        return ", ".join(parts) or "—"


def _s(v: Any, fallback: str = "—") -> str:
    """Safely convert a possibly-None / empty JSON value to a non-empty string.

    Returns *fallback* (default "—") instead of "Unknown" so the UI shows a
    clean dash rather than a misleading word when data is genuinely absent.
    """
    if v is None:
        return fallback
    s = str(v).strip()
    return s if s and s.lower() not in ("none", "null", "n/a", "") else fallback


def unknown_info(source: str = "none") -> Dict[str, str]:
    return {
        "country": "—",
        "city":    "—",
        "isp":     "—",
        "services": "—",
        "lookup_source": source,
    }


def should_disable_key(data: Dict[str, Any]) -> bool:
    merged = " ".join(
        str(data.get(k, "")).lower() for k in ("message", "error", "reason")
    )
    return any(w in merged for w in
               ("quota", "limit", "credit", "exceed", "invalid api", "unauthorized", "403"))


# ── Per-provider parsers ──────────────────────────────────────────────────────
# Each parser MUST return None only when the response is clearly unusable
# (missing mandatory fields like country).  Partial data (no city, no ASN) is
# still returned with "—" placeholders so the chain does NOT continue needlessly.

def parse_ipgeolocation_response(data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Parse api.ipgeolocation.io/v3/ipgeo response.

    Actual response keys (verified):
      data.location.country_name, .city, .state_prov, .continent_name
      data.asn.as_number, .organization
      data.time_zone.name
    """
    location = data.get("location")
    if not isinstance(location, dict):
        return None  # truly unusable

    asn_obj = data.get("asn") or {}
    tz_obj  = data.get("time_zone") or {}

    country = _s(location.get("country_name"))
    if country == "—":
        return None  # at minimum country must be present

    # City: prefer city, fall back to state/province, then continent
    city = (
        _s(location.get("city"))
        or _s(location.get("state_prov"))
        or _s(location.get("continent_name"))
    )

    isp       = _s(asn_obj.get("organization"))
    as_number = _s(asn_obj.get("as_number"), "")
    tz_name   = _s(tz_obj.get("name"), "")

    parts    = [p for p in (as_number, tz_name) if p and p != "—"]
    services = " | ".join(parts) or "—"

    return {"country": resolve_country_name(country), "city": city, "isp": isp,
            "services": services, "lookup_source": "ipgeolocation.io"}


def parse_ipapi_co_response(data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Parse ipapi.co/IP/json/ response.

    Actual response keys (verified):
      country_name, city, region (can be null!), org, asn, timezone
    Note: many fields can be null for certain IPs.
    """
    if data.get("error") or data.get("reserved"):
        return None

    country = _s(data.get("country_name"))
    if country == "—":
        return None

    # city → region (can be null) → country_capital → "—"
    city = (
        _s(data.get("city"))
        or _s(data.get("region"))
        or _s(data.get("country_capital"))
    )

    # ISP: prefer org, fall back to network
    isp = _s(data.get("org")) or _s(data.get("network"))

    asn      = _s(data.get("asn"), "")
    timezone = _s(data.get("timezone"), "")
    parts    = [p for p in (asn, timezone) if p and p != "—"]
    services = " | ".join(parts) or "—"

    return {"country": resolve_country_name(country), "city": city, "isp": isp,
            "services": services, "lookup_source": "ipapi.co"}


def parse_abstractapi_response(data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Parse ip-intelligence.abstractapi.com/v1/ response.

    Actual response keys (verified):
      data.location.country, .city, .region, .continent
      data.asn.asn, .name, .type
      data.timezone.name
    """
    if data.get("error"):
        return None

    location = data.get("location") or {}
    asn_obj  = data.get("asn")      or {}
    tz_obj   = data.get("timezone") or {}
    security = data.get("security") or {}

    country = _s(location.get("country"))
    if country == "—":
        return None

    # city → region → continent
    city = (
        _s(location.get("city"))
        or _s(location.get("region"))
        or _s(location.get("continent"))
    )

    isp  = _s(asn_obj.get("name"))
    asn  = _s(asn_obj.get("asn"), "")
    asn_str = f"AS{asn}" if asn and not str(asn).startswith("AS") else str(asn)

    tz   = _s(tz_obj.get("name"), "")

    # Security flags (vpn / proxy / tor / hosting)
    flags = [k.replace("is_", "") for k, v in security.items()
             if k.startswith("is_") and v is True]
    flags_str = ",".join(flags) if flags else ""

    parts    = [p for p in (asn_str, tz, flags_str) if p and p != "—"]
    services = " | ".join(parts) or "—"

    return {"country": resolve_country_name(country), "city": city, "isp": isp,
            "services": services, "lookup_source": "abstractapi.com"}


def parse_ipinfo_lite_response(data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Parse api.ipinfo.io/lite/IP response.

    Actual response keys (verified):
      ip, asn, as_name, as_domain, country_code, country, continent_code, continent
    Note: NO city field in lite version — use continent as geographic context.
    """
    if data.get("error") or data.get("bogon"):
        return None

    country = _s(data.get("country")) or _s(data.get("country_code"))
    if country == "—":
        return None

    # ipinfo lite has no city — use continent as best available geographic info
    city   = _s(data.get("continent"))   # e.g. "Asia", "Europe"
    isp    = _s(data.get("as_name"))
    asn    = _s(data.get("asn"), "")
    domain = _s(data.get("as_domain"), "")

    parts    = [p for p in (asn, domain) if p and p != "—"]
    services = " | ".join(parts) or "—"

    return {"country": resolve_country_name(country), "city": city, "isp": isp,
            "services": services, "lookup_source": "ipinfo.io/lite"}


def _to_plain(v: Any) -> Any:
    """Recursively convert maxminddb values to plain Python types."""
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, dict):
        return {k: _to_plain(vv) for k, vv in v.items()}
    if isinstance(v, (list, tuple)):
        return [_to_plain(i) for i in v]
    # maxminddb Record / Model objects expose .items()
    try:
        return {k: _to_plain(vv) for k, vv in v.items()}
    except (AttributeError, TypeError, ValueError):
        return str(v)


def _mmdb_to_dict(record: Any) -> Dict[str, Any]:
    """Safely convert a maxminddb record to a plain Python dict (recursive)."""
    if record is None:
        return {}
    if isinstance(record, dict):
        return {k: _to_plain(v) for k, v in record.items()}
    try:
        return {k: _to_plain(v) for k, v in record.items()}
    except (AttributeError, TypeError, ValueError):
        return {}


def parse_geolite2_city_record(record: Any) -> Dict[str, str]:
    """Parse GeoLite2-City.mmdb / ip-location-db city mmdb record.

    Verified schema from sapics/ip-location-db geolite2-city-ipv4/v6.mmdb:
      {
        "city":         "Palembang",   # may be empty string ""
        "country_code": "ID",          # ISO 3166-1 alpha-2
        "latitude":     -2.9146,
        "longitude":    104.7535,
        "postcode":     "30151",       # may be empty
        "state1":       "South Sumatra",  # province/region, may be empty
        "state2":       "",
        "timezone":     "Asia/Jakarta"
      }

    Also handles the MaxMind GeoLite2 nested schema (country.names.en, etc.)
    for compatibility with other mmdb sources.
    """
    d = _mmdb_to_dict(record)
    if not d:
        return {}

    def _names_en(obj: Any) -> str:
        """Extract .names.en from a MaxMind-style nested sub-object."""
        if not obj:
            return ""
        sub = _mmdb_to_dict(obj)
        names = _mmdb_to_dict(sub.get("names") or sub.get("name") or {})
        return _s(names.get("en") or names.get(""), "")

    # ── Country ──────────────────────────────────────────────────────────────
    # sapics flat layout uses "country_code" (ISO alpha-2, e.g. "ID", "HK")
    # MaxMind nested layout uses country.names.en / country.iso_code
    country_obj = d.get("country") or d.get("registered_country") or {}
    country = (
        _s(d.get("country_code"))                        # flat  (sapics)
        or _names_en(country_obj)                        # nested (MaxMind)
        or _s(d.get("country"))                          # flat country name
        or _s(d.get("country_name"))
    )

    # ── City ─────────────────────────────────────────────────────────────────
    # Priority: city → state1 (province) → state2 → MaxMind subdivisions
    #           → MaxMind continent → timezone region
    city_raw = _s(d.get("city"), "")
    city = city_raw if city_raw and city_raw != "—" else ""

    if not city:
        city = _s(d.get("state1"), "") or _s(d.get("state2"), "")

    if not city:
        # MaxMind nested subdivisions
        subdivisions = d.get("subdivisions") or []
        if subdivisions:
            try:
                city = _names_en(subdivisions[0])
            except Exception:
                city = ""

    if not city:
        city_obj = d.get("city") or {}
        city = _names_en(city_obj)

    if not city:
        city = _names_en(d.get("continent") or {}) or _s(d.get("continent"), "")

    if not city:
        # Last resort: extract region from timezone e.g. "Asia/Jakarta" → "Jakarta"
        tz = _s(d.get("timezone"), "")
        if tz and "/" in tz:
            city = tz.split("/", 1)[1].replace("_", " ")

    result: Dict[str, str] = {}
    if country and country != "—":
        result["country"] = resolve_country_name(country)
    result["city"] = city if city and city != "—" else "—"
    return result


def parse_geolite2_asn_record(record: Any) -> Dict[str, str]:
    """Parse GeoLite2-ASN.mmdb / dbip-asn.mmdb / geolite2-asn.mmdb record.

    GeoLite2-ASN schema (flat):
      autonomous_system_number         → int ASN
      autonomous_system_organization   → ISP name string

    DB-IP ASN schema (flat):
      asn                              → "AS12345" or int
      as_name / name / org            → ISP name
    """
    d = _mmdb_to_dict(record)
    if not d:
        return {}

    # ASN number: GeoLite2 uses autonomous_system_number (int); DB-IP uses "asn"
    asn_raw = (
        d.get("autonomous_system_number")
        or d.get("asn")
        or d.get("as_number")
        or ""
    )
    asn_str = str(asn_raw).strip()
    if asn_str and not asn_str.upper().startswith("AS"):
        asn_str = f"AS{asn_str}"

    # ISP/org name
    isp = (
        _s(d.get("autonomous_system_organization"))
        or _s(d.get("as_name"))
        or _s(d.get("name"))
        or _s(d.get("org"))
    )

    result: Dict[str, str] = {}
    if asn_str:
        result["asn"] = asn_str
    if isp and isp != "—":
        result["isp"] = isp
    return result


def merge_mmdb_lookup(
    city_pair: Any,   # MmdbPair or None
    asn_pair: Any,    # MmdbPair or None
    ip: str,
) -> Optional[Dict[str, str]]:
    """Query city + ASN MmdbPair objects, merge into a single geo info dict.

    Each pair automatically routes the query to the correct IPv4/IPv6 reader.
    Returns None only when no usable country data is found.
    """
    city_data: Dict[str, str] = {}
    asn_data:  Dict[str, str] = {}

    if city_pair is not None and city_pair.loaded:
        try:
            city_data = parse_geolite2_city_record(city_pair.get(ip)) or {}
        except Exception:
            city_data = {}

    if asn_pair is not None and asn_pair.loaded:
        try:
            asn_data = parse_geolite2_asn_record(asn_pair.get(ip)) or {}
        except Exception:
            asn_data = {}

    if not city_data and not asn_data:
        return None

    country = city_data.get("country", "—")
    if country == "—":
        return None

    city     = city_data.get("city", "—")
    isp      = asn_data.get("isp", "—")
    asn      = asn_data.get("asn", "")
    services = asn if asn else "—"

    # Indicate whether result came from v4 or v6 reader
    try:
        ver = f"ipv{ipaddress.ip_address(ip).version}"
    except Exception:
        ver = "ipv4"

    return {
        "country": resolve_country_name(country),
        "city":    city,
        "isp":     isp,
        "services": services,
        "lookup_source": f"geolite2-city+asn ({ver}, offline)",
    }


# ── Legacy ipinfo lite mmdb parser (kept for backward compat) ─────────────────
def parse_ipinfo_mmdb_record(record: Any) -> Optional[Dict[str, str]]:
    """Parse a record from ipinfo_lite.mmdb (flat layout matching ipinfo JSON API).

    Fields: country, country_code, asn, as_name, as_domain, continent
    """
    d = _mmdb_to_dict(record)
    if not d:
        return None

    country = _s(d.get("country")) or _s(d.get("country_code"))
    if country == "—":
        return None

    city   = _s(d.get("city")) or _s(d.get("continent"))
    isp    = _s(d.get("as_name")) or _s(d.get("org"))
    asn    = _s(d.get("asn"), "")
    domain = _s(d.get("as_domain"), "")
    parts  = [p for p in (asn, domain) if p and p != "—"]

    return {
        "country": resolve_country_name(country),
        "city":    city,
        "isp":     isp,
        "services": " | ".join(parts) or "—",
        "lookup_source": "ipinfo.mmdb (offline)",
    }


# ── HTTP fetchers ─────────────────────────────────────────────────────────────

def _fetch_json_bearer(url: str, token: str, timeout: float) -> Optional[Dict[str, Any]]:
    """Generic curl fetch with Bearer Authorization header → dict or None."""
    cmd = [
        "curl", "-sS", "-X", "GET",
        "--max-time",        f"{max(1.0, timeout)}",
        "--connect-timeout", f"{max(0.5, timeout)}",
        "-H", f"Authorization: Bearer {token}",
        url,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    text = (proc.stdout or "").strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _fetch_abstractapi(ip: str, api_key: str, timeout: float) -> Optional[Dict[str, Any]]:
    """Fetch ip-intelligence.abstractapi.com for *ip*."""
    url = (
        "https://ip-intelligence.abstractapi.com/v1/"
        f"?api_key={urllib.parse.quote(api_key)}"
        f"&ip_address={urllib.parse.quote(ip)}"
    )
    return run_curl_json(url, timeout)


# ── Main dispatcher ───────────────────────────────────────────────────────────

def lookup_ip_info(
    ip: str,
    key_pool: ApiKeyPool,
    timeout: float,
    geo_provider: str = GEO_AUTO,
    ipinfo_token: str = "",
    abstract_key: str = "",
    mmdb_city: Any = None,
    mmdb_asn: Any = None,
) -> Dict[str, str]:
    """Lookup geolocation for *ip*.

    Fallback chain (GEO_AUTO):
      1. ipgeolocation.io         — API key pool; all active keys tried in order
      2. ipapi.co                 — free, no key
      3. abstractapi.com          — free tier with API key
      4. ipinfo.io/lite           — free token (built-in or --ipinfo-token)
      5. GeoLite2-City + ASN mmdb — fully offline (--mmdb-city-v4/v6 + --mmdb-asn-v4/v6)
         Automatically routes IPv4/IPv6 IPs to the correct reader via MmdbPair.

    ip-api.com has been removed from the chain.
    """
    if not ip:
        return unknown_info("none")

    # ── Offline-only shortcut ─────────────────────────────────────────────────
    if geo_provider == GEO_OFFLINE:
        if mmdb_city is None and mmdb_asn is None:
            return unknown_info("mmdb-not-loaded")
        parsed = merge_mmdb_lookup(mmdb_city, mmdb_asn, ip)
        if parsed:
            return parsed
        return unknown_info("mmdb-miss")

    # ── ipinfo-only shortcut ──────────────────────────────────────────────────
    if geo_provider == GEO_IPINFO:
        token  = ipinfo_token or IPINFO_DEFAULT_TOKEN
        data   = _fetch_json_bearer(
            f"https://api.ipinfo.io/lite/{urllib.parse.quote(ip)}", token, timeout
        )
        parsed = parse_ipinfo_lite_response(data or {})
        return parsed if parsed else unknown_info("ipinfo-unavailable")

    # ── abstractapi-only shortcut ─────────────────────────────────────────────
    if geo_provider == GEO_ABSTRACT:
        key    = abstract_key or ABSTRACTAPI_DEFAULT_KEY
        data   = _fetch_abstractapi(ip, key, timeout)
        parsed = parse_abstractapi_response(data or {})
        return parsed if parsed else unknown_info("abstractapi-unavailable")

    # ── 1. ipgeolocation.io (API key pool) ───────────────────────────────────
    if geo_provider in (GEO_AUTO, GEO_APIKEY):
        for api_key in key_pool.ordered_keys():
            url = (
                "https://api.ipgeolocation.io/v3/ipgeo"
                f"?apiKey={urllib.parse.quote(api_key)}"
                f"&ip={urllib.parse.quote(ip)}"
            )
            data = run_curl_json(url, timeout)
            if data:
                parsed = parse_ipgeolocation_response(data)
                if parsed:
                    return parsed
                if should_disable_key(data):
                    key_pool.disable(api_key)

    if geo_provider == GEO_APIKEY:
        return unknown_info("apikey-unavailable")

    # ── 2. ipapi.co (free) ───────────────────────────────────────────────────
    if geo_provider in (GEO_AUTO, GEO_FREE):
        data   = run_curl_json(f"https://ipapi.co/{urllib.parse.quote(ip)}/json/", timeout)
        parsed = parse_ipapi_co_response(data or {})
        if parsed:
            return parsed

    # ── 3. abstractapi.com (free key) ────────────────────────────────────────
    if geo_provider in (GEO_AUTO, GEO_FREE):
        key    = abstract_key or ABSTRACTAPI_DEFAULT_KEY
        data   = _fetch_abstractapi(ip, key, timeout)
        parsed = parse_abstractapi_response(data or {})
        if parsed:
            return parsed

    # ── 4. ipinfo.io/lite (free token) ───────────────────────────────────────
    if geo_provider in (GEO_AUTO, GEO_FREE):
        token  = ipinfo_token or IPINFO_DEFAULT_TOKEN
        data   = _fetch_json_bearer(
            f"https://api.ipinfo.io/lite/{urllib.parse.quote(ip)}", token, timeout
        )
        parsed = parse_ipinfo_lite_response(data or {})
        if parsed:
            return parsed

    # ── 5. GeoLite2-City + ASN mmdb (offline last resort) ────────────────────
    if geo_provider in (GEO_AUTO, GEO_FREE) and (mmdb_city.loaded or mmdb_asn.loaded):
        parsed = merge_mmdb_lookup(mmdb_city, mmdb_asn, ip)
        if parsed:
            return parsed

    return unknown_info("unavailable")






# ════════════════════════════════════════════════════════════════════════════
# Checkpoint helpers
# ════════════════════════════════════════════════════════════════════════════

# Checkpoint file schema (JSON):
# {
#   "version": 1,
#   "source_label": "...",
#   "mode": "all",
#   "steps_done": ["parse", "geo", "connectivity"],   # completed steps
#   "rows": [...]
# }
#
# Steps in order:
#   parse        — token extraction + DNS resolve
#   geo          — IP geolocation
#   connectivity — TCP pre-filter + xray check

CHECKPOINT_VERSION = 1
STEPS_ALL = ["parse", "geo", "connectivity"]


def ckpt_load(path: str) -> Optional[Dict[str, Any]]:
    """Load checkpoint JSON.  Returns None if missing / incompatible."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        if data.get("version") != CHECKPOINT_VERSION:
            print(f"[ckpt] Incompatible checkpoint version, ignoring: {path}", file=sys.stderr)
            return None
        if not isinstance(data.get("rows"), list):
            return None
        return data
    except Exception as exc:
        print(f"[ckpt] Failed to load checkpoint {path!r}: {exc}", file=sys.stderr)
        return None


def ckpt_save(path: str, rows: List[Dict[str, Any]], steps_done: List[str],
              source_label: str, mode: str) -> None:
    """Atomically write checkpoint JSON (write to tmp then rename)."""
    if not path:
        return
    tmp = path + ".tmp"
    try:
        payload = {
            "version": CHECKPOINT_VERSION,
            "source_label": source_label,
            "mode": mode,
            "steps_done": steps_done,
            "rows": rows,
        }
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        print(f"  [ckpt] Saved checkpoint ({len(rows)} rows, steps done: {steps_done})",
              file=sys.stderr)
    except Exception as exc:
        print(f"[ckpt] Failed to save checkpoint {path!r}: {exc}", file=sys.stderr)
        try:
            os.remove(tmp)
        except Exception:
            pass


def ckpt_steps_done(ckpt: Optional[Dict[str, Any]]) -> List[str]:
    if not ckpt:
        return []
    return list(ckpt.get("steps_done") or [])


def ckpt_step_done(ckpt: Optional[Dict[str, Any]], step: str) -> bool:
    return step in ckpt_steps_done(ckpt)


# ════════════════════════════════════════════════════════════════════════════
# HTML report generation
# ════════════════════════════════════════════════════════════════════════════


def generate_html(rows: List[Dict[str, Any]], source_label: str, mode: str = MODE_ALL, ok_only: bool = True) -> str:
    """Generate a lightweight, virtual-scrolled HTML report.

    Optimisations vs the old version:
    1. Heavy per-row fields (original URI, decoded JSON, connectivity_detail)
       are stripped from the main `data` array and stored in two side arrays:
         uris[i]     – the raw vmess/vless config string (for Copy)
         details[i]  – {connectivity_detail, decoded}  (modal only)
       This typically cuts embedded JSON size by 60–80 %.
    2. Virtual scrolling: only PAGE_SIZE rows are rendered in the DOM at any
       time.  Scrolling / filtering repaints only the visible window.
    3. Debounced search input (150 ms) avoids re-filtering on every keystroke.
    """
    # ── Filter rows for HTML (ok_only keeps only connectivity=ok entries) ──────
    if ok_only:
        html_rows = [r for r in rows if r.get("connectivity") == "ok"]
        ok_label = " · ok only"
    else:
        html_rows = list(rows)
        ok_label = ""

    countries = sorted({row.get("country", "—") for row in html_rows if row.get("country","—") != "—"})
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_vmess = sum(1 for r in html_rows if r.get("protocol") == "vmess")
    total_vless = sum(1 for r in html_rows if r.get("protocol") == "vless")
    mode_label  = {"vmess": "VMess Only", "vless": "VLess Only", "all": "VMess + VLess"}.get(mode, "All")

    # ── Split heavy fields out of main data array ─────────────────────────────
    slim_rows = []
    uris      = []   # full config URI per row (for Copy button)
    details   = []   # {connectivity_detail, decoded} per row (modal only)

    HEAVY = {"original", "vmess_original", "vless_original", "decoded",
             "connectivity_detail"}

    for r in html_rows:
        uri = str(r.get("original") or r.get("vmess_original") or r.get("vless_original") or "")
        uris.append(uri)
        details.append({
            "connectivity_detail": str(r.get("connectivity_detail") or ""),
            "decoded": str(r.get("decoded") or ""),
        })
        slim_rows.append({k: v for k, v in r.items() if k not in HEAVY})

    data_json    = json.dumps(slim_rows, ensure_ascii=False, separators=(",", ":"))
    uris_json    = json.dumps(uris,      ensure_ascii=False, separators=(",", ":"))
    details_json = json.dumps(details,   ensure_ascii=False, separators=(",", ":"))
    countries_json = json.dumps(countries, ensure_ascii=False)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>V2Ray Proxy Report</title>
  <style>
    :root{{
      --bg:#0b111b;--bg-alt:#121b2a;--panel:#111827;
      --line:#273247;--text:#e5ecf5;--muted:#95a2b7;
      --accent:#19c8b4;--accent-2:#28a8ff;
      --good:#16c47f;--bad:#ef5350;--chip:#1b2638;
    }}
    *{{box-sizing:border-box;}}
    body{{margin:0;font-family:"Segoe UI","Helvetica Neue",Helvetica,Arial,sans-serif;color:var(--text);
      background:radial-gradient(1200px 700px at 10% 0%,#132138 0%,var(--bg) 50%),
                 linear-gradient(180deg,#0b111b 0%,#09101a 100%);min-height:100vh;}}
    .wrap{{max-width:1500px;margin:0 auto;padding:24px 16px 40px;}}
    .hero{{background:linear-gradient(130deg,rgba(25,200,180,.12),rgba(167,139,250,.12));
      border:1px solid var(--line);border-radius:16px;padding:18px;margin-bottom:14px;}}
    h1{{margin:0 0 5px;font-size:22px;}}
    .meta{{color:var(--muted);font-size:12px;}}
    .stats{{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;}}
    .chip{{background:var(--chip);border:1px solid var(--line);color:#c6d4e8;
      border-radius:999px;padding:5px 10px;font-size:12px;}}
    .chip-vmess{{border-color:#1e6090;color:#93d3ff;}}
    .chip-vless{{border-color:#6040b0;color:#c8b0ff;}}
    .controls{{display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr 1fr 1fr;gap:8px;margin:12px 0;}}
    @media(max-width:900px){{.controls{{grid-template-columns:1fr 1fr;}}}}
    @media(max-width:500px){{.controls{{grid-template-columns:1fr;}}}}
    input,select{{width:100%;background:var(--panel);color:var(--text);border:1px solid var(--line);
      border-radius:10px;height:40px;padding:0 11px;outline:none;font-size:13px;}}
    input:focus,select:focus{{border-color:var(--accent-2);box-shadow:0 0 0 3px rgba(40,168,255,.18);}}
    /* virtual scroll container */
    .tbl-wrap{{border:1px solid var(--line);border-radius:14px;overflow:hidden;
      background:rgba(17,24,39,.95);}}
    .tbl-scroll{{overflow-y:auto;max-height:72vh;}}
    table{{width:100%;border-collapse:collapse;table-layout:fixed;}}
    thead th{{position:sticky;top:0;z-index:2;background:#182235;color:#d3dff0;
      text-align:left;font-size:12px;letter-spacing:.3px;padding:11px 9px;
      border-bottom:1px solid var(--line);}}
    tbody td{{padding:9px;border-bottom:1px solid rgba(39,50,71,.55);
      vertical-align:top;font-size:13px;line-height:1.4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
    .td-isp{{max-width:180px;}}
    tbody tr:hover{{background:rgba(40,168,255,.06);}}
    .tag{{display:inline-block;border-radius:999px;padding:2px 7px;font-size:11px;
      background:var(--chip);border:1px solid var(--line);color:#cfe2ff;}}
    .proto-vmess{{background:#112840;border-color:#1e6090;color:#93d3ff;}}
    .proto-vless{{background:#1e1040;border-color:#6040b0;color:#c8b0ff;}}
    .ok{{color:var(--good);}} .err{{color:var(--bad);}}
    .conn-pill{{display:inline-block;padding:2px 7px;border-radius:999px;font-size:11px;
      border:1px solid var(--line);background:var(--chip);}}
    .conn-ok{{color:#baf5d8;border-color:#2c8c67;background:#123f31;}}
    .conn-failed{{color:#ffd1d1;border-color:#a84747;background:#4d1f1f;}}
    .conn-not-matched{{color:#ffe7bf;border-color:#a16b2f;background:#4a3114;}}
    .conn-skipped{{color:#c4d0df;border-color:#4c5f7a;background:#1f2b3e;}}
    .copy-btn{{border:1px solid #365177;background:#1b2b45;color:#d7e8ff;border-radius:8px;
      padding:5px 9px;font-size:12px;cursor:pointer;white-space:nowrap;}}
    .copy-btn:hover{{background:#23406d;}} .copy-btn.copied{{border-color:#219e78;background:#164e3f;color:#d5ffe8;}}
    /* pagination */
    .pager{{display:flex;align-items:center;gap:6px;padding:10px 14px;
      border-top:1px solid var(--line);flex-wrap:wrap;}}
    .pager button{{background:var(--chip);border:1px solid var(--line);color:var(--text);
      border-radius:8px;padding:4px 10px;cursor:pointer;font-size:12px;}}
    .pager button:hover{{background:#253448;}} .pager button:disabled{{opacity:.35;cursor:default;}}
    .pager button.active{{background:#1d3b5e;border-color:var(--accent-2);color:#7dcfff;}}
    .pager-info{{color:var(--muted);font-size:12px;margin-left:auto;}}
    /* modal */
    .modal{{position:fixed;inset:0;display:none;align-items:center;justify-content:center;
      background:rgba(8,12,22,.8);backdrop-filter:blur(3px);z-index:25;padding:14px;}}
    .modal.open{{display:flex;}}
    .modal-card{{width:min(860px,100%);max-height:90vh;overflow:auto;border:1px solid var(--line);
      border-radius:14px;background:#0f1727;box-shadow:0 20px 40px rgba(0,0,0,.4);}}
    .modal-head{{display:flex;justify-content:space-between;align-items:center;
      padding:13px;border-bottom:1px solid var(--line);}}
    .modal-title{{font-weight:600;}}
    .modal-body{{padding:13px;display:grid;gap:7px;}}
    .kv{{display:grid;grid-template-columns:160px 1fr;gap:9px;font-size:13px;}}
    .kv-sep{{border-top:1px solid var(--line);padding-top:7px;margin-top:3px;}}
    .k{{color:var(--muted);}} .v{{word-break:break-all;}}
    .mono{{font-family:Consolas,"Courier New",monospace;word-break:break-all;color:#d7e3f3;}}
    @media(max-width:600px){{
      .tbl-wrap{{border:0;background:transparent;}}
      table,thead,tbody,th,td,tr{{display:block;width:100%;}}
      thead{{display:none;}}
      tbody tr{{background:rgba(17,24,39,.95);border:1px solid var(--line);
        border-radius:12px;margin-bottom:10px;padding:8px;}}
      tbody td{{border-bottom:0;display:grid;grid-template-columns:110px 1fr;
        gap:8px;padding:7px;white-space:normal;}}
      tbody td::before{{content:attr(data-label);color:var(--muted);font-size:12px;}}
      .kv{{grid-template-columns:1fr;}}
    }}
  </style>
</head>
<body>
<div class="wrap">
  <section class="hero">
    <h1>&#128737; V2Ray Proxy Report <span style="font-size:13px;color:var(--muted);font-weight:400">({html.escape(mode_label + ok_label)})</span></h1>
    <div class="meta">Source: {html.escape(source_label)} &nbsp;|&nbsp; Generated: {html.escape(now)}</div>
    <div class="stats">
      <div class="chip" id="countAll">Total: 0</div>
      <div class="chip" id="countShown">Shown: 0</div>
      <div class="chip" id="countCtr">Countries: 0</div>
      <div class="chip chip-vmess">VMess: {total_vmess}</div>
      <div class="chip chip-vless">VLess: {total_vless}</div>
    </div>
  </section>

  <section class="controls">
    <input id="search" type="text" placeholder="Search host / IP / ISP / UUID / country..."/>
    <select id="proto"></select>
    <select id="country"></select>
    <select id="isp"></select>
    <select id="conn"></select>
    <select id="tls"></select>
  </section>

  <section class="tbl-wrap">
    <div class="tbl-scroll" id="tblScroll">
      <table>
        <thead>
          <tr>
            <th style="width:42px">#</th>
            <th style="width:76px">Proto</th>
            <th style="width:115px">Country</th>
            <th>ISP</th>
            <th style="width:108px">Connectivity</th>
            <th style="width:78px">Status</th>
            <th style="width:60px">TLS</th>
            <th style="width:76px">Action</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <div class="pager" id="pager"></div>
  </section>
</div>

<div id="detailModal" class="modal" onclick="closeModal()">
  <div class="modal-card" onclick="event.stopPropagation()">
    <div class="modal-head">
      <div class="modal-title" id="modalTitle">Proxy Detail</div>
      <button class="copy-btn" onclick="closeModal()">&#10005; Close</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<script>
// ── Data (heavy fields stripped; URIs and detail info stored separately) ────
const data    = {data_json};
const uris    = {uris_json};
const details = {details_json};
const countries = {countries_json};

// ── State ────────────────────────────────────────────────────────────────────
const PAGE_SIZE = 100;
let filtered  = [];   // indices into data[] after filter
let page      = 0;    // current page (0-based)
let searchDebounce = null;

// ── DOM refs ─────────────────────────────────────────────────────────────────
const rowsEl    = document.getElementById('rows');
const searchEl  = document.getElementById('search');
const protoEl   = document.getElementById('proto');
const countryEl = document.getElementById('country');
const ispEl     = document.getElementById('isp');
const connEl    = document.getElementById('conn');
const tlsEl     = document.getElementById('tls');
const pagerEl   = document.getElementById('pager');
const countAllEl   = document.getElementById('countAll');
const countShownEl = document.getElementById('countShown');
const countCtrEl   = document.getElementById('countCtr');

// ── Utilities ─────────────────────────────────────────────────────────────────
function esc(v) {{
  return String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}}
function enc(v){{return encodeURIComponent(String(v??''));}}

function connClass(s) {{
  const v=String(s||'unknown').toLowerCase();
  if(v==='ok') return 'conn-pill conn-ok';
  if(v==='not matched') return 'conn-pill conn-not-matched';
  if(v==='failed') return 'conn-pill conn-failed';
  return 'conn-pill conn-skipped';
}}
function protoBadge(p) {{
  const cl=p==='vless'?'proto-vless':'proto-vmess';
  return `<span class="tag ${{cl}}">${{esc(p||'vmess')}}</span>`;
}}

// ── Filter ────────────────────────────────────────────────────────────────────
function rowMatches(row, i, q, proto, country, isp, conn, tls) {{
  if(proto!=='ALL' && row.protocol!==proto) return false;
  if(country!=='ALL' && row.country!==country) return false;
  if(isp!=='ALL' && row.isp!==isp) return false;
  if(conn!=='ALL' && (row.connectivity||'unknown')!==conn) return false;
  if(tls!=='ALL' && (row.tls_enabled?'true':'false')!==tls) return false;
  if(!q) return true;
  const hay=[
    row.add, row.resolved_ip, row.country, row.city,
    row.isp, row.services, row.connectivity,
    row.status, row.error, row.uuid, row.protocol, row.name,
    uris[i]   // search inside the URI too
  ].join(' ').toLowerCase();
  return hay.includes(q);
}}

// ── Select helpers ─────────────────────────────────────────────────────────────
function buildSelect(el, values, allLabel) {{
  const prev=el.value||'ALL';
  el.innerHTML='';
  const o=document.createElement('option');
  o.value='ALL'; o.textContent=allLabel; el.appendChild(o);
  values.forEach(v=>{{const x=document.createElement('option');x.value=v;x.textContent=v;el.appendChild(x);}});
  el.value=values.includes(prev)?prev:'ALL';
}}
function buildProto()    {{buildSelect(protoEl,['vmess','vless'],'All Protocols');}}
function buildCountry()  {{buildSelect(countryEl,countries,'All Countries');}}
function buildIsp(pr,co) {{
  const list=data
    .filter(r=>(pr==='ALL'||r.protocol===pr)&&(co==='ALL'||r.country===co))
    .map(r=>r.isp||'—');
  buildSelect(ispEl,[...new Set(list)].sort((a,b)=>a.localeCompare(b)),
    co==='ALL'?'All ISP':`ISP (${{co}})`);
}}
function buildConn(pr,co,is) {{
  const list=data
    .filter(r=>(pr==='ALL'||r.protocol===pr)&&(co==='ALL'||r.country===co)&&(is==='ALL'||r.isp===is))
    .map(r=>r.connectivity||'unknown');
  buildSelect(connEl,[...new Set(list)].sort((a,b)=>a.localeCompare(b)),'All Connectivity');
}}
function buildTls()      {{buildSelect(tlsEl,['true','false'],'All TLS');}}

// ── Pagination ─────────────────────────────────────────────────────────────────
function renderPage() {{
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  if(page >= totalPages) page = totalPages - 1;

  const start = page * PAGE_SIZE;
  const end   = Math.min(start + PAGE_SIZE, filtered.length);
  const slice = filtered.slice(start, end);

  rowsEl.innerHTML = slice.map((di, si) => {{
    const row = data[di];
    const num = start + si + 1;
    return `<tr>
      <td data-label="#">${{num}}</td>
      <td data-label="Proto">${{protoBadge(row.protocol)}}</td>
      <td data-label="Country"><span class="tag">${{esc(row.country||'—')}}</span></td>
      <td data-label="ISP" class="td-isp" title="${{esc(row.isp||'—')}}">${{esc(row.isp||'—')}}</td>
      <td data-label="Connectivity">
        <span class="${{connClass(row.connectivity)}}"
          title="${{esc(details[di]?.connectivity_detail||'')}}">
          ${{esc(row.connectivity||'unknown')}}
        </span>
      </td>
      <td data-label="Status" class="${{row.status==='ok'?'ok':'err'}}">${{esc(row.status)}}${{row.error?' — '+esc(row.error):''}}</td>
      <td data-label="TLS"><span class="tag">${{row.tls_enabled?'true':'false'}}</span></td>
      <td data-label="Action"><button class="copy-btn" onclick="openDetail(${{di}})">Detail</button></td>
    </tr>`;
  }}).join('');

  // ── Pager controls ────────────────────────────────────────────────────────
  if(totalPages <= 1){{pagerEl.innerHTML='';return;}}
  let html='';
  html+=`<button onclick="goPage(0)"  ${{page===0?'disabled':''}}>&#171; First</button>`;
  html+=`<button onclick="goPage(${{page-1}})" ${{page===0?'disabled':''}}>&#8249; Prev</button>`;

  // page number buttons: show window of 5 around current
  const win=2;
  const lo=Math.max(0,page-win), hi=Math.min(totalPages-1,page+win);
  if(lo>0) html+=`<button onclick="goPage(0)">1</button>${{lo>1?'<span style="color:var(--muted);padding:0 4px">…</span>':''}}`;
  for(let p2=lo;p2<=hi;p2++){{
    html+=`<button onclick="goPage(${{p2}})" class="${{p2===page?'active':''}}">${{p2+1}}</button>`;
  }}
  if(hi<totalPages-1){{
    html+=`${{hi<totalPages-2?'<span style="color:var(--muted);padding:0 4px">…</span>':''}}`;
    html+=`<button onclick="goPage(${{totalPages-1}})">${{totalPages}}</button>`;
  }}
  html+=`<button onclick="goPage(${{page+1}})" ${{page===totalPages-1?'disabled':''}}>Next &#8250;</button>`;
  html+=`<button onclick="goPage(${{totalPages-1}})" ${{page===totalPages-1?'disabled':''}}>Last &#187;</button>`;
  html+=`<span class="pager-info">${{start+1}}–${{end}} of ${{filtered.length}}</span>`;
  pagerEl.innerHTML=html;
}}

function goPage(p) {{
  page = p;
  renderPage();
  document.getElementById('tblScroll').scrollTop=0;
}}

// ── Main render (filter + reset to page 0) ────────────────────────────────────
function render() {{
  const q       = searchEl.value.trim().toLowerCase();
  const proto   = protoEl.value  ||'ALL';
  const country = countryEl.value||'ALL';
  const isp     = ispEl.value    ||'ALL';
  const conn    = connEl.value   ||'ALL';
  const tls     = tlsEl.value    ||'ALL';

  filtered = [];
  for(let i=0;i<data.length;i++) {{
    if(rowMatches(data[i], i, q, proto, country, isp, conn, tls)) filtered.push(i);
  }}
  page = 0;

  const shownCtrs = new Set(filtered.map(i=>data[i].country)).size;
  countAllEl.textContent   = `Total: ${{data.length}}`;
  countShownEl.textContent = `Shown: ${{filtered.length}}`;
  countCtrEl.textContent   = `Countries: ${{shownCtrs}}`;

  renderPage();
}}

// ── Detail modal ───────────────────────────────────────────────────────────────
function openDetail(di) {{
  const row = data[di];
  const uri = uris[di] || '';
  const det = details[di] || {{}};
  const isVless = row.protocol==='vless';
  document.getElementById('modalTitle').textContent=(isVless?'VLess':'VMess')+' Detail';
  const body=document.getElementById('modalBody');

  let protoRows='';
  if(isVless){{
    protoRows=`
      <div class="kv kv-sep"><div class="k">Protocol</div><div class="v">${{protoBadge('vless')}}</div></div>
      <div class="kv"><div class="k">UUID</div><div class="v mono">${{esc(row.uuid||'—')}}</div></div>
      <div class="kv"><div class="k">Network</div><div class="v">${{esc(row.network||'tcp')}}</div></div>
      <div class="kv"><div class="k">Security</div><div class="v">${{esc(row.security_type||'none')}}</div></div>
      ${{row.sni?`<div class="kv"><div class="k">SNI</div><div class="v mono">${{esc(row.sni)}}</div></div>`:''}}
      ${{row.path&&row.path!=='/'?`<div class="kv"><div class="k">Path</div><div class="v mono">${{esc(row.path)}}</div></div>`:''}}
      ${{row.flow?`<div class="kv"><div class="k">Flow</div><div class="v">${{esc(row.flow)}}</div></div>`:''}}
      ${{row.pbk?`<div class="kv"><div class="k">PublicKey (Reality)</div><div class="v mono">${{esc(row.pbk)}}</div></div>`:''}}
      ${{row.name?`<div class="kv"><div class="k">Name</div><div class="v">${{esc(row.name)}}</div></div>`:''}}`;
  }}else{{
    protoRows=`
      <div class="kv kv-sep"><div class="k">Protocol</div><div class="v">${{protoBadge('vmess')}}</div></div>
      <div class="kv"><div class="k">Format</div><div class="v">${{esc(row.format||'—')}}</div></div>`;
  }}

  body.innerHTML=`
    <div class="kv"><div class="k">Country</div><div class="v">${{esc(row.country||'—')}}</div></div>
    <div class="kv"><div class="k">City</div><div class="v">${{esc(row.city||'—')}}</div></div>
    <div class="kv"><div class="k">ISP</div><div class="v">${{esc(row.isp||'—')}}</div></div>
    <div class="kv"><div class="k">ASN / Services</div><div class="v">${{esc(row.services||'—')}}</div></div>
    <div class="kv"><div class="k">Geo Source</div><div class="v">${{esc(row.lookup_source||'—')}}</div></div>
    <div class="kv kv-sep"><div class="k">Host</div><div class="v mono">${{esc(row.add||'—')}}</div></div>
    <div class="kv"><div class="k">Resolved IP</div><div class="v mono">${{esc(row.resolved_ip||'—')}}</div></div>
    <div class="kv"><div class="k">Port</div><div class="v">${{esc(row.endpoint_port||0)}}</div></div>
    <div class="kv"><div class="k">TLS</div><div class="v">${{row.tls_enabled?'true':'false'}}</div></div>
    ${{protoRows}}
    <div class="kv kv-sep"><div class="k">Connectivity</div>
      <div class="v"><span class="${{connClass(row.connectivity)}}">${{esc(row.connectivity||'unknown')}}</span>
      &nbsp;${{esc(det.connectivity_detail||'—')}}</div></div>
    <div class="kv"><div class="k">Status</div>
      <div class="v ${{row.status==='ok'?'ok':'err'}}">${{esc(row.status)}}${{row.error?' — '+esc(row.error):''}}</div></div>
    <div class="kv kv-sep"><div class="k">Config URI</div>
      <div class="v mono" style="font-size:11px;opacity:.8">${{esc(uri)}}</div></div>
    <button class="copy-btn" data-token="${{enc(uri)}}" onclick="copyToken(this)">
      Copy ${{isVless?'VLess':'VMess'}}
    </button>`;
  document.getElementById('detailModal').classList.add('open');
}}
function closeModal(){{document.getElementById('detailModal').classList.remove('open');}}

async function copyToken(btn){{
  const raw=btn.getAttribute('data-token')||'';
  try{{
    await navigator.clipboard.writeText(decodeURIComponent(raw));
    const old=btn.textContent;btn.textContent='✓ Copied';btn.classList.add('copied');
    setTimeout(()=>{{btn.textContent=old;btn.classList.remove('copied');}},1400);
  }}catch(_){{btn.textContent='Failed';setTimeout(()=>{{btn.textContent='Copy';}},1400);}}
}}

// ── Debounced search ───────────────────────────────────────────────────────────
searchEl.addEventListener('input',()=>{{
  clearTimeout(searchDebounce);
  searchDebounce=setTimeout(render,150);
}});
protoEl.addEventListener('change',()=>{{
  buildIsp(protoEl.value||'ALL',countryEl.value||'ALL');
  buildConn(protoEl.value||'ALL',countryEl.value||'ALL',ispEl.value||'ALL');
  render();
}});
countryEl.addEventListener('change',()=>{{
  buildIsp(protoEl.value||'ALL',countryEl.value||'ALL');
  buildConn(protoEl.value||'ALL',countryEl.value||'ALL',ispEl.value||'ALL');
  render();
}});
ispEl.addEventListener('change',()=>{{buildConn(protoEl.value||'ALL',countryEl.value||'ALL',ispEl.value||'ALL');render();}});
connEl.addEventListener('change',render);
tlsEl.addEventListener('change',render);

// ── Init ───────────────────────────────────────────────────────────────────────
buildProto();buildCountry();buildIsp('ALL','ALL');buildConn('ALL','ALL','ALL');buildTls();
render();
</script>
</body>
</html>
"""


# ════════════════════════════════════════════════════════════════════════════
# Core processing pipeline
# ════════════════════════════════════════════════════════════════════════════

def process_content(
    content: str,
    mode: str,
    timeout: float,
    api_keys: List[str],
    geo_provider: str = GEO_AUTO,
    show_progress: bool = True,
    max_entries: int = 0,
    parse_workers: int = 0,
    geo_workers: int = 0,
    ipinfo_token: str = "",
    abstract_key: str = "",
    mmdb_city: Any = None,
    mmdb_asn: Any = None,
    checkpoint_path: str = "",
    source_label: str = "",
) -> List[Dict[str, Any]]:
    """Full pipeline: extract → parse+DNS → geo lookup → merge.

    Saves a checkpoint JSON after each completed step so runs can be
    resumed with --resume.  Pass checkpoint_path="" to disable.
    """
    tokens = extract_tokens(content, mode)
    if max_entries > 0:
        tokens = tokens[:max_entries]

    n_parse = max(1, parse_workers or DEFAULT_PARSE_WORKERS)
    n_geo   = max(1, geo_workers   or DEFAULT_GEO_WORKERS)

    # ── Resume from checkpoint if available ──────────────────────────────────
    ckpt = ckpt_load(checkpoint_path)
    steps_done: List[str] = ckpt_steps_done(ckpt)

    if ckpt and steps_done:
        rows = list(ckpt["rows"])
        # Restore source_label from checkpoint when resuming
        if not source_label:
            source_label = ckpt.get("source_label", "")
        already = ", ".join(steps_done)
        remaining = [s for s in STEPS_ALL if s not in steps_done]
        print(f"  [ckpt] Resuming — steps already done: [{already}]", file=sys.stderr)
        print(f"  [ckpt] Steps remaining: {remaining}", file=sys.stderr)
    else:
        rows = []
        steps_done = []

    # ── Phase 1: Parse + DNS resolve ─────────────────────────────────────────
    if "parse" not in steps_done:
        tokens = extract_tokens(content, mode)
        if max_entries > 0:
            tokens = tokens[:max_entries]

        results: List[Optional[Dict[str, Any]]] = [None] * len(tokens)
        dns_cache: Dict[str, str] = {}
        dns_lock   = threading.Lock()
        completed_parse = 0
        parse_lock = threading.Lock()

        parse_bar = CliProgress(
            f"Parse+Resolve (×{n_parse})", len(tokens), enabled=show_progress
        )

        def _parse_one(idx: int, token: str) -> None:
            nonlocal completed_parse
            item = parse_token(token)
            ip, dns_error = resolve_ip(item.get("add", ""), dns_cache, dns_lock)
            item["resolved_ip"] = ip
            if dns_error:
                item["status"] = "error"
                if not item.get("error"):
                    item["error"] = dns_error
            if isinstance(item.get("decoded"), dict):
                item["decoded"] = json.dumps(
                    item["decoded"], ensure_ascii=False, separators=(",", ":")
                )
            results[idx] = item
            with parse_lock:
                completed_parse += 1
                parse_bar.update(completed_parse)

        with concurrent.futures.ThreadPoolExecutor(max_workers=n_parse) as ex:
            futs = [ex.submit(_parse_one, i, tok) for i, tok in enumerate(tokens)]
            for f in concurrent.futures.as_completed(futs):
                f.result()

        parse_bar.finish()
        rows = [r for r in results if r is not None]
        steps_done.append("parse")
        ckpt_save(checkpoint_path, rows, steps_done, source_label, mode)
    else:
        print(f"  [ckpt] Skipping parse — loaded {len(rows)} rows from checkpoint",
              file=sys.stderr)

    # ── Phase 2: IP geolocation (deduplicated) ────────────────────────────────
    if "geo" not in steps_done:
        key_pool   = ApiKeyPool(api_keys)
        ip_cache:  Dict[str, Dict[str, str]] = {}
        unique_ips = sorted({r["resolved_ip"] for r in rows if r.get("resolved_ip")})

        _offline_only = (
            geo_provider == GEO_OFFLINE
            or (
                geo_provider in (GEO_AUTO, GEO_FREE)
                and (mmdb_city is not None and mmdb_city.loaded)
                and (mmdb_asn  is not None and mmdb_asn.loaded)
                and not key_pool.has_active()
                and not ipinfo_token
                and not abstract_key
            )
        )

        if _offline_only or geo_provider == GEO_OFFLINE:
            # ── Offline: single tight loop — no thread overhead, no GIL fight ──
            lookup_bar = CliProgress("IP Geo offline", len(unique_ips), enabled=show_progress)
            for idx, ip in enumerate(unique_ips, start=1):
                ip_cache[ip] = lookup_ip_info(
                    ip, key_pool, timeout, geo_provider,
                    ipinfo_token=ipinfo_token,
                    abstract_key=abstract_key,
                    mmdb_city=mmdb_city,
                    mmdb_asn=mmdb_asn,
                )
                lookup_bar.update(idx)
            lookup_bar.finish()
        else:
            # ── Online: parallel thread pool (I/O-bound HTTP calls) ─────────────
            ip_lock           = threading.Lock()
            geo_progress_lock = threading.Lock()
            completed_geo     = 0

            lookup_bar = CliProgress(
                f"IP Geo (×{n_geo})", len(unique_ips), enabled=show_progress
            )

            def _geo_one(ip: str) -> None:
                nonlocal completed_geo
                info = lookup_ip_info(ip, key_pool, timeout, geo_provider,
                                      ipinfo_token=ipinfo_token,
                                      abstract_key=abstract_key,
                                      mmdb_city=mmdb_city,
                                      mmdb_asn=mmdb_asn)
                with ip_lock:
                    ip_cache[ip] = info
                with geo_progress_lock:
                    completed_geo += 1
                    lookup_bar.update(completed_geo)

            with concurrent.futures.ThreadPoolExecutor(max_workers=n_geo) as ex:
                futs = [ex.submit(_geo_one, ip) for ip in unique_ips]
                for f in concurrent.futures.as_completed(futs):
                    f.result()

            lookup_bar.finish()

        # Merge geo into rows
        for item in rows:
            ip = item.get("resolved_ip", "")
            if ip and ip in ip_cache:
                item.update(ip_cache[ip])

        steps_done.append("geo")
        ckpt_save(checkpoint_path, rows, steps_done, source_label, mode)
    else:
        print(f"  [ckpt] Skipping geo — already done in checkpoint", file=sys.stderr)

    return rows

    return rows


def _tcp_reachable(ip_or_host: str, port: int, timeout: float) -> bool:
    """Fast stage-1 check: can we TCP-connect at all?"""
    if not ip_or_host or not port:
        return False
    try:
        with socket.create_connection((ip_or_host, port), timeout=timeout):
            return True
    except Exception:
        return False


def update_connectivity_status(
    rows: List[Dict[str, Any]],
    timeout: float,
    workers: int,
    show_progress: bool,
    tcp_timeout: float = 3.0,
    xray_semaphore_n: int = 0,
    checkpoint_path: str = "",
    checkpoint_source_label: str = "",
    checkpoint_mode: str = MODE_ALL,
    checkpoint_interval: int = 200,
) -> None:
    """Two-stage pipeline:

    Stage 1 — TCP pre-filter (socket.connect, very fast, kills dead entries early).
    Stage 2 — xray proxy check (only for TCP-reachable entries, RAM-bounded via semaphore).

    Saves a rolling checkpoint every *checkpoint_interval* completed xray checks
    so a crashed run can be resumed without losing progress.
    """
    # ---- Collect candidates -------------------------------------------------
    candidates: List[Tuple[int, str, str, str, str, int]] = []
    for idx, row in enumerate(rows):
        derive_endpoint_fields(row)
        if str(row.get("status", "")).lower() != "ok":
            row["connectivity"] = "skipped"
            row["connectivity_detail"] = "Skipped: geolocation/parse status is not ok"
            continue
        original = str(
            row.get("original", row.get("vmess_original", row.get("vless_original", "")))
        ).strip()
        add      = str(row.get("add", "")).strip()
        ip       = str(row.get("resolved_ip", "")).strip()
        protocol = str(row.get("protocol", "vmess"))
        try:
            port = int(row.get("endpoint_port", 0) or 0)
        except Exception:
            port = 0
        candidates.append((idx, original, add, ip, protocol, port))

    if not candidates:
        CliProgress("TCP pre-filter", 0, enabled=show_progress).finish()
        CliProgress("xray check", 0, enabled=show_progress).finish()
        return

    n_tcp     = max(1, DEFAULT_TCP_WORKERS)
    n_xray    = max(1, workers)
    n_sem     = max(1, xray_semaphore_n or DEFAULT_XRAY_SEMAPHORE)
    xray_sem  = threading.Semaphore(n_sem)

    # ---- Stage 1: TCP pre-filter --------------------------------------------
    tcp_open: List[bool] = [False] * len(candidates)   # index -> reachable?
    tcp_done = 0
    tcp_lock = threading.Lock()
    tcp_bar  = CliProgress(
        f"TCP pre-filter (x{n_tcp})", len(candidates), enabled=show_progress
    )

    def _tcp_check(ci: int) -> None:
        nonlocal tcp_done
        _, _, add, ip, _, port = candidates[ci]
        target = ip or add
        tcp_open[ci] = _tcp_reachable(target, port, tcp_timeout)
        with tcp_lock:
            tcp_done += 1
            tcp_bar.update(tcp_done)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_tcp) as ex:
        futs = [ex.submit(_tcp_check, ci) for ci in range(len(candidates))]
        for f in concurrent.futures.as_completed(futs):
            try:
                f.result()
            except Exception:
                pass
    tcp_bar.finish()

    # Mark TCP-failed entries immediately
    xray_candidates: List[int] = []
    for ci, (idx, _, add, ip, proto, port) in enumerate(candidates):
        if not tcp_open[ci]:
            rows[idx]["connectivity"] = "failed"
            rows[idx]["connectivity_detail"] = (
                f"TCP connect failed: {ip or add}:{port} unreachable"
            )
        else:
            xray_candidates.append(ci)

    n_dead = len(candidates) - len(xray_candidates)
    print(
        f"  TCP pre-filter: {len(xray_candidates)} reachable, "
        f"{n_dead} dead (skipped xray)",
        file=sys.stderr,
    )

    # ---- Stage 2: xray check (only TCP-reachable) ---------------------------
    xray_done = 0
    xray_lock = threading.Lock()
    xray_bar  = CliProgress(
        f"xray check (x{n_xray}, sem={n_sem})", len(xray_candidates), enabled=show_progress
    )

    _ckpt_counter   = 0
    _ckpt_lock      = threading.Lock()

    def _xray_check_one(ci: int) -> None:
        nonlocal xray_done, _ckpt_counter
        idx, token, add, ip, proto, port = candidates[ci]
        with xray_sem:                # cap live xray processes
            try:
                state, detail = check_proxy_connectivity(token, add, ip, port, timeout, proto)
            except Exception as exc:
                state, detail = "failed", f"Error: {exc}"
        rows[idx]["connectivity"] = state
        rows[idx]["connectivity_detail"] = detail
        with xray_lock:
            xray_done += 1
            xray_bar.update(xray_done)
        # ── Rolling checkpoint every N completions ────────────────────────
        if checkpoint_path and checkpoint_interval > 0:
            with _ckpt_lock:
                _ckpt_counter += 1
                if _ckpt_counter % checkpoint_interval == 0:
                    ckpt_save(
                        checkpoint_path, rows,
                        ["parse", "geo"],   # connectivity not yet complete
                        checkpoint_source_label, checkpoint_mode,
                    )

    if xray_candidates:
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_xray) as ex:
            futs = [ex.submit(_xray_check_one, ci) for ci in xray_candidates]
            for f in concurrent.futures.as_completed(futs):
                try:
                    f.result()
                except Exception:
                    pass
    xray_bar.finish()

    # ── Mark connectivity step complete ───────────────────────────────────────
    if checkpoint_path:
        ckpt_save(
            checkpoint_path, rows,
            ["parse", "geo", "connectivity"],
            checkpoint_source_label, checkpoint_mode,
        )


# ════════════════════════════════════════════════════════════════════════════
# CLI entrypoint
# ════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "V2Ray Config Analyzer — Decode VMess/VLess configs and generate\n"
            "an HTML + JSON intelligence report with geolocation and connectivity info."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Input sources ──────────────────────────────────────────────────────
    inp = parser.add_argument_group("Input Sources")
    inp.add_argument(
        "-i", "--input", default=None,
        help=(
            "Combined input file containing vmess:// and/or vless:// lines. "
            "Used for all modes if dedicated files are not specified."
        ),
    )
    inp.add_argument(
        "--vmess-input", default=None, metavar="FILE",
        help="Dedicated VMess config file (vmess:// lines). "
             "Falls back to remote source if file not found.",
    )
    inp.add_argument(
        "--vless-input", default=None, metavar="FILE",
        help="Dedicated VLess config file (vless:// lines). "
             "Falls back to remote source if file not found.",
    )

    # ── Mode ──────────────────────────────────────────────────────────────
    parser.add_argument(
        "--mode",
        choices=[MODE_VMESS, MODE_VLESS, MODE_ALL],
        default=MODE_ALL,
        help="Protocol mode: vmess | vless | all  (default: all)",
    )

    # ── Output ────────────────────────────────────────────────────────────
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output", default="report.html", help="Output HTML report file")
    out.add_argument("--json", default="report.json", help="Output JSON data file")
    out.add_argument(
        "--ok-only",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "HTML report includes only entries with connectivity=ok (default: enabled). "
            "Use --no-ok-only to include all entries regardless of connectivity status."
        ),
    )

    # ── Report-only mode ──────────────────────────────────────────────────
    rpt = parser.add_argument_group("Report-only Mode")
    rpt.add_argument(
        "--report-only", action="store_true",
        help=(
            "Regenerate HTML from an existing JSON file without any processing. "
            "Automatically disables connectivity checks."
        ),
    )
    rpt.add_argument(
        "--report-json", default="report.json",
        help="Input JSON file when using --report-only (default: report.json)",
    )

    # ── Checkpoint / Resume ───────────────────────────────────────────────
    ckpt_grp = parser.add_argument_group("Checkpoint / Resume")
    ckpt_grp.add_argument(
        "--checkpoint", default="checkpoint.json", metavar="FILE",
        help=(
            "Path to checkpoint file (default: checkpoint.json). "
            "Checkpoint is saved after each completed step: parse, geo, connectivity. "
            "Pass empty string '' to disable checkpointing."
        ),
    )
    ckpt_grp.add_argument(
        "--resume", action="store_true",
        help=(
            "Resume from an existing checkpoint file (--checkpoint path). "
            "Already-completed steps are skipped automatically. "
            "If no checkpoint exists the run starts fresh."
        ),
    )
    ckpt_grp.add_argument(
        "--checkpoint-interval", type=int, default=200, metavar="N",
        help=(
            "Save a rolling checkpoint every N completed xray checks during "
            "connectivity phase (default: 200). Reduces data loss on crash."
        ),
    )

    # ── Connectivity ──────────────────────────────────────────────────────
    conn = parser.add_argument_group("Connectivity Check")
    conn.add_argument(
        "--check-connectivity",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Check TCP/proxy connectivity via xray (default: enabled)",
    )
    conn.add_argument(
        "--connect-timeout", type=float, default=8.0,
        help="Max seconds per xray proxy test (default: 8)",
    )
    conn.add_argument(
        "--tcp-timeout", type=float, default=3.0,
        help="Seconds for stage-1 TCP pre-filter per host:port (default: 3)",
    )
    conn.add_argument(
        "--connect-workers", type=int, default=DEFAULT_CONNECT_WORKERS,
        help=(
            f"Thread pool for stage-2 xray checks "
            f"(default: {DEFAULT_CONNECT_WORKERS} = CPU×128). "
            "Actual simultaneous xray procs capped by --xray-semaphore. No upper cap."
        ),
    )
    conn.add_argument(
        "--xray-semaphore", type=int, default=DEFAULT_XRAY_SEMAPHORE,
        help=(
            f"Max simultaneous live xray processes "
            f"(default: {DEFAULT_XRAY_SEMAPHORE} = CPU×16). "
            "Each xray proc uses ~30-50 MB RAM. Raise freely if RAM allows. No upper cap."
        ),
    )

    # ── Performance ───────────────────────────────────────────────────────
    perf = parser.add_argument_group("Performance (Parallelism)")
    perf.add_argument(
        "--parse-workers", type=int, default=DEFAULT_PARSE_WORKERS,
        help=(
            f"Threads for parse+DNS phase (default: {DEFAULT_PARSE_WORKERS} = CPU×32). "
            "DNS is pure I/O; very high thread counts work well. No upper cap."
        ),
    )
    perf.add_argument(
        "--geo-workers", type=int, default=DEFAULT_GEO_WORKERS,
        help=(
            f"Threads for geo/IP lookup phase (default: {DEFAULT_GEO_WORKERS} = CPU×32). "
            "Each worker makes independent HTTP calls. No upper cap."
        ),
    )

    # ── Geolocation ───────────────────────────────────────────────────────
    geo = parser.add_argument_group("Geolocation")
    geo.add_argument(
        "--geo-provider",
        choices=GEO_CHOICES,
        default=GEO_AUTO,
        help=(
            "Geo provider strategy (default: auto):\n"
            "  auto     — chain: ipgeolocation.io -> ipapi.co -> abstractapi -> ipinfo.io/lite -> mmdb\n"
            "  apikey   — only ipgeolocation.io (API key required)\n"
            "  free     — ipapi.co -> abstractapi -> ipinfo.io/lite -> mmdb\n"
            "  abstract — only abstractapi.com (--abstract-key)\n"
            "  ipinfo   — only ipinfo.io/lite (--ipinfo-token)\n"
            "  offline  — only local mmdb files (v4+v6 auto-downloaded if missing, no API calls)"
        ),
    )
    geo.add_argument(
        "--abstract-key", default="", dest="abstract_key",
        help=(
            "API key for abstractapi.com IP Intelligence. "
            f"Built-in free key used if omitted. "
            "Also reads ABSTRACTAPI_KEY from .env file. "
            "Get your key at https://app.abstractapi.com/"
        ),
    )
    geo.add_argument(
        "--ipinfo-token", default="",
        help=(
            "Bearer token for ipinfo.io/lite API. "
            "Built-in demo token used if omitted. "
            "Also reads IPINFO_TOKEN from .env file."
        ),
    )
    _mmdb_note = (
        "Auto-downloaded from sapics/ip-location-db if file not found locally. "
        "Requires: pip install maxminddb"
    )
    geo.add_argument(
        "--mmdb-city-v4", default=DEFAULT_MMDB_CITY_V4, metavar="FILE",
        dest="mmdb_city_v4",
        help=(
            f"City mmdb for IPv4 (default: {DEFAULT_MMDB_CITY_V4!r}). "
            "Provides Country + City for IPv4 addresses. " + _mmdb_note
        ),
    )
    geo.add_argument(
        "--mmdb-city-v6", default=DEFAULT_MMDB_CITY_V6, metavar="FILE",
        dest="mmdb_city_v6",
        help=(
            f"City mmdb for IPv6 (default: {DEFAULT_MMDB_CITY_V6!r}). "
            "Provides Country + City for IPv6 addresses. " + _mmdb_note
        ),
    )
    geo.add_argument(
        "--mmdb-asn-v4", default=DEFAULT_MMDB_ASN_V4, metavar="FILE",
        dest="mmdb_asn_v4",
        help=(
            f"ASN mmdb for IPv4 (default: {DEFAULT_MMDB_ASN_V4!r}). "
            "Provides ISP name + ASN number for IPv4 addresses. " + _mmdb_note
        ),
    )
    geo.add_argument(
        "--mmdb-asn-v6", default=DEFAULT_MMDB_ASN_V6, metavar="FILE",
        dest="mmdb_asn_v6",
        help=(
            f"ASN mmdb for IPv6 (default: {DEFAULT_MMDB_ASN_V6!r}). "
            "Provides ISP name + ASN number for IPv6 addresses. " + _mmdb_note
        ),
    )
    geo.add_argument(
        "--timeout", type=float, default=6.0,
        help="HTTP timeout per geo API request (seconds, default: 6)",
    )

    # ── Misc ──────────────────────────────────────────────────────────────
    parser.add_argument(
        "--max-entries", type=int, default=0,
        help="Max configs to process (0 = all)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Shorthand to process ALL entries (overrides --max-entries)",
    )
    parser.add_argument(
        "--no-progress", action="store_true",
        help="Disable CLI progress bars",
    )

    args = parser.parse_args()
    mode: str = args.mode
    show_progress = not args.no_progress

    # Load API keys
    env_keys = load_api_keys_from_env()
    api_keys = env_keys if env_keys else list(IPGEOLOCATION_KEYS)


    # ── Load ipinfo token (CLI > .env > built-in default) ────────────────
    ipinfo_token: str = getattr(args, 'ipinfo_token', '') or ''
    if not ipinfo_token:
        # Try IPINFO_TOKEN from .env
        ipinfo_token = _load_env_value('.env', 'IPINFO_TOKEN') or ''


    # ── Load abstractapi key (CLI > .env > built-in default) ──────────
    abstract_key: str = getattr(args, 'abstract_key', '') or ''
    if not abstract_key:
        abstract_key = _load_env_value('.env', 'ABSTRACTAPI_KEY') or ''

    # ── Load mmdb readers (once, shared across all geo workers) ──────────
    # Files are auto-downloaded from sapics/ip-location-db if not found locally.
    _need_mmdb = args.geo_provider in (GEO_OFFLINE, GEO_AUTO, GEO_FREE)
    _auto_dl   = _need_mmdb  # only download when actually needed

    mmdb_city_v4_path = args.mmdb_city_v4 or DEFAULT_MMDB_CITY_V4
    mmdb_city_v6_path = args.mmdb_city_v6 or DEFAULT_MMDB_CITY_V6
    mmdb_asn_v4_path  = args.mmdb_asn_v4  or DEFAULT_MMDB_ASN_V4
    mmdb_asn_v6_path  = args.mmdb_asn_v6  or DEFAULT_MMDB_ASN_V6

    if _need_mmdb and not show_progress:
        print("[mmdb] Checking/downloading mmdb files ...", file=sys.stderr)

    mmdb_city = MmdbPair(
        v4=_load_mmdb(mmdb_city_v4_path, auto_download=_auto_dl),
        v6=_load_mmdb(mmdb_city_v6_path, auto_download=_auto_dl),
    )
    mmdb_asn = MmdbPair(
        v4=_load_mmdb(mmdb_asn_v4_path,  auto_download=_auto_dl),
        v6=_load_mmdb(mmdb_asn_v6_path,  auto_download=_auto_dl),
    )

    if args.geo_provider == GEO_OFFLINE and not mmdb_city.loaded and not mmdb_asn.loaded:
        print(
            "[error] --geo-provider offline requires at least one mmdb file. "
            "Download failed and no local files found. "
            "Run: pip install maxminddb  (if not installed)",
            file=sys.stderr,
        )
        sys.exit(1)
    # ── Checkpoint path (empty string = disabled) ─────────────────────────
    checkpoint_path = args.checkpoint if args.resume or args.checkpoint else ""

    # ── Report-only mode ──────────────────────────────────────────────────
    if args.report_only:
        if not os.path.exists(args.report_json):
            print(
                f"[error] Report JSON not found: {args.report_json!r}. "
                "Run without --report-only first.",
                file=sys.stderr,
            )
            sys.exit(1)
        with open(args.report_json, "r", encoding="utf-8") as jf:
            rows = json.load(jf)
        if not isinstance(rows, list):
            print("[error] Invalid report JSON: expected a list of objects.", file=sys.stderr)
            sys.exit(1)
        rows = [r for r in rows if isinstance(r, dict)]
        source_label = args.report_json

    # ── Full processing mode ──────────────────────────────────────────────
    else:
        max_entries = 0 if args.all else max(0, args.max_entries)

        # Resolve input content based on mode and provided files
        if mode == MODE_VMESS:
            vmess_file = args.vmess_input or args.input
            content, source_label = read_source(vmess_file, DEFAULT_VMESS_URL)

        elif mode == MODE_VLESS:
            vless_file = args.vless_input or args.input
            content, source_label = read_source(vless_file, DEFAULT_VLESS_URL)

        else:  # MODE_ALL
            if args.input and not args.vmess_input and not args.vless_input:
                # Single combined file
                content, source_label = read_source(args.input, DEFAULT_VMESS_URL)
            else:
                # Separate files (or auto-fetch both)
                vmess_content, vmess_label = read_source(args.vmess_input, DEFAULT_VMESS_URL)
                vless_content, vless_label = read_source(args.vless_input, DEFAULT_VLESS_URL)
                content = vmess_content + "\n" + vless_content
                source_label = f"vmess:{vmess_label} | vless:{vless_label}"

        rows = process_content(
            content=content,
            mode=mode,
            timeout=args.timeout,
            api_keys=api_keys,
            geo_provider=args.geo_provider,
            show_progress=show_progress,
            max_entries=max_entries,
            parse_workers=args.parse_workers,
            geo_workers=args.geo_workers,
            ipinfo_token=ipinfo_token,
            abstract_key=abstract_key,
            mmdb_city=mmdb_city,
            mmdb_asn=mmdb_asn,
            checkpoint_path=checkpoint_path,
            source_label=source_label,
        )

    # ── Connectivity check ────────────────────────────────────────────────
    # --report-only = regenerate HTML only; never re-run connectivity checks
    # Skip connectivity if already done in checkpoint
    _ckpt_for_conn = ckpt_load(checkpoint_path) if checkpoint_path else None
    _conn_done_in_ckpt = ckpt_step_done(_ckpt_for_conn, "connectivity")

    if args.check_connectivity and not args.report_only:
        if _conn_done_in_ckpt:
            print("  [ckpt] Skipping connectivity — already done in checkpoint",
                  file=sys.stderr)
        else:
            update_connectivity_status(
                rows,
                timeout=max(0.1, args.connect_timeout),
                workers=max(1, args.connect_workers),
                show_progress=show_progress,
                tcp_timeout=max(0.1, args.tcp_timeout),
                xray_semaphore_n=max(1, args.xray_semaphore),
                checkpoint_path=checkpoint_path,
                checkpoint_source_label=source_label,
                checkpoint_mode=mode,
                checkpoint_interval=args.checkpoint_interval,
            )

    # ── Write JSON ────────────────────────────────────────────────────────
    json_path = args.report_json if args.report_only else args.json
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(rows, jf, ensure_ascii=False, indent=2)

    # ── Write HTML ────────────────────────────────────────────────────────
    html_text = generate_html(rows, source_label, mode, ok_only=args.ok_only)
    with open(args.output, "w", encoding="utf-8") as hf:
        hf.write(html_text)

    # ── Summary ───────────────────────────────────────────────────────────
    vmess_count = sum(1 for r in rows if r.get("protocol") == "vmess")
    vless_count = sum(1 for r in rows if r.get("protocol") == "vless")
    ok_count    = sum(1 for r in rows if r.get("connectivity") == "ok")

    # Close mmdb readers
    mmdb_city.close()
    mmdb_asn.close()

    print(f"\n{'-'*54}")
    print(f"  Mode             : {mode}")
    print(f"  Geo provider     : {args.geo_provider}")
    if ipinfo_token:
        masked = (ipinfo_token[:4] + '****' + ipinfo_token[-4:]
                  if len(ipinfo_token) > 8 else '****')
        print(f"  ipinfo token     : {masked}")
    if mmdb_city.loaded or mmdb_asn.loaded or args.geo_provider == GEO_OFFLINE:
        print(f"  MMDB City        : {mmdb_city.status(mmdb_city_v4_path, mmdb_city_v6_path)}")
        print(f"  MMDB ASN         : {mmdb_asn.status(mmdb_asn_v4_path,   mmdb_asn_v6_path)}")
    print(f"  Parse workers    : {args.parse_workers}")
    print(f"  Geo workers      : {args.geo_workers}")
    print(f"  TCP workers      : {DEFAULT_TCP_WORKERS}  (stage-1 pre-filter)")
    print(f"  xray threads     : {args.connect_workers}  (stage-2 thread pool)")
    print(f"  xray semaphore   : {args.xray_semaphore}  (max live xray procs)")
    print(f"  Total            : {len(rows)}  (VMess: {vmess_count}, VLess: {vless_count})")
    print(f"  Connectivity     : {ok_count} ok / {len(rows) - ok_count} not-ok")
    print(f"  HTML report      : {args.output}  (ok-only: {args.ok_only})")
    print(f"  JSON data        : {json_path}")
    print(f"{'-'*54}\n")


if __name__ == "__main__":
    main()