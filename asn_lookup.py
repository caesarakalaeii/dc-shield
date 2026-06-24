"""
ASN / Hosting Organization lookup module.

Mirrors ip_locator.py structure: lazy CSV download, in-memory binary search.
Uses dbip-asn CSV from the same sapics/ip-location-db repo (CC-BY-4.0, no license key).
"""
import csv
import ipaddress
import os
import time
from bisect import bisect_right
from typing import List, Tuple, Optional
import requests

# --- Config ---
ASN_IPV4_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-asn/dbip-asn-ipv4.csv"
ASN_IPV6_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-asn/dbip-asn-ipv6.csv"

DATA_DIR = os.path.join(os.path.dirname(__file__), "ipdb")
ASN_IPV4_PATH = os.path.join(DATA_DIR, "dbip-asn-ipv4.csv")
ASN_IPV6_PATH = os.path.join(DATA_DIR, "dbip-asn-ipv6.csv")

REFRESH_SECONDS = 7 * 24 * 60 * 60  # 7 days
HTTP_TIMEOUT = 15.0

l = None


def set_logger(logger):
    global l
    try:
        l = logger
    except NameError:
        import logging
        l = logging.getLogger(__name__)


_ranges_v4: List[Tuple[int, int, str, str]] = []  # (start, end, asn, org)
_starts_v4: List[int] = []
_ranges_v6: List[Tuple[int, int, str, str]] = []
_starts_v6: List[int] = []
_db_loaded = False

# Curated ASN classification (≤30 entries)
_KNOWN_DATACENTER_ASNS = frozenset({
    "AS13335",  # Cloudflare
    "AS15169",  # Google
    "AS16509",  # AWS
    "AS8075",   # Microsoft
    "AS14618",  # Amazon AES
    "AS8068",   # Microsoft Azure
    "AS16509",  # Amazon.com
    "AS14061",  # DigitalOcean
    "AS16276",  # OVH
    "AS24940",  # Hetzner
    "AS45102",  # Alibaba
    "AS132203", # Tencent
    "AS14618",  # Amazon
    "AS396982", # Google Cloud
    "AS32934",  # Facebook
    "AS2906",   # Netflix
    "AS20940",  # Akamai
    "AS13335",  # Cloudflare
    "AS4837",   # China Unicom (datacenter)
    "AS60068",  # Datacamp / CDN
    "AS59947",  # ByteDance
    "AS213230", # Tencent
    "AS9009",   # M247 (hosting)
    "AS62240",  # Clouvider
    "AS395974", # Akamai
    "AS714",    # Apple
    "AS6185",   # Apple
    "AS34164",  # Akamai
    "AS3352",   # Telefonica (mixed, treat as residential)
    "AS36352",  # ColoCrossing (hosting)
})


def _classify_asn(asn: str) -> str:
    """Return classification: Datacenter/CDN, VPN/Hosting, or Residential ISP."""
    if asn in _KNOWN_DATACENTER_ASNS:
        return "☁️ Datacenter/CDN"
    org_lower = ""
    # Will be filled from org field in lookup_asn
    return org_lower


def _classify(asn: str, org: str) -> str:
    """Classify ASN + org string into a type."""
    if asn in _KNOWN_DATACENTER_ASNS:
        return "☁️ Datacenter/CDN"
    org_l = (org or "").lower()
    hosting_keywords = ["hosting", "data center", "datacenter", "cloud", "server",
                        "vps", "dedicated", "colocation", "vpn", "proxy",
                        "digitalocean", "ovh", "hetzner", "linode", "vultr",
                        "amazon", "google", "microsoft", "azure"]
    if any(kw in org_l for kw in hosting_keywords):
        return "🛡️ VPN/Hosting"
    return "🏠 Residential ISP"


# --- Helpers ---
def _file_is_stale(path: str) -> bool:
    return not os.path.exists(path) or (
        time.time() - os.path.getmtime(path) > REFRESH_SECONDS
    )


def _download(url: str, dest: str):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if l:
        l.info(f"Downloading {url}")
    r = requests.get(url, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    with open(dest, "wb") as f:
        f.write(r.content)


def _ensure_files():
    if _file_is_stale(ASN_IPV4_PATH):
        _download(ASN_IPV4_URL, ASN_IPV4_PATH)
    if _file_is_stale(ASN_IPV6_PATH):
        _download(ASN_IPV6_URL, ASN_IPV6_PATH)


def _load_csv(path: str, is_v4: bool):
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 4:
                continue
            start, end, asn, org = row[0], row[1], row[2], row[3]
            try:
                start_int = int(ipaddress.ip_address(start))
                end_int = int(ipaddress.ip_address(end))
            except ValueError:
                continue
            if is_v4:
                _ranges_v4.append((start_int, end_int, asn, org))
            else:
                _ranges_v6.append((start_int, end_int, asn, org))


def _load_db():
    global _db_loaded, _starts_v4, _starts_v6
    if _db_loaded:
        return
    _ensure_files()
    _load_csv(ASN_IPV4_PATH, True)
    _load_csv(ASN_IPV6_PATH, False)
    _ranges_v4.sort(key=lambda r: r[0])
    _starts_v4 = [r[0] for r in _ranges_v4]
    _ranges_v6.sort(key=lambda r: r[0])
    _starts_v6 = [r[0] for r in _ranges_v6]
    _db_loaded = True
    if l:
        l.info(f"Loaded {len(_ranges_v4)} IPv4 ASN ranges, {len(_ranges_v6)} IPv6 ASN ranges.")


def _binary_search(
    ip_int: int, ranges: List[Tuple[int, int, str, str]], starts: List[int]
) -> Optional[Tuple[str, str, int, int]]:
    """Return (asn, org, start_int, end_int) or None."""
    idx = bisect_right(starts, ip_int) - 1
    if idx >= 0:
        start, end, asn, org = ranges[idx]
        if start <= ip_int <= end:
            return (asn, org, start, end)
    return None


def lookup_asn(ip_address: str) -> Optional[dict]:
    """
    Look up ASN and hosting organization for an IP address.

    Returns dict with asn, number, organization, network, ipVersion, classification
    or None if not found / invalid / DB not loaded.
    """
    try:
        _load_db()  # lazy + idempotent

        ip_obj = ipaddress.ip_address(ip_address)
        ip_int = int(ip_obj)

        if isinstance(ip_obj, ipaddress.IPv4Address):
            result = _binary_search(ip_int, _ranges_v4, _starts_v4)
        else:
            result = _binary_search(ip_int, _ranges_v6, _starts_v6)

        if not result:
            return None

        asn_raw, org, start_int, end_int = result
        # Normalize ASN: ensure "AS" prefix
        asn = asn_raw if asn_raw.upper().startswith("AS") else f"AS{asn_raw}"
        try:
            number = int(asn_raw.replace("AS", "").replace("as", ""))
        except (ValueError, AttributeError):
            number = 0

        # Compute CIDR from start/end
        try:
            if isinstance(ip_obj, ipaddress.IPv4Address):
                net = ipaddress.IPv4Network((start_int, end_int - start_int + 1), strict=False)
            else:
                net = ipaddress.IPv6Network((start_int, end_int - start_int + 1), strict=False)
            network = str(net)
        except (ValueError, TypeError):
            network = None

        classification = _classify(asn, org)

        return {
            "asn": asn,
            "number": number,
            "organization": org,
            "network": network,
            "ipVersion": 4 if isinstance(ip_obj, ipaddress.IPv4Address) else 6,
            "classification": classification,
        }
    except Exception as e:
        if l:
            l.error(f"Error in ASN lookup for {ip_address}: {e}")
        return None
