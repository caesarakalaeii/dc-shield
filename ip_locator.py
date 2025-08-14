import csv
import ipaddress
import os
import time
from bisect import bisect_right
from typing import List, Tuple, Optional
import requests

# --- Config ---
IPV4_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv"
IPV6_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv6.csv"

DATA_DIR = os.path.join(os.path.dirname(__file__), "ipdb")
IPV4_PATH = os.path.join(DATA_DIR, "dbip-country-ipv4.csv")
IPV6_PATH = os.path.join(DATA_DIR, "dbip-country-ipv6.csv")

REFRESH_SECONDS = 7 * 24 * 60 * 60  # 7 days
HTTP_TIMEOUT = 15.0

try:
    l
except NameError:
    import logging
    l = logging.getLogger(__name__)

_ranges_v4: List[Tuple[int, int, str]] = []
_starts_v4: List[int] = []
_ranges_v6: List[Tuple[int, int, str]] = []
_starts_v6: List[int] = []
_db_loaded = False

# --- Helpers ---
def _file_is_stale(path: str) -> bool:
    return not os.path.exists(path) or (time.time() - os.path.getmtime(path) > REFRESH_SECONDS)

def _download(url: str, dest: str):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    l.info(f"Downloading {url}")
    r = requests.get(url, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    with open(dest, "wb") as f:
        f.write(r.content)

def _ensure_files():
    if _file_is_stale(IPV4_PATH):
        _download(IPV4_URL, IPV4_PATH)
    if _file_is_stale(IPV6_PATH):
        _download(IPV6_URL, IPV6_PATH)

def _load_csv(path: str, is_v4: bool):
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 3 or row[0].startswith("start_ip"):
                continue
            start, end, cc = row
            start_int = int(ipaddress.ip_address(start))
            end_int = int(ipaddress.ip_address(end))
            if is_v4:
                _ranges_v4.append((start_int, end_int, cc))
            else:
                _ranges_v6.append((start_int, end_int, cc))

def _load_db():
    global _db_loaded, _starts_v4, _starts_v6
    if _db_loaded:
        return
    _ensure_files()
    _load_csv(IPV4_PATH, True)
    _load_csv(IPV6_PATH, False)
    _ranges_v4.sort(key=lambda r: r[0])
    _starts_v4 = [r[0] for r in _ranges_v4]
    _ranges_v6.sort(key=lambda r: r[0])
    _starts_v6 = [r[0] for r in _ranges_v6]
    _db_loaded = True
    l.info(f"Loaded {len(_ranges_v4)} IPv4 ranges, {len(_ranges_v6)} IPv6 ranges.")

def _binary_search(ip_int: int, ranges: List[Tuple[int, int, str]], starts: List[int]) -> Optional[str]:
    idx = bisect_right(starts, ip_int) - 1
    if idx >= 0:
        start, end, cc = ranges[idx]
        if start <= ip_int <= end:
            return cc
    return None