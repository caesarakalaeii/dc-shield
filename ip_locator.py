import csv
import ipaddress
import os
import time
from bisect import bisect_right
from typing import List, Tuple, Optional

import requests

# --- Configuration -----------------------------------------------------------

# Default source: raw file in sapics/ip-location-db (adjust if you keep a fork/mirror).
# The CSV is expected to have columns: start_ip,end_ip,country_code (header line allowed).
IP_DB_URL = os.getenv(
    "IP_DB_URL",
    "https://raw.githubusercontent.com/sapics/ip-location-db/main/db/country/ip-country.csv",
)

# Where to store the downloaded DB (e.g., alongside your code or in a cache dir).
DB_PATH = os.getenv(
    "IP_DB_PATH",
    os.path.join(os.path.dirname(__file__), "ip-country.csv"),
)

# Re-download if local file is older than this many seconds (default: 7 days).
REFRESH_SECONDS = int(os.getenv("IP_DB_REFRESH_SECONDS", str(7 * 24 * 60 * 60)))

# Timeout for HTTP GET
HTTP_TIMEOUT = float(os.getenv("IP_DB_HTTP_TIMEOUT", "15.0"))

def set_logger(logger):
    global l
    # Your logger (replace with your logger instance)
    try:
        l = logger
    except NameError:
        import logging
        l = logging.getLogger(__name__)
    l.info("Initialized Logger")


# --- Internal state ----------------------------------------------------------

# Sorted arrays for binary search
_ranges_v4: List[Tuple[int, int, str]] = []
_starts_v4: List[int] = []  # start ints for bisect

_ranges_v6: List[Tuple[int, int, str]] = []
_starts_v6: List[int] = []  # start ints for bisect

_db_loaded = False


# --- Download / refresh ------------------------------------------------------

def _file_is_stale(path: str, max_age_seconds: int) -> bool:
    if not os.path.exists(path):
        return True
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return True
    return (time.time() - mtime) > max_age_seconds


def _download_db(url: str, dest_path: str) -> None:
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    l.info(f"Downloading IP DB from {url} -> {dest_path}")
    r = requests.get(url, timeout=HTTP_TIMEOUT, stream=True)
    r.raise_for_status()
    tmp_path = dest_path + ".tmp"
    with open(tmp_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 64):
            if chunk:
                f.write(chunk)
    os.replace(tmp_path, dest_path)
    l.info("Download complete.")


def _ensure_db(url: str, path: str, refresh_seconds: int) -> None:
    try:
        if _file_is_stale(path, refresh_seconds):
            _download_db(url, path)
    except Exception as e:
        # If refresh fails but we have an existing file, log and continue with the old one
        if os.path.exists(path):
            l.warning(f"Failed to refresh IP DB ({e}); using existing file at {path}.")
        else:
            raise


# --- Load into memory --------------------------------------------------------

def _parse_row(start_ip: str, end_ip: str, country: str) -> Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress, str]:
    return ipaddress.ip_address(start_ip.strip()), ipaddress.ip_address(end_ip.strip()), country.strip()


def _load_ip_db(path: str) -> None:
    global _db_loaded, _ranges_v4, _ranges_v6, _starts_v4, _starts_v6
    if _db_loaded:
        return

    _ranges_v4.clear()
    _ranges_v6.clear()

    with open(path, newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        # Try to detect header
        first = next(reader, None)
        if first is None:
            raise ValueError("IP DB CSV is empty.")
        if any(h.lower() in ("start_ip", "start", "begin") for h in first):
            # header line detected -> continue with the rest
            pass
        else:
            # first row is data -> process it, and continue with the reader as-is
            try:
                s, e, c = first
            except ValueError:
                raise ValueError("Unexpected CSV format; expected 3 columns: start_ip,end_ip,country_code")
            a, b, cc = _parse_row(s, e, c)
            if isinstance(a, ipaddress.IPv4Address):
                _ranges_v4.append((int(a), int(b), cc))
            else:
                _ranges_v6.append((int(a), int(b), cc))

        for row in reader:
            if not row or len(row) < 3:
                continue
            s, e, c = row[0], row[1], row[2]
            a, b, cc = _parse_row(s, e, c)
            if isinstance(a, ipaddress.IPv4Address):
                _ranges_v4.append((int(a), int(b), cc))
            else:
                _ranges_v6.append((int(a), int(b), cc))

    # sort by range start for binary search
    _ranges_v4.sort(key=lambda t: t[0])
    _starts_v4 = [t[0] for t in _ranges_v4]

    _ranges_v6.sort(key=lambda t: t[0])
    _starts_v6 = [t[0] for t in _ranges_v6]

    _db_loaded = True
    l.info(
        f"Loaded IP DB: {len(_ranges_v4)} IPv4 ranges, {len(_ranges_v6)} IPv6 ranges."
    )


# --- Lookup helpers ----------------------------------------------------------

def _binary_search_country(ip_int: int, ranges: List[Tuple[int, int, str]], starts: List[int]) -> Optional[str]:
    """Find the country for ip_int given sorted ranges and their starts using bisect."""
    # Find rightmost start <= ip_int -> idx - 1 is candidate
    idx = bisect_right(starts, ip_int) - 1
    if idx >= 0:
        start, end, country = ranges[idx]
        if start <= ip_int <= end:
            return country
    return None


# --- Public API --------------------------------------------------------------

def refresh_ip_db(force: bool = False) -> None:
    """
    Ensure the local DB exists and is fresh.
    If 'force' is True, always re-download (ignoring age).
    """
    if force and os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except OSError:
            pass
    _ensure_db(IP_DB_URL, DB_PATH, 0 if force else REFRESH_SECONDS)


