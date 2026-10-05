"""VirusTotal API layer. All functions here are blocking: call them via asyncio.to_thread()."""
import base64
import hashlib
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

VT_API_KEY = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
SMALL_UPLOAD_LIMIT = 32 * 1024 * 1024  # larger files need a special upload URL

# 0 = no proactive limiting (default). Set VT_RPM=4 if you are on the free key
# and see 429 errors in logs. 429 responses are always retried automatically.
VT_RPM = int(os.environ.get("VT_RPM", "0") or 0)

HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")

_session = requests.Session()
if VT_API_KEY:
    _session.headers.update({"x-apikey": VT_API_KEY})

_rl_lock = threading.Lock()
_last_call = 0.0


# ---------------------------------------------------------------- report model
@dataclass
class Report:
    kind: str                       # "file" | "url"
    key: str                        # md5 for files, short sha1 token for urls (used in callback_data)
    link: str                       # VirusTotal GUI link
    pending: bool = True            # True while no engine results exist yet
    title: str = ""
    sha256: str = ""
    url: str = ""
    detected: List[Tuple[str, str]] = field(default_factory=list)   # (engine, result)
    clean: List[str] = field(default_factory=list)
    unsupported: List[str] = field(default_factory=list)
    file_type: str = ""
    size: int = 0
    submitted: int = 0
    first_seen: str = ""
    last_seen: str = ""
    threat: str = ""
    magic: str = ""
    package: str = ""
    version: str = ""
    # runtime state, managed by main.py
    official: Optional[list] = None
    mirrors: Optional[list] = None
    view: str = "m"
    busy: bool = False

    @property
    def det(self) -> int:
        return len(self.detected)

    @property
    def total(self) -> int:
        return len(self.detected) + len(self.clean)


# ---------------------------------------------------------------- helpers
def is_hash(text: str) -> bool:
    return bool(HASH_RE.match(text or ""))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _fmt_ts(ts) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _throttle():
    if VT_RPM <= 0:
        return
    global _last_call
    gap = 60.0 / VT_RPM
    with _rl_lock:
        wait = _last_call + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_call = time.monotonic()


def _request(method: str, path: str, retries: int = 3, upload_path: Optional[str] = None, **kw):
    """HTTP call with timeout and automatic retry on 429 / network errors. Returns Response or None."""
    url = path if path.startswith("http") else f"{BASE_URL}{path}"
    kw.setdefault("timeout", 30)
    for attempt in range(retries + 1):
        _throttle()
        try:
            if upload_path:
                with open(upload_path, "rb") as fp:
                    r = _session.request(
                        method, url, files={"file": (os.path.basename(upload_path), fp)}, **kw
                    )
            else:
                r = _session.request(method, url, **kw)
        except requests.RequestException as exc:
            logger.warning("VT request error (%s %s): %s", method, path, exc)
            if attempt == retries:
                return None
            time.sleep(2)
            continue
        if r.status_code == 429 and attempt < retries:
            try:
                delay = int(r.headers.get("Retry-After", "15"))
            except ValueError:
                delay = 15
            logger.warning("VT 429 rate limit, sleeping %ss", delay)
            time.sleep(min(max(delay, 5), 60))
            continue
        return r
    return None


def _ok_json(r) -> Optional[dict]:
    if r is None or not r.ok:
        return None
    try:
        return r.json()
    except ValueError:
        return None


# ---------------------------------------------------------------- parsing
def _parse(kind: str, key: str, obj: dict, link: str) -> Report:
    attrs = obj.get("attributes", {}) or {}
    results = attrs.get("last_analysis_results") or {}

    detected, clean, unsupported = [], [], []
    for entry in results.values():
        category = entry.get("category")
        name = entry.get("engine_name") or entry.get("engine") or "?"
        if category in ("malicious", "suspicious"):
            detected.append((name, entry.get("result") or category.title()))
        elif category in ("undetected", "harmless"):
            clean.append(name)
        else:
            unsupported.append(name)
    detected.sort(key=lambda x: x[0].lower())
    clean.sort(key=str.lower)
    unsupported.sort(key=str.lower)

    threat = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "")

    rep = Report(
        kind=kind,
        key=key,
        link=link,
        pending=not results,
        detected=detected,
        clean=clean,
        unsupported=unsupported,
        submitted=attrs.get("times_submitted", 0) or 0,
        first_seen=_fmt_ts(attrs.get("first_submission_date")),
        last_seen=_fmt_ts(attrs.get("last_analysis_date") or attrs.get("last_modification_date")),
        threat=threat,
    )

    if kind == "file":
        rep.sha256 = attrs.get("sha256") or obj.get("id", "")
        rep.title = attrs.get("meaningful_name") or (attrs.get("names") or [rep.sha256])[0]
        ext = attrs.get("type_extension", "") or ""
        tag = attrs.get("type_tag", "") or ""
        desc = attrs.get("type_description", "") or ""
        rep.file_type = f"{ext} ({tag})" if ext and tag else ext or tag or desc
        rep.size = attrs.get("size", 0) or 0
        magic = attrs.get("magic", "") or ""
        rep.magic = "" if magic.upper() == "N/A" else magic
        ag = attrs.get("androguard") or {}
        rep.package = ag.get("Package", "") or ""
        rep.version = ag.get("AndroidVersionName", "") or ""
    else:
        rep.url = attrs.get("url") or attrs.get("last_final_url") or ""
        rep.title = attrs.get("title", "") or rep.url
    return rep


# ---------------------------------------------------------------- files
def lookup_hash(h: str) -> Optional[Report]:
    """Fetch an existing report by md5/sha1/sha256. None if unknown to VirusTotal."""
    if not VT_API_KEY:
        return None
    body = _ok_json(_request("GET", f"/files/{h.lower()}"))
    if not body:
        return None
    obj = body.get("data", {})
    attrs = obj.get("attributes", {})
    sha = attrs.get("sha256") or obj.get("id", h)
    key = attrs.get("md5") or h.lower()
    return _parse("file", key, obj, f"https://www.virustotal.com/gui/file/{sha}")


def wait_for_analysis(analysis_id: str, timeout: int = 180) -> bool:
    """Poll with a growing interval (3s -> 10s). Returns True when completed."""
    end = time.time() + timeout
    delay = 3
    while time.time() < end:
        time.sleep(delay)
        body = _ok_json(_request("GET", f"/analyses/{analysis_id}"))
        if body and body.get("data", {}).get("attributes", {}).get("status") == "completed":
            return True
        delay = min(delay + 2, 10)
    return False


def scan_file(path: str, on_state: Optional[Callable[[str], None]] = None):
    """Returns (Report|None, state). state: cached | scanned | no_key | too_large | upload_failed."""
    if not VT_API_KEY:
        return None, "no_key"
    notify = on_state or (lambda s: None)

    sha = sha256_file(path)
    rep = lookup_hash(sha)
    if rep and not rep.pending:
        return rep, "cached"                      # known file: 1 API call, no upload

    size = os.path.getsize(path)
    if size > SMALL_UPLOAD_LIMIT:
        body = _ok_json(_request("GET", "/files/upload_url"))
        upload_url = (body or {}).get("data")
        if not upload_url:
            return None, "too_large"
    else:
        upload_url = f"{BASE_URL}/files"

    notify("uploading")
    r = _request("POST", upload_url, upload_path=path, timeout=(10, 900))
    body = _ok_json(r)
    if not body:
        logger.error("VT upload failed: %s", getattr(r, "text", "no response"))
        return None, "upload_failed"

    notify("analysing")
    analysis_id = body.get("data", {}).get("id")
    if analysis_id:
        wait_for_analysis(analysis_id, 180)

    rep = lookup_hash(sha)
    return rep, ("scanned" if rep else "upload_failed")


def rescan_file(sha256: str):
    """Ask VT to re-analyse an already known file. Returns (Report|None, state)."""
    if not VT_API_KEY:
        return None, "no_key"
    body = _ok_json(_request("POST", f"/files/{sha256}/analyse"))
    if not body:
        return None, "rescan_failed"
    analysis_id = body.get("data", {}).get("id")
    if analysis_id:
        wait_for_analysis(analysis_id, 180)
    rep = lookup_hash(sha256)
    return rep, ("scanned" if rep else "rescan_failed")


# ---------------------------------------------------------------- urls
def _url_key(url_id_hex: str) -> str:
    """43-char key from the 64-hex VT url id, so callback_data stays under 64 bytes."""
    return base64.urlsafe_b64encode(bytes.fromhex(url_id_hex)).decode().rstrip("=")


def _url_hex(key: str) -> str:
    return base64.urlsafe_b64decode(key + "=" * (-len(key) % 4)).hex()


def get_url_report(url_id: str, url: str = "") -> Optional[Report]:
    body = _ok_json(_request("GET", f"/urls/{url_id}"))
    if not body:
        return None
    obj = body.get("data", {})
    vt_id = obj.get("id", "")
    if not re.fullmatch(r"[0-9a-f]{64}", vt_id):
        vt_id = hashlib.sha256(url.encode()).hexdigest()
    rep = _parse("url", _url_key(vt_id), obj, f"https://www.virustotal.com/gui/url/{vt_id}")
    rep.url = rep.url or url
    return rep


def lookup_url_key(key: str) -> Optional[Report]:
    """Rebuild a URL report from the callback key (works after a bot restart)."""
    if not VT_API_KEY:
        return None
    try:
        return get_url_report(_url_hex(key))
    except (ValueError, TypeError):
        return None


def scan_url(url: str, on_state: Optional[Callable[[str], None]] = None):
    """Submit a URL, wait for the analysis, return (Report|None, state). Also used for rescans."""
    if not VT_API_KEY:
        return None, "no_key"
    body = _ok_json(_request("POST", "/urls", data={"url": url}))
    if not body:
        return None, "submit_failed"
    analysis_id = body.get("data", {}).get("id")
    if analysis_id:
        wait_for_analysis(analysis_id, 60)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    rep = get_url_report(url_id, url)
    return rep, ("scanned" if rep else "error")
