"""Link finder for Android packages. Everything is best-effort: a failed check just means no button."""
import asyncio
import logging
import re
from typing import List, Optional, Tuple
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

TIMEOUT = 3.5
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0 Safari/537.36",
    "Accept-Language": "en",
}
PKG_RE = re.compile(r"^[A-Za-z][\w]*(\.[A-Za-z_][\w]*)+$")

Link = Tuple[str, str]  # (button label, url)


def valid_package(pkg: str) -> bool:
    return bool(pkg and PKG_RE.match(pkg))


# ---------------------------------------------------------------- Play Store
def _check_play(pkg: str) -> Optional[str]:
    try:
        r = requests.get(
            "https://play.google.com/store/apps/details",
            params={"id": pkg, "hl": "en"},
            headers=HEADERS, timeout=TIMEOUT, stream=True,
        )
        ok = r.status_code == 200
        r.close()
        if ok:
            return f"https://play.google.com/store/apps/details?id={quote(pkg)}"
    except requests.RequestException as exc:
        logger.info("Play check failed for %s: %s", pkg, exc)
    return None


# ---------------------------------------------------------------- F-Droid (+ source repo)
_SRC_RE = re.compile(
    r'<a[^>]+href="([^"]+)"[^>]*>\s*(?:<[^>]+>\s*)*Source\s*Code', re.I
)
_REPO_RE = re.compile(r"https?://(?:www\.)?(github\.com|gitlab\.com|codeberg\.org)/([^/\s#?]+)/([^/\s#?]+)", re.I)


def _check_fdroid(pkg: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (f-droid page url, source repo url)."""
    try:
        r = requests.get(
            f"https://f-droid.org/en/packages/{quote(pkg)}/",
            headers=HEADERS, timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        logger.info("F-Droid check failed for %s: %s", pkg, exc)
        return None, None
    if r.status_code != 200:
        return None, None

    page = f"https://f-droid.org/packages/{quote(pkg)}/"
    m = _SRC_RE.search(r.text)
    src = m.group(1).strip() if m else None
    if src and not src.startswith("http"):
        src = None
    return page, src


def _source_button(src: str) -> Optional[Link]:
    m = _REPO_RE.match(src)
    if not m:
        return ("🧑‍💻 Source", src)
    host, owner, repo = m.group(1).lower(), m.group(2), m.group(3)
    repo = repo[:-4] if repo.endswith(".git") else repo
    if host == "github.com":
        return ("🐙 GitHub Releases", f"https://github.com/{owner}/{repo}/releases")
    return ("🧑‍💻 Source", f"https://{host}/{owner}/{repo}")


async def get_official_links(pkg: str) -> List[Link]:
    """Play Store + F-Droid + GitHub releases (via F-Droid). Checks run in parallel."""
    if not valid_package(pkg):
        return []
    play, fdroid = await asyncio.gather(
        asyncio.to_thread(_check_play, pkg),
        asyncio.to_thread(_check_fdroid, pkg),
    )
    out: List[Link] = []
    if play:
        out.append(("▶️ Play Store", play))
    fd_page, src = fdroid
    if fd_page:
        out.append(("📦 F-Droid", fd_page))
    if src:
        btn = _source_button(src)
        if btn:
            out.append(btn)
    return out


# ---------------------------------------------------------------- mirrors (plain search links, no network calls)
def get_mirrors(pkg: str) -> List[Link]:
    """APKMirror / APKPure / Uptodown search links. Instant, nothing to scrape."""
    if not valid_package(pkg):
        return []
    q = quote(pkg)
    return [
        ("🪞 APKMirror", f"https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s={q}"),
        ("🪞 APKPure", f"https://apkpure.com/search?q={q}"),
        ("🪞 Uptodown", f"https://www.google.com/search?q=site:uptodown.com+{q}"),
    ]
