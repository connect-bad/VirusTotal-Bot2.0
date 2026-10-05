import asyncio
import glob
import logging
import os
import re
import threading
import time
from collections import OrderedDict

import requests
from pyrogram import Client, enums, filters
from pyrogram.errors import FloodWait, MessageNotModified
from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup

import botfunctions as vt
import links
import ui
from queue_manager import Job, JobQueue

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- config
bot_token = os.environ.get("TOKEN", "")
api_hash = os.environ.get("HASH", "")
api_id = int(os.environ.get("ID", "0") or 0)

AUTHORIZED_USERS = os.environ.get("AUTHORIZED_USERS", "")   # "123,456"
AUTHORIZED_CHATS = os.environ.get("AUTHORIZED_CHATS", "")
authorized_user_list = [int(x.strip()) for x in AUTHORIZED_USERS.split(",") if x.strip().isdigit()]
authorized_chat_list = [int(x.strip()) for x in AUTHORIZED_CHATS.split(",") if x.strip().lstrip("-").isdigit()]

# 650 MB is VirusTotal's own maximum (files > 32 MB use the special upload URL).
MAX_FILE_MB = int(os.environ.get("MAX_FILE_MB", "650"))   # VirusTotal hard limit
MAX_BYTES = MAX_FILE_MB * 1024 * 1024
QUEUE_WORKERS = int(os.environ.get("QUEUE_WORKERS", "3"))
MAX_TRANSMISSIONS = int(os.environ.get("MAX_TRANSMISSIONS", "4"))   # parallel MTProto transfers
PUSH_URL = os.environ.get("PUSH_URL", "https://deliver.connectbadsha.workers.dev")
DOWNLOAD_DIR = "downloads"

app = Client(
    "my_bot",
    api_id=api_id,
    api_hash=api_hash,
    bot_token=bot_token,
    in_memory=True,
    parse_mode=enums.ParseMode.HTML,
    max_concurrent_transmissions=MAX_TRANSMISSIONS,
)
queue = JobQueue(workers=QUEUE_WORKERS)

stats = {"files": 0, "urls": 0, "hashes": 0, "rescans": 0, "cached": 0, "errors": 0}
start_time = time.time()

# ---------------------------------------------------------------- caches
REPORTS: "OrderedDict[str, vt.Report]" = OrderedDict()   # callback state, LRU
FILE_HASH: "OrderedDict[str, str]" = OrderedDict()       # telegram file_unique_id -> sha256


def cache_put(rep: vt.Report):
    k = f"{rep.kind[0]}{rep.key}"
    REPORTS[k] = rep
    REPORTS.move_to_end(k)
    while len(REPORTS) > 300:
        REPORTS.popitem(last=False)


def cache_get(kind: str, key: str):
    rep = REPORTS.get(f"{kind}{key}")
    if rep:
        REPORTS.move_to_end(f"{kind}{key}")
    return rep


async def ensure_report(kind: str, key: str):
    """Cache first; after a restart rebuild from VirusTotal (md5 for files, url-id for URLs)."""
    rep = cache_get(kind, key)
    if rep:
        return rep
    rep = await asyncio.to_thread(vt.lookup_hash if kind == "f" else vt.lookup_url_key, key)
    if rep:
        cache_put(rep)
    return rep


# ---------------------------------------------------------------- helpers
def cleanup_temp_files():
    cleaned = 0
    for f in glob.glob(f"{DOWNLOAD_DIR}/*"):
        try:
            if os.path.isfile(f):
                os.remove(f)
                cleaned += 1
        except OSError as exc:
            logger.warning("Could not remove %s: %s", f, exc)
    logger.info("Cleanup complete: %d files removed", cleaned)


def allowed(user_id, chat_id) -> bool:
    if not authorized_user_list and not authorized_chat_list:
        return True
    return user_id in authorized_user_list or chat_id in authorized_chat_list


def is_authorized(message) -> bool:
    uid = message.from_user.id if message.from_user else None
    return allowed(uid, message.chat.id)


async def reply(message, text, **kw):
    """Always reply WITH quote, so results of several files stay distinguishable."""
    for extra in ({"quote": True}, {"reply_to_message_id": message.id}, {}):
        try:
            return await message.reply_text(text, **extra, **kw)
        except TypeError:        # this library version does not know that kwarg
            continue
    return None


async def safe_edit(msg, text, markup=None):
    for _ in range(2):
        try:
            return await msg.edit_text(text, reply_markup=markup)
        except MessageNotModified:
            return None
        except FloodWait as exc:
            await asyncio.sleep(exc.value + 1)
        except Exception as exc:
            logger.warning("edit failed: %s", exc)
            return None


async def safe_markup(msg, markup):
    try:
        await msg.edit_reply_markup(markup)
    except MessageNotModified:
        pass
    except FloodWait as exc:
        await asyncio.sleep(exc.value + 1)
    except Exception as exc:
        logger.warning("markup edit failed: %s", exc)


_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
_BARE_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:[/?#]\S*)?$", re.I)
_FILE_EXT = {
    "txt", "py", "js", "json", "md", "zip", "rar", "7z", "apk", "exe", "msi", "pdf", "doc", "docx",
    "xls", "xlsx", "jpg", "jpeg", "png", "gif", "mp4", "mkv", "mp3", "html", "css", "sh", "log",
    "csv", "iso", "dll", "bat", "tar", "gz",
}


def extract_url(text: str):
    m = _URL_RE.search(text)
    if m:
        return m.group(0).rstrip(").,;")
    t = text.strip()
    if _BARE_RE.match(t):
        host = re.split(r"[/?#]", t)[0]
        if host == t and host.rsplit(".", 1)[-1].lower() in _FILE_EXT:
            return None                      # looks like "file.txt", not a site
        return "https://" + t
    return None


async def enqueue(status, runner):
    async def set_status(text):
        await safe_edit(status, text)

    job = Job(run=runner, set_status=set_status)
    pos = queue.submit(job)
    if pos > 0:
        job.shown_pos = pos
        await set_status(queue.queued_text(pos))
    return job


async def show_report(status, rep: vt.Report):
    cache_put(rep)
    rep.view = "m"
    await safe_edit(status, ui.render_main(rep), ui.build_keyboard(rep, "m"))
    # Result is already on screen; the extra link row appears 1-2 s later without delaying it.
    asyncio.create_task(attach_links(rep, status))


async def attach_links(rep: vt.Report, msg):
    if not rep.package or rep.official is not None:
        return
    rep.official = []                        # mark as in-progress
    try:
        rep.official = await links.get_official_links(rep.package)
    except Exception:
        logger.exception("link lookup failed")
    if rep.official and rep.view == "m":
        await safe_markup(msg, ui.build_keyboard(rep, "m"))


# ---------------------------------------------------------------- commands
@app.on_message(filters.command(["start"]))
async def cmd_start(client, message):
    if not is_authorized(message):
        await reply(message, "⛔️ Unauthorized. This bot is private.")
        return
    name = message.from_user.mention if message.from_user else "there"
    text = (
        f"👋 Hello {name}!\n"
        "<b>VirusTotal Scanner</b>\n\n"
        f"📁 Send a <b>file</b> (up to {MAX_FILE_MB} MB)\n"
        "🔗 Send a <b>URL</b>\n"
        "🔎 Send a <b>hash</b> (MD5 / SHA1 / SHA256) for an instant lookup\n\n"
        "/stats · /queue"
    )
    await reply(message, text, reply_markup=InlineKeyboardMarkup([[
        InlineKeyboardButton("📦 Source Code", url="https://github.com/connect-bad/VirusTotal-Bot2.0")
    ]]))


@app.on_message(filters.command(["stats"]))
async def cmd_stats(client, message):
    if not is_authorized(message):
        return
    up = int(time.time() - start_time)
    text = (
        "📊 <b>Bot Statistics</b>\n\n"
        f"⏱ Uptime · {up // 3600}h {(up % 3600) // 60}m\n"
        f"📁 Files · {stats['files']}  (cache hits {stats['cached']})\n"
        f"🔗 URLs · {stats['urls']}\n"
        f"🔎 Hash lookups · {stats['hashes']}\n"
        f"🔄 Rescans · {stats['rescans']}\n"
        f"❌ Errors · {stats['errors']}\n"
        f"📥 Queue · {queue.snapshot()}"
    )
    await reply(message, text)


@app.on_message(filters.command(["queue"]))
async def cmd_queue(client, message):
    if is_authorized(message):
        await reply(message, f"📥 <b>Queue</b>\n{queue.snapshot()}")


# ---------------------------------------------------------------- files
async def process_file(client, message, status, job: Job):
    doc = message.document
    loop = asyncio.get_running_loop()
    uid = doc.file_unique_id
    path = None

    def on_state(state: str):                # called from the VT thread
        text = {"uploading": "🔼 Uploading to VirusTotal…",
                "analysing": "🧬 Analysing…"}.get(state)
        if text:
            asyncio.run_coroutine_threadsafe(job.set_status(text), loop)

    try:
        rep = None
        known = FILE_HASH.get(uid)
        if known:                            # same file sent before: skip the download
            await job.set_status("⚙️ Fetching report…")
            rep = await asyncio.to_thread(vt.lookup_hash, known)
            if rep and rep.pending:
                rep = None
            if rep:
                stats["cached"] += 1

        if rep is None:
            safe = re.sub(r"[^\w.\-]", "_", doc.file_name or "file")
            path = os.path.join(DOWNLOAD_DIR, f"{message.chat.id}_{message.id}_{safe}")
            await job.set_status("⬇️ Downloading…")
            last = [0.0]

            async def progress(cur, total):
                now = time.monotonic()
                if total > 5 * 1024 * 1024 and now - last[0] > 3:
                    last[0] = now
                    await job.set_status(f"⬇️ Downloading… {cur * 100 / total:.0f}%")

            path = await client.download_media(message, file_name=path, progress=progress)
            if not path:
                await job.set_status("✖️ Download failed")
                stats["errors"] += 1
                return

            await job.set_status("⚙️ Checking…")
            rep, state = await asyncio.to_thread(vt.scan_file, path, on_state)
            if rep is None:
                msgs = {
                    "no_key": "✖️ VirusTotal API key is missing",
                    "too_large": (f"✖️ <b>Upload failed</b>\n\nThis file is {(doc.file_size or 0) / 1048576:.1f} MB "
                                  "and VirusTotal did not return a large-file upload URL."),
                }
                await job.set_status(msgs.get(state, "✖️ Upload failed. Please try again."))
                stats["errors"] += 1
                return
            if state == "cached":
                stats["cached"] += 1

        FILE_HASH[uid] = rep.sha256
        while len(FILE_HASH) > 500:
            FILE_HASH.popitem(last=False)
        stats["files"] += 1
        await show_report(status, rep)
    except Exception:
        logger.exception("process_file failed")
        stats["errors"] += 1
        await job.set_status("✖️ Something went wrong. Please try again.")
    finally:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


@app.on_message(filters.document)
async def on_document(client, message):
    if not is_authorized(message):
        await reply(message, "⛔️ Unauthorized")
        return
    size = message.document.file_size or 0
    if size > MAX_BYTES:
        await reply(message, f"⭕️ File is too big. Limit is {MAX_FILE_MB} MB.")
        return
    status = await reply(message, "⏳ Starting…")
    await enqueue(status, lambda job: process_file(client, message, status, job))


# ---------------------------------------------------------------- urls + hashes
async def process_url(status, url: str, job: Job):
    try:
        await job.set_status("🔍 Scanning URL…")
        rep, state = await asyncio.to_thread(vt.scan_url, url)
        if rep is None:
            await job.set_status("✖️ URL scan failed")
            stats["errors"] += 1
            return
        stats["urls"] += 1
        await show_report(status, rep)
    except Exception:
        logger.exception("process_url failed")
        stats["errors"] += 1
        await job.set_status("✖️ Something went wrong. Please try again.")


async def process_hash(message, h: str):
    status = await reply(message, "🔎 Looking up hash…")
    try:
        rep = await asyncio.to_thread(vt.lookup_hash, h)
        if rep is None:
            await safe_edit(status, "❔ <b>Not found on VirusTotal</b>\n\nSend the file itself to scan it.")
            return
        stats["hashes"] += 1
        await show_report(status, rep)
    except Exception:
        logger.exception("process_hash failed")
        stats["errors"] += 1
        await safe_edit(status, "✖️ Lookup failed. Please try again.")


@app.on_message(filters.text & ~filters.command(["start", "stats", "queue"]))
async def on_text(client, message):
    if not is_authorized(message):
        return
    text = message.text.strip()
    private = message.chat.type == enums.ChatType.PRIVATE

    scan_cmd = re.match(r"^/scan(?:@\w+)?\s*", text)
    if scan_cmd:
        text = text[scan_cmd.end():].strip()
    elif not private:
        reply = message.reply_to_message
        if not (reply and reply.from_user and reply.from_user.is_self):
            return                           # ignore normal group chatter

    if vt.is_hash(text):
        asyncio.create_task(process_hash(message, text))
        return

    url = extract_url(text)
    if not url:
        return
    status = await reply(message, "⏳ Starting…")
    await enqueue(status, lambda job: process_url(status, url, job))


# ---------------------------------------------------------------- callbacks
@app.on_callback_query()
async def on_callback(client, cq):
    uid = cq.from_user.id if cq.from_user else None
    cid = cq.message.chat.id if cq.message else None
    if not allowed(uid, cid):
        await cq.answer("⛔️ Not allowed", show_alert=True)
        return

    data = cq.data or ""
    if len(data) < 3 or data[0] not in "mdsrxh" or data[1] not in "fu":
        await cq.answer()
        return
    act, kind, key = data[0], data[1], data[2:]
    msg = cq.message

    rep = await ensure_report(kind, key)
    if rep is None:
        await cq.answer("⌛ Report no longer available on VirusTotal.", show_alert=True)
        return

    if act in "mds":
        await cq.answer()
        rep.view = act
        text = {"m": ui.render_main, "d": ui.render_detections, "s": ui.render_signatures}[act](rep)
        await safe_edit(msg, text, ui.build_keyboard(rep, act))
        if act == "m" and rep.package and rep.official is None:
            asyncio.create_task(attach_links(rep, msg))

    elif act == "x":
        await cq.answer("⚠️ Third-party mirrors. Verify the hash/signature before installing.")
        if rep.mirrors is None:
            rep.mirrors = links.get_mirrors(rep.package)
        await safe_markup(msg, ui.build_keyboard(rep, "m", mirrors_open=True))

    elif act == "h":
        await cq.answer()
        await safe_markup(msg, ui.build_keyboard(rep, "m"))

    elif act == "r":
        if rep.busy:
            await cq.answer("⏳ Already in the queue")
            return
        rep.busy = True
        await cq.answer("🔄 Rescan queued")

        async def runner(job: Job):
            try:
                await job.set_status("🔄 Rescanning…")
                if rep.kind == "file":
                    new, _ = await asyncio.to_thread(vt.rescan_file, rep.sha256)
                else:
                    new, _ = await asyncio.to_thread(vt.scan_url, rep.url)
                if new is None:
                    stats["errors"] += 1
                    await safe_edit(msg, "✖️ <b>Rescan failed</b>, showing the previous report\n\n"
                                    + ui.render_main(rep), ui.build_keyboard(rep, "m"))
                    return
                stats["rescans"] += 1
                new.official, new.mirrors = rep.official, rep.mirrors
                await show_report(msg, new)
            except Exception:
                logger.exception("rescan failed")
                stats["errors"] += 1
                await safe_edit(msg, ui.render_main(rep), ui.build_keyboard(rep, "m"))
            finally:
                rep.busy = False

        await enqueue(msg, runner)


# ---------------------------------------------------------------- keep-alive ping
def kuma_push():
    while True:
        try:
            r = requests.get(PUSH_URL, headers={"User-Agent": "Heroku-Bot"}, timeout=10)
            logger.info("Ping sent, status %s", r.status_code)
        except Exception as exc:
            logger.error("Ping failed: %s", exc)
        time.sleep(60)


if __name__ == "__main__":
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    cleanup_temp_files()
    logger.info("Bot is starting...")
    if PUSH_URL:
        threading.Thread(target=kuma_push, daemon=True).start()
    app.run()      # handles SIGINT/SIGTERM itself
