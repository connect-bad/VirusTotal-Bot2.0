import asyncio
import logging
import os
import time
import glob
import re

import pyrogram
from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from telegraph import Telegraph

import botfunctions

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Bot configuration from environment variables
bot_token = os.environ.get("TOKEN", "") 
api_hash = os.environ.get("HASH", "") 
api_id = os.environ.get("ID", "")

# Authorization from environment variables
# Format: "123456789,987654321" (comma-separated user IDs)
AUTHORIZED_USERS = os.environ.get("AUTHORIZED_USERS", "")
AUTHORIZED_CHATS = os.environ.get("AUTHORIZED_CHATS", "")

# Parse authorized users/chats
authorized_user_list = [int(uid.strip()) for uid in AUTHORIZED_USERS.split(",") if uid.strip().isdigit()]
authorized_chat_list = [int(cid.strip()) for cid in AUTHORIZED_CHATS.split(",") if cid.strip().lstrip('-').isdigit()]

logger.info(f"Authorized users: {authorized_user_list}")
logger.info(f"Authorized chats: {authorized_chat_list}")

# Bot settings
MAXSIZE = 681574400  # 650 MB
app = Client("my_bot", api_id=api_id, api_hash=api_hash, bot_token=bot_token)
telegraph = Telegraph()
telegraph.create_account(short_name='VirusTotal')

# Stats tracking
scan_stats = {"files": 0, "urls": 0, "errors": 0}
start_time = time.time()


def cleanup_temp_files():
    """Remove leftover temporary files from previous runs"""
    patterns = [
        "downloads/*",
        "*downstatus.txt",
        "*.session-journal"
    ]
    
    cleaned = 0
    for pattern in patterns:
        for file in glob.glob(pattern):
            try:
                if os.path.isfile(file) and file != "my_bot.session":
                    os.remove(file)
                    cleaned += 1
                    logger.info(f"Cleaned up: {file}")
            except Exception as e:
                logger.warning(f"Could not remove {file}: {e}")
    
    logger.info(f"Cleanup complete: {cleaned} files removed")


def is_authorized(message):
    """Check if user/chat is authorized"""
    # If no restrictions set, allow everyone
    if not authorized_user_list and not authorized_chat_list:
        return True
    
    user_id = message.from_user.id if message.from_user else None
    chat_id = message.chat.id
    
    if user_id in authorized_user_list:
        return True
    
    if chat_id in authorized_chat_list:
        return True
    
    return False


def status_file_path(message_id):
    return f"{message_id}downstatus.txt"


def log_task_error(task: asyncio.Task):
    if task.exception():
        logger.error("Task failed", exc_info=task.exception())
        scan_stats["errors"] += 1


def extract_url(text):
    """Extract URL from message text"""
    # More flexible URL pattern
    url_pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'
    match = re.search(url_pattern, text)
    if match:
        return match.group(0)
    
    # Also try to detect URLs without protocol
    text = text.strip()
    if '.' in text and ' ' not in text:
        # Might be a URL without http://
        if not text.startswith(('http://', 'https://')):
            return 'https://' + text
        return text
    
    return None


# Create downloads directory
os.makedirs("downloads", exist_ok=True)

# Run cleanup on startup
cleanup_temp_files()


# ============ COMMAND HANDLERS ============

@app.on_message(filters.command(["start"]))
async def strt(client: pyrogram.client.Client, message: pyrogram.types.messages_and_media.message.Message):
    if not is_authorized(message):
        await app.send_message(message.chat.id, "⛔️ Unauthorized. This bot is private.", reply_to_message_id=message.id)
        logger.warning(f"Unauthorized access from user {message.from_user.id}")
        return

    START = f'👋🏻 Hello! {message.from_user.mention}\
    \nI am a VirusTotal Scanner Bot\
\
    \n\n__• Send me a **file** (up to 650 MB) and I will scan it with over 70 antiviruses on **[VirusTotal](http://virustotal.com/)**__\
\
    \n\n__• Send me a **URL/link** and I will check if it\'s safe__\
\
    \n\n__• Use /stats to see bot statistics__\
\
    \n\n__• You can also add me to your chats to scan files sent by participants__'

    await app.send_message(message.chat.id, START, reply_to_message_id=message.id, disable_web_page_preview=True,
    reply_markup=InlineKeyboardMarkup([[
        InlineKeyboardButton("📦 Source Code", url="https://github.com/connect-bad/VirusTotal-Bot2.0")
    ]]))


@app.on_message(filters.command(["stats"]))
async def stats_command(client, message):
    if not is_authorized(message):
        return
    
    uptime = time.time() - start_time
    hours = int(uptime // 3600)
    minutes = int((uptime % 3600) // 60)
    
    stats_text = (
        f"📊 **Bot Statistics**\n\n"
        f"⏱ **Uptime**: {hours}h {minutes}m\n"
        f"📁 **Files Scanned**: {scan_stats['files']}\n"
        f"🔗 **URLs Scanned**: {scan_stats['urls']}\n"
        f"❌ **Errors**: {scan_stats['errors']}\n"
    )
    
    await app.send_message(message.chat.id, stats_text, reply_to_message_id=message.id)


# ============ FILE SCANNING ============

async def downstatus(statusfile, message):
    while not os.path.exists(statusfile):
        await asyncio.sleep(1)

    while os.path.exists(statusfile):
        with open(statusfile, "r") as upread:
            txt = upread.read()
        try:
            await app.edit_message_text(message.chat.id, message.id, f"🔽 Downloaded... {txt}")
            await asyncio.sleep(10)
        except Exception:
            await asyncio.sleep(5)


def progress(current, total, message):
    with open(status_file_path(message.id),"w") as fileup:
        fileup.write(f"{current * 100 / total:.1f}%")


async def checkvirus(message):
    msg = await app.send_message(message.chat.id, '🔽 Downloading...', reply_to_message_id=message.id)
    logger.info("Downloading: ID: %s size: %s", message.id, message.document.file_size)
    dnsta = asyncio.create_task(downstatus(status_file_path(message.id), msg))

    file = await app.download_media(message, file_name=f"downloads/{message.id}_{message.document.file_name}", progress=progress, progress_args=[message])
    status_path = status_file_path(message.id)
    if os.path.exists(status_path):
        os.remove(status_path)
    
    await app.edit_message_text(message.chat.id, msg.id, '🔼 Uploading to VirusTotal...')
    logger.info("Uploading: ID: %s size: %s", message.id, message.document.file_size)

    hash = await asyncio.to_thread(botfunctions.uploadfile, file)
    os.remove(file)
    logger.info('ID: %s HASH: %s', message.id, hash)

    if not hash:
        file_size_mb = message.document.file_size / (1024 * 1024)
        if message.document.file_size > 32 * 1024 * 1024:
            await app.edit_message_text(
                message.chat.id, msg.id, 
                f"✖️ Upload Failed\n\n"
                f"Your file is {file_size_mb:.1f} MB. "
                f"The free VirusTotal API only supports files up to 32 MB.\n\n"
                f"Premium API required for larger files (up to 650 MB)."
            )
        else:
            await app.edit_message_text(message.chat.id, msg.id, "✖️ Upload Failed - Please try again")
        logger.error("HASH is empty")
        scan_stats["errors"] += 1
        return

    await app.edit_message_text(message.chat.id, msg.id, '⚙️ Checking...')
    logger.info("Checking: ID: %s size: %s", message.id, message.document.file_size)
    maintext, checktext, signatures, link = await asyncio.to_thread(botfunctions.cleaninfo, hash)

    if maintext == None:
        await app.edit_message_text(message.chat.id, msg.id, "✖️ Failed")
        logger.error("Function returned None")
        scan_stats["errors"] += 1
        return

    response = await asyncio.to_thread(telegraph.create_page, 'VT', content=[f'{maintext}-|-{checktext}-|-{signatures}-|-{link}'])
    tlink = response['url']

    await app.edit_message_text(message.chat.id, msg.id, maintext,
            reply_markup=InlineKeyboardMarkup([[  
                InlineKeyboardButton("🧪 Detections", callback_data=f"D|{tlink}"),
                InlineKeyboardButton("🌡 Signatures", callback_data=f"S|{tlink}"),
            ], [
                InlineKeyboardButton("🔗 View on VirusTotal", url=link)
            ]]))
    
    scan_stats["files"] += 1


@app.on_message(filters.document)
async def docu(client: pyrogram.client.Client, message: pyrogram.types.messages_and_media.message.Message):
    if not is_authorized(message):
        await app.send_message(message.chat.id, "⛔️ Unauthorized", reply_to_message_id=message.id)
        return
    
    if int(message.document.file_size) > MAXSIZE:
        await app.send_message(message.chat.id, "⭕️ File is too Big for VirusTotal. It should be less than 650 MB", reply_to_message_id=message.id)
        return
    
    task = asyncio.create_task(checkvirus(message))
    task.add_done_callback(log_task_error)


# ============ URL SCANNING ============

async def check_url(message, url):
    msg = await app.send_message(message.chat.id, '🔍 Scanning URL...', reply_to_message_id=message.id)
    logger.info("Scanning URL: %s", url)
    
    url_id = await asyncio.to_thread(botfunctions.scan_url, url)
    
    if not url_id:
        await app.edit_message_text(message.chat.id, msg.id, "✖️ URL scan failed")
        scan_stats["errors"] += 1
        return
    
    await app.edit_message_text(message.chat.id, msg.id, '⚙️ Checking results...')
    maintext, checktext, signatures, link = await asyncio.to_thread(botfunctions.cleanurl, url_id)
    
    if maintext is None:
        await app.edit_message_text(message.chat.id, msg.id, "✖️ Failed to get results")
        scan_stats["errors"] += 1
        return
    
    response = await asyncio.to_thread(telegraph.create_page, 'VT', content=[f'{maintext}-|-{checktext}-|-{signatures}-|-{link}'])
    tlink = response['url']
    
    await app.edit_message_text(message.chat.id, msg.id, maintext,
        reply_markup=InlineKeyboardMarkup([[  
            InlineKeyboardButton("🧪 Detections", callback_data=f"D|{tlink}"),
            InlineKeyboardButton("🌡 Signatures", callback_data=f"S|{tlink}"),
        ], [
            InlineKeyboardButton("🔗 View on VirusTotal", url=link)
        ]]))
    
    scan_stats["urls"] += 1


@app.on_message(filters.text & filters.private & ~filters.command(["start", "stats"]))
async def handle_url_private(client, message):
    """Handle URLs in private chats"""
    if not is_authorized(message):
        return
    
    url = extract_url(message.text)
    if url:
        logger.info(f"URL detected: {url}")
        task = asyncio.create_task(check_url(message, url))
        task.add_done_callback(log_task_error)


@app.on_message(filters.text & (filters.group | filters.channel) & ~filters.command(["start", "stats"]))
async def handle_url_groups(client, message):
    """Handle URLs in groups/channels"""
    if not is_authorized(message):
        return
    
    # In groups, only scan if message starts with /scan or is a reply to bot
    if message.text.startswith('/scan '):
        url = extract_url(message.text[6:])  # Remove '/scan '
    elif message.reply_to_message and message.reply_to_message.from_user.is_self:
        url = extract_url(message.text)
    else:
        return  # Ignore regular group messages
    
    if url:
        logger.info(f"URL detected in group: {url}")
        task = asyncio.create_task(check_url(message, url))
        task.add_done_callback(log_task_error)


# ============ CALLBACK HANDLER ============

@app.on_callback_query()
async def callbck(client: pyrogram.client.Client, message: pyrogram.types.CallbackQuery):
    await message.answer()
    url = message.message.reply_markup.inline_keyboard[-1][0].url
    datas = message.data.split("|")
    action = datas[0]
    tlink = datas[1]
    
    res = await asyncio.to_thread(telegraph.get_page, tlink.split("https://telegra.ph/")[1], return_content=True, return_html=False)
    result = res["content"][0].split("-|-")
    maintext = result[0]
    checktext = result[1]
    signatures = result[2]

    if action == "B":
        await app.edit_message_text(message.message.chat.id, message.message.id, maintext,
                reply_markup=InlineKeyboardMarkup([[  
                    InlineKeyboardButton("🧪 Detections", callback_data=f"D|{tlink}"),
                    InlineKeyboardButton("🌡 Signatures", callback_data=f"S|{tlink}")
                ], [
                    InlineKeyboardButton("🔗 View on VirusTotal", url=url)
                ]]))

    elif action == "D":
        await app.edit_message_text(message.message.chat.id, message.message.id, checktext,
                reply_markup=InlineKeyboardMarkup([[  
                    InlineKeyboardButton("🔙 Back", callback_data=f"B|{tlink}"),
                    InlineKeyboardButton("🌡 Signatures", callback_data=f"S|{tlink}"),
                ], [
                    InlineKeyboardButton("🔗 View on VirusTotal", url=url)
                ]]))

    elif action == "S":
        await app.edit_message_text(message.message.chat.id, message.message.id, signatures,
                reply_markup=InlineKeyboardMarkup([[  
                    InlineKeyboardButton("🔙 Back", callback_data=f"B|{tlink}"),
                    InlineKeyboardButton("🧪 Detections", callback_data=f"D|{tlink}")
                ], [
                    InlineKeyboardButton("🔗 View on VirusTotal", url=url)
                ]]))


# ============ BOT STARTUP ============

if __name__ == "__main__":
    import signal
    
    logger.info("Bot is starting...")
    
    def signal_handler(sig, frame):
        logger.info("Stopping bot...")
        app.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        logger.info("✅ Bot started and running!")
        app.run()
    except Exception as e:
        logger.error(f"Bot crashed: {e}", exc_info=True)
    finally:
        logger.info("Bot stopped")