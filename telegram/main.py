import asyncio
import logging
import os

import pyrogram
from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from telegraph import Telegraph

import botfunctions

# bot
bot_token = os.environ.get("TOKEN", "") 
api_hash = os.environ.get("HASH", "") 
api_id = os.environ.get("ID", "")
app = Client("my_bot", api_id=api_id, api_hash=api_hash, bot_token=bot_token)
MAXSIZE = 681574400
telegraph = Telegraph()
telegraph.create_account(short_name='VirusTotal')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
def status_file_path(message_id):
    return f"{message_id}downstatus.txt"


def log_task_error(task: asyncio.Task):
    if task.exception():
        logger.error("Scan task failed", exc_info=task.exception())

# start command
@app.on_message(filters.command(["start"]))
async def strt(client: pyrogram.client.Client, message: pyrogram.types.messages_and_media.message.Message):

    START = f'👋🏻 Hello! {message.from_user.mention}\
    \nI am a Bot based on **[VirusTotal-Bot](https://github.com/bipinkrish/VirusTotal-Bot)**\
\
    \n\n__• You can send the file to the bot or forward it from another channel, and it will check file to **[VirusTotal](http://virustotal.com/)** with over **70** different antiviruses.\
\
    \n\n• To get scan results - send me any a file up to **650 MB** in size, and you will receive a detailed analysis of it.\
\
    \n\n• With the help of a bot, you can analyse suspicious files to identify virus and other bad programs.\
\
    \n\n• You can also add me to your chats, and I will be able to analyse the files sent by participants.\
\

     \n\n• ⚠️ Important Warning: Do NOT upload sensitive files (passwords, personal photos, financial docs). Once uploaded to Virus Total, files may be visible to security researchers worldwide.__'

    await app.send_message(message.chat.id, START, reply_to_message_id=message.id, disable_web_page_preview=True,
    reply_markup=InlineKeyboardMarkup([[
                                           InlineKeyboardButton( "📦 Source Code", url="https://github.com/connect-bad/VirusTotal-Bot" )
                                      ]]))


# status updater
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


# progress function
def progress(current, total, message):
    with open(status_file_path(message.id),"w") as fileup:
        fileup.write(f"{current * 100 / total:.1f}%")


# check function
async def checkvirus(message):
    msg = await app.send_message(message.chat.id, '🔽 Downloading...', reply_to_message_id=message.id)
    logger.info("Downloading: ID: %s size: %s", message.id, message.document.file_size)
    dnsta = asyncio.create_task(downstatus(status_file_path(message.id), msg))

    file = await app.download_media(message, progress=progress, progress_args=[message])
    status_path = status_file_path(message.id)
    if os.path.exists(status_path):
        os.remove(status_path)
    await app.edit_message_text(message.chat.id, msg.id, '🔼 Uploading to VirusTotal...')
    logger.info("Uploading: ID: %s size: %s", message.id, message.document.file_size)

    hash = await asyncio.to_thread(botfunctions.uploadfile, file)
    os.remove(file)
    logger.info('ID: %s HASH: %s', message.id, hash)
    
    if not hash:
        await app.edit_message_text(message.chat.id, msg.id, "✖️ Failed")
        logger.error("HASH is empty")
        return
        
    await app.edit_message_text(message.chat.id, msg.id, '⚙️ Checking...')
    logger.info("Checking: ID: %s size: %s", message.id, message.document.file_size)
    maintext, checktext, signatures, link = await asyncio.to_thread(botfunctions.cleaninfo, hash)
    
    if maintext == None:
        await app.edit_message_text(message.chat.id, msg.id, "✖️ Failed")
        logger.error("Function returned None")
        return

    response = telegraph.create_page('VT', content=[f'{maintext}-|-{checktext}-|-{signatures}-|-{link}'])
    tlink = response['url']

    await app.edit_message_text(message.chat.id, msg.id, maintext,
            reply_markup=InlineKeyboardMarkup([[  
                                                    InlineKeyboardButton( "🧪 Detections", callback_data=f"D|{tlink}"),
                                                    InlineKeyboardButton( "🌡 Signatures", callback_data=f"S|{tlink}"),
                                              ],
                                              [
                                                InlineKeyboardButton( "🔗 View on VirusTotal", url=link )
                                              ]]))
                                               
                                               
# document
@app.on_message(filters.document)
async def docu(client: pyrogram.client.Client, message: pyrogram.types.messages_and_media.message.Message):
    if int(message.document.file_size) > MAXSIZE:
        await app.send_message(message.chat.id, "⭕️ File is too Big for VirusTotal. It should be less than 650 MB", reply_to_message_id=message.id)
        return
    task = asyncio.create_task(checkvirus(message))
    task.add_done_callback(log_task_error)
	

# call back functon
@app.on_callback_query()
async def callbck(client: pyrogram.client.Client, message: pyrogram.types.CallbackQuery):
    await message.answer()
    url = message.message.reply_markup.inline_keyboard[1][0].url
    datas = message.data.split("|")
    action = datas[0]
    tlink = datas[1]
    res = telegraph.get_page(tlink.split("https://telegra.ph/")[1], return_content=True, return_html=False)
    result = res["content"][0].split("-|-")
    maintext = result[0]
    checktext = result[1]
    signatures = result[2]

    if action == "B":
        await app.edit_message_text(message.message.chat.id, message.message.id, maintext,
                reply_markup=InlineKeyboardMarkup([[  
                                                        InlineKeyboardButton( "🧪 Detections", callback_data=f"D|{tlink}"),
                                                        InlineKeyboardButton( "🌡 Signatures", callback_data=f"S|{tlink}")
                                                ],
                                                [
                                                InlineKeyboardButton( "🔗 View on VirusTotal", url=url )
                                                ]]))

    if action == "D":
        await app.edit_message_text(message.message.chat.id, message.message.id, checktext,
                reply_markup=InlineKeyboardMarkup([[  
                                                        InlineKeyboardButton( "🔙 Back", callback_data=f"B|{tlink}"),
                                                        InlineKeyboardButton( "🌡 Signatures", callback_data=f"S|{tlink}"),
                                                ],
                                                [
                                                InlineKeyboardButton( "🔗 View on VirusTotal", url=url )
                                                ]]))

    if action == "S":
        await app.edit_message_text(message.message.chat.id, message.message.id, signatures,
                reply_markup=InlineKeyboardMarkup([[  
                                                        InlineKeyboardButton( "🔙 Back", callback_data=f"B|{tlink}"),
                                                        InlineKeyboardButton( "🧪 Detections", callback_data=f"D|{tlink}")
                                                ],
                                                [
                                                InlineKeyboardButton( "🔗 View on VirusTotal", url=url )
                                                ]]))
	           
    
# app run
if __name__ == "__main__":
    logger.info("Bot is starting...")
    app.run()
    logger.info("Bot stopped")
