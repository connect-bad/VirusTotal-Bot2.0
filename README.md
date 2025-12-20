# VirusTotal Bot

a Telegram Bot to check file in [VirusTotal](http://virustotal.com/) with over 70 different antiviruses.

Inspired from https://github.com/Brijeshkrishna/virustotal-scrapper

---

## Variables

- `HASH` Your API Hash from my.telegram.org
- `ID` Your API ID from my.telegram.org
- `TOKEN` Your bot token from @BotFather
- `VT_API_KEY` Your personal VirusTotal API key (or set `VIRUSTOTAL_API_KEY`)

---

# Usage

You can send a file up to **650 MB** in size to the bot or forward it from another chat, and it will check file in **[VirusTotal](http://virustotal.com/)** with over **70** different antiviruses to get scan results and you will receive a detailed analysis of it. The bot uploads directly to VirusTotal using your own API key—no scraping required.

---

# Deploy

You can use the bot locally by running 'main.py' in 'telegram' folder or deploy using Procfile, Dokerfile, docker-compose.yml
