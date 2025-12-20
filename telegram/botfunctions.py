import hashlib
import os
import time
from datetime import datetime

import requests
import logging

VT_API_KEY = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
logger = logging.getLogger(__name__)

session = requests.Session()
if VT_API_KEY:
    session.headers.update({"x-apikey": VT_API_KEY})


def _hash_file(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def uploadfile(file_path: str):
    if not VT_API_KEY:
        logger.error("VirusTotal API key is missing")
        return None

    file_hash = _hash_file(file_path)
    with open(file_path, "rb") as fp:
        response = session.post(f"{BASE_URL}/files", files={"file": (os.path.basename(file_path), fp)})

    if not response.ok:
        logger.error("VirusTotal upload failed: %s - %s", response.status_code, response.text)
        return None

    analysis_id = response.json().get("data", {}).get("id")
    if analysis_id:
        wait_for_analysis(analysis_id)

    return file_hash


def wait_for_analysis(analysis_id: str, timeout: int = 120, interval: int = 5):
    end_time = time.time() + timeout
    while time.time() < end_time:
        response = session.get(f"{BASE_URL}/analyses/{analysis_id}")
        if response.ok:
            status = response.json().get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return
        time.sleep(interval)


def file_info(file_hash: str):
    if not VT_API_KEY:
        return None

    response = session.get(f"{BASE_URL}/files/{file_hash}")
    if response.status_code == 404:
        return None
    if response.ok:
        return response.json().get("data")
    return None


def counttests(results):
    dcount = 0
    ucount = 0
    ncount = 0
    detected = []
    undetected = []
    notsupported = []
    dresult = []

    for ele in results.values():
        category = ele.get("category")
        engine = ele.get("engine_name") or ele.get("engine")
        result = ele.get("result")

        if category in ("malicious", "suspicious"):
            dcount += 1
            detected.append(engine)
            dresult.append(result)
        elif category in ("undetected", "harmless"):
            ucount += 1
            undetected.append(engine)
        else:
            ncount += 1
            notsupported.append(engine)

    return dcount, ucount, ncount, detected, undetected, notsupported, dresult


def _format_time(timestamp: int):
    if not timestamp:
        return "N/A"
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")


def cleaninfo(hash):
    obj = file_info(hash)
    if obj is None:
        logger.warning("File does not Exist")
        return None, None, None, None

    attributes = obj.get("attributes", {})
    results = attributes.get("last_analysis_results") or {}
    malicious_count, undetected_count, unsupported_count, DL, UL, NL, DR = counttests(results)

    filename = attributes.get("meaningful_name") or (attributes.get("names") or [hash])[0]
    type_description = attributes.get("type_description", "Unknown")
    file_type = attributes.get("type_tag", "unknown")
    size = attributes.get("size", 0)
    times_submitted = attributes.get("times_submitted", 0)
    first_submission = _format_time(attributes.get("first_submission_date"))
    last_modification = _format_time(attributes.get("last_modification_date"))
    magic = attributes.get("magic", "N/A")

    fronttext = f'🧬 **Detections**: __{malicious_count} / {malicious_count+undetected_count}__\
        \n\n🔖 **File Name**: __{filename}__\
        \n🔒 **File Type**: __{type_description} ({file_type})__\
        \n📁 **File Size**: __{pow(2,-20)*size:.2f} MB__\
        \n⏱ **Times Submitted**: __{times_submitted}__\
        \n\n🔬 **First Analysis**\n• __{first_submission}__\
        \n🔭 **Last Analysis**\n• __{last_modification}__\
        \n\n🎉 **Magic**\n• __{magic}__'

    testtext = '**❌ - Malicious/Suspicious\n✅ - UnDetected/Harmless\n⚠️ -  Not Supported**\n➖➖➖➖➖➖➖➖➖➖\n'
    for ele in DL:
        testtext = f'{testtext}❌ {ele}\n'
    for ele in UL:
        testtext = f'{testtext}✅ {ele}\n'
    for ele in NL:
        testtext = f'{testtext}⚠️ {ele}\n'

    signatures_list = [f'❌ {engine}\n╰ {result or "Malicious"}\n' for engine, result in zip(DL, DR)]
    signatures = ''.join(signatures_list)

    if malicious_count == 0:
        signatures = "✅ Your File is Safe"

    link = f'https://virustotal.com/gui/file/{hash}'
    return fronttext, testtext, signatures, link
