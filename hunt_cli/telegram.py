"""Telegram bot delivery."""
import os
import requests

BASE = "https://api.telegram.org"


class TelegramError(Exception):
    pass


def _get_creds():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        raise TelegramError("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set")
    return token, chat_id


def send_message(text):
    """Send text message to Telegram."""
    token, chat_id = _get_creds()
    url = f"{BASE}/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    }
    r = requests.post(url, json=payload, timeout=30)
    if r.status_code != 200:
        raise TelegramError(f"failed to send message: {r.text[:200]}")
    return r.json()


def send_document(filename, caption=""):
    """Send file to Telegram."""
    token, chat_id = _get_creds()
    url = f"{BASE}/bot{token}/sendDocument"
    with open(filename, "rb") as f:
        files = {"document": f}
        data = {
            "chat_id": chat_id,
            "caption": caption,
            "parse_mode": "HTML",
        }
        r = requests.post(url, files=files, data=data, timeout=30)
    if r.status_code != 200:
        raise TelegramError(f"failed to send document: {r.text[:200]}")
    return r.json()
