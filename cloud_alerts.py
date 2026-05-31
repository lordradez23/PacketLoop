import urllib.request
import urllib.parse
import json
import time
import os

# Feature 6: Cloud Alerts - Discord and Telegram Notifications
# Sends real-time push notifications when:
# - A new unauthorized client is detected.
# - A WPA handshake is captured.
# - The attack session ends (summary report).
# Requires no third-party libraries - uses urllib only.

class CloudAlerts:
    def __init__(self, discord_webhook=None, telegram_token=None, telegram_chat_id=None):
        self.discord_webhook = discord_webhook or os.getenv("PACKETLOOP_DISCORD_WEBHOOK")
        self.telegram_token = telegram_token or os.getenv("PACKETLOOP_TELEGRAM_TOKEN")
        self.telegram_chat_id = telegram_chat_id or os.getenv("PACKETLOOP_TELEGRAM_CHAT_ID")
        self._enabled = bool(self.discord_webhook or (self.telegram_token and self.telegram_chat_id))

    def log(self, msg):
        print(f"[CloudAlerts] {msg}")

    def _send_discord(self, message):
        """Sends a message to a Discord channel via webhook."""
        if not self.discord_webhook:
            return
        payload = json.dumps({"content": message}).encode("utf-8")
        req = urllib.request.Request(
            self.discord_webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status not in (200, 204):
                    self.log(f"Discord alert failed with status: {resp.status}")
        except Exception as e:
            self.log(f"Discord request failed: {e}")

    def _send_telegram(self, message):
        """Sends a message via Telegram Bot API."""
        if not (self.telegram_token and self.telegram_chat_id):
            return
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = json.dumps({
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    self.log(f"Telegram alert failed with status: {resp.status}")
        except Exception as e:
            self.log(f"Telegram request failed: {e}")

    def alert(self, message):
        """Broadcasts an alert to all configured services."""
        if not self._enabled:
            return
        self._send_discord(message)
        self._send_telegram(message)

    def new_client_detected(self, mac, bssid):
        msg = (
            f"**[PacketLoop] Unauthorized Client Detected**\n"
            f"BSSID: `{bssid}`\n"
            f"Client MAC: `{mac}`\n"
            f"Time: `{time.strftime('%Y-%m-%d %H:%M:%S')}`\n"
            f"Action: Deauth initiated."
        )
        self.log(f"Alerting: new client {mac}")
        self.alert(msg)

    def handshake_captured(self, bssid, filepath):
        msg = (
            f"**[PacketLoop] WPA Handshake Captured!**\n"
            f"BSSID: `{bssid}`\n"
            f"File: `{filepath}`\n"
            f"Time: `{time.strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        self.log("Alerting: handshake captured.")
        self.alert(msg)

    def session_ended(self, bssid, duration, deauth_count):
        msg = (
            f"**[PacketLoop] Session Complete**\n"
            f"BSSID: `{bssid}`\n"
            f"Duration: `{duration}s`\n"
            f"Total Deauths Sent: `{deauth_count}`\n"
            f"Time: `{time.strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        self.log("Alerting: session ended.")
        self.alert(msg)
