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
    def __init__(self, discord_webhook=None, telegram_token=None, telegram_chat_id=None, 
                 matrix_url=None, slack_webhook=None, pushbullet_token=None):
        self.discord_webhook = discord_webhook or os.getenv("PACKETLOOP_DISCORD_WEBHOOK")
        self.telegram_token = telegram_token or os.getenv("PACKETLOOP_TELEGRAM_TOKEN")
        self.telegram_chat_id = telegram_chat_id or os.getenv("PACKETLOOP_TELEGRAM_CHAT_ID")
        self.matrix_url = matrix_url or os.getenv("PACKETLOOP_MATRIX_URL")
        self.slack_webhook = slack_webhook or os.getenv("PACKETLOOP_SLACK_WEBHOOK")
        self.pushbullet_token = pushbullet_token or os.getenv("PACKETLOOP_PUSHBULLET_TOKEN")
        self._enabled = bool(
            self.discord_webhook or 
            (self.telegram_token and self.telegram_chat_id) or 
            self.matrix_url or
            self.slack_webhook or
            self.pushbullet_token
        )

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

    def _send_matrix(self, message):
        """Sends a message to a Matrix room via homeserver URL."""
        if not self.matrix_url:
            return
        payload = json.dumps({
            "msgtype": "m.text",
            "body": message.replace("**", "").replace("`", "")
        }).encode("utf-8")
        req = urllib.request.Request(
            self.matrix_url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    self.log(f"Matrix alert failed with status: {resp.status}")
        except Exception as e:
            self.log(f"Matrix request failed: {e}")

    def _send_slack(self, message):
        """Sends a message to a Slack channel via webhook."""
        if not self.slack_webhook:
            return
        payload = json.dumps({"text": message}).encode("utf-8")
        req = urllib.request.Request(
            self.slack_webhook, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    self.log(f"Slack alert failed with status: {resp.status}")
        except Exception as e:
            self.log(f"Slack request failed: {e}")

    def _send_pushbullet(self, message):
        """Sends a push notification via Pushbullet API."""
        if not self.pushbullet_token:
            return
        payload = json.dumps({
            "type": "note",
            "title": "PacketLoop Alert",
            "body": message.replace("**", "").replace("`", "")
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.pushbullet.com/v2/pushes", data=payload,
            headers={
                "Content-Type": "application/json",
                "Access-Token": self.pushbullet_token
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    self.log(f"Pushbullet alert failed with status: {resp.status}")
        except Exception as e:
            self.log(f"Pushbullet request failed: {e}")

    def alert(self, message):
        """Broadcasts an alert to all configured services."""
        if not self._enabled:
            return
        self._send_discord(message)
        self._send_telegram(message)
        self._send_matrix(message)
        self._send_slack(message)
        self._send_pushbullet(message)

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
