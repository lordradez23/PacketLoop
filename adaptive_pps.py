import time
import subprocess
import threading
import os

# Feature 3: Adaptive PPS Control
# Dynamically adjusts injection speed based on channel congestion and adapter stability.
# Avoids crashing the wifi adapter while maintaining max possible throughput.

class AdaptivePPS:
    def __init__(self, interface, min_pps=100, max_pps=3000, step=100):
        self.interface = interface
        self.min_pps = min_pps
        self.max_pps = max_pps
        self.step = step
        self.current_pps = min_pps
        self._lock = threading.Lock()
        self._running = False
        self._monitor_thread = None

    def log(self, msg):
        print(f"[AdaptivePPS] {msg}")

    def get_tx_errors(self):
        """
        Reads TX error count from /proc/net/dev (Linux) to detect adapter stress.
        Returns 0 on Windows or if file is unavailable.
        """
        if os.name == 'nt':
            return 0
        try:
            with open("/proc/net/dev", "r") as f:
                for line in f:
                    if self.interface.replace("mon", "") in line:
                        parts = line.split()
                        # TX errors are at index 10 (0-based)
                        if len(parts) > 10:
                            return int(parts[10])
        except (FileNotFoundError, ValueError):
            return 0
        return 0

    def _adjust_loop(self):
        """Background thread that continuously adjusts PPS based on adapter error rate."""
        prev_errors = self.get_tx_errors()
        while self._running:
            time.sleep(2)
            current_errors = self.get_tx_errors()
            error_delta = current_errors - prev_errors
            prev_errors = current_errors

            with self._lock:
                if error_delta > 30:
                    # Congestion detected: aggressive back-off
                    # We use an exponential back-off factor for safety
                    self.current_pps = max(self.min_pps, int(self.current_pps * 0.7))
                    self.log(f"⚠ CONGESTION ALERT! Delta: {error_delta}. Backed off to {self.current_pps} PPS.")
                elif error_delta < 10:
                    # Channel clear: smooth linear ramp-up
                    self.current_pps = min(self.max_pps, self.current_pps + self.step)
                    if self.current_pps % 500 == 0:
                        self.log(f"✔ Channel stable. Performance at {self.current_pps} PPS.")

    def start(self):
        """Starts the background PPS monitor thread."""
        self._running = True
        self._monitor_thread = threading.Thread(target=self._adjust_loop, daemon=True)
        self._monitor_thread.start()
        self.log(f"Adaptive PPS started. Range: {self.min_pps} - {self.max_pps} PPS.")

    def stop(self):
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=3)
        self.log(f"Adaptive PPS stopped. Final rate: {self.current_pps} PPS.")

    @property
    def pps(self):
        """Returns the current adaptive PPS value in a thread-safe manner."""
        with self._lock:
            return self.current_pps
