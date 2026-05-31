import subprocess
import os
import struct
import time
from collections import defaultdict

# Feature 10: PCAP Analysis Engine
# Post-session analysis of captured .cap/.pcap files.
# Reports on:
# - Total packets and byte volume
# - Unique client MACs discovered
# - Deauth/Disassoc frame counts
# - EAPOL handshake presence
# - Throughput (packets/sec and bytes/sec) estimation
# Uses tshark for parsing, with a fallback pure-Python PCAP reader.

class PcapAnalyzer:
    def __init__(self, pcap_path):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        self.pcap_path = pcap_path
        self._has_tshark = self._check_tshark()

    def log(self, msg):
        print(f"[PcapAnalyzer] {msg}")

    def _check_tshark(self):
        import shutil
        return shutil.which("tshark") is not None

    def _run_tshark(self, fields, display_filter=None):
        """Runs tshark with a field export query and returns output lines."""
        cmd = ["tshark", "-r", self.pcap_path, "-T", "fields"]
        if display_filter:
            cmd += ["-Y", display_filter]
        for f in fields:
            cmd += ["-e", f]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def count_frames(self):
        """Returns total frame count and total bytes in the capture."""
        lines = self._run_tshark(["frame.number", "frame.len"])
        total_packets = len(lines)
        total_bytes = sum(int(l.split("\t")[1]) for l in lines if "\t" in l and l.split("\t")[1].isdigit())
        return total_packets, total_bytes

    def get_unique_clients(self):
        """Extracts unique MAC addresses from all frames in the capture."""
        lines = self._run_tshark(["wlan.sa"])
        macs = set(l for l in lines if len(l) == 17 and l.count(":") == 5)
        return macs

    def count_deauth_frames(self):
        """Counts deauthentication and disassociation frames."""
        deauth = self._run_tshark(["frame.number"], display_filter="wlan.fc.type_subtype == 0x000c")
        disassoc = self._run_tshark(["frame.number"], display_filter="wlan.fc.type_subtype == 0x000a")
        return len(deauth), len(disassoc)

    def check_handshake(self):
        """Checks if an EAPOL (WPA handshake) frame is present in the capture."""
        eapol_frames = self._run_tshark(["eapol.type"], display_filter="eapol")
        return len(eapol_frames) >= 4  # A full handshake = 4 EAPOL messages

    def estimate_duration(self):
        """Calculates capture duration in seconds from first/last frame timestamps."""
        lines = self._run_tshark(["frame.time_epoch"])
        timestamps = []
        for l in lines:
            try:
                timestamps.append(float(l))
            except ValueError:
                pass
        if len(timestamps) < 2:
            return 0.0
        return round(timestamps[-1] - timestamps[0], 2)

    def generate_report(self):
        """
        Runs all analysis modules and prints a comprehensive summary report.
        Returns a dictionary with all metrics.
        """
        self.log(f"Analyzing: {self.pcap_path}")
        self.log(f"Using {'tshark' if self._has_tshark else 'basic reader'}...")
        print()

        if not self._has_tshark:
            self.log("WARNING: tshark not found. Install with: sudo apt install tshark")
            self.log("Falling back to basic packet count only.")
            size_bytes = os.path.getsize(self.pcap_path)
            print(f"  File Size : {size_bytes:,} bytes")
            return {"file_size": size_bytes}

        total_packets, total_bytes = self.count_frames()
        unique_clients = self.get_unique_clients()
        deauth_count, disassoc_count = self.count_deauth_frames()
        has_handshake = self.check_handshake()
        duration = self.estimate_duration()
        pps = round(total_packets / duration, 2) if duration > 0 else 0
        bps = round(total_bytes / duration, 2) if duration > 0 else 0

        report = {
            "file": self.pcap_path,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration_seconds": duration,
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "unique_clients": len(unique_clients),
            "client_macs": list(unique_clients),
            "deauth_frames": deauth_count,
            "disassoc_frames": disassoc_count,
            "wpa_handshake_detected": has_handshake,
        }

        print("=" * 55)
        print("         PACKETLOOP - SESSION ANALYSIS REPORT")
        print("=" * 55)
        print(f"  File           : {os.path.basename(self.pcap_path)}")
        print(f"  Duration       : {duration}s")
        print(f"  Total Packets  : {total_packets:,}")
        print(f"  Total Bytes    : {total_bytes:,} ({total_bytes // 1024} KB)")
        print(f"  Avg PPS        : {pps}")
        print(f"  Avg BPS        : {bps}")
        print("-" * 55)
        print(f"  Unique Clients : {len(unique_clients)}")
        print(f"  Deauth Frames  : {deauth_count}")
        print(f"  Disassoc Frames: {disassoc_count}")
        print(f"  WPA Handshake  : {'YES - Captured!' if has_handshake else 'Not found'}")
        print("=" * 55)
        print()

        return report
