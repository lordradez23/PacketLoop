import subprocess
import re
import os

def get_clients(bssid, interface):
    """
    Attempts to find connected clients on a specific BSSID using airodump-ng.
    This is a simplified version that would ideally parse a temporary CSV file.
    """
    # Note: In a real implementation, you would run airodump-ng in the background
    # and periodically read its CSV output.
    # For this demonstration, we return an empty list or a mock if needed.
    return []

def is_valid_mac(mac):
    """Validates if a string is a valid MAC address."""
    return re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac) is not None

def enable_monitor_mode(interface):
    """Enables monitor mode using airmon-ng."""
    try:
        subprocess.run(["airmon-ng", "check", "kill"], check=True)
        subprocess.run(["airmon-ng", "start", interface], check=True)
        return f"{interface}mon" # Usually airmon-ng appends 'mon'
    except Exception as e:
        print(f"Failed to enable monitor mode: {e}")
        return interface

def disable_monitor_mode(interface):
    """Disables monitor mode."""
    try:
        subprocess.run(["airmon-ng", "stop", interface], check=True)
    except Exception as e:
        print(f"Failed to disable monitor mode: {e}")
