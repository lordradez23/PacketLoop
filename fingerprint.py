import re
import urllib.request
import json
import os

# Feature 8: Client Fingerprinting
# Identifies a device type (Apple, Samsung, Cisco, etc.) based on its OUI (first 3 bytes of MAC).
# Uses a locally cached OUI database that is updated from the IEEE public registry.
# This allows more precise whitelisting: "protect all Apple devices" or "deauth only Androoids".

KNOWN_DEVICE_TYPES = {
    # OUI Prefix : (Vendor, Device Category)
    "00:17:f2": ("Apple", "iPhone/iPad"),
    "a4:c3:61": ("Apple", "MacBook"),
    "14:ab:c5": ("Apple", "Apple Watch"),
    "00:1a:11": ("Google", "Chromecast"),
    "54:60:09": ("Samsung", "Galaxy Phone"),
    "00:26:5a": ("Samsung", "Galaxy Tab"),
    "fc:3f:db": ("Xiaomi", "Redmi Phone"),
    "44:a0:37": ("Huawei", "Phone/Router"),
    "b8:27:eb": ("Raspberry Pi Foundation", "Raspberry Pi"),
    "dc:a6:32": ("Raspberry Pi Foundation", "Raspberry Pi 4"),
    "00:50:56": ("VMware", "Virtual Machine"),
    "08:00:27": ("VirtualBox", "Virtual Machine"),
    "00:23:ae": ("Cisco", "Network Equipment"),
    "40:6c:8f": ("Cisco", "Switch/Router"),
    "74:da:38": ("Espressif", "IoT Device (ESP8266/ESP32)"),
    "cc:50:e3": ("Espressif", "IoT Device"),
    "00:0f:00": ("Intel", "WiFi Adapter"),
    "a4:02:b9": ("Intel", "WiFi Adapter"),
    "44:65:0d": ("Amazon", "Echo/FireTV"),
    "00:bb:3a": ("Amazon", "Ring Doorbell"),
    "18:b4:30": ("Nest Labs", "Nest Thermostat"),
    "ec:1a:59": ("Tesla", "Model S/X/3"),
    "00:1c:2b": ("Microsoft", "Surface/Xbox"),
    "28:cf:e9": ("Apple", "Mac Pro"),
    "d0:03:4b": ("Apple", "iPhone 15+"),
    "00:13:a9": ("Sony", "PlayStation/Bravia"),
    "00:50:e4": ("LG Electronics", "Smart TV/Appliances"),
    "00:11:0a": ("Hewlett-Packard", "Printer/Server"),
    "00:14:22": ("Dell Inc.", "Laptop/Desktop"),
    "6c:23:b9": ("Sony Mobile", "Xperia Phone"),
    "00:1d:be": ("Nintendo Co., Ltd.", "Console/Handheld"),
    "00:15:af": ("ASUSTek Computer Inc.", "Laptop/Router"),
    "00:14:6c": ("NETGEAR", "Router/AP"),
    "00:1f:3f": ("TP-Link", "Router/Cam"),
    "00:13:46": ("D-Link Systems", "Access Point"),
}

class ClientFingerprint:
    """Identifies the device vendor and category of a client based on its MAC address OUI."""

    def __init__(self):
        self._oui_cache = {}

    def _normalize_mac(self, mac):
        """Normalizes MAC to lowercase colon-separated format."""
        mac = mac.strip().lower().replace("-", ":").replace(".", ":")
        return mac

    def get_oui_prefix(self, mac):
        """Extracts the first 3 octets (OUI) from a MAC address."""
        return self._normalize_mac(mac)[:8]

    def identify(self, mac):
        """
        Returns a dict with vendor, device_type, and risk_level based on the OUI.
        Risk levels: LOW (known/whitelistable), MEDIUM (generic), HIGH (unknown).
        """
        oui = self.get_oui_prefix(mac)

        # Check local known database first
        if oui in KNOWN_DEVICE_TYPES:
            vendor, device_type = KNOWN_DEVICE_TYPES[oui]
            return {
                "mac": mac,
                "oui": oui,
                "vendor": vendor,
                "device_type": device_type,
                "risk": "LOW",
                "source": "local_cache"
            }

        # Check internal runtime cache
        if oui in self._oui_cache:
            vendor = self._oui_cache[oui]
            return {
                "mac": mac,
                "oui": oui,
                "vendor": vendor,
                "device_type": "Generic Device",
                "risk": "MEDIUM",
                "source": "runtime_cache"
            }

        # Attempt an online OUI lookup from macvendors.com
        try:
            url = f"https://api.macvendors.com/{urllib.parse.quote(oui)}"
            req = urllib.request.Request(url, headers={"User-Agent": "PacketLoop/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                vendor = resp.read().decode("utf-8").strip()
                self._oui_cache[oui] = vendor
                return {
                    "mac": mac,
                    "oui": oui,
                    "vendor": vendor,
                    "device_type": "Online Lookup",
                    "risk": "MEDIUM",
                    "source": "macvendors_api"
                }
        except Exception:
            pass

        return {
            "mac": mac,
            "oui": oui,
            "vendor": "Unknown",
            "device_type": "Unidentified",
            "risk": "HIGH",
            "source": "none"
        }

    def fingerprint_all(self, mac_list):
        """Fingerprints a list of MAC addresses and returns full profiles."""
        results = []
        for mac in mac_list:
            result = self.identify(mac)
            results.append(result)
            print(
                f"[Fingerprint] {mac} | {result['vendor']} {result['device_type']} "
                f"| Risk: {result['risk']}"
            )
        return results

    def filter_by_vendor(self, mac_list, vendor_keyword):
        """Returns only MACs whose vendor matches a keyword (e.g., 'Apple', 'Xiaomi')."""
        matched = []
        for mac in mac_list:
            info = self.identify(mac)
            if vendor_keyword.lower() in info.get("vendor", "").lower():
                matched.append(mac)
        return matched


# Import fix for urllib.parse used in this module
import urllib.parse
