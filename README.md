# PacketLoop 🚀

**PacketLoop** is a professional-grade network stress testing and traffic orchestration tool. It leverages the power of `aireplay-ng` and `tcpreplay` to create controlled network environments where specific devices are prioritized while others are restricted.

## Core Features

- **Automated Deauth Loops**: Continuously monitors an Access Point and disconnects all clients EXCEPT for those on a user-defined whitelist.
- **Traffic Replay (Turbo Mode)**: Uses `tcpreplay` to inject high-speed traffic from a PCAP file, effectively testing the network's bandwidth limits and congestion handling.
- **Timed Operations**: Run loops for a specific timeframe, allowing for automated and scheduled network testing.
- **Airplay/WiFi Optimization**: Designed to clear interference and ensure maximum "crazy speed" for prioritized devices.

## Research & Logic

### 1. The "Whitelist" Mechanism
Since standard WiFi tools don't natively support whitelisting for deauthentication, PacketLoop implements a "Targeted Scan & Kill" strategy:
1. **Discover**: Background monitoring of the channel for new client associations.
2. **Filter**: Compare discovered MAC addresses against the `WHITELIST`.
3. **Execute**: Spawn individual `aireplay-ng -0` processes for every non-whitelisted device.

### 2. High-Speed Injection (The "Crazy Speed" Tool)
To achieve "crazy speed", PacketLoop uses two methods:
- **`tcpreplay --topspeed`**: Replays captured high-throughput sessions back onto the channel at the maximum Physical Layer rate possible.
- **`aireplay-ng -3` (ARP Replay)**: Loops ARP requests to stimulate traffic generation from the AP, increasing the overall packet frequency on the network.

## Prerequisites

- **OS**: Linux (Kali Linux, Ubuntu) or WSL2 (with USB WiFi passthrough).
- **Hardare**: Wireless card supporting **Monitor Mode** and **Packet Injection** (e.g., Alfa AWUS036ACM).
- **Tools**: `aircrack-ng` suite, `tcpreplay`.

## Usage

```bash
sudo python3 packet_loop.py -i wlan0mon -b 00:11:22:33:44:55 -w AA:BB:CC:DD:EE:FF -t 300 -p speed_test.pcap
```

- `-i`: Your monitor mode interface.
- `-b`: The target Access Point BSSID.
- `-w`: MAC addresses that should STAY connected.
- `-t`: Duration in seconds.
- `-p`: (Optional) PCAP file for traffic injection.

---
**Disclaimer**: This tool is for educational purposes only. Unauthorized use on networks without explicit permission is illegal.
