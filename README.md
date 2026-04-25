Live Network Map Engine
A real-time, browser-based network traffic visualization tool. It renders interactive D3.js force-directed graphs from packet captures and supports live 802.11 WiFi sniffing directly from an ESP32 microcontroller via WebSerial. Windump ethtap pipeline provided aswell

Features
Live WebSerial Capture: Stream raw 802.11 frames directly from an ESP32 to the browser at 921600 baud.

Multi-Format Parsing: Native browser parsing for binary PCAP/PCAPNG (Ethernet and 802.11 LinkTypes), Wireshark CSVs, and live NDJSON streams.

Real-time OUI Resolution: Automatically fetches IEEE OUI data to resolve MAC addresses into human-readable vendor names (e.g., Apple_ab:cd:ef) mirroring Wireshark's behavior.

Interactive Visualization: D3.js physics-based node graph with protocol filtering, timeline scrubbing, and dynamic node sizing based on traffic volume.

supports precaptured pcaps, csv exports visualization (including timing).



SCREENSHOTS:
<br>
From example pcaps on https://www.wireshark.org/download/automated/captures/ <br>
fuzz-2006-07-05-6279.pcap
<img width="1820" height="985" alt="image" src="https://github.com/user-attachments/assets/ccca3d95-2b4c-4a6f-b8d5-8ddc34326ca5" />

randpkt-2020-09-06-16170.pcap
<img width="1630" height="718" alt="image" src="https://github.com/user-attachments/assets/f39db83c-7d12-4c6d-b39c-716d9817af18" />
