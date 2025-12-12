Network Traffic Analysis and Manipulation Techniques
Author: Odebode Seun



This repository documents various techniques for network traffic analysis and manipulation using tools like Nmap and Scapy. The focus is on host discovery, OS fingerprinting, aggressive scanning, SMB enumeration, and basic packet sniffing. All activities were performed in a controlled lab environment for educational purposes. Important: Always obtain permission before scanning networks, as unauthorized scanning may be illegal.
Objectives

Discover live hosts on a network subnet.
Identify the operating system running on a specific host.
Perform detailed and aggressive port scanning to detect services, versions, and vulnerabilities.
Enumerate SMB (Server Message Block) shares on a target host.
Use Scapy for packet sniffing to capture and analyze network traffic.
Demonstrate practical commands and their outputs to understand network reconnaissance and manipulation.

Setup
Environment

Operating System: Linux (e.g., Kali Linux or Ubuntu), as commands require sudo for privileged access.
Network: A lab network with IP range 10.6.6.0/24 (private subnet).
Tools Required:
Nmap: For scanning and enumeration.
Scapy: For packet crafting and sniffing (Python library).

Installation:BashCopysudo apt update
sudo apt install nmap python3-scapy
Permissions: Run commands with sudo where necessary for raw socket access.
Target Host: Focused on 10.6.6.23 (a sample host in the lab).
Screenshots: Stored in the screenshots/ directory for visual reference (e.g., terminal outputs).

Run all commands in a terminal. For Scapy, start an interactive session with sudo scapy.
Results and Demonstrations
Below are the key sections with commands, brief explanations, results, and screenshots where applicable.
1. Identifying Network Hosts
Command:
BashCopynmap -sn 10.6.6.0/24
Explanation: This performs a ping scan (-sn) to discover live hosts on the subnet without port scanning. It sends ICMP echo requests (or ARP on local networks) to check for responses.
Results: 7 hosts were found up in the network.
Host Discovery Screenshot
(Screenshot shows Nmap output listing live hosts like 10.6.6.11, 10.6.6.12, etc., with latency and MAC addresses.)
2. Finding an Operating System
Command:
BashCopysudo nmap -O 10.6.6.23
Explanation: OS fingerprinting (-O) analyzes responses to various probes (e.g., TCP/IP stack behavior) to guess the remote operating system.
Results: Linux 4.15 - 5.8 is running on this host. The scan also detected open ports and potential device types.
OS Detection Screenshot
(Screenshot displays Nmap report with OS details, open ports like TCP 21, and network distance.)
3. Aggressive Scanning
Command:
BashCopysudo nmap -p21 -sV -A -T4 10.6.6.23
Explanation:

-p21: Scans only port 21 (FTP).
-sV: Detects service versions.
-A: Enables aggressive mode (OS detection, version detection, script scanning, and traceroute).
-T4: Sets timing to "aggressive" for faster scanning.

This combines multiple scans for comprehensive reconnaissance.
Results: Detected FTP service (vsftpd 3.0.3), OS details, and no vulnerabilities in this run.
Aggressive Scan Screenshot
(Screenshot includes port state, service info, and script outputs like FTP anonymous login check.)
Additional Aggressive Scan Variant:
BashCopynmap -A -p139,445 10.6.6.23
Explanation:

-A: Aggressive mode.
-p139,445: Targets NetBIOS (139) and SMB (445) ports for Windows-related services.

Results: Detailed service info on ports 139/445, including SMB version and shares if accessible.
Aggressive Ports Scan Screenshot
(Screenshot shows open ports, SMB service details, and script results.)
4. SMB Enumeration Techniques
Command:
BashCopynmap --script smb-enum-shares.nse -p445 10.6.6.23
Explanation: Uses Nmap Scripting Engine (NSE) script smb-enum-shares.nse to list SMB shares on port 445. It attempts anonymous or guest access to enumerate share names, types, and permissions.
Results: Enumerated shares like IPC$, print$, and others with access levels (e.g., read-only). No authentication required in this case, but security warnings noted.
SMB Enumeration Screenshot
(Screenshot lists shares, types (e.g., disk tree), and anonymous access details.)
5. Scapy Packet Sniffing
Command (in Scapy interactive shell):
PythonCopysniff()
Explanation: Scapy's sniff() function captures packets on the default interface. Use parameters like iface="br-internal", filter="icmp", count=4 for specificity:

iface: Interface to listen on (e.g., a bridge in virtual environments).
filter: BPF filter (e.g., "icmp" for ICMP packets).
count: Number of packets to capture.

Note: The underscore (_) automatically stores the last returned value, including captured packets (a PacketList object).
Example Enhanced Command:
PythonCopysniff(iface="br-internal", filter="icmp", count=4)
Results: Captures 4 ICMP packets (e.g., pings). Packets can be inspected with _.summary() or saved to PCAP.
Scapy Sniff Screenshot
(Screenshot shows captured packet summaries, including Ethernet/IP/ICMP layers.)
Repository Structure

README.md: This file.
screenshots/: Folder containing all terminal output images (e.g., host_discovery.png).
scripts/: Optional folder for saved Scapy scripts or Nmap output files (e.g., export with nmap -oX output.xml).
No unnecessary files; all content is organized and version-controlled.

Conclusion
This project demonstrates foundational network analysis techniques. Results highlight the target host (10.6.6.23) running Linux with exposed services like FTP and SMB. For manipulation (e.g., packet crafting in Scapy), extend with functions like send(IP()/ICMP()). Always prioritize ethical use and security best practices.
If reproducing, ensure a safe lab setup. Contributions welcome!
