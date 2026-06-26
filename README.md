# 🌐 PacketSleuth – Network Packet Analyzer

## 📖 Overview

PacketSleuth is a Python-based Network Packet Analyzer featuring live packet capture, network interface selection, protocol-based filtering, packet decoding, safe payload preview, live protocol statistics, CSV export, and session summary reporting.

This project was developed as part of the **Prodigy InfoTech Cyber Security Internship Program**.

---

# Network Packet Analysis Concept

Network packet analysis is the process of capturing and examining data packets as they travel across a network. Every packet contains useful information such as source and destination IP addresses, communication protocols, port numbers, and payload data.

Packet analyzers are commonly used by network administrators, cybersecurity professionals, and SOC analysts for:

* Network troubleshooting
* Traffic monitoring
* Protocol analysis
* Security investigations
* Identifying suspicious network activity

PacketSleuth demonstrates how packet capture and analysis work in an ethical and controlled environment for educational and cybersecurity learning purposes.

---

# ✨ Features

## Ethical Startup Banner

* Displays an educational usage disclaimer
* Promotes authorized and responsible packet analysis

## Network Interface Selection

* Lists available network interfaces
* Allows the user to choose the desired interface for packet capture

## Capture Filters

Supports packet capture using:

* All Traffic
* TCP
* UDP
* ICMP
* DNS
* Custom IP Address
* Custom Port Number

## Live Packet Capture

* Captures packets in real time
* Displays decoded packet information immediately

## Packet Decoding

Extracts important packet information including:

* Source IP Address
* Destination IP Address
* Source Port
* Destination Port
* Protocol
* Packet Length

## Safe Payload Preview

* Displays only a hexadecimal preview of packet payloads
* Limits payload preview for safer inspection
* Avoids reconstructing complete transmitted content

## Live Protocol Statistics

Maintains live counts for protocols including:

* TCP
* UDP
* ICMP
* DNS
* Others

## CSV Export

* Saves captured packet information into a CSV file
* Useful for later analysis and reporting

## Session Summary Report

Displays a summary after packet capture including:

* Total packets captured
* Protocol distribution
* Capture statistics

---

# 🛠️ Technologies Used

* Python
* Scapy
* Colorama
* Socket Programming
* CSV Module
* Collections Module

---

# 📂 Project Structure

```text
PacketSleuth/
│
├── sniffer.py
├── requirements.txt
├── captures/
└── reports/
```

---

# 🚀 Installation & Usage

## Windows

### 1. Clone the Repository

```powershell
git clone https://github.com/manigandanb02/PRODIGY_CS_05.git PacketSleuth
```

**Output**

```text
Cloning into 'PacketSleuth'...
Receiving objects: 100% (XX/XX), done.
Resolving deltas: 100%, done.
```

### 2. Navigate to the Project Folder

```powershell
cd PacketSleuth
```

**Output**

```text
C:\Users\YourName\PacketSleuth>
```

### 3. Install Dependencies

```powershell
py -m pip install -r requirements.txt
```

**Output**

```text
Collecting scapy
Collecting colorama
Installing collected packages: colorama, scapy
Successfully installed colorama-0.4.6 scapy-2.6.1
```

### 4. Run PacketSleuth

> **Run Command Prompt or PowerShell as Administrator.**

```powershell
python sniffer.py
```

**Output**

```text
======================================================================
PacketSleuth - Network Packet Analyzer
Version 1.0 | CLI Edition
======================================================================

Educational & Authorized Use Only

[✓] Initializing PacketSleuth
[✓] Loading network interfaces
[✓] Ready to capture packets
```

---

## Linux

### 1. Clone the Repository

```powershell
git clone https://github.com/manigandanb02/PRODIGY_CS_05.git PacketSleuth
```

**Output**

```text
Cloning into 'PacketSleuth'...
Receiving objects: 100% (XX/XX), done.
Resolving deltas: 100%, done.
```

### 2. Navigate to the Project Folder

```powershell
cd PacketSleuth
```

**Output**

```text
user@ubuntu:~/PacketSleuth$
```

### 3. Install Python & Required Tools

```powershell
sudo apt update
```
```bash
sudo apt install python3 python3-pip python3-venv
```

**Output**

```text
Reading package lists... Done
Building dependency tree... Done
The following NEW packages will be installed:
python3-pip python3-venv
...
Setting up python3-pip...
Setting up python3-venv...
```

### 4. Create a Virtual Environment

```powershell
python3 -m venv venv
```

**Output**

```text
(No output)
```

### 5. Activate the Virtual Environment

```powershell
source venv/bin/activate
```

**Output**

```text
(venv) user@ubuntu:~/PacketSleuth$
```

### 6. Install Dependencies

```powershell
pip install -r requirements.txt
```

**Output**

```text
Collecting scapy
Collecting colorama
Installing collected packages: colorama, scapy
Successfully installed colorama-0.4.6 scapy-2.6.1
```

### 7. Run PacketSleuth

```powershell
sudo ./venv/bin/python sniffer.py
```

**Output**

```text
======================================================================
PacketSleuth - Network Packet Analyzer
Version 1.0 | CLI Edition
======================================================================

Educational & Authorized Use Only

[✓] Initializing PacketSleuth
[✓] Loading network interfaces
[✓] Ready to capture packets
```

---

# Generating Network Traffic

While PacketSleuth is running, open another terminal and generate some traffic.

### ICMP Traffic

```bash
ping 8.8.8.8
```

**Output**

```text
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=18.4 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=18.1 ms
```

### DNS Traffic

```bash
nslookup google.com
```

**Output**

```text
Server: 8.8.8.8
Address: 8.8.8.8#53

Name: google.com
Address: 142.250.xxx.xxx
```

### HTTP/HTTPS Traffic

```bash
curl https://example.com
```

**Output**

```html
<!doctype html>
<html>
<head>
<title>Example Domain</title>
...
</html>
```

---

# Stop Packet Capture

Press:

```text
Ctrl + C
```

**Example Output**

```text
Stopping packet capture...

======================================================================
Capture Summary
======================================================================

Capture Duration : 00:01:42
Total Packets    : 146

Protocol Distribution
-----------------------------------
TCP       : 82
UDP       : 31
DNS       : 17
ICMP      : 10
ARP       : 6

======================================================================

[✓] CSV exported successfully.
[✓] Saved to: captures/capture_20260626_103512.csv

[✓] Report saved to: reports/report_20260626_103512.txt
```

> **Note:** PacketSleuth captures live network packets. Administrator (Windows) or root (Linux) privileges are required to access network interfaces for packet capture.

---

## Demo Video

Watch the project demonstration on LinkedIn:

[LinkedIn Demo Video](https://www.linkedin.com/posts/manigandanb02_prodigyinfotech-cybersecurity-python-ugcPost-7476353112828727296-BKIJ/?utm_source=share&utm_medium=member_desktop&rcm=ACoAAFJ8ul4BQ42d707c6KxMYCd3agIPNUqbyhA)

---

# 📚 Learning Outcomes

Through this project, I learned:

* Fundamentals of network packet analysis
* Live packet capture using Scapy
* IP, TCP, UDP, ICMP, and DNS packet decoding
* Network protocol inspection
* Packet filtering techniques
* Safe payload inspection
* CSV data export
* Real-time network traffic monitoring
* Command-line application development

---

# ⚠️ Disclaimer

This project is developed for educational purposes and cybersecurity learning.

PacketSleuth is intended to demonstrate network packet capture and analysis techniques in an ethical and controlled environment. It should only be used on networks and systems that you own or are explicitly authorized to monitor.

Unauthorized packet capture or network monitoring may violate privacy laws, organizational policies, or applicable regulations.
