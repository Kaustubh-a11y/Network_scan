# 🔍 NetProbe — Port Intelligence Scanner

> A fast, multithreaded network port scanner with a cyberpunk-themed terminal GUI built in Python.

---

## 📸 Preview

![NetProbe Screenshot](https://files.catbox.moe/xflg0l.png)

---

## 📖 Overview

NetProbe is a desktop port scanning tool that probes a target host across a specified port range and reports open ports along with their associated services. It features a real-time dark-themed GUI, live progress tracking, and exportable results — all powered by Python's standard library.

---

## ✨ Features

- ⚡ **Multithreaded scanning** — up to 500 concurrent threads for fast results
- 🎯 **Service detection** — identifies common services (HTTP, SSH, FTP, MySQL, etc.)
- 📊 **Live stats** — real-time open port count, scanned count, and elapsed timer
- 🖥️ **Terminal-style GUI** — dark cyberpunk theme with neon progress bar
- 💾 **Export results** — save findings to a formatted `.txt` report
- 🛑 **Graceful stop** — cancel mid-scan without crashing

---

## 🚀 Getting Started

### Prerequisites

- Python **3.8+**
- No third-party packages required — uses only the standard library

### Run

```bash
python port_scanner.py
```

---

## 🛠️ Usage

| Field | Description |
|---|---|
| **Host / IP** | Target hostname or IPv4 address |
| **Start Port** | Beginning of the port range (default: `1`) |
| **End Port** | End of the port range (default: `1024`) |

1. Enter the target host and port range
2. Click **▶ SCAN**
3. Watch open ports appear in the terminal output in real time
4. Click **↓ SAVE RESULTS** to export when done

---

## 🖨️ Sample Output

```
NETPROBE Port Scanner ready.
Enter a target and port range above, then press SCAN.

────────────────────────────────────────────────────────────
  TARGET   192.168.1.1 (192.168.1.1)
  PORTS    1 → 1024  (1024 total)
  THREADS  500   TIMEOUT  0.5s
────────────────────────────────────────────────────────────

  [OPEN]  port 53      DNS
  [OPEN]  port 80      HTTP
  [OPEN]  port 443     HTTPS

────────────────────────────────────────────────────────────
  SCAN COMPLETE  3 open port(s) found in 1.56s
────────────────────────────────────────────────────────────
```

> Scanned 1024 ports on a local router in **1.56 seconds** — DNS, HTTP, and HTTPS confirmed open.

---

## 🗂️ Project Structure

```
port_scanner.py      # Main application (scanner + GUI)
README.md            # This file
```

---

## 🔌 Supported Services

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 3306 | MySQL |
| 23 | Telnet | 3389 | RDP |
| 25 | SMTP | 5900 | VNC |
| 53 | DNS | 8080 | HTTP-Alt |
| 80 | HTTP | 110 | POP3 |

---

## ⚙️ Internal Defaults

```
Threads   : 500 (concurrent)
Timeout   : 0.5 seconds per port
Protocol  : TCP (SOCK_STREAM)
```

---

## ⚠️ Disclaimer

> **Only scan hosts you own or have explicit written permission to test.**  
> Unauthorized port scanning may violate local laws and network policies.

---

## 👤 Author

Built as part of an internship project.  
GUI redesigned with a cyberpunk terminal aesthetic using Python `tkinter`.
