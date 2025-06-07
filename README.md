# 🔐 Secure & Adaptive File Transfer System (TCP / UDP / Hybrid)

A GUI-based secure file transfer application built in Python, supporting **TCP**, **UDP**, and a smart **HYBRID** mode that dynamically switches protocols based on real-time network latency. Includes **AES + RSA encryption**, **packet corruption simulation**, **adaptive congestion control**, and **iperf3 performance measurement**.

---

## 🚀 Features

- ✅ **TCP Mode**: Reliable, connection-oriented file transfer with encryption and hash-based integrity checks.
- 📦 **UDP Mode**: Custom-built reliable UDP protocol with ACK/NACK, retry mechanism, and adaptive delay tuning.
- 🤖 **HYBRID Mode**: Automatically selects UDP or TCP based on measured ping (threshold: 100ms).
- 🔐 **Security**: 
  - AES-CBC (128-bit) encryption for file chunks
  - RSA encryption for securely sharing AES key
  - SHA-256 hashing for integrity validation
- ⚠️ **Corrupted Packet Simulation**: Option to simulate N corrupted packets (0–10) for robustness testing
- 📊 **iperf3 Integration**: Real-time network performance measurement for both TCP and UDP ports
- 🖥️ **GUI**: User-friendly interface for file selection, protocol choice, and log display (using `tkinter`)

---

## 🧠 Architecture
[ Client GUI ]
│
├── TCP Transfer ──────────────► [ Server TCP ]
│ └── Save file if hash verified
│
├── UDP Transfer ──────────────► [ Server UDP ]
│ └─ Adaptive retry + ACK/NACK + packet integrity check
│
└── HYBRID Mode ─ Ping-based decision → TCP or UDP


---

## 🛠 Requirements

- Python 3.8+
- Libraries:
  - `pycryptodome`
  - `cryptography`
  - `tkinter` (comes preinstalled with Python)
- External:
  - [iperf3](https://iperf.fr/iperf-download.php) (place `iperf3.exe` in `Tools/` directory)
  - RSA key pair (`public_key.pem`, `private_key.pem`)

To install dependencies:

```bash
pip install pycryptodome cryptography

