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

## 🧠 System Architecture Overview

```
┌─────────────┐           ┌───────────────────────┐
│   CLIENT    │           │        SERVER         │
│  (GUI App)  │           │   (TCP/UDP Listener)  │
└────┬────────┘           └──────────┬────────────┘
     │                               │
     │   TCP (Port 5001)            │
     ├─────────────────────────────►│
     │   - Auth via Token           │
     │   - Encrypted AES Key        │
     │   - Chunked File Transfer    │
     │   - Hash Integrity Check     │
     │                              ▼
     │                        File Saved (if valid)
     │
     │
     │   UDP (Port 5002)            │
     ├─────────────────────────────►│
     │   - FILENAME / KEY init      │
     │   - CHUNK:<seq><hash><data>  │
     │   - ACK / NACK handshake     │
     │   - Adaptive Delay Control   │
     │                              ▼
     │                        Reassembled & Saved
     │
     │
     │   HYBRID MODE                │
     └────── Ping Test ───────────►│
             (selects TCP or UDP based on latency)
```

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
```

---

## 🔧 Usage

### 🖥️ Start the Server

```bash
python server.py
```

- Listens on `0.0.0.0:5001` (TCP) and `0.0.0.0:5002` (UDP)
- Automatically starts `iperf3` server on both ports
- Requires `private_key.pem` in the root directory
-Note: You can run server.py on a different machine within the same local network. Make sure the server's IP address is reachable from the client machine and that ports 5001 and 5002 are open in the server's firewall.

### 🧑‍💻 Run the Client

```bash
python client.py
```

- Select a file to send
- Enter the server IP address
- Choose the protocol (TCP, UDP, HYBRID)
- Optionally set a number of packets to corrupt
- Click **Start Transfer**

---

## 📁 Folder Structure

```
.
├── client.py
├── server.py
├── Tools/
│   └── iperf3.exe
├── public_key.pem
├── private_key.pem
├── RecievedFiles/
│   └── [Received files saved here]
```

---

## 🔐 Security Notes

- AES-128 with CBC mode is used for confidentiality.
- Each file chunk is hashed (SHA-256) and verified on the receiver side.
- The AES key is RSA-encrypted before being transmitted.
- Authentication is handled via a static token (can be improved to session-based).

---

## 📈 Performance Monitoring

The client automatically runs `iperf3` tests on both TCP and UDP ports before transfer and logs the results in real-time.

---

## 🧪 Testing and Development

- Simulate packet loss by setting a corruption count (GUI Spinbox)
- Monitor adaptive delay behavior in UDP mode based on RTT
- Manually test with various network conditions or VPN

---

## 📌 TODO / Improvements

- 🔒 Switch from static token to JWT or session-based authentication
- 📡 NAT traversal and peer-to-peer support
- 🧾 Progress bar in GUI
- 🗂️ Support for multiple concurrent transfers and clients

---

## 📃 License

MIT License © 2025

---

## 👨‍💻 Authors

Developed by [Your Name / Team Name] as part of the **Advanced Secure File Transfer System** project.
