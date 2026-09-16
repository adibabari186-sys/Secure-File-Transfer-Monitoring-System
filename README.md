# Secure File Transfer Monitoring System 🛡️

This project is a real-time file system monitoring and integrity verification tool built using Python and Flask. It helps track file activities in a specific directory, calculates SHA-256 hashes to check for file integrity, flags unauthorized access or policy violations based on sensitive keywords, and lets you download complete security audit logs.

---

## 📌 Main Features

* **Real-time File Tracking:** Monitors file events like creation, updates, and movement using Python's `watchdog` library.
* **SHA-256 Hash Verification:** Automatically calculates hash values for every file to make sure data hasn't been altered or tampered with.
* **Policy Violation Alerts:** Instantly catches files containing sensitive terms (like `confidential`) and flags them as unauthorized.
* **Web Dashboard:** Simple Flask-based UI that displays live logs, timestamps, user info, and hash details clearly.
* **Audit Logs Export:** Allows you to download the entire system activity log as a text file (`Security_Audit_Report.txt`) with a single click.

---

## 🛠️ Tech Stack

* **Language:** Python 3
* **Web Framework:** Flask
* **File System Monitoring:** Watchdog
* **Security & Cryptography:** Hashlib (SHA-256)
* **Frontend:** Basic HTML5 & CSS3 (Bootstrap)

---

## 📂 Project Directory Structure

```text
FileMonitorProject/
├── file_monitor.py            # Main script running the watchdog listener & Flask app
├── templates/
│   └── dashboard.html         # Frontend template for the web dashboard
├── monitored_folder/          # Folder monitored for file events
└── README.md                  # Project documentation
```
---

## 🚀 How to Run the Project

1. **Clone this repository:**
   ```bash
   git clone https://github.com/adibabari186-sys/Secure-File-Transfer-Monitoring-System.git
   cd Secure-File-Transfer-Monitoring-System
   ```
2. **Install required dependencies:**
   ```bash
   pip install flask watchdog
   ```

3. **Start the application:**
   ```bash
   python file_monitor.py
   ```
4. **Open the dashboard:**
   Go to your web browser and open `http://127.0.0.1:5000`

---

## ✍️ Developed By
**Adiba Bari**  
*Cybersecurity Intern | Unified Mentor*
