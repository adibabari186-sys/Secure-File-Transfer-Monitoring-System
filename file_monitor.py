import os
import time
import json
import hashlib
import getpass
import psutil
from flask import Flask, render_template, Response
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = Flask(__name__)

# Configured monitoring directories
WATCH_DIR = "./monitored_folder"
RESTRICTED_DIR = "./restricted_folder"
AUDIT_LOG_FILE = "file_transfer_audit.log"

SENSITIVE_KEYWORDS = ["confidential", "secret", "restricted", "passwords", "financial"]

def get_current_user_and_process():
    try:
        user = getpass.getuser()
    except Exception:
        user = "SystemUser"
        
    try:
        proc_name = psutil.Process().name()
    except Exception:
        proc_name = "unknown.exe"
        
    return user, proc_name

def calculate_sha256(file_path):
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return "N/A"
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "ERROR_READING_FILE"

def is_file_sensitive(file_path):
    filename = os.path.basename(file_path).lower()
    for word in SENSITIVE_KEYWORDS:
        if word in filename:
            return True
    if RESTRICTED_DIR in file_path:
        return True
    return False

def write_audit_log(event_type, src, dest="N/A", is_sensitive=False, is_unauthorized=False, hash_val="N/A"):
    user, process = get_current_user_and_process()
    log_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "source": src,
        "destination": dest,
        "user": user,
        "process": process,
        "sensitive": is_sensitive,
        "unauthorized": is_unauthorized,
        "hash": hash_val
    }
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(json.dumps(log_data) + "\n")

class FileWatcherHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        sensitive = is_file_sensitive(path)
        file_hash = calculate_sha256(path)
        unauthorized = True if sensitive else False
        write_audit_log("FILE_CREATED", path, "N/A", sensitive, unauthorized, file_hash)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path
        sensitive = is_file_sensitive(path)
        file_hash = calculate_sha256(path)
        write_audit_log("FILE_MODIFIED", path, "N/A", sensitive, False, file_hash)

    def on_moved(self, event):
        if event.is_directory:
            return
        src = event.src_path
        dest = event.dest_path
        sensitive = is_file_sensitive(src) or is_file_sensitive(dest)
        file_hash = calculate_sha256(dest)
        unauthorized = False
        if sensitive and ("usb" in dest.lower() or "temp" in dest.lower() or "external" in dest.lower()):
            unauthorized = True
        write_audit_log("FILE_MOVED", src, dest, sensitive, unauthorized, file_hash)

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = event.src_path
        sensitive = is_file_sensitive(path)
        write_audit_log("FILE_DELETED", path, "N/A", sensitive, sensitive, "FILE_REMOVED")

@app.route("/")
def index():
    logs = []
    stats = {"total": 0, "sensitive": 0, "alerts": 0}
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        entry = json.loads(line)
                        logs.append(entry)
                        stats["total"] += 1
                        if entry.get("sensitive"):
                            stats["sensitive"] += 1
                        if entry.get("unauthorized"):
                            stats["alerts"] += 1
                    except Exception:
                        continue
    logs.reverse()
    return render_template("dashboard.html", logs=logs, stats=stats)

@app.route("/download-report")
def download_report():
    report = "=========================================================\n"
    report += "       SECURE FILE TRANSFER MONITORING REPORT            \n"
    report += f"       Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += "=========================================================\n\n"
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        item = json.loads(line)
                        status = "VIOLATION ALERT" if item['unauthorized'] else "NORMAL"
                        report += f"[{item['timestamp']}] Event: {item['event_type']} | User: {item['user']} | Status: {status}\n"
                        report += f"Path: {item['source']}\n"
                        report += f"SHA-256: {item['hash']}\n"
                        report += "---------------------------------------------------------\n"
                    except Exception:
                        continue
    return Response(report, mimetype="text/plain", headers={"Content-disposition": "attachment; filename=Security_Audit_Report.txt"})

if __name__ == "__main__":
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)
    if not os.path.exists(RESTRICTED_DIR):
        os.makedirs(RESTRICTED_DIR)
    if not os.path.exists(AUDIT_LOG_FILE):
        open(AUDIT_LOG_FILE, "w").close()

    event_handler = FileWatcherHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIR, recursive=True)
    observer.start()
    
    print(">>> Monitoring Started Successfully!")
    print(">>> Open Browser: http://127.0.0.1:5000/")
    
    try:
        app.run(debug=True, port=5000, use_reloader=False)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
