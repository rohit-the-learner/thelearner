import psutil
import sqlite3
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import threading

# Database setup
DB_PATH = "data/logs.db"
stop_event = threading.Event()

def init_database():
    """Initialize the SQLite database with a logs table."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("Database initialized.")

class FileChangeHandler(FileSystemEventHandler):
    EXCLUDED_FILES = {"logs.db", "logs.db-journal", "logs.db-shm", "logs.db-wal"}

    def on_modified(self, event):
        if not stop_event.is_set() and not self._is_excluded(event.src_path):
            if os.path.isdir(event.src_path):
                log_event("Folder Modified", f"Folder modified: {event.src_path}")
            else:
                log_event("File Modified", f"File changed: {event.src_path}")

    def on_created(self, event):
        if not stop_event.is_set() and not self._is_excluded(event.src_path):
            if os.path.isdir(event.src_path):
                log_event("Folder Created", f"Folder created: {event.src_path}")
            else:
                log_event("File Created", f"File created: {event.src_path}")

    def on_deleted(self, event):
        if not stop_event.is_set() and not self._is_excluded(event.src_path):
            if os.path.isdir(event.src_path):
                log_event("Folder Deleted", f"Folder deleted: {event.src_path}")
            else:
                log_event("File Deleted", f"File deleted: {event.src_path}")

    def _is_excluded(self, filepath):
        filename = os.path.basename(filepath)
        return filename in self.EXCLUDED_FILES

def log_event(event_type, details):
    """Log an event to the database with thread safety."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logs (timestamp, event_type, details) VALUES (?, ?, ?)",
                       (timestamp, event_type, details))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging event: {e}")
    finally:
        conn.close()

def monitor_processes():
    """Monitor running processes and log new app launches."""
    known_processes = set()
    while not stop_event.is_set():
        current_processes = set(psutil.pids())
        new_processes = current_processes - known_processes
        for pid in new_processes:
            try:
                process = psutil.Process(pid)
                cmdline = " ".join(process.cmdline()) if process.cmdline() else "No command line"
                details = f"PID: {pid}, Name: {process.name()}, Cmdline: {cmdline}"
                log_event("App Opened", details)
                if process.name().lower() in ["explorer.exe", "cmd.exe", "powershell.exe"]:
                    if cmdline and os.path.isdir(cmdline.split()[-1]):
                        log_event("Folder Opened", f"Folder accessed via {process.name()}: {cmdline}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        known_processes = current_processes
        time.sleep(1)

def monitor_files(directory="./data"):
    """Monitor file changes in the specified directory."""
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

def create_file(filename, directory="./data"):
    """Create a file in the specified directory."""
    filepath = os.path.join(directory, filename)
    with open(filepath, "w") as f:
        f.write("Test file created by Security Event Recorder")
    # The FileChangeHandler will log this automatically

def create_folder(foldername, directory="./data"):
    """Create a folder in the specified directory."""
    folderpath = os.path.join(directory, foldername)
    os.makedirs(folderpath, exist_ok=True)
    # The FileChangeHandler will log this automatically

def delete_file(filename, directory="./data"):
    """Delete a file from the specified directory."""
    filepath = os.path.join(directory, filename)
    if os.path.exists(filepath) and os.path.isfile(filepath):
        os.remove(filepath)
    # The FileChangeHandler will log this automatically


def delete_folder(foldername, directory="./data"):
    """Delete a folder from the specified directory."""
    folderpath = os.path.join(directory, foldername)
    if os.path.exists(folderpath) and os.path.isdir(folderpath):
        import shutil
        shutil.rmtree(folderpath)
    # The FileChangeHandler will log this automatically

def start_capture():
    """Start capturing events (processes and files)."""
    if not os.path.exists("data"):
        os.makedirs("data")
    init_database()
    process_thread = threading.Thread(target=monitor_processes)
    file_thread = threading.Thread(target=monitor_files, args=("./data",))
    process_thread.start()
    file_thread.start()
    process_thread.join()
    file_thread.join()