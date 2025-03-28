from modules.capture1 import start_capture
from modules.analysis1 import analyze_logs  # Changed from analysis to analysis1
from modules.ui1 import SecurityUI  # Changed from ui to ui1
import tkinter as tk
import threading

if __name__ == "__main__":
    # Start capture in a thread
    capture_thread = threading.Thread(target=start_capture)
    capture_thread.start()

    # Start UI in the main thread (Tkinter requires this)
    root = tk.Tk()
    app = SecurityUI(root)
    root.mainloop()

    # Stop capture when UI closes
    capture_thread.join()