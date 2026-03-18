import tkinter as tk
from tkinter import ttk
from datetime import datetime
import os
import psutil

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- IMPORT OUR ACTUAL AI ENGINE & CONFIG ---
from rdefender_agent import MLScannerEngine, quarantine_file, SUPPORTED_EXTENSIONS, LOG_FILE


# ---------------- FILE MONITOR HANDLER ----------------
class FileHandler(FileSystemEventHandler):
    def __init__(self, ui):
        self.ui = ui

    def on_created(self, event):
        if not event.is_directory:
            self.ui.process_file(event.src_path)


# ---------------- MAIN UI ----------------
class RDefenderUI:

    def __init__(self, root):
        self.root = root
        self.root.title("RDefender – Real-Time Protection")
        self.root.geometry("1000x700")
        self.root.configure(bg="#0f172a")

        self.monitoring = False
        self.observer = None
        self.agent_process = psutil.Process(os.getpid())

        self.setup_styles()
        self.create_header()
        self.create_status_panel()
        self.create_controls()
        self.create_alerts_table()
        self.create_metrics_panel()

        # 🧠 BOOT UP THE ML ENGINE INTO RAM
        self.scanner = MLScannerEngine()
        self.proc_label.config(text="Engine Status: LOADED & READY", fg="#22c55e")

        self.update_agent_metrics()

    # ---------------- STYLE ----------------
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "Treeview",
            background="#1e293b",
            foreground="white",
            rowheight=28,
            fieldbackground="#1e293b",
            font=("Segoe UI", 10)
        )

        style.configure(
            "Treeview.Heading",
            background="#111827",
            foreground="white",
            font=("Segoe UI", 11, "bold")
        )

    # ---------------- HEADER ----------------
    def create_header(self):
        header = tk.Frame(self.root, bg="#111827", height=60)
        header.pack(fill="x")

        title = tk.Label(
            header,
            text="RDEFENDER – Real-Time Ransomware Detection",
            font=("Segoe UI", 18, "bold"),
            fg="white",
            bg="#111827"
        )
        title.pack(pady=10)

    # ---------------- STATUS ----------------
    def create_status_panel(self):
        frame = tk.Frame(self.root, bg="#0f172a")
        frame.pack(fill="x", pady=10)

        self.status_label = tk.Label(
            frame,
            text="● STATUS: STOPPED",
            fg="#ef4444",
            bg="#0f172a",
            font=("Segoe UI", 12, "bold")
        )
        self.status_label.pack()

    # ---------------- BUTTONS ----------------
    def create_controls(self):
        frame = tk.Frame(self.root, bg="#0f172a")
        frame.pack(pady=10)

        start_btn = tk.Button(
            frame,
            text="START MONITORING",
            bg="#22c55e",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            width=20,
            command=self.start_monitoring
        )
        start_btn.pack(side="left", padx=10)

        stop_btn = tk.Button(
            frame,
            text="STOP MONITORING",
            bg="#ef4444",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            width=20,
            command=self.stop_monitoring
        )
        stop_btn.pack(side="left", padx=10)

    # ---------------- ALERT TABLE ----------------
    def create_alerts_table(self):
        frame = tk.LabelFrame(
            self.root,
            text="Detection Alerts",
            bg="#0f172a",
            fg="white",
            font=("Segoe UI", 12)
        )
        frame.pack(fill="both", expand=True, padx=20, pady=10)

        columns = ("time", "file", "result", "action")
        self.tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )

        self.tree.heading("time", text="Time")
        self.tree.heading("file", text="File")
        self.tree.heading("result", text="Detection")
        self.tree.heading("action", text="Action")

        self.tree.column("time", width=120)
        self.tree.column("file", width=480)
        self.tree.column("result", width=150)
        self.tree.column("action", width=150)

        # UI Color Tags for Threat Levels
        self.tree.tag_configure('malware', foreground='#ef4444')     # Red
        self.tree.tag_configure('suspicious', foreground='#facc15')  # Yellow
        self.tree.tag_configure('clean', foreground='#22c55e')       # Green
        self.tree.tag_configure('error', foreground='#a855f7')       # Purple

        self.tree.pack(fill="both", expand=True)

    # ---------------- METRICS ----------------
    def create_metrics_panel(self):
        frame = tk.LabelFrame(
            self.root,
            text="System Metrics (RDefender Agent)",
            bg="#0f172a",
            fg="white",
            font=("Segoe UI", 12)
        )
        frame.pack(fill="x", padx=20, pady=10)

        self.cpu_label = tk.Label(
            frame, text="Agent CPU: Calculating...", bg="#0f172a", fg="#38bdf8", font=("Segoe UI", 11)
        )
        self.cpu_label.pack(anchor="w", padx=10)

        self.mem_label = tk.Label(
            frame, text="Agent RAM: Calculating...", bg="#0f172a", fg="#38bdf8", font=("Segoe UI", 11)
        )
        self.mem_label.pack(anchor="w", padx=10)

        self.proc_label = tk.Label(
            frame, text="Engine Status: LOADING...", bg="#0f172a", fg="#facc15", font=("Segoe UI", 11, "bold")
        )
        self.proc_label.pack(anchor="w", padx=10)

    # ---------------- FILE MONITOR ----------------
    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.status_label.config(text="● STATUS: RUNNING", fg="#22c55e")
            self.proc_label.config(text="Engine Status: ACTIVE SCANNING", fg="#22c55e")

            # Change this to your test folder!
            path = r"C:\Users\hp world\Downloads"

            event_handler = FileHandler(self)
            self.observer = Observer()
            self.observer.schedule(event_handler, path, recursive=True)
            self.observer.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.status_label.config(text="● STATUS: STOPPED", fg="#ef4444")
        self.proc_label.config(text="Engine Status: IDLE", fg="#facc15")

        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None

    # ---------------- LIVE AI SCANNER ----------------
    def process_file(self, path):
        name = os.path.basename(path)

        # 1. Filter out logs and non-executables
        if LOG_FILE.lower() in name.lower() or not name.lower().endswith(SUPPORTED_EXTENSIONS):
            return

        # 2. Run the actual ML Engine
        label, score = self.scanner.scan_file(path)

        # 3. Handle the results
        if label == "ERROR":
            result_str = "SCAN FAILED"
            action = "Ignored"
            tag = "error"
        else:
            score_pct = float(score) * 100
            result_str = f"{label} ({score_pct:.1f}%)"
            
            # 🛡️ THE QUARANTINE TRIGGER
            if label == "MALWARE":
                action = "QUARANTINED"
                tag = "malware"
                success = quarantine_file(path)
                if not success:
                    action = "Q-FAILED (LOCKED)"
            elif label == "SUSPICIOUS":
                action = "Logged/Flagged"
                tag = "suspicious"
            else:
                action = "Allowed"
                tag = "clean"

        time_str = datetime.now().strftime("%H:%M:%S")

        # 4. Safely push updates to the UI thread
        self.root.after(0, lambda: self._insert_to_tree(time_str, name, result_str, action, tag))

    def _insert_to_tree(self, time_str, name, result_str, action, tag):
        item_id = self.tree.insert("", 0, values=(time_str, name, result_str, action)) # insert at index 0 pushes to top
        self.tree.item(item_id, tags=(tag,))

    # ---------------- METRIC UPDATE ----------------
    def update_agent_metrics(self):
        try:
            cpu = self.agent_process.cpu_percent(interval=None)
            mem = self.agent_process.memory_info().rss / (1024 * 1024)

            self.cpu_label.config(text=f"Agent CPU: {cpu:.2f}%")
            self.mem_label.config(text=f"Agent RAM: {mem:.2f} MB")
        except Exception:
            pass

        self.root.after(1000, self.update_agent_metrics)


# ---------------- RUN ----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = RDefenderUI(root)
    root.mainloop()