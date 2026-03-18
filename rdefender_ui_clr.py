import tkinter as tk
from tkinter import ttk
from datetime import datetime
import os
import random
import psutil

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ---------------- FILE MONITOR HANDLER ----------------
class FileHandler(FileSystemEventHandler):
    def __init__(self, ui):
        self.ui = ui

    def on_created(self, event):
        if not event.is_directory:
            self.ui.process_file(event.src_path)

    def on_modified(self, event):
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

        self.setup_styles()

        self.create_header()
        self.create_status_panel()
        self.create_controls()
        self.create_alerts_table()
        self.create_metrics_panel()

        self.update_chrome_metrics()

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

        self.tree.column("time", width=200)
        self.tree.column("file", width=400)
        self.tree.column("result", width=150)
        self.tree.column("action", width=150)

        self.tree.pack(fill="both", expand=True)

    # ---------------- METRICS ----------------
    def create_metrics_panel(self):

        frame = tk.LabelFrame(
            self.root,
            text="System Metrics (Chrome)",
            bg="#0f172a",
            fg="white",
            font=("Segoe UI", 12)
        )

        frame.pack(fill="x", padx=20, pady=10)

        self.cpu_label = tk.Label(
            frame,
            text="CPU Usage: Detecting...",
            bg="#0f172a",
            fg="#38bdf8",
            font=("Segoe UI", 11)
        )

        self.cpu_label.pack(anchor="w", padx=10)

        self.mem_label = tk.Label(
            frame,
            text="Memory Usage: Detecting...",
            bg="#0f172a",
            fg="#38bdf8",
            font=("Segoe UI", 11)
        )

        self.mem_label.pack(anchor="w", padx=10)

        self.proc_label = tk.Label(
            frame,
            text="Process Status: Checking...",
            bg="#0f172a",
            fg="#facc15",
            font=("Segoe UI", 11, "bold")
        )

        self.proc_label.pack(anchor="w", padx=10)

    # ---------------- FILE MONITOR ----------------
    def start_monitoring(self):

        if not self.monitoring:

            self.monitoring = True
            self.status_label.config(text="● STATUS: RUNNING", fg="#22c55e")

            path = r"C:\Users\hp world\Downloads"

            event_handler = FileHandler(self)

            self.observer = Observer()
            self.observer.schedule(event_handler, path, recursive=True)
            self.observer.start()

    def stop_monitoring(self):

        self.monitoring = False
        self.status_label.config(text="● STATUS: STOPPED", fg="#ef4444")

        if self.observer:

            self.observer.stop()
            self.observer.join()
            self.observer = None

    # ---------------- FILE PROCESS ----------------
    def process_file(self, path):

        name = os.path.basename(path)

        result = random.choice(["Benign", "Suspicious"])
        action = "Allowed" if result == "Benign" else "Monitored"

        time = datetime.now().strftime("%H:%M:%S")

        self.tree.insert("", "end", values=(time, name, result, action))

    # ---------------- CHROME PROCESS ----------------
    def find_chrome(self):

        procs = []

        for p in psutil.process_iter(['name']):
            try:
                if p.info['name'] and 'chrome' in p.info['name'].lower():
                    procs.append(p)
            except:
                pass

        return procs

    # ---------------- METRIC UPDATE ----------------
    def update_chrome_metrics(self):

        chrome = self.find_chrome()

        if chrome:

            cpu = 0
            mem = 0

            for p in chrome:
                try:
                    cpu += p.cpu_percent(interval=0)
                    mem += p.memory_info().rss
                except:
                    pass

            mem = mem / (1024 * 1024)

            self.cpu_label.config(text=f"CPU Usage: {cpu:.2f}%")
            self.mem_label.config(text=f"Memory Usage: {mem:.2f} MB")

            self.proc_label.config(
                text=f"Chrome Running ({len(chrome)} processes)",
                fg="#22c55e"
            )

        else:

            self.proc_label.config(
                text="Chrome Not Running",
                fg="#ef4444"
            )

        self.root.after(1000, self.update_chrome_metrics)


# ---------------- RUN ----------------
if __name__ == "__main__":

    root = tk.Tk()
    app = RDefenderUI(root)
    root.mainloop()