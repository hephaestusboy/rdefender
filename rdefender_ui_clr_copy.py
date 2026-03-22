import os
import warnings
import logging
import json
import hashlib

# --- KILL JOBLIB SPAM DEAD ---
os.environ["PYTHONWARNINGS"] = "ignore"
os.environ["LOKY_MAX_CPU_COUNT"] = "1"
os.environ["JOBLIB_MULTIPROCESSING"] = "0"
warnings.filterwarnings("ignore")
logging.getLogger('joblib').setLevel(logging.ERROR) 

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import psutil
import time
import shutil

# --- NEW CONCURRENCY IMPORTS ---
import threading
import queue

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from rdefender_agent import MLScannerEngine, quarantine_file, SUPPORTED_EXTENSIONS, LOG_FILE, TARGET_WATCH_DIR

# --- WHITELIST CONFIGURATION ---
WHITELIST_FILE = "rdefender_whitelist.json"

def compute_file_hash(filepath):
    """Compute SHA256 hash of a file for whitelisting purposes."""
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def load_whitelist():
    """Load whitelisted file hashes from disk."""
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                return set(json.load(f).get("hashes", []))
        except Exception:
            return set()
    return set()

def save_whitelist(whitelist_set):
    """Save whitelisted file hashes to disk."""
    try:
        with open(WHITELIST_FILE, 'w') as f:
            json.dump({"hashes": list(whitelist_set)}, f, indent=2)
    except Exception:
        pass

# ---------------- FILE MONITOR HANDLER ----------------
class FileHandler(FileSystemEventHandler):
    def __init__(self, ui):
        self.ui = ui

    def on_created(self, event):
        if not event.is_directory:
            self.ui.evaluate_and_queue(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.ui.evaluate_and_queue(event.src_path)

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

        # --- THE RAM QUEUE & FILE STATE DATABASE ---
        self.file_queue = queue.Queue()
        self.file_state_db = {} # Remembers every file and its last modified time
        self.db_lock = threading.Lock() # Makes the database thread-safe
        
        # --- ACTIVE SCANS TRACKER ---
        self.active_scans = set()
        self.active_scans_lock = threading.Lock()
        
        # --- WHITELIST DATABASE ---
        self.whitelist = load_whitelist()
        self.whitelist_lock = threading.Lock()

        self.setup_styles()
        self.create_header()
        self.create_status_panel()
        self.create_controls()
        self.create_alerts_table()
        self.create_metrics_panel()

        self.scanner = MLScannerEngine()
        self.proc_label.config(text="Engine Status: LOADED & READY", fg="#22c55e")

        self.start_queue_workers()
        self.update_agent_metrics()

    # ---------------- QUEUE & SWEEPER WORKERS ----------------
    def start_queue_workers(self):
        """Spawns background agents to read the queue."""
        workers = os.cpu_count() or 4
        for _ in range(workers):
            t = threading.Thread(target=self._process_queue_loop, daemon=True)
            t.start()

    def _process_queue_loop(self):
        while True:
            filepath = self.file_queue.get() 
            try:
                self.process_file(filepath)
            except Exception as e:
                pass
            finally:
                self.file_queue.task_done()

    def start_sweeper(self):
        """The Ultimate EDR Fallback: Sweeps the folder every 3 seconds to catch dropped OS events."""
        t = threading.Thread(target=self._sweeper_loop, daemon=True)
        t.start()

    def _sweeper_loop(self):
        while True:
            if self.monitoring:
                try:
                    for root_dir, _, files in os.walk(TARGET_WATCH_DIR):
                        for file in files:
                            filepath = os.path.join(root_dir, file)
                            self.evaluate_and_queue(filepath)
                except Exception:
                    pass
            time.sleep(3) # Wait 3 seconds before sweeping again

    def evaluate_and_queue(self, filepath):
        """Checks if a file is new, intercepts it by renaming, and queues it."""
        if not filepath.lower().endswith(SUPPORTED_EXTENSIONS):
            return

        # 1. THE SYSTEM BYPASS: Ignore protected Windows background folders
        lower_path = filepath.lower()
        if "$recycle.bin" in lower_path or "system volume information" in lower_path:
            return

        try:
            # 2. THE SIZE LIMIT: Skip files larger than 25 MB (Prevents Entropy Hangs)
            if os.path.getsize(filepath) > 10485760:
                return 

            # 3. WHITELIST CHECK: Skip files that have been recovered
            file_hash = compute_file_hash(filepath)
            if file_hash:
                with self.whitelist_lock:
                    if file_hash in self.whitelist:
                        return  # File is whitelisted, skip scanning

            current_mtime = os.path.getmtime(filepath)
            
            with self.db_lock:
                last_mtime = self.file_state_db.get(filepath, 0)
                if current_mtime == last_mtime:
                    return 
                self.file_state_db[filepath] = current_mtime
                
            # 🛡️ THE PRE-EMPTIVE LOCK (Extension Hijack)
            locked_path = filepath + ".scanning"
            os.rename(filepath, locked_path)
            
            # Put the locked file into the queue
            self.file_queue.put(locked_path)

        except OSError:
            # File is actively writing or strictly locked by the OS Kernel
            pass

    # ---------------- UI ELEMENTS ----------------
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#1e293b", foreground="white", rowheight=28, fieldbackground="#1e293b", font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background="#111827", foreground="white", font=("Segoe UI", 11, "bold"))

    def create_header(self):
        header = tk.Frame(self.root, bg="#111827", height=60)
        header.pack(fill="x")
        title = tk.Label(header, text="RDEFENDER – Real-Time Ransomware Detection", font=("Segoe UI", 18, "bold"), fg="white", bg="#111827")
        title.pack(pady=10)

    def create_status_panel(self):
        frame = tk.Frame(self.root, bg="#0f172a")
        frame.pack(fill="x", pady=10)
        self.status_label = tk.Label(frame, text="● STATUS: STOPPED", fg="#ef4444", bg="#0f172a", font=("Segoe UI", 12, "bold"))
        self.status_label.pack()

    def create_controls(self):
        frame = tk.Frame(self.root, bg="#0f172a")
        frame.pack(pady=10)
        self.monitor_btn = tk.Button(frame, text="START MONITORING", bg="#22c55e", fg="white", font=("Segoe UI", 11, "bold"), width=20, command=self.toggle_monitoring)
        self.monitor_btn.pack(side="left", padx=10)
        scan_folder_btn = tk.Button(frame, text="SCAN FOLDER", bg="#8b5cf6", fg="white", font=("Segoe UI", 11, "bold"), width=20, command=self.scan_specific_folder)
        scan_folder_btn.pack(side="left", padx=10)
        restore_btn = tk.Button(frame, text="RECOVER FILES", bg="#3b82f6", fg="white", font=("Segoe UI", 11, "bold"), width=20, command=self.restore_quarantined_file)
        restore_btn.pack(side="left", padx=10)
        whitelist_btn = tk.Button(frame, text="MANAGE WHITELIST", bg="#f59e0b", fg="white", font=("Segoe UI", 11, "bold"), width=20, command=self.manage_whitelist)
        whitelist_btn.pack(side="left", padx=10)

    def create_alerts_table(self):
        frame = tk.LabelFrame(self.root, text="Detection Alerts", bg="#0f172a", fg="white", font=("Segoe UI", 12))
        frame.pack(fill="both", expand=True, padx=20, pady=10)
        columns = ("time", "file", "result", "action")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings")
        self.tree.heading("time", text="Time")
        self.tree.heading("file", text="File")
        self.tree.heading("result", text="Detection")
        self.tree.heading("action", text="Action")
        self.tree.column("time", width=120)
        self.tree.column("file", width=480)
        self.tree.column("result", width=150)
        self.tree.column("action", width=150)
        self.tree.tag_configure('malware', foreground='#ef4444')     
        self.tree.tag_configure('suspicious', foreground='#facc15')  
        self.tree.tag_configure('clean', foreground='#22c55e')       
        self.tree.tag_configure('error', foreground='#a855f7')       
        self.tree.pack(fill="both", expand=True)

    def create_metrics_panel(self):
        frame = tk.LabelFrame(self.root, text="System Metrics (RDefender Agent)", bg="#0f172a", fg="white", font=("Segoe UI", 12))
        frame.pack(fill="x", padx=20, pady=10)
        self.cpu_label = tk.Label(frame, text="Agent CPU: Calculating...", bg="#0f172a", fg="#38bdf8", font=("Segoe UI", 11))
        self.cpu_label.pack(anchor="w", padx=10)
        self.mem_label = tk.Label(frame, text="Agent RAM: Calculating...", bg="#0f172a", fg="#38bdf8", font=("Segoe UI", 11))
        self.mem_label.pack(anchor="w", padx=10)
        self.proc_label = tk.Label(frame, text="Engine Status: LOADING...", bg="#0f172a", fg="#facc15", font=("Segoe UI", 11, "bold"))
        self.proc_label.pack(anchor="w", padx=10)
        
        # --- NEW UI ELEMENT: Active Scans Display ---
        self.active_scans_label = tk.Label(frame, text="Active Scans: None", bg="#0f172a", fg="#a855f7", font=("Segoe UI", 10, "italic"))
        self.active_scans_label.pack(anchor="w", padx=10, pady=(5, 0))

        # Store button reference for dynamic updates
        self.monitor_btn = None

    # ---------------- MONITORING LOGIC ----------------
    def toggle_monitoring(self):
        """Toggle monitoring on/off with single button."""
        if not self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.status_label.config(text="● STATUS: RUNNING", fg="#22c55e")
            
            # Update button to show STOP state
            self.monitor_btn.config(text="STOP MONITORING", bg="#ef4444", command=self.toggle_monitoring)

            # 1. Take a silent snapshot of all existing files FIRST
            self.build_initial_baseline()

            # 2. Start the background Sweeper thread
            self.start_sweeper()

            # 3. Start Watchdog
            path = TARGET_WATCH_DIR
            event_handler = FileHandler(self)
            self.observer = Observer()
            self.observer.schedule(event_handler, path, recursive=True)
            self.observer.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.status_label.config(text="● STATUS: STOPPED", fg="#ef4444")
        self.proc_label.config(text="Engine Status: IDLE", fg="#facc15")
        
        # Update button to show START state
        self.monitor_btn.config(text="START MONITORING", bg="#22c55e", command=self.toggle_monitoring)
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None

    def process_file(self, locked_path):
        # Strip the ".scanning" extension to get the real name for our UI log
        original_path = locked_path.replace(".scanning", "")
        name = os.path.basename(original_path)

        if LOG_FILE.lower() in name.lower(): return

        # Thread Checks In: Add file to active scans list
        with self.active_scans_lock:
            self.active_scans.add(name)

        try:
            # Scan the locked file safely away from Windows Explorer's eyes
            label, score = self.scanner.scan_file(locked_path)

            if label == "ERROR":
                result_str, action, tag = "SCAN FAILED", "Ignored", "error"
                # Failsafe: Put the original name back if the scan crashed
                try: os.rename(locked_path, original_path) 
                except: pass
            else:
                score_pct = float(score) * 100
                result_str = f"{label} ({score_pct:.1f}%)"
                
                if label == "MALWARE":
                    tag = "malware"
                    success = quarantine_file(locked_path, label)
                    action = "QUARANTINED" if success else "Q-FAILED (LOCKED)"
                elif label == "SUSPICIOUS":
                    action, tag = "Logged/Flagged", "suspicious"
                    quarantine_file(locked_path, label)
                else:
                    action, tag = "Allowed", "clean"
                    # ✅ IT IS CLEAN! Remove the lock and give it back to the user.
                    try: os.rename(locked_path, original_path)
                    except: pass

            time_str = datetime.now().strftime("%H:%M:%S")
            self.root.after(0, lambda: self._insert_to_tree(time_str, name, result_str, action, tag))
            
        finally:
            # Thread Checks Out: Remove file from active scans list, even if it crashed
            with self.active_scans_lock:
                self.active_scans.discard(name)

    def _insert_to_tree(self, time_str, name, result_str, action, tag):
        item_id = self.tree.insert("", 0, values=(time_str, name, result_str, action)) 
        self.tree.item(item_id, tags=(tag,))

    def build_initial_baseline(self):
        """Silently maps existing files on startup so we only scan new/modified ones."""
        self.proc_label.config(text="Engine Status: BUILDING BASELINE...", fg="#facc15")
        self.root.update() # Force UI to show the loading text

        with self.db_lock:
            for root_dir, _, files in os.walk(TARGET_WATCH_DIR):
                for file in files:
                    if file.lower().endswith(SUPPORTED_EXTENSIONS):
                        filepath = os.path.join(root_dir, file)
                        try:
                            # Silently record the timestamp WITHOUT sending it to the queue
                            self.file_state_db[filepath] = os.path.getmtime(filepath)
                        except OSError:
                            pass # Skip files locked by the OS

        self.proc_label.config(text="Engine Status: ACTIVE SCANNING", fg="#22c55e")

    def restore_quarantined_file(self):
        import stat
        import json
        quarantine_root = "C:\\RDefender_Quarantine"
        if not os.path.exists(quarantine_root):
            messagebox.showinfo("Empty", "Quarantine vault is currently empty.")
            return

        # Load metadata
        metadata_file = os.path.join(quarantine_root, "metadata.json")
        metadata = {}
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except:
                pass

        if not metadata:
            messagebox.showinfo("Empty", "Quarantine vault is currently empty.")
            return

        # Separate files by severity
        malware_files = {}
        suspicious_files = {}
        for quarantine_name, info in metadata.items():
            original_path = info.get("original_path", "Unknown")
            severity = info.get("severity", "Unknown")
            display_name = os.path.basename(original_path)
            
            if severity == "MALWARE":
                malware_files[display_name] = (quarantine_name, original_path)
            else:
                suspicious_files[display_name] = (quarantine_name, original_path)

        # Create a custom dialog for multi-selection
        select_window = tk.Toplevel(self.root)
        select_window.title("Select Files to Recover")
        select_window.geometry("750x550")
        select_window.configure(bg="#0f172a")
        
        title_label = tk.Label(select_window, text="Select files to recover", font=("Segoe UI", 12, "bold"), bg="#0f172a", fg="white")
        title_label.pack(pady=10)

        info_label = tk.Label(select_window, text="Use Shift+Click to select range or Ctrl+Click for multiple files:", 
                             font=("Segoe UI", 9), bg="#0f172a", fg="#cbd5e1")
        info_label.pack(pady=5)

        # Container for both sections
        container = tk.Frame(select_window, bg="#0f172a")
        container.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        all_files = {}

        # Helper function to create category section
        def create_category_section(parent, title, files_dict, color_tag):
            section_frame = tk.LabelFrame(parent, text=f"{title} ({len(files_dict)})", 
                                         bg="#0f172a", fg=color_tag, font=("Segoe UI", 10, "bold"))
            section_frame.pack(fill=tk.BOTH, expand=True, pady=5)

            # Scrollbar
            scrollbar = tk.Scrollbar(section_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            # Listbox
            listbox = tk.Listbox(section_frame, selectmode=tk.MULTIPLE, yscrollcommand=scrollbar.set, 
                                font=("Segoe UI", 9), bg="#1e293b", fg="white", 
                                selectbackground="#3b82f6", activestyle="none", height=8)
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=listbox.yview)

            # Store last selected index for Shift+Click range selection
            last_selected_index = [None]

            def on_listbox_click(event):
                """Handle Shift+Click for range selection and Ctrl+Click for multi-select."""
                index = listbox.nearest(event.y)
                if index < 0:
                    return

                if event.state & 0x1:  # Shift key is pressed
                    if last_selected_index[0] is not None:
                        start = min(last_selected_index[0], index)
                        end = max(last_selected_index[0], index)
                        listbox.selection_clear(0, tk.END)
                        for i in range(start, end + 1):
                            listbox.selection_set(i)
                    else:
                        listbox.selection_set(index)
                    last_selected_index[0] = index
                elif event.state & 0x4:  # Ctrl key is pressed
                    if listbox.selection_includes(index):
                        listbox.selection_clear(index)
                    else:
                        listbox.selection_set(index)
                    last_selected_index[0] = index
                else:
                    listbox.selection_clear(0, tk.END)
                    listbox.selection_set(index)
                    last_selected_index[0] = index

            listbox.bind("<Button-1>", on_listbox_click)

            # Populate listbox
            for display_name in sorted(files_dict.keys()):
                listbox.insert(tk.END, display_name)
                all_files[display_name] = files_dict[display_name]

            return listbox

        # Create sections
        if malware_files:
            malware_listbox = create_category_section(container, "🛑 MALWARE", malware_files, "#ef4444")
        else:
            malware_listbox = None

        if suspicious_files:
            suspicious_listbox = create_category_section(container, "⚠️ SUSPICIOUS", suspicious_files, "#facc15")
        else:
            suspicious_listbox = None

        def recover_selected():
            selections = []
            if malware_listbox:
                selections.extend([malware_listbox.get(i) for i in malware_listbox.curselection()])
            if suspicious_listbox:
                selections.extend([suspicious_listbox.get(i) for i in suspicious_listbox.curselection()])

            if not selections:
                messagebox.showwarning("No Selection", "Please select at least one file to recover.")
                return

            # Show ONE consolidated recovery options dialog for all files
            recovery_strategy = messagebox.askyesnocancel(
                "Recovery Options",
                f"Recovering {len(selections)} file(s)\n\n"
                "Yes = Restore all to original locations\n"
                "No = Choose locations for each file\n"
                "Cancel = Skip recovery"
            )

            if recovery_strategy is None:  # Cancel
                return
            
            select_window.destroy()

            recovered_count = 0
            failed_count = 0
            error_messages = []

            for display_name in selections:
                quarantine_name, original_path = all_files[display_name]
                restore_path = original_path
                
                try:
                    # Find the quarantined file
                    quarantine_path = None
                    for root, dirs, files in os.walk(quarantine_root):
                        if quarantine_name in files:
                            quarantine_path = os.path.join(root, quarantine_name)
                            break
                    
                    if not quarantine_path or not os.path.exists(quarantine_path):
                        error_messages.append(f"{display_name}: Not found in quarantine")
                        failed_count += 1
                        continue

                    # If user chose "No", ask for custom location per file
                    if recovery_strategy is False:  # No - Choose new location
                        restore_path = filedialog.asksaveasfilename(
                            initialfile=display_name,
                            title=f"Specify restore location for {display_name}"
                        )
                        if not restore_path:
                            error_messages.append(f"Skipped: {display_name}")
                            failed_count += 1
                            continue

                    # Create destination directory if needed
                    dest_dir = os.path.dirname(restore_path)
                    if dest_dir and not os.path.exists(dest_dir):
                        try:
                            os.makedirs(dest_dir, exist_ok=True)
                        except:
                            error_messages.append(f"{display_name}: Cannot create destination folder")
                            failed_count += 1
                            continue

                    # Restore file
                    os.chmod(quarantine_path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                    shutil.move(quarantine_path, restore_path)
                    
                    # Add to whitelist
                    file_hash = compute_file_hash(restore_path)
                    if file_hash:
                        with self.whitelist_lock:
                            self.whitelist.add(file_hash)
                            save_whitelist(self.whitelist)

                    time_str = datetime.now().strftime("%H:%M:%S")
                    self.root.after(0, lambda ts=time_str, name=display_name: self._insert_to_tree(ts, name, "RESTORED", "Un-Quarantined", "clean"))
                    
                    recovered_count += 1

                except Exception as e:
                    error_messages.append(f"{display_name}: {str(e)}")
                    failed_count += 1

            # Update metadata file to remove recovered files
            try:
                remaining_metadata = {k: v for k, v in metadata.items() if k not in [all_files[s][0] for s in selections if s in all_files]}
                if remaining_metadata:
                    with open(metadata_file, 'w') as f:
                        json.dump(remaining_metadata, f, indent=2)
                else:
                    if os.path.exists(metadata_file):
                        os.remove(metadata_file)
            except:
                pass

            # Show summary
            summary = f"✅ Recovered: {recovered_count}\n❌ Failed: {failed_count}"
            if error_messages:
                summary += f"\n\nDetails:\n" + "\n".join(error_messages[:5])
                if len(error_messages) > 5:
                    summary += f"\n... and {len(error_messages) - 5} more"

            messagebox.showinfo("Recovery Complete", summary)

        # Buttons
        button_frame = tk.Frame(select_window, bg="#0f172a")
        button_frame.pack(pady=15)

        tk.Button(button_frame, text="Recover Selected", bg="#10b981", fg="white", command=recover_selected, font=("Segoe UI", 10, "bold"), width=20).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", bg="#ef4444", fg="white", command=select_window.destroy, font=("Segoe UI", 10, "bold"), width=20).pack(side=tk.LEFT, padx=5)

    def manage_whitelist(self):
        """Manage whitelisted files - view and remove."""
        if not self.whitelist:
            messagebox.showinfo("Whitelist Empty", "No files are currently whitelisted.")
            return

        # Create management window
        manage_window = tk.Toplevel(self.root)
        manage_window.title("Manage Whitelist")
        manage_window.geometry("700x500")
        manage_window.configure(bg="#0f172a")

        # Title
        title_label = tk.Label(manage_window, text=f"Whitelisted Files ({len(self.whitelist)})", 
                              font=("Segoe UI", 12, "bold"), bg="#0f172a", fg="white")
        title_label.pack(pady=10)

        # Info text
        info_label = tk.Label(manage_window, 
                             text="Use Shift+Click to select range or Ctrl+Click for multiple files:",
                             font=("Segoe UI", 9), bg="#0f172a", fg="#cbd5e1")
        info_label.pack(pady=5)

        # Listbox with scrollbar
        frame = tk.Frame(manage_window, bg="#0f172a")
        frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        scrollbar = tk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        listbox = tk.Listbox(frame, selectmode=tk.MULTIPLE, yscrollcommand=scrollbar.set, 
                            font=("Segoe UI", 9), bg="#1e293b", fg="white", 
                            selectbackground="#3b82f6", activestyle="none")
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox.yview)

        # Store last selected index for Shift+Click range selection
        last_selected_index = [None]

        def on_listbox_click(event):
            """Handle Shift+Click for range selection and Ctrl+Click for multi-select."""
            index = listbox.nearest(event.y)
            if index < 0:
                return

            if event.state & 0x1:  # Shift key is pressed
                # Select range from last_selected to current
                if last_selected_index[0] is not None:
                    start = min(last_selected_index[0], index)
                    end = max(last_selected_index[0], index)
                    listbox.selection_clear(0, tk.END)
                    for i in range(start, end + 1):
                        listbox.selection_set(i)
                else:
                    listbox.selection_set(index)
                last_selected_index[0] = index
            elif event.state & 0x4:  # Ctrl key is pressed
                # Toggle selection of clicked item
                if listbox.selection_includes(index):
                    listbox.selection_clear(index)
                else:
                    listbox.selection_set(index)
                last_selected_index[0] = index
            else:
                # Regular click - select only this item
                listbox.selection_clear(0, tk.END)
                listbox.selection_set(index)
                last_selected_index[0] = index

        listbox.bind("<Button-1>", on_listbox_click)

        # Populate listbox with hashes
        hash_list = sorted(list(self.whitelist))
        for file_hash in hash_list:
            listbox.insert(tk.END, file_hash)

        def remove_selected():
            selections = [listbox.get(i) for i in listbox.curselection()]
            if not selections:
                messagebox.showwarning("No Selection", "Please select at least one file to remove.")
                return

            if messagebox.askyesno("Confirm Removal", 
                                  f"Remove {len(selections)} file(s) from whitelist?\n\n"
                                  "They will be scanned again on next detection."):
                with self.whitelist_lock:
                    for file_hash in selections:
                        self.whitelist.discard(file_hash)
                    save_whitelist(self.whitelist)

                messagebox.showinfo("Success", f"✅ Removed {len(selections)} file(s) from whitelist")
                manage_window.destroy()

        def clear_all():
            if messagebox.askyesno("Clear All Whitelist", 
                                  "Remove ALL files from whitelist?\n\n"
                                  "This action is irreversible."):
                with self.whitelist_lock:
                    self.whitelist.clear()
                    save_whitelist(self.whitelist)

                messagebox.showinfo("Success", "✅ Whitelist cleared")
                manage_window.destroy()

        # Button frame
        button_frame = tk.Frame(manage_window, bg="#0f172a")
        button_frame.pack(pady=15)

        tk.Button(button_frame, text="Remove Selected", bg="#ef4444", fg="white", 
                 command=remove_selected, font=("Segoe UI", 10, "bold"), width=18).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Clear All", bg="#dc2626", fg="white", 
                 command=clear_all, font=("Segoe UI", 10, "bold"), width=18).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Close", bg="#64748b", fg="white", 
                 command=manage_window.destroy, font=("Segoe UI", 10, "bold"), width=18).pack(side=tk.LEFT, padx=5)

    # ----------------FOLDER SCAN LOGIC ----------------
    def scan_specific_folder(self):
        """Opens a dialog to select a folder and starts scanning it in the background."""
        folder_path = filedialog.askdirectory(title="Select Folder to Scan")
        if not folder_path:
            return
        
        # Start the folder scan in a background thread
        t = threading.Thread(target=self._scan_folder_worker, args=(folder_path,), daemon=True)
        t.start()

    def _scan_folder_worker(self, folder_path):
        """Background worker that recursively scans all supported files in a folder."""
        scanned_count = 0
        detected_count = 0
        
        try:
            self.proc_label.config(text=f"Engine Status: FOLDER SCAN ACTIVE ({folder_path})", fg="#a855f7")
            self.root.update()
            
            # Walk through all files in the folder recursively
            for root_dir, _, files in os.walk(folder_path):
                for file in files:
                    if not file.lower().endswith(SUPPORTED_EXTENSIONS):
                        continue
                    
                    filepath = os.path.join(root_dir, file)
                    
                    # Skip system folders
                    lower_path = filepath.lower()
                    if "$recycle.bin" in lower_path or "system volume information" in lower_path:
                        continue
                    
                    try:
                        # Skip if file is too large
                        if os.path.getsize(filepath) > 10485760:
                            continue
                        
                        # Check whitelist
                        file_hash = compute_file_hash(filepath)
                        if file_hash:
                            with self.whitelist_lock:
                                if file_hash in self.whitelist:
                                    continue
                        
                        # Scan the file
                        scanned_count += 1
                        name = os.path.basename(filepath)
                        
                        # Thread Checks In
                        with self.active_scans_lock:
                            self.active_scans.add(f"[FOLDER] {name}")
                        
                        try:
                            label, score = self.scanner.scan_file(filepath)
                            
                            score_pct = float(score) * 100
                            result_str = f"{label} ({score_pct:.1f}%)"
                            
                            if label == "MALWARE":
                                detected_count += 1
                                tag = "malware"
                                success = quarantine_file(filepath, label)
                                action = "QUARANTINED" if success else "Q-FAILED (LOCKED)"
                            elif label == "SUSPICIOUS":
                                detected_count += 1
                                action, tag = "Logged/Flagged", "suspicious"
                                quarantine_file(filepath, label)
                            else:
                                action, tag = "Allowed", "clean"
                            
                            time_str = datetime.now().strftime("%H:%M:%S")
                            self.root.after(0, lambda t=time_str, n=name, r=result_str, a=action, tg=tag: self._insert_to_tree(t, n, r, a, tg))
                        
                        finally:
                            # Thread Checks Out
                            with self.active_scans_lock:
                                self.active_scans.discard(f"[FOLDER] {name}")
                    
                    except Exception:
                        continue
            
            # Scan complete message
            complete_msg = f"Folder Scan Complete: {scanned_count} files scanned, {detected_count} threats detected"
            self.proc_label.config(text=f"Engine Status: {complete_msg}", fg="#22c55e")
            self.root.after(3000, lambda: self._reset_engine_status())
            messagebox.showinfo("Scan Complete", complete_msg)
        
        except Exception as e:
            messagebox.showerror("Scan Error", f"Error scanning folder:\n{str(e)}")
            self.proc_label.config(text="Engine Status: ACTIVE SCANNING", fg="#22c55e")

    def _reset_engine_status(self):
        """Reset engine status based on monitoring state."""
        if self.monitoring:
            self.proc_label.config(text="Engine Status: ACTIVE SCANNING", fg="#22c55e")
        else:
            self.proc_label.config(text="Engine Status: IDLE", fg="#facc15")

    def update_agent_metrics(self):
        try:
            cpu = self.agent_process.cpu_percent(interval=None)
            mem = self.agent_process.memory_info().rss / (1024 * 1024)
            self.cpu_label.config(text=f"Agent CPU: {cpu:.2f}%")
            self.mem_label.config(text=f"Agent RAM: {mem:.2f} MB")
            
            # Read the active scans set and update the UI
            with self.active_scans_lock:
                if not self.active_scans:
                    self.active_scans_label.config(text="Active Scans: None")
                else:
                    # Join up to 4 file names together
                    scan_text = "Scanning: " + " | ".join(list(self.active_scans)[:4])
                    self.active_scans_label.config(text=scan_text)
                    
        except Exception:
            pass
        self.root.after(1000, self.update_agent_metrics)

if __name__ == "__main__":
    root = tk.Tk()
    app = RDefenderUI(root)
    root.mainloop()