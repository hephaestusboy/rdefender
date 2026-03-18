import time
import os
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ✅ LOG FILE (ignored by monitor)
LOG_FILE = "rdefender_events.log"


class RDefenderHandler(FileSystemEventHandler):

    def log_event(self, event_type, path):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"{timestamp} | {event_type} | {path}"

        print(message)

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(message + "\n")

    def should_ignore(self, path):
        return LOG_FILE.lower() in path.lower()

    def on_created(self, event):
     if not event.is_directory:
        if self.should_ignore(event.src_path):
            return
        self.log_event("CREATED", event.src_path)

    
def get_paths_to_monitor():
    return ["C:\\"]

def main():
    print("🔥 RDefender Agent Running...")

    paths_to_watch = get_paths_to_monitor()
    event_handler = RDefenderHandler()
    observer = Observer()

    print("Monitoring paths:")

    for path in paths_to_watch:
        if os.path.exists(path):
            print("✔", path)
            observer.schedule(event_handler, path, recursive=True)
        else:
            print("❌ Path not found:", path)

    observer.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Stopping agent...")
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()