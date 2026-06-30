import os
import time
import logging
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = "watched_folder"
LOG_FILE = "audit_log.txt"

# create folder if not exists
if not os.path.exists(WATCH_DIR):
    os.makedirs(WATCH_DIR)

delete_log = deque(maxlen=10)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

class Handler(FileSystemEventHandler):

    def on_created(self, event):
        msg = f"CREATED: {event.src_path}"
        print(msg)
        logging.info(msg)

    def on_modified(self, event):
        msg = f"MODIFIED: {event.src_path}"
        print(msg)
        logging.info(msg)

    def on_deleted(self, event):
        msg = f"DELETED: {event.src_path}"
        print(msg)
        logging.info(msg)

        delete_log.append(time.time())
        check_alert()

def check_alert():
    if len(delete_log) >= 5:
        if delete_log[-1] - delete_log[-5] < 20:
            print("\n🚨 ALERT: Too many deletions!\n")
            logging.info("ALERT TRIGGERED")

if __name__ == "__main__":
    print("Monitoring started...")

    observer = Observer()
    observer.schedule(Handler(), WATCH_DIR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()