import os
import time
import logging
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from openai import OpenAI

# ==========================
# Configuration
# ==========================

WATCH_DIR = "watched_folder"
LOG_FILE = "audit_log.txt"

# Set your OpenAI API Key
# Recommended: set OPENAI_API_KEY as an environment variable
client = OpenAI(api_key="YOUR_OPENAI_API_KEY")

# Create watch folder if it doesn't exist
if not os.path.exists(WATCH_DIR):
    os.makedirs(WATCH_DIR)

# Store timestamps of recent deletions
delete_log = deque(maxlen=10)

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ==========================
# LLM Alert Function
# ==========================

def analyze_with_llm():

    prompt = """
A file monitoring system detected suspicious activity.

Details:
- 5 files were deleted within 20 seconds.

Analyze the situation and provide:

1. Risk Level
2. Possible Cause
3. Recommended Action

Keep the response short.
"""

    try:
        response = client.responses.create(
            model="gpt-5",
            input=prompt
        )

        ai_result = response.output_text

        print("\n========== AI SECURITY ALERT ==========")
        print(ai_result)
        print("=======================================\n")

        logging.info("LLM Analysis:")
        logging.info(ai_result)

    except Exception as e:
        print("LLM Error:", e)
        logging.error(f"LLM Error: {e}")

# ==========================
# Alert Checker
# ==========================

def check_alert():

    if len(delete_log) >= 5:

        # If 5 deletions occurred within 20 seconds
        if delete_log[-1] - delete_log[-5] < 20:

            print("\n🚨 Suspicious activity detected!")

            logging.info("Suspicious activity detected")

            analyze_with_llm()

# ==========================
# File Event Handler
# ==========================

class Handler(FileSystemEventHandler):

    def on_created(self, event):

        if event.is_directory:
            return

        msg = f"CREATED : {event.src_path}"

        print(msg)
        logging.info(msg)

    def on_modified(self, event):

        if event.is_directory:
            return

        msg = f"MODIFIED : {event.src_path}"

        print(msg)
        logging.info(msg)

    def on_deleted(self, event):

        if event.is_directory:
            return

        msg = f"DELETED : {event.src_path}"

        print(msg)
        logging.info(msg)

        delete_log.append(time.time())

        check_alert()

# ==========================
# Main Program
# ==========================

if __name__ == "__main__":

    print("===================================")
    print(" Real-Time File Monitor Started")
    print(" Watching Folder:", WATCH_DIR)
    print("===================================\n")

    event_handler = Handler()

    observer = Observer()

    observer.schedule(
        event_handler,
        WATCH_DIR,
        recursive=True
    )

    observer.start()

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()
        print("\nMonitoring Stopped.")

    observer.join()
