import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess

# MyHandler class extends FileSystemEventHandler for handling file system events
class MyHandler(FileSystemEventHandler):
    # on_modified is called when a file is modified
    def on_modified(self, event):
        # Ignore directory modifications
        if event.is_directory:
            return
        # React only to modifications in Python files
        if event.src_path.endswith(".py"):
            print(f"Detected change in {event.src_path}. Restarting server...")
            # Terminate the current instance of the server script
            subprocess.run(["pkill", "-f", "server.py"])
            # Restart the server script in a non-blocking manner
            subprocess.run(["nohup", "python3", "/var/www/html/server.py", "&"])

# Main execution starts here
if __name__ == "__main__":
    event_handler = MyHandler()
    observer = Observer()
    # Set up the observer to watch for modifications in the specified directory
    observer.schedule(event_handler, path="/var/www/html/", recursive=True)
    observer.start()

    try:
        # Keep the script running to continuously monitor for changes
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Stop the observer if the script execution is interrupted manually
        observer.stop()
    # Ensure that all threads are joined before exiting
    observer.join()
