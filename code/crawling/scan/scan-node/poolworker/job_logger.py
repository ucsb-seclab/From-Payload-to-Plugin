import time
from pathlib import Path

class JobLogger:

    def __init__(self, log_path):
        self.log_path = log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = open(log_path, "a", encoding="utf-8")

    def log(self, message):
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}"
        print(line)
        self.stream.write(line + "\n")
        self.stream.flush()

    def close(self):
        self.stream.close()
