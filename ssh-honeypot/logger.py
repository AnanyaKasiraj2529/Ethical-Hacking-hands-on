from datetime import datetime
import os

def write_log(file_path, message):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "a") as f:
        f.write(f"{datetime.now()} | {message}\n")
