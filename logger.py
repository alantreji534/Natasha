import json, datetime, os
from config import LOG_FILE

os.makedirs("logs", exist_ok=True)

def log(event: dict):
    event["timestamp"] = datetime.datetime.utcnow().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
