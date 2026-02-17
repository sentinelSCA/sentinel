import hashlib
import time

def variable_timestamp(command: str):
    now = str(time.time_ns())
    payload = command + now
    return hashlib.sha256(payload.encode()).hexdigest()
