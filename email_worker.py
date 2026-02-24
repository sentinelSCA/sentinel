# Legacy wrapper: keep this file so docker-compose references don't break.
# Real implementation now lives in worker_email.py (Redis queue mode).

from worker_email import run_loop

if __name__ == "__main__":
    run_loop()
