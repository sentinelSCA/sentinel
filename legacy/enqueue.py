import sys
import json
from queue_redis import qpush

USAGE = """Usage:
  python enqueue.py <queue> '<json-payload>'

Examples:
  python enqueue.py tasks:writer '{"topic":"Weekly update","tone":"professional"}'
  python enqueue.py tasks:verify '{"source_path":"outputs_writer/FILE.txt"}'
"""

def main():
    if len(sys.argv) < 3:
        print(USAGE)
        sys.exit(1)

    queue = sys.argv[1].strip()
    payload_raw = sys.argv[2].strip()
    payload = json.loads(payload_raw)

    qpush(queue, payload)
    print("ENQUEUED ->", queue, payload)

if __name__ == "__main__":
    main()
