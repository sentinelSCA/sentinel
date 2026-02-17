#!/usr/bin/env bash

CMD="$*"

~/sentinel/venv/bin/python ~/sentinel/sentinel_guard.py "$CMD" "openclaw:local"
RC=$?

if [ $RC -ne 0 ]; then
  echo "⛔ BLOCKED by Sentinel"
  exit $RC
fi

exit 0
