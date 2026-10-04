#!/bin/bash
set -euo pipefail

agent_id=${1:?agent id}
run_id=${2:?run id}
max_polls=${MAX_POLLS:-240}
poll_seconds=${POLL_SECONDS:-15}

for _ in $(seq 1 "$max_polls"); do
  status=$(
    curl --fail-with-body -sS -u "${CURSOR_API_KEY}:" \
      "https://api.cursor.com/v1/agents/${agent_id}/runs/${run_id}" \
      | python -c 'import json,sys; print(json.load(sys.stdin)["status"])'
  )
  case "$status" in
    FINISHED|ERROR|CANCELLED|EXPIRED)
      printf '%s\n' "$status"
      exit 0
      ;;
  esac
  sleep "$poll_seconds"
done

printf 'TIMEOUT\n'
