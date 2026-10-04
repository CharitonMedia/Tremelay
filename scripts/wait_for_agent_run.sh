#!/bin/bash
# Print the Cloud Agent run status. Prints TIMEOUT and exits 0 if the run
# is still going when the poll budget ends, so the caller can decide not
# to request another review.
set -euo pipefail

agent_id=${1:?agent id}
run_id=${2:?run id}
max_polls=${MAX_POLLS:-480}
poll_seconds=${POLL_SECONDS:-30}

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
exit 0
