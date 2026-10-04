#!/bin/bash
# Fail before an identity-sensitive GitHub write when the owner token is absent.
# Do not print the token value.
set -euo pipefail

if [ -z "${GOAL_GITHUB_TOKEN:-}" ]; then
  echo "GOAL_GITHUB_TOKEN is not set. Add a fine-grained personal access token for your GitHub account as the repository Actions secret GOAL_GITHUB_TOKEN. Codex does not act on comments posted by github-actions[bot]."
  exit 1
fi
