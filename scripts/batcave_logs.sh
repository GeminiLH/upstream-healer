#!/usr/bin/env bash
# Read the per-scan diag logs on batcave via the read-only `cline-logs` account.
#
# Usage:
#   scripts/batcave_logs.sh                      # ls -lat of the log dir
#   scripts/batcave_logs.sh 'ls -lat'
#   scripts/batcave_logs.sh 'cat diag_…_nmap_dc:a6:32:02:59:63_7.log'
#   scripts/batcave_logs.sh 'grep run_scan diag_….log'
#
# Notes:
#   * The `cline-logs` account is ForceCommand-restricted to
#     {ls cat tail grep head wc file stat} and auto-cd's into the scan-log
#     directory (/logs = /mnt/data/upstream-healer/logs), so pass the command
#     with NO path. Do NOT double-quote the filename (the wrapper keeps inner
#     quotes literal); colons in the name are fine unquoted.
#   * The password is read from the gitignored .env.local (CLINE_LOGS_SSH_PASS)
#     — never hardcode or commit it. There is no sshpass/expect/paramiko on
#     this box, so we use the SSH_ASKPASS + setsid trick (see memory-bank).
set -euo pipefail
cd "$(dirname "$0")/.."

set -a; source ./.env.local; set +a
: "${CLINE_LOGS_SSH_PASS:?set CLINE_LOGS_SSH_PASS in .env.local}"
host="${CLINE_LOGS_SSH_HOST:-batcave}"
user="${CLINE_LOGS_SSH_USER:-cline-logs}"
cmd="${1:-ls -lat}"

askpass="$(mktemp /tmp/ua_askpass.XXXXXX)"
trap 'rm -f "$askpass"' EXIT
printf '#!/bin/sh\necho "%s"\n' "$CLINE_LOGS_SSH_PASS" >"$askpass"
chmod +x "$askpass"

SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
  setsid -w ssh -o BatchMode=no -o StrictHostKeyChecking=accept-new \
  "${user}@${host}" "$cmd"
