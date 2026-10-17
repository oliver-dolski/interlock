#!/bin/sh
# OSDP lab control wrapper.
#
# Usage: sh ./lab.sh up <scenario>
#
# Selects a scenario by exporting LAB_SCENARIO and brings the lab up with
# docker compose. An unknown or missing scenario is rejected with the full list
# of valid values (ASVS V5), so a bad value never silently falls back to a
# scenario. Any extra arguments after the scenario are passed through to
# docker compose up (for example -d to run detached).
set -eu

VALID_CSV="cleartext, sc-scbkd, downgrade, cve-replay"

usage() {
    echo "usage: sh ./lab.sh up <scenario>" >&2
    echo "valid scenarios: ${VALID_CSV}" >&2
}

reject() {
    echo "lab.sh: $1" >&2
    usage
    exit 1
}

cmd="${1:-}"
[ "$cmd" = "up" ] || reject "unknown command '${cmd}'"
shift

scenario="${1:-}"
[ -n "$scenario" ] || reject "missing scenario"
shift

case "$scenario" in
    cleartext | sc-scbkd | downgrade)
        exec env LAB_SCENARIO="$scenario" docker compose up "$@"
        ;;
    cve-replay)
        # Seam for plan 02-04: cve-replay runs on the pinned-vulnerable libosdp
        # v2.4.0 image via a compose override (docker-compose.vuln.yml), which
        # does not exist yet. Until then it is a known value that is not servable
        # on the fixed image.
        reject "cve-replay runs on the vuln image, wired in plan 02-04"
        ;;
    *)
        reject "unknown scenario '${scenario}'"
        ;;
esac
