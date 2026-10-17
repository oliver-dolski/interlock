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
        # cve-replay runs on the pinned-vulnerable libosdp v2.4.0 image via the
        # docker-compose.vuln.yml override, layered on top of the base compose
        # file. The override swaps pd and cp onto the vuln image and keeps the lab
        # internal with no published ports (SAFE-01).
        exec env LAB_SCENARIO="$scenario" \
            docker compose -f docker-compose.yml -f docker-compose.vuln.yml up "$@"
        ;;
    *)
        reject "unknown scenario '${scenario}'"
        ;;
esac
