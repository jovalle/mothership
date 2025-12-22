#!/usr/bin/env bash
set -euo pipefail

GERBIL_CONTAINER_NAME="${GERBIL_CONTAINER_NAME:-gerbil}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if ! docker inspect "${GERBIL_CONTAINER_NAME}" >/dev/null 2>&1; then
  echo "Gerbil container '${GERBIL_CONTAINER_NAME}' not found" >&2
  exit 1
fi

# Pick the IP on the network that Traefik is on (in this repo, gerbil is only on one network).
gerbil_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${GERBIL_CONTAINER_NAME}" | awk '{print $1}')
if [[ -z "${gerbil_ip}" ]]; then
  echo "Failed to determine Gerbil container IP" >&2
  exit 1
fi

# Extract WireGuard-routed CIDRs from inside gerbil.
# We intentionally filter to RFC6598-ish 100.x ranges Pangolin uses.
mapfile -t wg_cidrs < <(
  docker exec "${GERBIL_CONTAINER_NAME}" sh -lc "ip route show dev wg0 2>/dev/null" \
    | awk '{print $1}' \
    | grep -E '^100\.' \
    | sort -u
)

if [[ ${#wg_cidrs[@]} -eq 0 ]]; then
  echo "No wg0 routes found in Gerbil (is WireGuard up?)" >&2
  exit 1
fi

for cidr in "${wg_cidrs[@]}"; do
  # Ensure host routes the WG subnet via the gerbil container on the Docker bridge.
  # `replace` keeps this idempotent.
  ip route replace "${cidr}" via "${gerbil_ip}" >/dev/null
done
