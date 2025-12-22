#!/bin/sh
set -e

# Add routes to WireGuard networks via gerbil container
# This allows Traefik to route traffic to remote sites managed by Pangolin

GERBIL_CONTAINER="${GERBIL_CONTAINER:-gerbil}"
# Pangolin uses 100.64.0.0/10 (RFC6598) for WireGuard networks
# Default to common subnets, but can be overridden via env vars
WG_SUBNETS="${WG_SUBNETS:-100.64.0.0/10}"

# Wait for network to be ready
sleep 2

# Get gerbil's IPv4 address on the external network
GERBIL_IP=$(getent ahostsv4 "$GERBIL_CONTAINER" | grep STREAM | head -1 | awk '{ print $1 }')

if [ -z "$GERBIL_IP" ]; then
    echo "Error: Could not resolve gerbil IPv4 address"
    exit 1
fi

echo "Configuring WireGuard routes via gerbil gateway at $GERBIL_IP"

# Add routes for each subnet
echo "$WG_SUBNETS" | tr ',' '\n' | while read -r subnet; do
    subnet=$(echo "$subnet" | xargs)  # trim whitespace
    if [ -n "$subnet" ]; then
        echo "  Adding route: $subnet via $GERBIL_IP"
        ip route add "$subnet" via "$GERBIL_IP" 2>&1 || echo "    (route already exists)"
    fi
done

echo "WireGuard routes configured:"
ip route | grep -E "^100\." || echo "  (none found)"

# Start Traefik
exec traefik "$@"
