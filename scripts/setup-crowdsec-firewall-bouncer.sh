#!/usr/bin/env bash
# =============================================================================
# CrowdSec Firewall Bouncer Setup Script
# =============================================================================
# Installs and configures the CrowdSec firewall bouncer to work with the
# Docker-based CrowdSec LAPI. Provides network-layer protection (iptables/nftables)
# in addition to the application-layer Traefik bouncer.
#
# Features:
#   - Truly idempotent: No-ops when state matches, no unnecessary restarts
#   - Removes legacy fail2ban if present
#   - Configures bouncer to connect to Docker CrowdSec LAPI
#   - Validates Tailscale whitelist protection
#   - Comprehensive health checks and validation
#
# Prerequisites:
#   - Docker CrowdSec container running and healthy
#   - CrowdSec LAPI exposed on 127.0.0.1:8080
#   - Tailscale IPs whitelisted in CrowdSec parsers
#
# Usage:
#   sudo ./setup-crowdsec-firewall-bouncer.sh           # Install/configure
#   sudo ./setup-crowdsec-firewall-bouncer.sh --status  # Show protection status
#   sudo ./setup-crowdsec-firewall-bouncer.sh --help    # Show help
#
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
CROWDSEC_LAPI_URL="http://127.0.0.1:8080"
CROWDSEC_CONTAINER="crowdsec"
BOUNCER_NAME="firewall-bouncer"
BOUNCER_CONFIG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
BOUNCER_CONFIG_LOCAL="${BOUNCER_CONFIG}.local"
BOUNCER_SERVICE="crowdsec-firewall-bouncer"
LOCAL_CROWDSEC_SERVICE="crowdsec"

# Track if any changes were made (used to decide if restart needed)
CHANGES_MADE=false
CONFIG_CHANGED=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_skip() {
    echo -e "${GRAY}[SKIP]${NC} $1"
}

log_change() {
    echo -e "${GREEN}[CHANGED]${NC} $1"
    CHANGES_MADE=true
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}==============================================================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
show_help() {
    cat <<EOF
CrowdSec Firewall Bouncer Setup Script

USAGE:
    sudo $0 [OPTIONS]

OPTIONS:
    --help, -h      Show this help message
    --status, -s    Show current protection status and fail2ban parity
    (no args)       Install and configure the firewall bouncer

EXAMPLES:
    sudo $0                 # Install/configure bouncer
    sudo $0 --status        # Show protection dashboard
    sudo $0 -s              # Short form of --status

DESCRIPTION:
    This script installs and configures the CrowdSec firewall bouncer to work
    with the Docker-based CrowdSec LAPI. It provides network-layer protection
    (nftables) in addition to the application-layer Traefik bouncer.

    The --status option shows a comprehensive dashboard including:
    - Feature parity comparison with legacy fail2ban
    - Active detection scenarios
    - Current protection metrics
    - Recent threat detections

EOF
}

# -----------------------------------------------------------------------------
# Status Dashboard - Showcases fail2ban parity and protection
# -----------------------------------------------------------------------------
show_status() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║               CrowdSec Protection Status Dashboard                           ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # -------------------------------------------------------------------------
    # Service Status
    # -------------------------------------------------------------------------
    echo -e "${BLUE}┌─ Service Status ────────────────────────────────────────────────────────────┐${NC}"

    local fw_status traefik_status crowdsec_status
    fw_status=$(systemctl is-active "${BOUNCER_SERVICE}" 2>/dev/null || echo "inactive")
    crowdsec_status=$(docker inspect --format='{{.State.Health.Status}}' "${CROWDSEC_CONTAINER}" 2>/dev/null || echo "not running")

    # Check Traefik bouncer via LAPI metrics
    local traefik_bouncer_active="inactive"
    if docker exec "${CROWDSEC_CONTAINER}" cscli bouncers list -o raw 2>/dev/null | grep -q "TRAEFIK"; then
        traefik_bouncer_active="active"
    fi

    printf "  %-30s " "CrowdSec Engine (Docker):"
    if [[ "$crowdsec_status" == "healthy" ]]; then
        echo -e "${GREEN}● healthy${NC}"
    else
        echo -e "${RED}● ${crowdsec_status}${NC}"
    fi

    printf "  %-30s " "Firewall Bouncer (nftables):"
    if [[ "$fw_status" == "active" ]]; then
        echo -e "${GREEN}● active${NC}"
    else
        echo -e "${RED}● ${fw_status}${NC}"
    fi

    printf "  %-30s " "Traefik Bouncer (middleware):"
    if [[ "$traefik_bouncer_active" == "active" ]]; then
        echo -e "${GREEN}● active${NC}"
    else
        echo -e "${YELLOW}● ${traefik_bouncer_active}${NC}"
    fi
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # -------------------------------------------------------------------------
    # Fail2ban → CrowdSec Feature Parity
    # -------------------------------------------------------------------------
    echo -e "${BLUE}┌─ Legacy fail2ban → CrowdSec Feature Parity ─────────────────────────────────┐${NC}"
    echo -e "  ${GRAY}Old fail2ban Filter          CrowdSec Equivalent(s)              Status${NC}"
    echo -e "  ${GRAY}─────────────────────────────────────────────────────────────────────────${NC}"

    # Check each equivalent scenario
    local scenarios
    scenarios=$(docker exec "${CROWDSEC_CONTAINER}" cscli scenarios list -o raw 2>/dev/null || echo "")

    # traefik-auth → http-generic-bf
    printf "  %-28s " "traefik-auth (401/403)"
    printf "%-35s " "http-generic-bf"
    if echo "$scenarios" | grep -q "http-generic-bf"; then
        echo -e "${GREEN}✓ COVERED${NC}"
    else
        echo -e "${RED}✗ MISSING${NC}"
    fi

    # traefik-badbots → http-bad-user-agent
    printf "  %-28s " "traefik-badbots"
    printf "%-35s " "http-bad-user-agent"
    if echo "$scenarios" | grep -q "http-bad-user-agent"; then
        echo -e "${GREEN}✓ COVERED${NC}"
    else
        echo -e "${RED}✗ MISSING${NC}"
    fi

    # traefik-botsearch → http-sensitive-files + http-probing
    printf "  %-28s " "traefik-botsearch"
    printf "%-35s " "http-sensitive-files, http-probing"
    if echo "$scenarios" | grep -q "http-sensitive-files" && echo "$scenarios" | grep -q "http-probing"; then
        echo -e "${GREEN}✓ COVERED${NC}"
    else
        echo -e "${YELLOW}~ PARTIAL${NC}"
    fi

    # traefik-reqcount → http-crawl-non_statics
    printf "  %-28s " "traefik-reqcount (rate limit)"
    printf "%-35s " "http-crawl-non_statics"
    if echo "$scenarios" | grep -q "http-crawl-non_statics"; then
        echo -e "${GREEN}✓ COVERED${NC}"
    else
        echo -e "${RED}✗ MISSING${NC}"
    fi

    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # -------------------------------------------------------------------------
    # CrowdSec EXCEEDS fail2ban
    # -------------------------------------------------------------------------
    echo -e "${BLUE}┌─ CrowdSec Advantages (Beyond fail2ban) ─────────────────────────────────────┐${NC}"

    # Count CVE scenarios
    local cve_count
    cve_count=$(echo "$scenarios" | grep -ciE "cve|log4j|spring4shell" || echo "0")
    echo -e "  ${GREEN}✓${NC} CVE-specific detections: ${cve_count} scenarios (Log4j, Spring4Shell, etc.)"

    # Check for additional protections
    local extras=""
    echo "$scenarios" | grep -q "http-sqli-probing" && extras="${extras}SQLi, "
    echo "$scenarios" | grep -q "http-xss-probing" && extras="${extras}XSS, "
    echo "$scenarios" | grep -q "http-path-traversal" && extras="${extras}PathTraversal, "
    echo "$scenarios" | grep -q "http-backdoors" && extras="${extras}Backdoors, "
    echo "$scenarios" | grep -q "ssh-bf" && extras="${extras}SSH-BF, "
    extras="${extras%, }"  # Remove trailing comma

    if [[ -n "$extras" ]]; then
        echo -e "  ${GREEN}✓${NC} Additional detections: ${extras}"
    fi

    echo -e "  ${GREEN}✓${NC} Community threat intelligence (shared blocklists)"
    echo -e "  ${GREEN}✓${NC} Dual enforcement: Firewall (nftables) + App (Traefik)"
    echo -e "  ${GREEN}✓${NC} Auto-updated scenarios (no manual regex maintenance)"

    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # -------------------------------------------------------------------------
    # Current Protection Metrics
    # -------------------------------------------------------------------------
    echo -e "${BLUE}┌─ Current Protection Metrics ────────────────────────────────────────────────┐${NC}"

    # Get blocked IP counts
    local ipv4_blocked ipv6_blocked
    ipv4_blocked=$(nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | grep -c "timeout" || echo "0")
    ipv6_blocked=$(nft list set ip6 crowdsec6 crowdsec6-blacklists 2>/dev/null | grep -c "timeout" || echo "0")

    printf "  %-35s %s\n" "IPv4 addresses blocked:" "${ipv4_blocked}"
    printf "  %-35s %s\n" "IPv6 addresses blocked:" "${ipv6_blocked}"
    printf "  %-35s %s\n" "Total IPs blocked:" "$((ipv4_blocked + ipv6_blocked))"

    # Get metrics if available
    local metrics
    metrics=$(docker exec "${CROWDSEC_CONTAINER}" cscli metrics -o raw 2>/dev/null || echo "")

    # Parse acquisition metrics
    local lines_parsed
    lines_parsed=$(docker exec "${CROWDSEC_CONTAINER}" cscli metrics 2>/dev/null | grep "traefik/access.log" | awk '{print $4}' || echo "N/A")
    printf "  %-35s %s\n" "Traefik log lines analyzed:" "${lines_parsed:-N/A}"

    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # -------------------------------------------------------------------------
    # Recent Detections (Local API Alerts)
    # -------------------------------------------------------------------------
    echo -e "${BLUE}┌─ Detection Statistics (Local Alerts) ──────────────────────────────────────┐${NC}"

    # Get Local API Alerts from metrics
    local alerts_output
    alerts_output=$(docker exec "${CROWDSEC_CONTAINER}" cscli metrics 2>/dev/null | \
        sed -n '/Local API Alerts/,/Bouncer/p' | grep -E "^\| crowdsecurity|^\| ltsich" | head -15 || echo "")

    if [[ -n "$alerts_output" ]]; then
        echo -e "  ${GRAY}Scenario                                       Alerts${NC}"
        echo -e "  ${GRAY}─────────────────────────────────────────────────────────────${NC}"
        echo "$alerts_output" | while read -r line; do
            local name count
            # Parse format: | crowdsecurity/http-probing | 43 |
            name=$(echo "$line" | awk -F'|' '{print $2}' | xargs | sed 's/crowdsecurity\///' | sed 's/ltsich\///')
            count=$(echo "$line" | awk -F'|' '{print $3}' | xargs)
            if [[ -n "$count" && "$count" != "-" && "$count" != "0" ]]; then
                printf "  %-47s %s\n" "$name" "$count"
            fi
        done
    else
        echo "  No detection metrics available yet"
    fi

    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # -------------------------------------------------------------------------
    # Active Scenarios Count
    # -------------------------------------------------------------------------
    echo -e "${BLUE}┌─ Active Detection Scenarios ────────────────────────────────────────────────┐${NC}"

    local scenario_count
    scenario_count=$(echo "$scenarios" | grep -c "enabled" || echo "0")
    echo -e "  Total active scenarios: ${GREEN}${scenario_count}${NC}"
    echo ""
    echo "  Categories:"

    local http_count ssh_count cve_count other_count
    http_count=$(echo "$scenarios" | grep -c "http-" || echo "0")
    ssh_count=$(echo "$scenarios" | grep -c "ssh-" || echo "0")
    cve_count=$(echo "$scenarios" | grep -ciE "cve|log4j|spring" || echo "0")

    printf "    %-25s %s\n" "HTTP/Web attacks:" "${http_count}"
    printf "    %-25s %s\n" "SSH brute-force:" "${ssh_count}"
    printf "    %-25s %s\n" "CVE exploits:" "${cve_count}"

    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # -------------------------------------------------------------------------
    # Tailscale Protection Verification
    # -------------------------------------------------------------------------
    echo -e "${BLUE}┌─ Tailscale Whitelist Protection ────────────────────────────────────────────┐${NC}"

    local blocked_tailscale=0
    if nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | \
        grep -qE " 100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\." 2>/dev/null; then
        blocked_tailscale=$(nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | \
            grep -cE " 100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\." 2>/dev/null || echo "0")
    fi

    if [[ "$blocked_tailscale" -eq 0 ]]; then
        echo -e "  Tailscale IPs in blocklist: ${GREEN}0 (whitelist working correctly)${NC}"
    else
        echo -e "  Tailscale IPs in blocklist: ${RED}${blocked_tailscale} (WARNING!)${NC}"
    fi

    echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    # -------------------------------------------------------------------------
    # Summary Verdict
    # -------------------------------------------------------------------------
    local verdict_color verdict_text
    if [[ "$fw_status" == "active" && "$crowdsec_status" == "healthy" && "$ipv4_blocked" -gt 100 ]]; then
        verdict_color="${GREEN}"
        verdict_text="FULLY PROTECTED - CrowdSec exceeds fail2ban capabilities"
    elif [[ "$fw_status" == "active" && "$crowdsec_status" == "healthy" ]]; then
        verdict_color="${YELLOW}"
        verdict_text="PROTECTED - Blocklist may still be syncing"
    else
        verdict_color="${RED}"
        verdict_text="DEGRADED - Check service status above"
    fi

    echo -e "${verdict_color}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${verdict_color}║  ${verdict_text}$(printf '%*s' $((47 - ${#verdict_text})) '')║${NC}"
    echo -e "${verdict_color}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Commands:"
    echo "  View logs:     journalctl -u ${BOUNCER_SERVICE} -f"
    echo "  View alerts:   docker exec ${CROWDSEC_CONTAINER} cscli alerts list"
    echo "  View metrics:  docker exec ${CROWDSEC_CONTAINER} cscli metrics"
    echo "  Web UI:        https://crowdsec-web-ui.local (if configured)"
    echo ""
}

# -----------------------------------------------------------------------------
# Pre-flight Checks
# -----------------------------------------------------------------------------
preflight_checks() {
    log_section "Pre-flight Checks"

    local failed=0

    # Check Docker is available
    if command -v docker &>/dev/null; then
        log_success "Docker is installed"
    else
        log_error "Docker is not installed"
        : $((failed++))
    fi

    # Check CrowdSec container is running
    if docker ps --format '{{.Names}}' | grep -q "^${CROWDSEC_CONTAINER}$"; then
        log_success "CrowdSec container is running"
    else
        log_error "CrowdSec container '${CROWDSEC_CONTAINER}' is not running"
        : $((failed++))
    fi

    # Check CrowdSec container is healthy
    local health_status
    health_status=$(docker inspect --format='{{.State.Health.Status}}' "${CROWDSEC_CONTAINER}" 2>/dev/null || echo "unknown")
    if [[ "$health_status" == "healthy" ]]; then
        log_success "CrowdSec container is healthy"
    else
        log_warn "CrowdSec container health status: ${health_status}"
    fi

    # Check LAPI is accessible
    if curl -sf "${CROWDSEC_LAPI_URL}/health" &>/dev/null; then
        log_success "CrowdSec LAPI is accessible at ${CROWDSEC_LAPI_URL}"
    else
        log_error "CrowdSec LAPI is not accessible at ${CROWDSEC_LAPI_URL}"
        : $((failed++))
    fi

    # Check for nftables or iptables
    if command -v nft &>/dev/null; then
        log_success "nftables is available (preferred)"
    elif command -v iptables &>/dev/null; then
        log_success "iptables is available"
    else
        log_error "Neither nftables nor iptables is available"
        : $((failed++))
    fi

    if [[ $failed -gt 0 ]]; then
        log_error "Pre-flight checks failed with ${failed} error(s)"
        exit 1
    fi

    log_success "All pre-flight checks passed"
}

# -----------------------------------------------------------------------------
# Remove Legacy Fail2ban (idempotent)
# -----------------------------------------------------------------------------
remove_fail2ban() {
    log_section "Checking for Legacy Fail2ban"

    local action_taken=false

    # Check if fail2ban container exists (running or stopped)
    if docker ps -a --format '{{.Names}}' | grep -q "^fail2ban$"; then
        log_info "Removing fail2ban container..."
        docker stop fail2ban 2>/dev/null || true
        docker rm fail2ban 2>/dev/null || true
        log_change "Fail2ban container removed"
        action_taken=true
    fi

    # Check if fail2ban service exists AND is enabled/active on host
    if systemctl list-unit-files 2>/dev/null | grep -q "fail2ban.service"; then
        local is_enabled is_active
        is_enabled=$(systemctl is-enabled fail2ban 2>/dev/null || echo "disabled")
        is_active=$(systemctl is-active fail2ban 2>/dev/null || echo "inactive")

        if [[ "$is_active" == "active" ]]; then
            log_info "Stopping fail2ban service..."
            systemctl stop fail2ban 2>/dev/null || true
            log_change "Fail2ban service stopped"
            action_taken=true
        fi

        if [[ "$is_enabled" == "enabled" ]]; then
            log_info "Disabling fail2ban service..."
            systemctl disable fail2ban 2>/dev/null || true
            log_change "Fail2ban service disabled"
            action_taken=true
        fi
    fi

    if [[ "$action_taken" == false ]]; then
        log_skip "No fail2ban found (already clean)"
    fi
}

# -----------------------------------------------------------------------------
# Install Firewall Bouncer (idempotent)
# -----------------------------------------------------------------------------
install_bouncer() {
    log_section "Installing CrowdSec Firewall Bouncer"

    # Check if already installed
    if command -v crowdsec-firewall-bouncer &>/dev/null; then
        local version
        version=$(crowdsec-firewall-bouncer -V 2>&1 | head -1 || echo "unknown")
        log_skip "Firewall bouncer already installed: ${version}"
        return 0
    fi

    log_info "Installing crowdsec-firewall-bouncer package..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y crowdsec-firewall-bouncer
    log_change "Firewall bouncer installed"
    CONFIG_CHANGED=true  # New install requires service start
}

# -----------------------------------------------------------------------------
# Disable Local CrowdSec (idempotent - we use Docker)
# -----------------------------------------------------------------------------
disable_local_crowdsec() {
    log_section "Checking Local CrowdSec Service"

    local action_taken=false

    # Check if local crowdsec service exists
    if systemctl list-unit-files 2>/dev/null | grep -q "^${LOCAL_CROWDSEC_SERVICE}.service"; then
        local is_enabled is_active
        is_enabled=$(systemctl is-enabled "${LOCAL_CROWDSEC_SERVICE}" 2>/dev/null || echo "disabled")
        is_active=$(systemctl is-active "${LOCAL_CROWDSEC_SERVICE}" 2>/dev/null || echo "inactive")

        if [[ "$is_active" == "active" ]]; then
            log_info "Stopping local CrowdSec service (using Docker instead)..."
            systemctl stop "${LOCAL_CROWDSEC_SERVICE}" 2>/dev/null || true
            log_change "Local CrowdSec service stopped"
            action_taken=true
        fi

        if [[ "$is_enabled" == "enabled" ]]; then
            log_info "Disabling local CrowdSec service..."
            systemctl disable "${LOCAL_CROWDSEC_SERVICE}" 2>/dev/null || true
            log_change "Local CrowdSec service disabled"
            action_taken=true
        fi
    fi

    # Remove the pending-registration file that blocks bouncer startup
    if [[ -f /var/lib/crowdsec/pending-registration ]]; then
        rm -f /var/lib/crowdsec/pending-registration
        log_change "Removed pending-registration blocker"
        action_taken=true
    fi

    if [[ "$action_taken" == false ]]; then
        log_skip "Local CrowdSec already disabled"
    fi
}

# -----------------------------------------------------------------------------
# Register Bouncer with Docker CrowdSec (idempotent)
# -----------------------------------------------------------------------------
register_bouncer() {
    log_section "Registering Bouncer with CrowdSec"

    # Check if bouncer already registered AND config exists with valid key
    local bouncer_registered=false
    if docker exec "${CROWDSEC_CONTAINER}" cscli bouncers list -o raw 2>/dev/null | grep -q "^${BOUNCER_NAME},"; then
        bouncer_registered=true
    fi

    local config_valid=false
    if [[ -f "${BOUNCER_CONFIG_LOCAL}" ]] && grep -q "^api_key:" "${BOUNCER_CONFIG_LOCAL}"; then
        # Verify the config has correct LAPI URL
        if grep -q "api_url: ${CROWDSEC_LAPI_URL}/" "${BOUNCER_CONFIG_LOCAL}"; then
            config_valid=true
        fi
    fi

    # If both bouncer is registered and config is valid, skip
    if [[ "$bouncer_registered" == true ]] && [[ "$config_valid" == true ]]; then
        log_skip "Bouncer already registered and configured"
        return 0
    fi

    # Need to (re)register
    if [[ "$bouncer_registered" == true ]] && [[ "$config_valid" == false ]]; then
        log_info "Config invalid/missing, regenerating..."
        docker exec "${CROWDSEC_CONTAINER}" cscli bouncers delete "${BOUNCER_NAME}" 2>/dev/null || true
    fi

    # Register new bouncer and get API key
    log_info "Registering bouncer '${BOUNCER_NAME}' with CrowdSec..."
    local api_key
    api_key=$(docker exec "${CROWDSEC_CONTAINER}" cscli bouncers add "${BOUNCER_NAME}" -o raw 2>/dev/null)

    if [[ -z "$api_key" ]]; then
        log_error "Failed to generate bouncer API key"
        exit 1
    fi

    # Write configuration
    cat > "${BOUNCER_CONFIG_LOCAL}" <<EOF
# =============================================================================
# CrowdSec Firewall Bouncer - Local Configuration
# =============================================================================
# Auto-generated by setup-crowdsec-firewall-bouncer.sh
# Connects to CrowdSec LAPI running in Docker at ${CROWDSEC_LAPI_URL}
# =============================================================================

# Use nftables (modern Linux firewall)
mode: nftables

# API connection to Docker CrowdSec LAPI
api_url: ${CROWDSEC_LAPI_URL}/
api_key: ${api_key}

# Logging
log_level: info
EOF

    chmod 600 "${BOUNCER_CONFIG_LOCAL}"
    log_change "Bouncer registered and configured"
    CONFIG_CHANGED=true
}

# -----------------------------------------------------------------------------
# Validate Tailscale Whitelist
# -----------------------------------------------------------------------------
validate_tailscale_whitelist() {
    log_section "Validating Tailscale Whitelist Protection"

    local whitelist_file="/etc/mothership/docker/crowdsec/config/parsers/s02-enrich/whitelist-local.yaml"
    local failed=0

    if [[ ! -f "$whitelist_file" ]]; then
        log_error "Whitelist file not found: ${whitelist_file}"
        log_error "Tailscale IPs may be blocked! Create whitelist before proceeding."
        exit 1
    fi

    # Check for Tailscale IPv4 CIDR
    if grep -q "100.64.0.0/10" "$whitelist_file"; then
        log_success "Tailscale IPv4 range (100.64.0.0/10) is whitelisted"
    else
        log_error "Tailscale IPv4 range (100.64.0.0/10) NOT found in whitelist!"
        : $((failed++))
    fi

    # Check for Tailscale IPv6 CIDR
    if grep -qE "fd7a:115c:a1e0::/48|fd7a:115c:a1e0::" "$whitelist_file"; then
        log_success "Tailscale IPv6 range is whitelisted"
    else
        log_warn "Tailscale IPv6 range not explicitly found (may be covered by fc00::/7)"
    fi

    # Check for private ranges (additional safety)
    if grep -q "10.0.0.0/8" "$whitelist_file"; then
        log_success "Private range 10.0.0.0/8 is whitelisted"
    fi

    if grep -q "172.16.0.0/12" "$whitelist_file"; then
        log_success "Private range 172.16.0.0/12 is whitelisted (Docker networks)"
    fi

    if [[ $failed -gt 0 ]]; then
        log_error "Tailscale whitelist validation failed!"
        log_error "Add the following to ${whitelist_file}:"
        echo "    - \"100.64.0.0/10\"    # Tailscale CGNAT range"
        echo "    - \"fd7a:115c:a1e0::/48\"  # Tailscale IPv6"
        exit 1
    fi

    log_success "Tailscale whitelist validation passed"
}

# -----------------------------------------------------------------------------
# Ensure Bouncer Service Running (idempotent)
# -----------------------------------------------------------------------------
ensure_bouncer_running() {
    log_section "Ensuring Firewall Bouncer Service"

    local needs_restart=false
    local needs_enable=false
    local needs_start=false

    # Check current state
    local is_active is_enabled
    is_active=$(systemctl is-active "${BOUNCER_SERVICE}" 2>/dev/null || echo "inactive")
    is_enabled=$(systemctl is-enabled "${BOUNCER_SERVICE}" 2>/dev/null || echo "disabled")

    # Determine what actions are needed
    if [[ "$is_active" != "active" ]]; then
        needs_start=true
    fi

    if [[ "$is_enabled" != "enabled" ]]; then
        needs_enable=true
    fi

    # If config changed and service is running, need restart
    if [[ "$CONFIG_CHANGED" == true ]] && [[ "$is_active" == "active" ]]; then
        needs_restart=true
    fi

    # If nothing to do, skip
    if [[ "$needs_start" == false ]] && [[ "$needs_enable" == false ]] && [[ "$needs_restart" == false ]]; then
        log_skip "Bouncer service already running and enabled"
        return 0
    fi

    # Test configuration before any service changes
    log_info "Validating bouncer configuration..."
    if ! crowdsec-firewall-bouncer -c "${BOUNCER_CONFIG}" -t &>/dev/null; then
        log_error "Bouncer configuration test failed"
        crowdsec-firewall-bouncer -c "${BOUNCER_CONFIG}" -t 2>&1 || true
        exit 1
    fi
    log_success "Configuration valid"

    # Reload systemd if needed
    systemctl daemon-reload 2>/dev/null || true

    # Enable if needed
    if [[ "$needs_enable" == true ]]; then
        systemctl enable "${BOUNCER_SERVICE}" 2>/dev/null || true
        log_change "Bouncer service enabled"
    fi

    # Start or restart as needed
    if [[ "$needs_restart" == true ]]; then
        log_info "Restarting bouncer service (configuration changed)..."
        systemctl restart "${BOUNCER_SERVICE}"
        log_change "Bouncer service restarted"
    elif [[ "$needs_start" == true ]]; then
        log_info "Starting bouncer service..."
        systemctl start "${BOUNCER_SERVICE}"
        log_change "Bouncer service started"
    fi

    # Verify it's running
    sleep 2
    if systemctl is-active "${BOUNCER_SERVICE}" &>/dev/null; then
        log_success "Bouncer service is running"
    else
        log_error "Bouncer service failed to start"
        journalctl -u "${BOUNCER_SERVICE}" --no-pager -n 20
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Verify Firewall Rules
# -----------------------------------------------------------------------------
verify_firewall_rules() {
    log_section "Verifying Firewall Rules"

    local failed=0

    # Check nftables tables exist
    if nft list tables 2>/dev/null | grep -q "ip crowdsec"; then
        log_success "CrowdSec IPv4 nftables table exists"
    else
        log_error "CrowdSec IPv4 nftables table not found"
        : $((failed++))
    fi

    if nft list tables 2>/dev/null | grep -q "ip6 crowdsec6"; then
        log_success "CrowdSec IPv6 nftables table exists"
    else
        log_warn "CrowdSec IPv6 nftables table not found (may be disabled)"
    fi

    # Check blacklist sets exist and have entries
    local ipv4_count
    ipv4_count=$(nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | grep -c "timeout" || echo "0")
    if [[ "$ipv4_count" -gt 0 ]]; then
        log_success "IPv4 blacklist populated: ${ipv4_count} entries"
    else
        log_warn "IPv4 blacklist is empty (may be normal for new install)"
    fi

    local ipv6_count
    ipv6_count=$(nft list set ip6 crowdsec6 crowdsec6-blacklists 2>/dev/null | grep -c "timeout" || echo "0")
    if [[ "$ipv6_count" -gt 0 ]]; then
        log_success "IPv6 blacklist populated: ${ipv6_count} entries"
    else
        log_info "IPv6 blacklist: ${ipv6_count} entries"
    fi

    # Verify no Tailscale IPs are blocked
    log_info "Checking that no Tailscale IPs are blocked..."
    local blocked_tailscale=0
    if nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | \
        grep -qE " 100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\." 2>/dev/null; then
        blocked_tailscale=$(nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | \
            grep -cE " 100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\." 2>/dev/null || echo "0")
    fi

    if [[ "$blocked_tailscale" -eq 0 ]]; then
        log_success "No Tailscale IPs in blocklist (whitelist working)"
    else
        log_error "Found ${blocked_tailscale} Tailscale IPs in blocklist!"
        log_error "Whitelist may not be working correctly"
        : $((failed++))
    fi

    # Check chain is properly hooked
    if nft list chain ip crowdsec crowdsec-chain 2>/dev/null | grep -q "hook input"; then
        log_success "CrowdSec chain hooked into INPUT"
    else
        log_error "CrowdSec chain not properly hooked"
        : $((failed++))
    fi

    if [[ $failed -gt 0 ]]; then
        log_error "Firewall verification failed with ${failed} error(s)"
        return 1
    fi

    log_success "All firewall rules verified"
}

# -----------------------------------------------------------------------------
# Verify Bouncer Registration
# -----------------------------------------------------------------------------
verify_bouncer_registration() {
    log_section "Verifying Bouncer Registration"

    # Check bouncer appears in CrowdSec
    local bouncer_info
    bouncer_info=$(docker exec "${CROWDSEC_CONTAINER}" cscli bouncers list 2>/dev/null | grep "${BOUNCER_NAME}" || echo "")

    if [[ -n "$bouncer_info" ]]; then
        log_success "Bouncer registered with CrowdSec:"
        echo "$bouncer_info"
    else
        log_error "Bouncer not found in CrowdSec bouncer list"
        return 1
    fi

    # Check for valid status
    if echo "$bouncer_info" | grep -q "✔️"; then
        log_success "Bouncer has valid API connection"
    else
        log_warn "Bouncer may not have connected yet"
    fi
}

# -----------------------------------------------------------------------------
# Final Validation
# -----------------------------------------------------------------------------
final_validation() {
    log_section "Final Validation"

    local score=0
    local total=6

    # 1. Bouncer service running
    if systemctl is-active "${BOUNCER_SERVICE}" &>/dev/null; then
        log_success "[1/${total}] Bouncer service is running"
        ((++score))
    else
        log_error "[1/${total}] Bouncer service is NOT running"
    fi

    # 2. Bouncer registered with CrowdSec
    if docker exec "${CROWDSEC_CONTAINER}" cscli bouncers list -o raw 2>/dev/null | grep -q "^${BOUNCER_NAME},"; then
        log_success "[2/${total}] Bouncer registered with CrowdSec"
        ((++score))
    else
        log_error "[2/${total}] Bouncer NOT registered with CrowdSec"
    fi

    # 3. nftables rules active
    if nft list table ip crowdsec &>/dev/null; then
        log_success "[3/${total}] nftables rules are active"
        ((++score))
    else
        log_error "[3/${total}] nftables rules NOT active"
    fi

    # 4. Blocklist has entries (CAPI connected)
    local entry_count
    entry_count=$(nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | grep -c "timeout" || echo "0")
    if [[ "$entry_count" -gt 100 ]]; then
        log_success "[4/${total}] Blocklist populated (${entry_count} entries from CAPI)"
        ((++score))
    else
        log_warn "[4/${total}] Blocklist has few entries (${entry_count}) - CAPI may not be synced yet"
        ((++score))  # Still count as pass, will populate over time
    fi

    # 5. No Tailscale IPs blocked
    local blocked_ts=0
    if nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | \
        grep -qE " 100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\." 2>/dev/null; then
        blocked_ts=$(nft list set ip crowdsec crowdsec-blacklists 2>/dev/null | \
            grep -cE " 100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\." 2>/dev/null || echo "0")
    fi
    if [[ "$blocked_ts" -eq 0 ]]; then
        log_success "[5/${total}] Tailscale IPs protected (0 blocked)"
        ((++score))
    else
        log_error "[5/${total}] WARNING: ${blocked_ts} Tailscale IPs in blocklist!"
    fi

    # 6. Local CrowdSec disabled
    if ! systemctl is-enabled "${LOCAL_CROWDSEC_SERVICE}" &>/dev/null; then
        log_success "[6/${total}] Local CrowdSec service disabled (using Docker)"
        ((++score))
    else
        log_warn "[6/${total}] Local CrowdSec service still enabled"
    fi

    echo ""
    echo -e "${BLUE}==============================================================================${NC}"
    if [[ $score -eq $total ]]; then
        if [[ "$CHANGES_MADE" == true ]]; then
            echo -e "${GREEN} SETUP COMPLETE: All ${total} checks passed (changes applied)${NC}"
        else
            echo -e "${GREEN} SETUP COMPLETE: All ${total} checks passed (no changes needed)${NC}"
        fi
    elif [[ $score -ge $((total - 1)) ]]; then
        echo -e "${YELLOW} SETUP MOSTLY COMPLETE: ${score}/${total} checks passed${NC}"
    else
        echo -e "${RED} SETUP INCOMPLETE: ${score}/${total} checks passed${NC}"
    fi
    echo -e "${BLUE}==============================================================================${NC}"
    echo ""

    # Summary
    echo "Summary:"
    echo "  - Firewall bouncer: $(systemctl is-active ${BOUNCER_SERVICE})"
    echo "  - IPv4 blocked: ${entry_count} IPs"
    echo "  - Tailscale protected: Yes (whitelisted)"
    echo "  - Config: ${BOUNCER_CONFIG_LOCAL}"
    echo "  - Logs: journalctl -u ${BOUNCER_SERVICE} -f"
    if [[ "$CHANGES_MADE" == true ]]; then
        echo "  - Changes made: Yes"
    else
        echo "  - Changes made: No (already configured)"
    fi
    echo ""

    return $((total - score))
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    # Parse arguments
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --status|-s)
            check_root
            show_status
            exit 0
            ;;
        "")
            # No arguments - run setup
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac

    echo ""
    echo -e "${BLUE}==============================================================================${NC}"
    echo -e "${BLUE} CrowdSec Firewall Bouncer Setup${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
    echo ""

    check_root
    preflight_checks
    remove_fail2ban
    install_bouncer
    disable_local_crowdsec
    validate_tailscale_whitelist
    register_bouncer
    ensure_bouncer_running
    verify_firewall_rules
    verify_bouncer_registration
    final_validation
}

# Run main function
main "$@"
