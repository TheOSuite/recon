#!/usr/bin/env bash
# Usage: ./precon.sh <domain> [max_save] [--full] [--stealth]

set -euo pipefail

VERSION="1.0-merged"
TARGET=""
OUTPUT_DIR=""
MODE="demo" # demo | full | stealth
MAX_SAVE=200
START_TIME=$(date +%s)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Logging functions
log() { echo -e "${BLUE}[*] $1${NC}"; }
success() { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }
error() { echo -e "${RED}[✗] $1${NC}"; }

show_help() {
    cat <<EOF
${WHITE}recon-validator${NC} - Discover & validate subdomains in one go

${CYAN}Usage:${NC} $0 <domain> [max_save] [--full] [--stealth]

${YELLOW}Arguments:${NC}
  domain      Target domain (e.g., example.com)
  max_save    Max live hosts to save (default: 200)
  --full      Deeper crawl + nmap scanning
  --stealth   Route through Tor (requires tor on port 9050)

${YELLOW}Examples:${NC}
  $0 example.com
  $0 example.com 500 --full
  $0 target.com 300 --stealth

${YELLOW}Output:${NC}
  All results saved to ~/storage/shared/recon-<timestamp>/
  - subdomains.txt      (all discovered subdomains)
  - live_hosts.txt      (validated live hosts)
  - report.html         (visual report)
EOF
}

# Check for required tools
check_tool() {
    command -v "$1" >/dev/null || warn "$1 not found — will skip this step"
}

# === PHASE 1: SUBDOMAIN DISCOVERY ===
passive_subs() {
    log "Phase 1: Discovering subdomains for $TARGET"
    mkdir -p "$OUTPUT_DIR/subs"

    # 1. crt.sh (SSL certificate transparency logs)
    log "Querying crt.sh..."
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | \
        sort -u > "$OUTPUT_DIR/subs/crtsh.txt" || true

    # 2. AlienVault OTX
    log "Querying AlienVault OTX..."
    curl -s "https://otx.alienvault.com/api/v1/domains/$TARGET/subdomains?limit=500" 2>/dev/null | \
        jq -r '.data[].hostname' 2>/dev/null > "$OUTPUT_DIR/subs/otx.txt" || true

    # 3. DNS bufferover
    log "Querying dns.bufferover.run..."
    curl -s "https://dns.bufferover.run/dns?q=$TARGET" 2>/dev/null | \
        jq -r '.FDNS_A[],.FDNS_CNAME[]' 2>/dev/null | \
        cut -d',' -f2 | sort -u > "$OUTPUT_DIR/subs/bufferover.txt" || true

    # 4. Amass passive mode (if available)
    if command -v amass >/dev/null; then
        log "Running Amass passive enumeration (180s timeout)..."
        timeout 180 amass enum -passive -d "$TARGET" -o "$OUTPUT_DIR/subs/amass.txt" 2>/dev/null || true
    fi

    # Combine and deduplicate
    cat "$OUTPUT_DIR/subs/"*.txt 2>/dev/null | \
        sort -u | \
        grep -E "\.$TARGET\$" > "$OUTPUT_DIR/subdomains.txt" || true
   
    local sub_count=$(wc -l < "$OUTPUT_DIR/subdomains.txt" 2>/dev/null || echo 0)
    success "Discovered $sub_count unique subdomains"
}

# === PHASE 2: LIVE HOST VALIDATION ===
validate_live_hosts() {
    log "Phase 2: Validating live hosts (parallel ping)"
   
    local INPUT="$OUTPUT_DIR/subdomains.txt"
    local OUTPUT="$OUTPUT_DIR/live_hosts.txt"
   
    if [[ ! -f "$INPUT" || ! -s "$INPUT" ]]; then
        error "No subdomains to validate!"
        return 1
    fi
   
    local total_hosts=$(wc -l < "$INPUT")
    echo -e "${CYAN}Starting parallel validation...${NC}"
    echo -e "${YELLOW}Subdomains: ${WHITE}$total_hosts${NC}"
    echo -e "${YELLOW}Max to save: ${WHITE}$MAX_SAVE${NC}\n"
   
    # Config
    local PING_COUNT=1
    local TIMEOUT=2
    local CONCURRENCY=50
   
    # Temp files
    local tmp=$(mktemp)
    local live_tmp=$(mktemp)
    trap 'rm -f "$tmp" "$live_tmp"' EXIT
   
    # Clean input
    grep -vE '^\s*$|^\s*#' "$INPUT" | \
        sed 's/^[[:space:]]\+//;s/[[:space:]]\+$//' > "$tmp"
   
    # Ping function
    check_host() {
        local h="$1"
        if ping -c 1 -W 2 "$h" >/dev/null 2>&1; then
            echo "$h" >> "$live_tmp"
        fi
    }
    export -f check_host
    export live_tmp
   
    # Run parallel validation
    cat "$tmp" | xargs -I{} -P $CONCURRENCY bash -c 'check_host "{}"' &
    local pid=$!
   
    # Progress bar
    while kill -0 $pid 2>/dev/null; do
        local checked=$(cat "$tmp" 2>/dev/null | wc -l || echo 0)
        local live=$(wc -l < "$live_tmp" 2>/dev/null || echo 0)
        local percent=$(( checked * 100 / total_hosts ))
        local bar=$(printf "█%.0s" $(seq 1 $((percent / 2)) 2>/dev/null) || echo "")
       
        printf "\r${WHITE}[%3d%%]${NC} %s ${GREEN}%d live${NC} | ${YELLOW}%d/%d saved${NC}" \
            "$percent" "$bar" "$live" "$live" "$MAX_SAVE"
       
        # Stop if we hit max
        if [[ $live -ge $MAX_SAVE ]]; then
            kill $pid 2>/dev/null || true
            break
        fi
        sleep 0.5
    done
   
    wait $pid 2>/dev/null || true
    echo ""
   
    # Save results (up to MAX_SAVE)
    head -n "$MAX_SAVE" "$live_tmp" > "$OUTPUT" 2>/dev/null || touch "$OUTPUT"
    local live_final=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
   
    success "Validated $live_final live hosts → $OUTPUT"
}

# === PHASE 3: ADDITIONAL SCANNING (optional) ===
probe_http() {
    log "Phase 3: Probing HTTP services"
   
    if [[ ! -s "$OUTPUT_DIR/live_hosts.txt" ]]; then
        warn "No live hosts to probe"
        return
    fi
   
    if command -v httpx >/dev/null; then
        httpx -list "$OUTPUT_DIR/live_hosts.txt" -silent -title -status-code -timeout 10 \
            -o "$OUTPUT_DIR/http_services.txt" 2>/dev/null || true
        success "HTTP probe complete → http_services.txt"
    else
        warn "httpx not found — skipping HTTP probe"
    fi
}

urls_endpoints() {
    [[ "$MODE" == "demo" ]] && return
    log "Crawling URLs (gau + katana)"
   
    if [[ -s "$OUTPUT_DIR/live_hosts.txt" ]]; then
        cat "$OUTPUT_DIR/live_hosts.txt" | gau --subs 2>/dev/null > "$OUTPUT_DIR/urls.txt" || true
        cat "$OUTPUT_DIR/live_hosts.txt" | katana -silent -headless -timeout 10 2>/dev/null >> "$OUTPUT_DIR/urls.txt" || true
        success "URL crawling complete"
    fi
}

nuclei_scan() {
    [[ "$MODE" == "demo" ]] && return
    log "Running Nuclei vulnerability scan"
   
    if [[ ! -s "$OUTPUT_DIR/live_hosts.txt" ]]; then
        warn "No live hosts — skipping Nuclei"
        return
    fi
   
    local tags="-t cves/,exposures/,misconfiguration/,default-credentials/,takeovers/"
    [[ "$MODE" == "full" ]] && tags="-all"
   
    nuclei -l "$OUTPUT_DIR/live_hosts.txt" $tags -c 15 -silent -jsonl \
        -o "$OUTPUT_DIR/nuclei.jsonl" 2>/dev/null || true
    success "Nuclei scan complete"
}

# === REPORTING ===
generate_report() {
    log "Generating HTML report..."
   
    local sub_count=$(wc -l < "$OUTPUT_DIR/subdomains.txt" 2>/dev/null || echo 0)
    local live_count=$(wc -l < "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || echo 0)
    local runtime=$(( $(date +%s) - START_TIME ))
   
    cat > "$OUTPUT_DIR/report.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Recon Report • $TARGET</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        body { background: #0a0a0a; color: #00ff00; font-family: 'Courier New', monospace; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00ff00; border-bottom: 2px solid #00ff00; padding-bottom: 10px; }
        .stats { background: #1a1a1a; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .stat-item { display: inline-block; margin: 10px 20px; }
        .stat-label { color: #888; }
        .stat-value { color: #00ff00; font-size: 24px; font-weight: bold; }
        .section { background: #1a1a1a; padding: 15px; margin: 15px 0; border-radius: 8px; }
        .host-list { max-height: 400px; overflow-y: auto; }
        .host { padding: 5px; border-bottom: 1px solid #333; }
        button { background: #003300; color: #00ff00; border: 1px solid #00ff00;
                 padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px; }
        button:hover { background: #004400; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Recon Report: $TARGET</h1>
       
        <div class="stats">
            <div class="stat-item">
                <div class="stat-label">Subdomains Discovered</div>
                <div class="stat-value">$sub_count</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">Live Hosts Validated</div>
                <div class="stat-value">$live_count</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">Runtime</div>
                <div class="stat-value">${runtime}s</div>
            </div>
        </div>
       
        <div class="section">
            <h2>📡 Live Hosts (Top $MAX_SAVE)</h2>
            <div class="host-list">
EOF
   
    # Add live hosts to report
    if [[ -f "$OUTPUT_DIR/live_hosts.txt" ]]; then
        while IFS= read -r host; do
            echo "                <div class=\"host\">$host</div>" >> "$OUTPUT_DIR/report.html"
        done < "$OUTPUT_DIR/live_hosts.txt"
    fi
   
    cat >> "$OUTPUT_DIR/report.html" <<EOF
            </div>
        </div>
       
        <div class="section">
            <h2>📁 Output Files</h2>
            <ul>
                <li>subdomains.txt - All discovered subdomains</li>
                <li>live_hosts.txt - Validated live hosts</li>
                <li>http_services.txt - HTTP probe results (if available)</li>
            </ul>
        </div>
       
        <button onclick="navigator.clipboard.writeText(location.href)">📋 Copy Report Link</button>
        <button onclick="window.print()">🖨️ Print Report</button>
    </div>
</body>
</html>
EOF
   
    success "Report generated → $OUTPUT_DIR/report.html"
    termux-open "$OUTPUT_DIR/report.html" 2>/dev/null || true
}

# === MAIN EXECUTION ===

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) show_help; exit 0;;
        --full) MODE="full"; shift;;
        --stealth)
            export HTTPS_PROXY=socks5h://127.0.0.1:9050
            log "Stealth mode enabled via Tor"
            shift;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
            elif [[ "$1" =~ ^[0-9]+$ ]]; then
                MAX_SAVE="$1"
            fi
            shift;;
    esac
done

# Validate input
if [[ -z "$TARGET" ]]; then
    error "Missing target domain!"
    show_help
    exit 1
fi

# Setup output directory
OUTPUT_DIR="$HOME/storage/shared/recon-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════╗"
echo "║   Recon Validator v${VERSION}         ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"
log "Target: ${WHITE}$TARGET${NC}"
log "Mode: ${WHITE}$MODE${NC}"
log "Max live hosts: ${WHITE}$MAX_SAVE${NC}"
log "Output: ${WHITE}$OUTPUT_DIR${NC}"
echo ""

# Execute workflow
passive_subs
validate_live_hosts
probe_http

# Additional scans in full mode
if [[ "$MODE" == "full" ]]; then
    urls_endpoints
    nuclei_scan
fi

# Generate final report
generate_report

# Summary
echo ""
echo -e "${GREEN}╔════════════════════════════════╗${NC}"
echo -e "${GREEN}║    Scan Complete! ✓            ║${NC}"
echo -e "${GREEN}╔════════════════════════════════╗${NC}"
echo ""
success "Results saved to: $OUTPUT_DIR"
success "Total runtime: $(( $(date +%s) - START_TIME )) seconds"
echo ""
