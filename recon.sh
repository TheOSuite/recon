#!/usr/bin/env bash
# recon-validator.sh - Discover subdomains and validate live hosts in one flow
# Usage: ./recon-validator.sh <domain> [max_save] [--full] [--stealth] [--skip-ports]
set -euo pipefail

VERSION="2.0-enhanced"
TARGET=""
OUTPUT_DIR=""
MODE="demo" # demo | full | stealth
MAX_SAVE=200
SKIP_PORTS=false
TCP_VALIDATE=false
START_TIME=$(date +%s)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Logging functions
log() { echo -e "${BLUE}[*] $1${NC}"; }
success() { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }
error() { echo -e "${RED}[✗] $1${NC}"; }
info() { echo -e "${CYAN}[i] $1${NC}"; }

show_help() {
    cat <<EOF
${WHITE}recon-validator${NC} - Discover & validate subdomains with intelligence

${CYAN}Usage:${NC} $0 <domain> [max_save] [--full] [--stealth] [--skip-ports] [--tcp-validate]

${YELLOW}Arguments:${NC}
  domain          Target domain (e.g., example.com)
  max_save        Max live hosts to save (default: 200)
  --full          Deeper crawl + nmap scanning + Nuclei
  --stealth       Route through Tor (requires tor on port 9050)
  --skip-ports    Skip port scanning phase
  --tcp-validate  Use TCP port checks instead of ICMP ping (auto-enabled on Android/Termux)

${YELLOW}Examples:${NC}
  $0 example.com
  $0 example.com 500 --full
  $0 target.com 300 --tcp-validate
  $0 target.com --stealth

${YELLOW}Features:${NC}
  ✓ Passive subdomain enumeration
  ✓ Parallel live host validation (ICMP or TCP)
  ✓ DNS resolution & IP mapping
  ✓ Common port scanning
  ✓ Technology detection
  ✓ Infrastructure grouping
  ✓ Auto-detects Android/Termux environment

${YELLOW}Output:${NC}
  All results saved to ~/storage/shared/recon-<timestamp>/
  - subdomains.txt      (all discovered subdomains)
  - live_hosts.txt      (validated live hosts)
  - dns_resolved.txt    (IPs + DNS records)
  - ip_groups.txt       (hosts grouped by IP)
  - port_scan.txt       (open ports per host)
  - tech_stack.txt      (detected technologies)
  - report.html         (visual report)
EOF
}

# Check for required tools
check_tool() { 
    command -v "$1" >/dev/null || warn "$1 not found — will skip this step"
}

# Port to service mapper
port_to_service() {
    case $1 in
        21) echo "FTP" ;;
        22) echo "SSH" ;;
        23) echo "Telnet" ;;
        25|465|587) echo "SMTP" ;;
        53) echo "DNS" ;;
        80) echo "HTTP" ;;
        81|8081) echo "HTTP-Alt" ;;
        110) echo "POP3" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        445) echo "SMB" ;;
        993) echo "IMAPS" ;;
        995) echo "POP3S" ;;
        1433) echo "MSSQL" ;;
        3000) echo "Node.js/Dev" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5000) echo "Flask/Dev" ;;
        5432) echo "PostgreSQL" ;;
        5900|5901) echo "VNC" ;;
        6379) echo "Redis" ;;
        8000|8008) echo "HTTP-Dev" ;;
        8080) echo "HTTP-Proxy" ;;
        8443) echo "HTTPS-Alt" ;;
        8888) echo "HTTP-Alt" ;;
        9000) echo "Dev-Server" ;;
        *) echo "Unknown" ;;
    esac
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
    log "Phase 2: Validating live hosts"
    
    local INPUT="$OUTPUT_DIR/subdomains.txt"
    local OUTPUT="$OUTPUT_DIR/live_hosts.txt"
    
    if [[ ! -f "$INPUT" || ! -s "$INPUT" ]]; then
        error "No subdomains to validate!"
        return 1
    fi
    
    local total_hosts=$(wc -l < "$INPUT")
    
    # Auto-detect Android/Termux environment
    if [[ "$TCP_VALIDATE" == false ]]; then
        if [[ -d "/data/data/com.termux" ]] || [[ "$PREFIX" == *"com.termux"* ]]; then
            warn "Android/Termux detected - switching to TCP validation mode"
            TCP_VALIDATE=true
        fi
    fi
    
    if [[ "$TCP_VALIDATE" == true ]]; then
        info "Using TCP port validation (80/443/8080/8443 + DNS fallback)"
    else
        info "Using ICMP ping validation"
    fi
    
    echo -e "${CYAN}Starting parallel validation...${NC}"
    echo -e "${YELLOW}Subdomains: ${WHITE}$total_hosts${NC}"
    echo -e "${YELLOW}Max to save: ${WHITE}$MAX_SAVE${NC}\n"
    
    # Config
    local CONCURRENCY=50
    
    # Temp files
    local input_tmp=$(mktemp)
    local live_tmp=$(mktemp)
    trap 'rm -f "$input_tmp" "$live_tmp"' RETURN
    
    # Clean input
    grep -vE '^\s*$|^\s*#' "$INPUT" | \
        sed 's/^[[:space:]]\+//;s/[[:space:]]\+$//' > "$input_tmp"
    
    if [[ "$TCP_VALIDATE" == true ]]; then
        # TCP-based validation (better for Android/Termux and web-focused recon)
        check_host() {
            local h="$1"
            # Try common web ports first (fastest signal of life)
            for port in 80 443 8080 8443; do
                if timeout 3 bash -c "echo > /dev/tcp/$h/$port" 2>/dev/null; then
                    echo "$h" >> "$live_tmp"
                    return 0
                fi
            done
            # Fallback: DNS resolution means it's probably live
            if dig +short A "$h" 2>/dev/null | grep -q "^[0-9]"; then
                echo "$h" >> "$live_tmp"
                return 0
            fi
            return 1
        }
    else
        # ICMP ping validation (traditional method)
        check_host() {
            local h="$1"
            if ping -c 1 -W 2 "$h" >/dev/null 2>&1; then
                echo "$h" >> "$live_tmp"
                return 0
            fi
            return 1
        }
    fi
    
    export -f check_host
    export live_tmp
    export TCP_VALIDATE
    
    # Run parallel validation
    cat "$input_tmp" | xargs -I{} -P $CONCURRENCY bash -c 'check_host "{}"' &
    local pid=$!
    
    # Progress bar
    local last_count=0
    while kill -0 $pid 2>/dev/null; do
        local live=$(wc -l < "$live_tmp" 2>/dev/null || echo 0)
        local percent=$(( live * 100 / total_hosts ))
        [[ $percent -gt 100 ]] && percent=100
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
    
    # Deduplicate and save results (up to MAX_SAVE)
    sort -u "$live_tmp" | head -n "$MAX_SAVE" > "$OUTPUT" 2>/dev/null || touch "$OUTPUT"
    local live_final=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
    
    success "Validated $live_final live hosts → $OUTPUT"
    
    if [[ "$TCP_VALIDATE" == true ]]; then
        info "TCP validation: Hosts respond on web ports or have valid DNS"
    fi
}

# === PHASE 3: DNS RESOLUTION & IP MAPPING ===
resolve_dns() {
    log "Phase 3: Resolving DNS records and mapping IPs"
    
    local INPUT="$OUTPUT_DIR/live_hosts.txt"
    local DNS_OUTPUT="$OUTPUT_DIR/dns_resolved.txt"
    local IP_MAP="$OUTPUT_DIR/ip_groups.txt"
    local IP_DETAILS="$OUTPUT_DIR/ip_details.json"
    
    if [[ ! -f "$INPUT" || ! -s "$INPUT" ]]; then
        warn "No live hosts to resolve"
        return 1
    fi
    
    > "$DNS_OUTPUT"
    > "$IP_DETAILS"
    
    local total=$(wc -l < "$INPUT")
    local current=0
    
    # Temporary file for IP mapping
    local ip_map_tmp=$(mktemp)
    trap 'rm -f "$ip_map_tmp"' RETURN
    
    info "Resolving DNS for $total hosts..."
    
    while IFS= read -r host; do
        ((current++))
        printf "\r${CYAN}Progress: ${WHITE}%d/%d${NC}" "$current" "$total"
        
        # Get A records
        local ips=$(dig +short A "$host" 2>/dev/null | grep -E '^[0-9]+\.')
        
        # Get CNAME if no A record
        if [[ -z "$ips" ]]; then
            local cname=$(dig +short CNAME "$host" 2>/dev/null | head -1)
            if [[ -n "$cname" ]]; then
                echo "$host -> CNAME: $cname" >> "$DNS_OUTPUT"
                ips=$(dig +short A "$cname" 2>/dev/null | grep -E '^[0-9]+\.')
            fi
        fi
        
        if [[ -n "$ips" ]]; then
            for ip in $ips; do
                echo "$host -> $ip" >> "$DNS_OUTPUT"
                echo "$ip|$host" >> "$ip_map_tmp"
                
                # Detect cloud provider
                local provider="Unknown"
                local org=$(whois "$ip" 2>/dev/null | grep -i "OrgName\|Organization" | head -1 | cut -d: -f2 | xargs || echo "Unknown")
                
                case "$org" in
                    *Amazon*|*AWS*) provider="AWS" ;;
                    *Google*|*GCP*) provider="Google Cloud" ;;
                    *Microsoft*|*Azure*) provider="Azure" ;;
                    *Cloudflare*) provider="Cloudflare" ;;
                    *DigitalOcean*) provider="DigitalOcean" ;;
                    *Akamai*) provider="Akamai" ;;
                esac
                
                # Save to JSON
                echo "{\"host\":\"$host\",\"ip\":\"$ip\",\"provider\":\"$provider\",\"org\":\"$org\"}" >> "$IP_DETAILS"
            done
        else
            echo "$host -> NO_IP" >> "$DNS_OUTPUT"
        fi
        
    done < "$INPUT"
    
    echo ""
    
    # Generate IP grouping report
    info "Generating IP groups..."
    > "$IP_MAP"
    
    if [[ -s "$ip_map_tmp" ]]; then
        sort "$ip_map_tmp" | awk -F'|' '
        {
            ip=$1
            host=$2
            hosts[ip] = hosts[ip] (hosts[ip] ? "," : "") host
            count[ip]++
        }
        END {
            for (ip in hosts) {
                print "=== IP: " ip " (" count[ip] " hosts) ==="
                split(hosts[ip], arr, ",")
                for (i in arr) {
                    print "  - " arr[i]
                }
                print ""
            }
        }
        ' > "$IP_MAP"
    fi
    
    # Summary
    local unique_ips=$(grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" "$DNS_OUTPUT" 2>/dev/null | sort -u | wc -l || echo 0)
    success "DNS resolution complete"
    info "Unique IPs: ${WHITE}$unique_ips${NC}"
    info "Results: dns_resolved.txt, ip_groups.txt, ip_details.json"
}

# === PHASE 4: PORT SCANNING ===
scan_ports() {
    if [[ "$SKIP_PORTS" == true ]]; then
        warn "Port scanning skipped (--skip-ports)"
        return 0
    fi
    
    log "Phase 4: Scanning common ports with service detection"
    
    local INPUT="$OUTPUT_DIR/live_hosts.txt"
    local OUTPUT="$OUTPUT_DIR/port_scan.txt"
    
    if [[ ! -f "$INPUT" || ! -s "$INPUT" ]]; then
        warn "No live hosts to scan"
        return 1
    fi
    
    # Expanded port list with common dev/staging ports
    local PORTS="21,22,23,25,53,80,81,110,143,443,445,465,587,993,995,1433,3000,3306,3389,5000,5432,5900,5901,6379,8000,8008,8080,8081,8443,8888,9000"
    
    info "Scanning ports: $PORTS"
    > "$OUTPUT"
    
    # Check if naabu is available
    local HAS_NAABU=false
    if command -v naabu >/dev/null 2>&1; then
        HAS_NAABU=true
        success "naabu detected → using for high-speed scanning"
    fi
    
    local total=$(wc -l < "$INPUT")
    local current=0
    
    if [[ "$HAS_NAABU" == true ]]; then
        # Use naabu for blazing fast scanning
        log "Running naabu scan..."
        local naabu_tmp=$(mktemp)
        
        naabu -list "$INPUT" -p "$PORTS" -silent -rate 1000 -c 50 -o "$naabu_tmp" 2>/dev/null || true
        
        if [[ -s "$naabu_tmp" ]]; then
            # Convert naabu output (host:port format) to our format
            local current_host=""
            local host_ports=""
            
            sort "$naabu_tmp" | while IFS=: read -r host port; do
                if [[ "$host" != "$current_host" ]]; then
                    # New host - save previous if exists
                    if [[ -n "$current_host" && -n "$host_ports" ]]; then
                        echo "$current_host:$host_ports" >> "$OUTPUT"
                        for p in $host_ports; do
                            local service=$(port_to_service "$p")
                            echo "  $p/$service" >> "$OUTPUT"
                        done
                        echo "" >> "$OUTPUT"
                    fi
                    current_host="$host"
                    host_ports="$port"
                else
                    host_ports="$host_ports $port"
                fi
            done
            
            # Save last host
            if [[ -n "$current_host" && -n "$host_ports" ]]; then
                echo "$current_host:$host_ports" >> "$OUTPUT"
                for p in $host_ports; do
                    local service=$(port_to_service "$p")
                    echo "  $p/$service" >> "$OUTPUT"
                done
                echo "" >> "$OUTPUT"
            fi
        fi
        
        rm -f "$naabu_tmp"
        
    else
        # Fallback to pure bash TCP connect scan (slower but always works)
        info "Using bash TCP connect scan (install naabu for 10x speed boost)"
        
        while IFS= read -r host; do
            ((current++))
            printf "\r${CYAN}Scanning: ${WHITE}%d/%d${NC} - %s" "$current" "$total" "$host"
            
            local open_ports=""
            
            # Parallel port checking for speed
            for port in ${PORTS//,/ }; do
                if timeout 1.5 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
                    open_ports="$open_ports $port"
                fi
            done
            
            if [[ -n "$open_ports" ]]; then
                echo "$host:$open_ports" >> "$OUTPUT"
                
                # Identify services
                for port in $open_ports; do
                    local service=$(port_to_service "$port")
                    echo "  $port/$service" >> "$OUTPUT"
                done
                echo "" >> "$OUTPUT"
            fi
            
        done < "$INPUT"
        
        echo ""
    fi
    
    local hosts_with_ports=$(grep -c ":" "$OUTPUT" 2>/dev/null || echo 0)
    success "Port scan complete"
    info "Hosts with open ports: ${WHITE}$hosts_with_ports${NC}"
    
    # Show interesting findings
    if [[ -s "$OUTPUT" ]]; then
        local redis_count=$(grep -c "6379/Redis" "$OUTPUT" 2>/dev/null || echo 0)
        local rdp_count=$(grep -c "3389/RDP" "$OUTPUT" 2>/dev/null || echo 0)
        local ssh_count=$(grep -c "22/SSH" "$OUTPUT" 2>/dev/null || echo 0)
        
        [[ $redis_count -gt 0 ]] && warn "Found $redis_count hosts with Redis exposed (potential security risk!)"
        [[ $rdp_count -gt 0 ]] && info "Found $rdp_count hosts with RDP open"
        [[ $ssh_count -gt 0 ]] && info "Found $ssh_count hosts with SSH open"
    fi
}

# === PHASE 5: TECHNOLOGY DETECTION ===
detect_technologies() {
    log "Phase 5: Detecting web technologies"
    
    local INPUT="$OUTPUT_DIR/live_hosts.txt"
    local OUTPUT="$OUTPUT_DIR/tech_stack.txt"
    local JSON_OUTPUT="$OUTPUT_DIR/tech_stack.json"
    
    if [[ ! -f "$INPUT" || ! -s "$INPUT" ]]; then
        warn "No live hosts to analyze"
        return 1
    fi
    
    > "$OUTPUT"
    > "$JSON_OUTPUT"
    
    local total=$(wc -l < "$INPUT")
    local current=0
    
    # Check if httpx is available
    local HAS_HTTPX=false
    if command -v httpx >/dev/null 2>&1; then
        HAS_HTTPX=true
        success "httpx detected → using for advanced tech + WAF detection"
    fi
    
    if [[ "$HAS_HTTPX" == true ]]; then
        log "Running httpx technology detection..."
        
        # Run httpx with full tech detection
        httpx -list "$INPUT" -title -tech-detect -waf -server -status-code -content-length \
            -timeout 12 -retries 2 -silent -json -o "$JSON_OUTPUT" 2>/dev/null || true
        
        # Generate human-readable output from JSON
        if [[ -s "$JSON_OUTPUT" ]]; then
            info "Parsing httpx results..."
            
            # Parse JSON and create readable format
            jq -r '.[] | "=== \(.host // .url) (\(.status_code // "N/A")) ===\nTitle: \(.title // "N/A")\nServer: \(.webserver // "Unknown")\nTechnologies: \(.technologies // [] | join(", "))\nWAF: \(.waf // "None")\nContent-Length: \(.content_length // 0)\n"' "$JSON_OUTPUT" 2>/dev/null > "$OUTPUT" || true
            
            # Generate statistics
            local total_scanned=$(jq -r '. | length' "$JSON_OUTPUT" 2>/dev/null || echo 0)
            local cms_count=$(jq -r '[.[] | select(.technologies[]? | test("WordPress|Joomla|Drupal|Magento"; "i"))] | length' "$JSON_OUTPUT" 2>/dev/null || echo 0)
            local waf_count=$(jq -r '[.[] | select(.waf != null and .waf != "")] | length' "$JSON_OUTPUT" 2>/dev/null || echo 0)
            local react_count=$(jq -r '[.[] | select(.technologies[]? | test("React"; "i"))] | length' "$JSON_OUTPUT" 2>/dev/null || echo 0)
            local angular_count=$(jq -r '[.[] | select(.technologies[]? | test("Angular"; "i"))] | length' "$JSON_OUTPUT" 2>/dev/null || echo 0)
            local vue_count=$(jq -r '[.[] | select(.technologies[]? | test("Vue"; "i"))] | length' "$JSON_OUTPUT" 2>/dev/null || echo 0)
            
            success "Technology detection complete"
            info "Hosts analyzed: ${WHITE}$total_scanned${NC}"
            [[ $cms_count -gt 0 ]] && info "CMS detected: ${WHITE}$cms_count${NC} sites"
            [[ $waf_count -gt 0 ]] && warn "WAF protected: ${WHITE}$waf_count${NC} sites"
            [[ $react_count -gt 0 ]] && info "React apps: ${WHITE}$react_count${NC}"
            [[ $angular_count -gt 0 ]] && info "Angular apps: ${WHITE}$angular_count${NC}"
            [[ $vue_count -gt 0 ]] && info "Vue.js apps: ${WHITE}$vue_count${NC}"
            
            # Show interesting findings
            local wordpress=$(jq -r '[.[] | select(.technologies[]? | test("WordPress"; "i")) | .host // .url] | .[]' "$JSON_OUTPUT" 2>/dev/null || true)
            if [[ -n "$wordpress" ]]; then
                echo ""
                info "WordPress sites found:"
                echo "$wordpress" | head -5 | sed 's/^/  → /'
                local wp_count=$(echo "$wordpress" | wc -l)
                [[ $wp_count -gt 5 ]] && echo "  ... and $(($wp_count - 5)) more"
            fi
        fi
        
    else
        # Fallback to pure-bash technology fingerprinting
        warn "httpx not found — using pure-bash detection (install httpx for better results)"
        info "Analyzing technologies for $total hosts..."
        
        while IFS= read -r host; do
            ((current++))
            printf "\r${CYAN}Analyzing: ${WHITE}%d/%d${NC} - %s" "$current" "$total" "$host"
            
            # Try both HTTP and HTTPS
            for proto in https http; do
                local url="${proto}://${host}"
                local response=$(curl -sS -L -m 10 -A "Mozilla/5.0" "$url" 2>/dev/null || echo "")
                
                if [[ -z "$response" ]]; then
                    continue
                fi
                
                echo "=== $host ($proto) ===" >> "$OUTPUT"
                
                # Detect technologies from headers and content
                local headers=$(curl -sS -I -L -m 10 -A "Mozilla/5.0" "$url" 2>/dev/null || echo "")
                
                # Server detection
                local server=$(echo "$headers" | grep -i "^Server:" | cut -d: -f2- | xargs || echo "Unknown")
                echo "Server: $server" >> "$OUTPUT"
                
                # X-Powered-By
                local powered_by=$(echo "$headers" | grep -i "^X-Powered-By:" | cut -d: -f2- | xargs || echo "")
                [[ -n "$powered_by" ]] && echo "X-Powered-By: $powered_by" >> "$OUTPUT"
                
                # CMS Detection
                local cms="Unknown"
                if echo "$response" | grep -q "wp-content\|wordpress"; then
                    cms="WordPress"
                elif echo "$response" | grep -q "joomla"; then
                    cms="Joomla"
                elif echo "$response" | grep -q "drupal"; then
                    cms="Drupal"
                elif echo "$response" | grep -q "Magento\|mage"; then
                    cms="Magento"
                elif echo "$response" | grep -q "shopify"; then
                    cms="Shopify"
                fi
                [[ "$cms" != "Unknown" ]] && echo "CMS: $cms" >> "$OUTPUT"
                
                # Framework detection
                local frameworks=""
                if echo "$response" | grep -q "react"; then
                    frameworks="$frameworks React"
                fi
                if echo "$response" | grep -q "angular"; then
                    frameworks="$frameworks Angular"
                fi
                if echo "$response" | grep -q "vue"; then
                    frameworks="$frameworks Vue.js"
                fi
                [[ -n "$frameworks" ]] && echo "Framework:$frameworks" >> "$OUTPUT"
                
                # WAF Detection
                local waf="None"
                if echo "$headers" | grep -iq "cloudflare"; then
                    waf="Cloudflare"
                elif echo "$headers" | grep -iq "aws"; then
                    waf="AWS WAF"
                elif echo "$headers" | grep -iq "akamai"; then
                    waf="Akamai"
                fi
                [[ "$waf" != "None" ]] && echo "WAF: $waf" >> "$OUTPUT"
                
                # SSL/TLS info (for HTTPS)
                if [[ "$proto" == "https" ]]; then
                    local ssl_info=$(echo | openssl s_client -connect "${host}:443" -servername "$host" 2>/dev/null | grep "subject=\|issuer=" || echo "")
                    [[ -n "$ssl_info" ]] && echo "$ssl_info" >> "$OUTPUT"
                fi
                
                # Create JSON entry for compatibility
                echo "{\"host\":\"$host\",\"protocol\":\"$proto\",\"server\":\"$server\",\"cms\":\"$cms\",\"waf\":\"$waf\"}" >> "$JSON_OUTPUT"
                
                echo "" >> "$OUTPUT"
                break # Stop after first successful protocol
            done
            
        done < "$INPUT"
        
        echo ""
        success "Technology detection complete (bash method)"
    fi
    
    info "Results: tech_stack.txt, tech_stack.json"
}

# === PHASE 6: HTTP PROBING (OPTIONAL) ===
probe_http() {
    log "Phase 6: Probing HTTP services"
    
    if [[ ! -s "$OUTPUT_DIR/live_hosts.txt" ]]; then
        warn "No live hosts to probe"
        return
    fi
    
    if command -v httpx >/dev/null; then
        httpx -list "$OUTPUT_DIR/live_hosts.txt" -silent -title -status-code -timeout 10 \
            -o "$OUTPUT_DIR/http_services.txt" 2>/dev/null || true
        success "HTTP probe complete → http_services.txt"
    else
        warn "httpx not found — skipping HTTP probe (technology detection covers this)"
    fi
}

# === ADDITIONAL SCANNING (FULL MODE) ===
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
    local unique_ips=$(grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" "$OUTPUT_DIR/dns_resolved.txt" 2>/dev/null | sort -u | wc -l || echo 0)
    local hosts_with_ports=$(grep -c ":" "$OUTPUT_DIR/port_scan.txt" 2>/dev/null || echo 0)
    local runtime=$(( $(date +%s) - START_TIME ))
    
    # Parse tech data
    local tech_summary=""
    if [[ -f "$OUTPUT_DIR/tech_stack.txt" ]]; then
        tech_summary=$(grep -E "CMS:|Server:|Framework:|WAF:" "$OUTPUT_DIR/tech_stack.txt" | sort | uniq -c | sort -rn || echo "")
    fi
    
    cat > "$OUTPUT_DIR/report.html" <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
HTMLEOF

    cat >> "$OUTPUT_DIR/report.html" <<EOF
    <title>Recon Report • $TARGET</title>
EOF

    cat >> "$OUTPUT_DIR/report.html" <<'HTMLEOF'
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        * { box-sizing: border-box; }
        body { 
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%); 
            color: #00ff00; 
            font-family: 'Courier New', monospace; 
            padding: 20px; 
            margin: 0;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { 
            color: #00ff00; 
            border-bottom: 3px solid #00ff00; 
            padding-bottom: 15px; 
            text-shadow: 0 0 10px #00ff00;
        }
        h2 { color: #00ffff; margin-top: 30px; }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 20px 0; 
        }
        .stat-card { 
            background: rgba(26, 26, 46, 0.8); 
            padding: 20px; 
            border-radius: 10px; 
            border: 1px solid #00ff00;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.2);
        }
        .stat-label { color: #888; font-size: 14px; margin-bottom: 10px; }
        .stat-value { color: #00ff00; font-size: 32px; font-weight: bold; }
        .section { 
            background: rgba(26, 26, 46, 0.6); 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 10px; 
            border-left: 4px solid #00ffff;
        }
        .host-list, .tech-list { 
            max-height: 400px; 
            overflow-y: auto; 
            background: rgba(0, 0, 0, 0.3);
            padding: 10px;
            border-radius: 5px;
        }
        .host, .tech-item { 
            padding: 8px; 
            border-bottom: 1px solid #333; 
            font-size: 14px;
        }
        .host:hover, .tech-item:hover { background: rgba(0, 255, 0, 0.1); }
        .ip-group { 
            background: rgba(0, 100, 100, 0.2); 
            margin: 10px 0; 
            padding: 10px; 
            border-radius: 5px;
            border-left: 3px solid #00ffff;
        }
        .ip-header { color: #00ffff; font-weight: bold; margin-bottom: 5px; }
        .port-info { color: #ffaa00; margin-left: 20px; }
        button { 
            background: linear-gradient(135deg, #003300, #006600); 
            color: #00ff00; 
            border: 2px solid #00ff00; 
            padding: 12px 24px; 
            border-radius: 6px; 
            cursor: pointer; 
            margin: 5px; 
            font-family: 'Courier New', monospace;
            font-weight: bold;
            transition: all 0.3s;
        }
        button:hover { 
            background: linear-gradient(135deg, #006600, #009900);
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.5);
            transform: translateY(-2px);
        }
        .badge { 
            display: inline-block; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-size: 12px; 
            margin: 2px;
        }
        .badge-high { background: #ff4444; color: white; }
        .badge-medium { background: #ffaa00; color: black; }
        .badge-low { background: #44ff44; color: black; }
        .badge-info { background: #4444ff; color: white; }
        ::-webkit-scrollbar { width: 10px; }
        ::-webkit-scrollbar-track { background: #1a1a2e; }
        ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
HTMLEOF

    cat >> "$OUTPUT_DIR/report.html" <<EOF
        <h1>🔍 Advanced Recon Report: $TARGET</h1>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Subdomains Discovered</div>
                <div class="stat-value">$sub_count</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Live Hosts Validated</div>
                <div class="stat-value">$live_count</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique IP Addresses</div>
                <div class="stat-value">$unique_ips</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Hosts with Open Ports</div>
                <div class="stat-value">$hosts_with_ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Scan Runtime</div>
                <div class="stat-value">${runtime}s</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🌐 Live Hosts (Top $MAX_SAVE)</h2>
            <div class="host-list">
EOF
    
    # Add live hosts
    if [[ -f "$OUTPUT_DIR/live_hosts.txt" ]]; then
        while IFS= read -r host; do
            echo "                <div class=\"host\">✓ $host</div>" >> "$OUTPUT_DIR/report.html"
        done < "$OUTPUT_DIR/live_hosts.txt"
    fi
    
    cat >> "$OUTPUT_DIR/report.html" <<'HTMLEOF'
            </div>
        </div>
        
        <div class="section">
            <h2>🗺️ IP Address Mapping</h2>
HTMLEOF
    
    # Add IP groups
    if [[ -f "$OUTPUT_DIR/ip_groups.txt" ]]; then
        awk '
        /^=== IP:/ {
            if (ip != "") print "            </div>"
            ip = $0
            gsub(/=== IP: /, "", ip)
            gsub(/ ===/, "", ip)
            print "            <div class=\"ip-group\">"
            print "                <div class=\"ip-header\">" ip "</div>"
            next
        }
        /^  - / {
            gsub(/^  - /, "")
            print "                <div class=\"host\">→ " $0 "</div>"
        }
        END {
            if (ip != "") print "            </div>"
        }
        ' "$OUTPUT_DIR/ip_groups.txt" >> "$OUTPUT_DIR/report.html"
    fi
    
    cat >> "$OUTPUT_DIR/report.html" <<'HTMLEOF'
        </div>
        
        <div class="section">
            <h2>🔌 Port Scan Results</h2>
HTMLEOF
    
    # Add port scan results
    if [[ -f "$OUTPUT_DIR/port_scan.txt" && -s "$OUTPUT_DIR/port_scan.txt" ]]; then
        echo "            <div class=\"host-list\">" >> "$OUTPUT_DIR/report.html"
        awk '
        /^[a-zA-Z]/ && /:/ {
            split($0, parts, ":")
            host = parts[1]
            ports = parts[2]
            print "                <div class=\"host\"><strong>" host "</strong>"
            next
        }
        /^  [0-9]/ {
            gsub(/^  /, "")
            print "                    <span class=\"port-info\">• " $0 "</span><br>"
        }
        /^$/ {
            print "                </div>"
        }
        ' "$OUTPUT_DIR/port_scan.txt" >> "$OUTPUT_DIR/report.html"
        echo "            </div>" >> "$OUTPUT_DIR/report.html"
    else
        echo "            <p>No open ports detected or scan was skipped.</p>" >> "$OUTPUT_DIR/report.html"
    fi
    
    cat >> "$OUTPUT_DIR/report.html" <<'HTMLEOF'
        </div>
        
        <div class="section">
            <h2>🔧 Technology Stack Detection</h2>
HTMLEOF
    
    # Add technology detection summary
    if [[ -f "$OUTPUT_DIR/tech_stack.txt" && -s "$OUTPUT_DIR/tech_stack.txt" ]]; then
        echo "            <div class=\"tech-list\">" >> "$OUTPUT_DIR/report.html"
        
        # Count technologies
        local cms_count=$(grep -c "CMS:" "$OUTPUT_DIR/tech_stack.txt" 2>/dev/null || echo 0)
        local server_count=$(grep -c "Server:" "$OUTPUT_DIR/tech_stack.txt" 2>/dev/null || echo 0)
        local waf_count=$(grep -c "WAF:" "$OUTPUT_DIR/tech_stack.txt" 2>/dev/null || echo 0)
        
        cat >> "$OUTPUT_DIR/report.html" <<EOF
                <div style='margin-bottom: 20px;'>
                    <span class='badge badge-info'>CMS Detected: $cms_count</span>
                    <span class='badge badge-info'>Servers: $server_count</span>
                    <span class='badge badge-medium'>WAF Protected: $waf_count</span>
                </div>
EOF
        
        # Show tech summary
        if [[ -n "$tech_summary" ]]; then
            cat >> "$OUTPUT_DIR/report.html" <<EOF
                <h3 style='color: #00ffff;'>Technology Summary:</h3>
                <pre style='color: #00ff00; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px;'>$tech_summary</pre>
EOF
        fi
        
        # Show detailed results
        echo "                <h3 style='color: #00ffff;'>Detailed Results:</h3>" >> "$OUTPUT_DIR/report.html"
        awk '
        /^=== / {
            if (block != "") print "                </div>"
            gsub(/^=== /, "")
            gsub(/ ===$/, "")
            print "                <div class=\"tech-item\">"
            print "                    <strong style=\"color: #00ffff;\">" $0 "</strong><br>"
            block = $0
            next
        }
        /^[A-Z]/ {
            print "                    <span style=\"color: #ffaa00;\">• " $0 "</span><br>"
        }
        END {
            if (block != "") print "                </div>"
        }
        ' "$OUTPUT_DIR/tech_stack.txt" >> "$OUTPUT_DIR/report.html"
        echo "            </div>" >> "$OUTPUT_DIR/report.html"
    else
        echo "            <p>Technology detection not available.</p>" >> "$OUTPUT_DIR/report.html"
    fi
    
    cat >> "$OUTPUT_DIR/report.html" <<EOF
        </div>
        
        <div class="section">
            <h2>📁 Output Files</h2>
            <ul style="color: #00ff00; line-height: 1.8;">
                <li><strong>subdomains.txt</strong> - All discovered subdomains ($sub_count total)</li>
                <li><strong>live_hosts.txt</strong> - Validated live hosts ($live_count total)</li>
                <li><strong>dns_resolved.txt</strong> - DNS resolution results</li>
                <li><strong>ip_groups.txt</strong> - Hosts grouped by IP address</li>
                <li><strong>ip_details.json</strong> - IP metadata (cloud providers, organizations)</li>
                <li><strong>port_scan.txt</strong> - Open ports and services</li>
                <li><strong>tech_stack.txt</strong> - Technology detection results</li>
                <li><strong>tech_stack.json</strong> - Technology data in JSON format</li>
                <li><strong>http_services.txt</strong> - HTTP probe results (if httpx available)</li>
            </ul>
        </div>
        
        <div style="text-align: center; margin-top: 30px;">
            <button onclick="navigator.clipboard.writeText(location.href)">📋 Copy Report Link</button>
            <button onclick="window.print()">🖨️ Print Report</button>
            <button onclick="window.location.reload()">🔄 Refresh</button>
        </div>
        
        <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
            Generated by recon-validator v$VERSION • Runtime: ${runtime}s
        </div>
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
        --skip-ports) SKIP_PORTS=true; shift;;
        --tcp-validate) TCP_VALIDATE=true; shift;;
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
cat << "BANNER"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗             ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║             ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║             ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║             ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║             ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝             ║
║                                                           ║
║   Advanced Subdomain Recon & Validation Framework         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

log "Target: ${WHITE}$TARGET${NC}"
log "Mode: ${WHITE}$MODE${NC}"
log "Max live hosts: ${WHITE}$MAX_SAVE${NC}"
if [[ "$TCP_VALIDATE" == true ]]; then
    log "Validation method: ${WHITE}TCP (web ports)${NC}"
else
    log "Validation method: ${WHITE}ICMP (ping)${NC}"
fi
log "Output: ${WHITE}$OUTPUT_DIR${NC}"
echo ""

# Execute workflow
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
passive_subs
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
validate_live_hosts
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
resolve_dns
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
scan_ports
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
detect_technologies
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Optional HTTP probe
probe_http

# Additional scans in full mode
if [[ "$MODE" == "full" ]]; then
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    urls_endpoints
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    nuclei_scan
fi

# Generate final report
echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
generate_report

# Final summary
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                ║${NC}"
echo -e "${GREEN}║           🎉 Scan Complete! ✓                 ║${NC}"
echo -e "${GREEN}║                                                ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo ""
success "Results saved to: ${WHITE}$OUTPUT_DIR${NC}"
success "Total runtime: ${WHITE}$(( $(date +%s) - START_TIME )) seconds${NC}"
echo ""
echo -e "${CYAN}📊 Quick Stats:${NC}"
echo -e "   ${YELLOW}•${NC} Subdomains: ${WHITE}$(wc -l < "$OUTPUT_DIR/subdomains.txt" 2>/dev/null || echo 0)${NC}"
echo -e "   ${YELLOW}•${NC} Live Hosts: ${WHITE}$(wc -l < "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || echo 0)${NC}"
echo -e "   ${YELLOW}•${NC} Unique IPs: ${WHITE}$(grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" "$OUTPUT_DIR/dns_resolved.txt" 2>/dev/null | sort -u | wc -l || echo 0)${NC}"
echo -e "   ${YELLOW}•${NC} Open Ports: ${WHITE}$(grep -c ":" "$OUTPUT_DIR/port_scan.txt" 2>/dev/null || echo 0) hosts${NC}"
echo ""
echo -e "${BLUE}💡 Tip: Open ${WHITE}report.html${BLUE} for visual analysis${NC}"
echo ""
