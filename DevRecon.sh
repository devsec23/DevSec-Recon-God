#!/bin/bash
# DevRecon.sh v5.1 - Fixed Report + Safe File Check
# Author: DevSec Pro | 2025

set -euo pipefail

G="\033[0;32m"; R="\033[0;31m"; Y="\033[1;33m"; C="\033[0;36m"; B="\033[0;34m"; N="\033[0m"
msg() { echo -e "${2:-$G}[DevRecon v5.1] $1$N"; }

loading() {
    local msg="$1"
    local pid=$!
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 10 ))
        printf "\r${Y}[Loading] ${spin:$i:1} $msg...${N}"
        sleep 0.1
    done
    printf "\r${G}[Success] $msg Done!${N}\n"
}

export PATH="$PATH:$(go env GOPATH)/bin"

install_tool() {
    local name=$1 cmd=$2 repo=$3
    if ! command -v "$cmd" &>/dev/null; then
        msg "Installing $name..." "$Y"
        (go install "$repo"@latest 2>/dev/null || pip install "$name" 2>/dev/null || true) & loading "Installing $name"
    else
        msg "$name is ready" "$C"
    fi
}

install_tool "httpx" "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_tool "nuclei" "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_tool "naabu" "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install_tool "gf" "gf" "github.com/tomnomnom/gf"
install_tool "ParamSpider" "paramspider" "paramspider"
nuclei -update-templates &>/dev/null && msg "Nuclei templates updated" "$C"

usage() {
    cat <<'EOF'

DevRecon.sh v5.1 - Ultimate Recon Tool (English)

Usage:
  ./DevRecon.sh -d <domain>           → Full Recon
  ./DevRecon.sh -d <domain> -a        → All
  ./DevRecon.sh -d <domain> -s        → Subdomains only
  ./DevRecon.sh -d <domain> -l        → Live URLs only
  ./DevRecon.sh -d <domain> -p        → Parameters only
  ./DevRecon.sh -d <domain> -b        → Ports + OS + Vulns
  ./DevRecon.sh -f <file> -n          → Nuclei on file
  ./DevRecon.sh -h                    → Help

Examples:
  ./DevRecon.sh -d tesla.com
  ./DevRecon.sh -d tesla.com -s
  ./DevRecon.sh -f live.txt -n

EOF
    exit 0
}

DOMAIN=""; FILE=""; MODE="full"
while [[ $# -gt 0 ]]; do
    case $1 in
        -d) DOMAIN="$2"; shift ;;
        -f) FILE="$2"; shift ;;
        -a) MODE="full" ;;
        -s) MODE="subs" ;;
        -l) MODE="live" ;;
        -p) MODE="params" ;;
        -b) MODE="ports" ;;
        -n) MODE="nuclei" ;;
        -h) usage ;;
        *) msg "Invalid option: $1" "$R"; usage ;;
    esac
    shift
done

[[ -z "$DOMAIN" && -z "$FILE" ]] && { msg "Use -d domain.com or -f file.txt" "$R"; usage; }

WORKDIR="$HOME/DevRecon-$DOMAIN-$(date +%s)"
[[ -n "$FILE" ]] && WORKDIR="$HOME/DevRecon-file-$(date +%s)"
mkdir -p "$WORKDIR"/{subs,live,urls,params,ports,vulns} && cd "$WORKDIR"

msg "Starting recon on $DOMAIN..." "$B"

# Subdomains
if [[ "$MODE" =~ subs|full ]]; then
    msg "Enumerating subdomains..." "$C"
    (
        subfinder -d "$DOMAIN" -silent -o subs.txt
        amass enum -passive -d "$DOMAIN" 2>/dev/null | grep -oE "[a-zA-Z0-9.-]+\.$DOMAIN" >> subs.txt
        assetfinder --subs-only "$DOMAIN" >> subs.txt
        sort -u subs.txt -o subs.txt
    ) & loading "Subdomains"
    msg "Found $(wc -l < subs.txt) subdomains → subs.txt" "$G"
fi

# Live URLs
if [[ "$MODE" =~ live|full ]]; then
    [[ ! -s subs.txt ]] && { msg "No subdomains to probe. Run -s first." "$R"; exit 1; }
    msg "Probing live hosts..." "$C"
    (
        httpx -l subs.txt -silent -sc -title -o live.txt
        grep -E "200|301|302" live.txt | cut -d' ' -f1 > live_urls.txt
    ) & loading "Live Probing"
    msg "Live URLs: $(wc -l < live_urls.txt) → live_urls.txt" "$G"
fi

# Parameters
if [[ "$MODE" =~ params|full ]]; then
    [[ ! -s live_urls.txt ]] && { msg "No live URLs. Run -l first." "$R"; exit 1; }
    msg "Hunting parameters..." "$Y"
    (
        gf xss live_urls.txt > params/xss.txt
        gf sqli live_urls.txt > params/sqli.txt
        gf lfi live_urls.txt > params/lfi.txt
        head -50 live_urls.txt > top50.txt
        paramspider -l top50.txt -o params/paramspider.txt --quiet
    ) & loading "Parameter Extraction"
    TOTAL_PARAMS=$(find params -type f -name "*.txt" -exec wc -l {} + 2>/dev/null | awk 'END{print $1}' || echo 0)
    msg "Parameters found: $TOTAL_PARAMS" "$G"
fi

# Ports + OS
if [[ "$MODE" =~ ports|full ]]; then
    [[ ! -s subs.txt ]] && { msg "No subdomains. Run -s first." "$R"; exit 1; }
    msg "Scanning ports & OS..." "$R"
    (
        naabu -list subs.txt -p 1-1000 -o ports/open.txt
        nmap -iL ports/open.txt -sV -O --script vuln -oN ports/nmap.txt -oX ports/nmap.xml 2>/dev/null || true
    ) & loading "Port & OS Scan"
    msg "Open ports: $(wc -l < ports/open.txt 2>/dev/null || echo 0)" "$G"
fi

# Nuclei
if [[ "$MODE" =~ nuclei|full ]]; then
    INPUT="live_urls.txt"
    [[ -n "$FILE" ]] && INPUT="$FILE"
    [[ ! -s "$INPUT" ]] && { msg "No URLs to scan. Run -l or provide -f" "$R"; exit 1; }
    msg "Running Nuclei (All Severities)..." "$R"
    (
        nuclei -l "$INPUT" -severity critical,high,medium,low -o vulns.txt -silent -c 100
    ) & loading "Vulnerability Scan"
    msg "Vulnerabilities: $(wc -l < vulns.txt 2>/dev/null || echo 0)" "$G"
fi

# Final Report (Safe Check)
cat > REPORT.txt <<EOF
=== DevRecon v5.1 Report ===
Target: $DOMAIN
Date: $(date)
$( [[ -s subs.txt ]] && echo "Subdomains: $(wc -l < subs.txt)" || echo "Subdomains: 0" )
$( [[ -s live_urls.txt ]] && echo "Live URLs: $(wc -l < live_urls.txt)" || echo "Live URLs: 0" )
$( [[ -d params ]] && find params -type f -name "*.txt" -exec wc -l {} + 2>/dev/null | awk 'END{print "Parameters: " $1}' || echo "Parameters: 0" )
$( [[ -s ports/open.txt ]] && echo "Open Ports: $(wc -l < ports/open.txt)" || echo "Open Ports: 0" )
$( [[ -s vulns.txt ]] && echo "Vulnerabilities: $(wc -l < vulns.txt)" || echo "Vulnerabilities: 0" )
Generated by DevRecon v5.1
EOF

msg "MISSION COMPLETE! Report: $WORKDIR/REPORT.txt" "$B"
