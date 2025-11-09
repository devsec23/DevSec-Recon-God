#!/bin/bash
# DevRecon.sh v2.0 - Fixed + Full Recon + Help + Auto-Install
# Author: DevSec Pro | 2025

set -euo pipefail

# Colors
G="\033[0;32m"; R="\033[0;31m"; Y="\033[1;33m"; C="\033[0;36m"; N="\033[0m"
msg() { echo -e "${2:-$G}[DevRecon] $1$N"; }

# Help
usage() {
    cat <<'EOF'

DevRecon.sh v2.0 - Ultimate Recon Tool

Usage:
  ./DevRecon.sh -d <domain>        → Full recon
  ./DevRecon.sh -d <domain> -a     → All (same as above)
  ./DevRecon.sh -d <domain> -s     → Subdomains only
  ./DevRecon.sh -d <domain> -l     → Live URLs only
  ./DevRecon.sh -d <domain> -p     → Ports + OS + Vulns
  ./DevRecon.sh -f <file> -n       → Nuclei on file
  ./DevRecon.sh -h                 → Show this help

Examples:
  ./DevRecon.sh -d tesla.com
  ./DevRecon.sh -d tesla.com -p
  ./DevRecon.sh -f live.txt -n

EOF
    exit 0
}

# Auto-Install Tools
install() {
    [[ -z "$(command -v $1)" ]] && {
        msg "Installing $1..." "$Y"
        if [[ "$1" == "nuclei" || "$1" == "httpx" || "$1" == "naabu" ]]; then
            go install "$2" 2>/dev/null || true
        elif [[ "$1" == "paramspider" ]]; then
            pip install paramspider 2>/dev/null || true
        fi
    }
}

install httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
install nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
install paramspider paramspider
nuclei -update-templates &>/dev/null || true

# Parse Args
DOMAIN=""; FILE=""; MODE="full"
while [[ $# -gt 0 ]]; do
    case $1 in
        -d) DOMAIN="$2"; shift ;;
        -f) FILE="$2"; shift ;;
        -a) MODE="full" ;;
        -s) MODE="subs" ;;
        -l) MODE="live" ;;
        -p) MODE="ports" ;;
        -n) MODE="nuclei" ;;
        -h) usage ;;
        *) msg "Invalid option: $1" "$R"; usage ;;
    esac
    shift
done

[[ -z "$DOMAIN" && -z "$FILE" ]] && { msg "Error: Use -d domain.com or -f file.txt" "$R"; usage; }

WORKDIR="$HOME/DevRecon-$DOMAIN-$(date +%s)"
[[ -n "$FILE" ]] && WORKDIR="$HOME/DevRecon-file-$(date +%s)"
mkdir -p "$WORKDIR" && cd "$WORKDIR"

# === MODES ===
case "$MODE" in
    "file")
        [[ ! -f "$FILE" ]] && { msg "File not found: $FILE" "$R"; exit 1; }
        msg "Nuclei on $FILE..."
        nuclei -l "$FILE" -severity critical,high,medium,low -o vulns.txt -c 200
        msg "Done! Vulns: $(wc -l < vulns.txt)"
        ;;
    "subs")
        msg "Subdomains for $DOMAIN..."
        {
            subfinder -d "$DOMAIN" -silent 2>/dev/null || true
            amass enum -passive -d "$DOMAIN" 2>/dev/null | grep -oE "[a-zA-Z0-9.-]+\.$DOMAIN" || true
            assetfinder --subs-only "$DOMAIN" 2>/dev/null || true
        } | sort -u > subs.txt
        msg "Found $(wc -l < subs.txt) → subs.txt"
        ;;
    "live")
        [[ ! -s subs.txt ]] && ./DevRecon.sh -d "$DOMAIN" -s
        msg "Live Probing..."
        sed 's/^/https:\/\//' subs.txt | httpx -silent -sc -title > live.txt
        grep -E "200|301|302" live.txt | awk '{print $1}' > live_urls.txt
        msg "Live: $(wc -l < live_urls.txt) → live_urls.txt"
        ;;
    "ports")
        [[ ! -s subs.txt ]] && ./DevRecon.sh -d "$DOMAIN" -s
        msg "Port Scanning + OS + Services..."
        naabu -list subs.txt -p 1-1000 -o ports/open.txt
        nmap -iL ports/open.txt -sV -O --script vuln -oN ports/nmap.txt -oX ports/nmap.xml
        msg "Ports: $(wc -l < ports/open.txt)"
        ;;
    "nuclei")
        [[ ! -s live_urls.txt ]] && ./DevRecon.sh -d "$DOMAIN" -l
        msg "Nuclei FULL Scan (All Severities)..."
        nuclei -l live_urls.txt -severity critical,high,medium,low -o vulns.txt -c 200
        msg "Vulns: $(wc -l < vulns.txt)"
        ;;
    "full")
        msg "FULL RECON MODE: $DOMAIN"
        ./DevRecon.sh -d "$DOMAIN" -s
        ./DevRecon.sh -d "$DOMAIN" -l
        ./DevRecon.sh -d "$DOMAIN" -p
        ./DevRecon.sh -d "$DOMAIN" -n
        ;;
esac

# Final Report
cat > REPORT.txt <<EOF
=== DevRecon v2.0 Report ===
Target: $DOMAIN
Date: $(date)
Subdomains: $(wc -l < subs.txt 2>/dev/null || echo 0)
Live URLs: $(wc -l < live_urls.txt 2>/dev/null || echo 0)
Open Ports: $(wc -l < ports/open.txt 2>/dev/null || echo 0)
Vulnerabilities: $(wc -l < vulns.txt 2>/dev/null || echo 0)
EOF

msg "DONE! Report: $WORKDIR/REPORT.txt" "$G"
