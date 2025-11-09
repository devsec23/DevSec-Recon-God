#!/bin/bash
# DevRecon v10.0 - FULL RECON TOOL (All Features + -f file -l -n + Cloud Shell Ready)
# Author: DevSec Pro | 2025

set -euo pipefail

G="\033[0;32m"; R="\033[0;31m"; Y="\033[1;33m"; C="\033[0;36m"; B="\033[0;34m"; N="\033[0m"
msg() { echo -e "${2:-$G}[DevRecon v10.0] $1$N"; }

loading() {
    local msg="$1"
    local pid=$!
    local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
    local i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 8 ))
        printf "\r${Y}[Loading] ${spin:$i:1} $msg...${N}"
        sleep 0.1
    done
    printf "\r${G}[Success] $msg Done!${N}\n"
}

# Fix PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# Force Reinstall httpx (Fix -l issue)
msg "Updating httpx..." "$Y"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest &>/dev/null || true
msg "httpx ready!" "$G"

# Install Tools
install() {
    local name=$1 cmd=$2 repo=$3
    if ! command -v "$cmd" &>/dev/null; then
        msg "Installing $name..." "$Y"
        (go install "$repo"@latest 2>/dev/null || pip install "$name" 2>/dev/null || true) & loading "$name"
    else
        msg "$name ready" "$C"
    fi
}

install "nuclei" "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install "naabu" "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install "subfinder" "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install "amass" "amass" "github.com/owasp-amass/amass/v4/..."
install "assetfinder" "assetfinder" "github.com/tomnomnom/assetfinder"
install "gf" "gf" "github.com/tomnomnom/gf"
install "paramspider" "paramspider" "paramspider"
install "gowitness" "gowitness" "github.com/sensepost/gowitness@latest"
nuclei -update-templates &>/dev/null && msg "Nuclei templates updated" "$C"

# === ARGUMENTS ===
DOMAIN=""; FILE=""; MODE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -d) DOMAIN="$2"; shift ;;
        -f) FILE="$2"; shift ;;
        -s) MODE+="subs " ;;
        -l) MODE+="live " ;;
        -p) MODE+="params " ;;
        -b) MODE+="ports " ;;
        -n) MODE+="nuclei " ;;
        -a) MODE="all" ;;
        -h) 
            cat <<'EOF'

DevRecon v10.0 - GOD MODE RECON

Usage:
  ./DevRecon.sh -d domain.com -a          → FULL RECON
  ./DevRecon.sh -d domain.com -s -l       → Subdomains + Live
  ./DevRecon.sh -f file.txt -l            → Live URLs from file
  ./DevRecon.sh -f file.txt -n            → Nuclei on file
  ./DevRecon.sh -d domain.com -p          → Parameters
  ./DevRecon.sh -d domain.com -b          → Ports + OS
  ./DevRecon.sh -h                        → Help

Examples:
  ./DevRecon.sh -d tesla.com -a
  ./DevRecon.sh -f subs.txt -l
  ./DevRecon.sh -f urls.txt -n

EOF
            exit 0 ;;
        *) msg "Invalid: $1" "$R"; exit 1 ;;
    esac
    shift
done

[[ -z "$DOMAIN" && -z "$FILE" ]] && { msg "Use -d domain or -f file.txt" "$R"; exit 1; }

# === WORKDIR ===
if [[ -n "$FILE" && -f "$FILE" ]]; then
    WORKDIR="$HOME/DevRecon-file-$(date +%s)"
    mkdir -p "$WORKDIR"/{live,vulns}
    cp "$FILE" "$WORKDIR/input.txt"
    cd "$WORKDIR"
    msg "Input file: $FILE" "$C"
else
    WORKDIR="$HOME/DevRecon-$DOMAIN-$(date +%s)"
    mkdir -p "$WORKDIR"/{subs,live,urls,params,ports,vulns,screenshots} && cd "$WORKDIR"
fi

# === SUBDOMAINS ===
if [[ "$MODE" == *"subs"* || "$MODE" == "all" ]]; then
    msg "Subdomain Enumeration..." "$C"
    (
        subfinder -d "$DOMAIN" -silent -o subs.txt
        amass enum -passive -d "$DOMAIN" 2>/dev/null | awk '{print $1}' >> subs.txt
        assetfinder --subs-only "$DOMAIN" >> subs.txt
        sort -u subs.txt -o subs.txt
    ) & loading "Subdomains"
    msg "Found $(wc -l < subs.txt) subdomains" "$G"
fi

# === LIVE URLs ===
if [[ "$MODE" == *"live"* || "$MODE" == "all" ]]; then
    INPUT="subs.txt"
    [[ -f "input.txt" ]] && INPUT="input.txt"
    [[ ! -s "$INPUT" ]] && { msg "No input!" "$R"; exit 1; }

    msg "Live Probing..." "$C"
    (
        httpx -list "$INPUT" -silent -sc -title -o live.txt
        grep -E "200|301|302" live.txt | cut -d' ' -f1 > live_urls.txt
    ) & loading "Live URLs"
    msg "Live: $(wc -l < live_urls.txt)" "$G"
fi

# === PARAMETERS ===
if [[ "$MODE" == *"params"* || "$MODE" == "all" ]]; then
    [[ ! -s live_urls.txt ]] && { msg "No live URLs!" "$R"; exit 1; }
    msg "Parameter Hunting..." "$Y"
    (
        gf xss live_urls.txt > params/xss.txt 2>/dev/null || true
        gf sqli live_urls.txt > params/sqli.txt 2>/dev/null || true
        head -50 live_urls.txt | paramspider -o params/paramspider.txt --quiet 2>/dev/null || true
    ) & loading "Parameters"
    msg "Parameters extracted" "$G"
fi

# === PORTS + OS ===
if [[ "$MODE" == *"ports"* || "$MODE" == "all" ]]; then
    [[ ! -s subs.txt ]] && { msg "No subs!" "$R"; exit 1; }
    msg "Port Scanning..." "$R"
    (
        naabu -list subs.txt -p 1-1000 -o ports/open.txt
        nmap -iL ports/open.txt -sV -O --script vuln -oN ports/nmap.txt 2>/dev/null || true
    ) & loading "Ports"
    msg "Open ports: $(wc -l < ports/open.txt 2>/dev/null || echo 0)" "$G"
fi

# === NUCLEI ===
if [[ "$MODE" == *"nuclei"* || "$MODE" == "all" ]]; then
    INPUT="live_urls.txt"
    [[ -f "input.txt" ]] && INPUT="input.txt"
    [[ ! -s "$INPUT" ]] && { msg "No URLs!" "$R"; exit 1; }

    msg "Vulnerability Scan..." "$R"
    (
        nuclei -l "$INPUT" -severity critical,high,medium,low -o vulns.txt -silent -c 100
    ) & loading "Nuclei"
    msg "Vulns: $(wc -l < vulns.txt 2>/dev/null || echo 0)" "$G"
fi

# === SCREENSHOTS ===
if [[ "$MODE" == "all" ]]; then
    [[ -s live_urls.txt ]] && {
        msg "Taking screenshots..." "$C"
        gowitness file -f live_urls.txt -P screenshots/ --threads 10 & loading "Screenshots"
    }
fi

# === HTML REPORT ===
cat > report.html <<EOF
<!DOCTYPE html>
<html><head><title>DevRecon v10.0 - $DOMAIN</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:#000;color:#0f0;font-family:monospace;padding:20px}</style></head>
<body>
<div class="container">
<h1 class="text-success">DEVRECON v10.0 REPORT</h1>
<h2>$DOMAIN</h2>
<pre>Subdomains : $(wc -l < subs.txt 2>/dev/null || echo 0)</pre>
<pre>Live URLs   : $(wc -l < live_urls.txt 2>/dev/null || echo 0)</pre>
<pre>Vulns      : $(wc -l < vulns.txt 2>/dev/null || echo 0)</pre>
<pre>Open Ports : $(wc -l < ports/open.txt 2>/dev/null || echo 0)</pre>
<p>Generated: $(date)</p>
</div></body></html>
EOF

msg "MISSION COMPLETE! Report: $WORKDIR/report.html" "$B"
echo -e "${B}Open: firefox $WORKDIR/report.html${N}"
