#!/bin/bash
# DevRecon.sh v8.0 - FULL RECON + -f file.txt -n + -f file.txt -l
# Author: DevSec Pro | 2025

set -euo pipefail

G="\033[0;32m"; R="\033[0;31m"; Y="\033[1;33m"; C="\033[0;36m"; B="\033[0;34m"; N="\033[0m"
msg() { echo -e "${2:-$G}[DevRecon v8.0] $1$N"; }

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
install_tool "gf" "gf" "github.com/tomnomtom/gf"
install_tool "paramspider" "paramspider" "paramspider"
install_tool "gowitness" "gowitness" "github.com/sensepost/gowitness@latest"
nuclei -update-templates &>/dev/null && msg "Nuclei templates updated" "$C"

# === ARG PARSING ===
DOMAIN=""; INPUT_FILE=""; DO_SUBS=false; DO_LIVE=false; DO_PARAMS=false; DO_PORTS=false; DO_NUCLEI=false; DO_FULL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -d) DOMAIN="$2"; shift ;;
        -f) INPUT_FILE="$2"; shift ;;
        -s) DO_SUBS=true ;;
        -l) DO_LIVE=true ;;
        -p) DO_PARAMS=true ;;
        -b) DO_PORTS=true ;;
        -n) DO_NUCLEI=true ;;
        -a) DO_FULL=true ;;
        -h) 
            cat <<'EOF'

DevRecon.sh v8.0 - GOD MODE RECON

Usage:
  ./DevRecon.sh -d domain.com -a              → Full Recon
  ./DevRecon.sh -d domain.com -s -l           → Subdomains + Live
  ./DevRecon.sh -f subs.txt -l                → Live from file
  ./DevRecon.sh -f urls.txt -n                → Nuclei on file
  ./DevRecon.sh -d domain.com -p              → Parameters
  ./DevRecon.sh -d domain.com -b              → Ports + OS
  ./DevRecon.sh -h                            → Help

Examples:
  ./DevRecon.sh -f ~/live_urls.txt -n
  ./DevRecon.sh -f ~/subs.txt -l

EOF
            exit 0 ;;
        *) msg "Invalid option: $1" "$R"; exit 1 ;;
    esac
    shift
done

# === WORKDIR & INPUT ===
if [[ -n "$INPUT_FILE" && -f "$INPUT_FILE" ]]; then
    WORKDIR="$(pwd)/recon-from-file-$(date +%s)"
    mkdir -p "$WORKDIR"/{live,vulns,screenshots}
    cp "$INPUT_FILE" "$WORKDIR/input.txt"
    cd "$WORKDIR"
    msg "Using input file: $INPUT_FILE" "$C"
elif [[ -n "$DOMAIN" ]]; then
    WORKDIR="$HOME/DevRecon-$DOMAIN-$(date +%s)"
    mkdir -p "$WORKDIR"/{subs,live,urls,params,ports,vulns,screenshots} && cd "$WORKDIR"
else
    msg "Use -d domain.com or -f file.txt" "$R"; exit 1
fi

# === SUBDOMAINS ===
if $DO_SUBS || $DO_FULL; then
    [[ -z "$DOMAIN" ]] && { msg "Need -d domain for -s" "$R"; exit 1; }
    msg "Enumerating subdomains..." "$C"
    (
        subfinder -d "$DOMAIN" -silent -o subs.txt
        amass enum -passive -d "$DOMAIN" 2>/dev/null | grep -oE "[a-zA-Z0-9.-]+\.$DOMAIN" >> subs.txt
        assetfinder --subs-only "$DOMAIN" >> subs.txt
        sort -u subs.txt -o subs.txt
    ) & loading "Subdomains"
    msg "Found $(wc -l < subs.txt) subdomains" "$G"
fi

# === LIVE FROM FILE OR SUBS ===
if $DO_LIVE || $DO_FULL; then
    INPUT="subs.txt"
    [[ -f "input.txt" ]] && INPUT="input.txt"
    [[ ! -s "$INPUT" ]] && { msg "No input! Use -f or -s" "$R"; exit 1; }
    msg "Probing live hosts..." "$C"
    (
        httpx -l "$INPUT" -silent -sc -title -o live.txt
        grep -E "200|301|302" live.txt | cut -d' ' -f1 > live_urls.txt
    ) & loading "Live Probing"
    msg "Live URLs: $(wc -l < live_urls.txt)" "$G"
fi

# === NUCLEI ON FILE OR LIVE ===
if $DO_NUCLEI || $DO_FULL; then
    INPUT="live_urls.txt"
    [[ -f "input.txt" ]] && INPUT="input.txt"
    [[ ! -s "$INPUT" ]] && { msg "No URLs! Run -l or -f" "$R"; exit 1; }
    msg "Running Nuclei (All Severities)..." "$R"
    (
        nuclei -l "$INPUT" -severity critical,high,medium,low -o vulns.txt -silent -c 100
    ) & loading "Vulnerability Scan"
    msg "Vulnerabilities: $(wc -l < vulns.txt)" "$G"
fi

# === PARAMETERS, PORTS, SCREENSHOTS (Full Mode) ===
if $DO_FULL; then
    [[ -s live_urls.txt ]] && {
        msg "Hunting parameters..." "$Y"
        (
            gf xss live_urls.txt > params/xss.txt
            gf sqli live_urls.txt > params/sqli.txt
            paramspider -l <(head -50 live_urls.txt) -o params/paramspider.txt --quiet
        ) & loading "Parameters"
        msg "Parameters found"
        
        msg "Scanning ports..." "$R"
        naabu -list subs.txt -p 1-1000 -o ports/open.txt & loading "Ports"
        
        msg "Taking screenshots..." "$C"
        gowitness file -f live_urls.txt -P screenshots/ --threads 10 & loading "Screenshots"
    }
fi

# === HTML REPORT ===
cat > report.html <<EOF
<!DOCTYPE html>
<html><head><title>DevRecon v8.0 - $DOMAIN</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:#000;color:#0f0;font-family:monospace}</style></head>
<body class="p-5">
<div class="container text-center">
<h1 class="text-success">DEVRECON v8.0</h1>
<h2>$DOMAIN</h2>
<pre>Subdomains: $(wc -l < subs.txt 2>/dev/null || echo 0)</pre>
<pre>Live URLs: $(wc -l < live_urls.txt 2>/dev/null || echo 0)</pre>
<pre>Vulnerabilities: $(wc -l < vulns.txt 2>/dev/null || echo 0)</pre>
<p>Generated: $(date)</p>
</div></body></html>
EOF

msg "MISSION COMPLETE! Report: $WORKDIR/report.html" "$B"
