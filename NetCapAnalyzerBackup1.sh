#!/bin/bash

# =============================================================================
# Enhanced Network Traffic Capture and Analysis Script - macOS Edition
# Version 4.0 - macOS M1 Compatible with C2/Malware Detection
# Merged with C2 Hunter v5.0 - Fileless Malware & C2 Abuse Detection
# =============================================================================

set -u  # Exit on undefined vars

# Initialize arrays to avoid unbound variable errors (from Fileless.sh)
DISCOVERED_INTERFACES=()

# Color codes (merged - includes additional colors from Fileless.sh)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration (original)
CAPTURE_DURATION=${1:-1000}
PCAP_FILE="/tmp/traffic_$(date +%Y%m%d_%H%M%S).pcap"
REPORT_DIR="/tmp/network_analysis_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/tmp/netcap_$(date +%Y%m%d_%H%M%S).log"
TCPDUMP_PIDS=""

# Additional configuration from Fileless.sh
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DESKTOP_DIR="$HOME/Desktop"
FILELESS_PCAP_FILE="$DESKTOP_DIR/PCAP_FILE_${TIMESTAMP}.pcap"
RAW_PCAP_FILE="$DESKTOP_DIR/RAW_PCAP_FILE_${TIMESTAMP}.pcap"
MONITOR_PCAP_FILE="$DESKTOP_DIR/MONITOR_PCAP_FILE_${TIMESTAMP}.pcap"
FILELESS_REPORT_DIR="$DESKTOP_DIR/REPORT_DIR_${TIMESTAMP}"
FILELESS_LOG_FILE="$DESKTOP_DIR/LOG_FILE_${TIMESTAMP}.log"
TCPDUMP_PIDS_ARRAY=()
MONITOR_INTERFACES=()
ORIGINAL_INTERFACE_STATES=()

# Capture settings - NO LIMITS (from Fileless.sh)
SNAPLEN=65535          # Maximum packet size (0 not supported on all platforms)
BUFFER_SIZE=256        # MB - maximum ring buffer
PACKET_COUNT=0         # 0 = unlimited packets
PROMISC_MODE=1         # Enable promiscuous mode

# =============================================================================
# COMPREHENSIVE C2/MALICIOUS NETWORK INDICATORS (from Fileless.sh)
# Sources: MITRE ATT&CK, Cobalt Strike docs, Metasploit, Sliver, Empire,
#          SANS, Picus Security Red Report 2024, threat intelligence feeds
# Last Updated: 2025-12-02
# =============================================================================

# -----------------------------------------------------------------------------
# DNS-over-HTTPS (DoH) Resolvers - Legitimate but often abused by malware
# These are commonly used by malware to bypass DNS monitoring/filtering
# Sources: Cloudflare, Google, Quad9, OpenDNS, CleanBrowsing, Comodo, AdGuard,
#          NextDNS, Control D, Mullvad
# -----------------------------------------------------------------------------
DOH_SERVERS=(
    # Cloudflare
    "1.1.1.1" "1.0.0.1" "1.1.1.2" "1.0.0.2" "1.1.1.3" "1.0.0.3"
    # Google
    "8.8.8.8" "8.8.4.4"
    # Quad9
    "9.9.9.9" "149.112.112.112" "9.9.9.10" "149.112.112.10"
    # OpenDNS
    "208.67.222.222" "208.67.220.220" "208.67.222.123" "208.67.220.123"
    # CleanBrowsing
    "185.228.168.168" "185.228.169.168" "185.228.168.9" "185.228.169.9"
    # Comodo Secure DNS
    "8.26.56.26" "8.20.247.20"
    # AdGuard
    "94.140.14.14" "94.140.15.15" "94.140.14.15" "94.140.15.16"
    # NextDNS
    "45.90.28.0" "45.90.30.0"
    # Control D
    "76.76.2.0" "76.76.10.0" "76.76.19.19"
    # Mullvad
    "194.242.2.2" "193.19.108.2"
    # LibreDNS
    "116.202.176.26"
    # DNS.SB
    "185.222.222.222" "45.11.45.11"
)

# -----------------------------------------------------------------------------
# SUSPICIOUS PORTS - Classic Backdoor/RAT/Trojan Ports
# Sources: MITRE ATT&CK T1571, historical malware analysis, SANS
# -----------------------------------------------------------------------------
SUSPICIOUS_PORTS=(
    # Classic backdoor ports
    4444        # Metasploit default, DarkVishnya
    4445        # DarkVishnya alternate
    5555        # Android ADB exploitation, various RATs
    6666        # DarkComet, various trojans
    7777        # Various backdoors
    8888        # Sliver C2 default (mTLS/TCP)
    9999        # Various RATs
    1337        # "Elite" backdoor port
    31337       # "Elite" - Back Orifice, DarkVishnya
    12345       # NetBus trojan
    54321       # Back Orifice 2000
    
    # IRC-based botnets
    6667        # IRC default
    6668        # IRC alternate
    6669        # IRC alternate
    6697        # IRC over TLS
    
    # Tor network
    9001        # Tor ORPort
    9030        # Tor DirPort
    9050        # Tor SOCKS proxy
    9051        # Tor control port
    9150        # Tor Browser SOCKS
    
    # XMPP/Jabber (used by some C2)
    5222        # XMPP client
    5223        # XMPP client TLS
    5269        # XMPP server-to-server
    5280        # XMPP BOSH
    5281        # XMPP BOSH TLS
    
    # Additional known malware ports (MITRE ATT&CK documented)
    1058        # Bankshot HTTP
    1224        # BeaverTail
    1244        # BeaverTail alternate
    7080        # Emotet
    14146       # APT32 HTTP
    46769       # GravityRAT HTTP
    33666       # GoldenSpy WebSocket
    50000       # Emotet
    
    # Classic RAT ports
    1981        # Shockwave
    2001        # Trojan Cow
    2023        # Ripper Pro
    2140        # Deep Throat
    3150        # Deep Throat
    3700        # Portal of Doom
    5400        # Back Construction
    5401        # Back Construction
    5402        # Back Construction
    5569        # Robo-Hack
    6670        # DeepThroat
    6771        # DeepThroat
    6969        # GateCrasher, Priority
    10067       # Portal of Doom
    10167       # Portal of Doom
    11000       # Senna Spy
    11223       # Progenic Trojan
    12223       # Hack99 KeyLogger
    12346       # NetBus
    20034       # NetBus Pro
    21544       # GirlFriend
    22222       # Prosiak
    27374       # SubSeven
    27444       # Trinoo
    27665       # Trinoo
    29891       # The Unexplained
    30100       # NetSphere
    30129       # Masters Paradise
    30303       # Socket de Troie
    30999       # Kuang2
    31338       # Back Orifice, DeepBO
    31339       # NetSpy DK
    33333       # Prosiak
    33911       # Spirit 2001
    34324       # BigGluck
    40412       # The Spy
    40421       # Masters Paradise
    40422       # Masters Paradise
    40423       # Masters Paradise
    40426       # Masters Paradise
    65000       # Devil
)

# -----------------------------------------------------------------------------
# C2 FRAMEWORK PORTS - Known defaults for offensive security tools
# Sources: Cobalt Strike, Metasploit, Sliver, Empire, Havoc, Mythic, Brute Ratel,
#          PoshC2, Covenant, Merlin, SILENTTRINITY, Villain
# -----------------------------------------------------------------------------
C2_FRAMEWORKS_PORTS=(
    # Cobalt Strike
    50050       # Cobalt Strike team server default
    50051       # Cobalt Strike alternate
    
    # Metasploit
    4444        # Meterpreter default handler
    4445        # Meterpreter alternate
    
    # Common C2 web ports
    2222        # SSH tunneling / alternate SSH
    4443        # HTTPS alternate
    8443        # HTTPS alternate (common C2)
    8080        # HTTP proxy / C2
    8000        # HTTP alternate / BADCALL
    8001        # HTTP alternate
    8008        # HTTP alternate
    8081        # HTTP alternate
    8082        # HTTP alternate
    8181        # HTTP alternate
    8888        # Sliver mTLS/TCP default
    9090        # Various C2 admin panels
    9091        # Various C2
    7443        # HTTPS alternate
    6443        # Kubernetes API / C2 masquerading
    
    # VNC (used for remote access in attacks)
    5900        # VNC default
    5901        # VNC display :1
    5902        # VNC display :2
    5903        # VNC display :3
    5904        # VNC display :4
    5905        # VNC display :5
    
    # Havoc C2
    40056       # Havoc default
    443         # Havoc HTTPS listener
    
    # Mythic C2
    7443        # Mythic default
    
    # Brute Ratel C4
    8443        # Common BR listener
    443         # BR HTTPS
    
    # PoshC2
    443         # PoshC2 HTTPS
    8080        # PoshC2 HTTP
    
    # Covenant
    7443        # Covenant default
    80          # Covenant HTTP
    443         # Covenant HTTPS
    
    # Merlin
    443         # Merlin HTTPS
    80          # Merlin HTTP
    
    # Sliver C2
    8888        # Sliver mTLS
    443         # Sliver HTTPS
    80          # Sliver HTTP
    
    # Empire / Starkiller
    1337        # Empire RESTful API
    443         # Empire HTTPS listeners
    80          # Empire HTTP listeners
    
    # Villain
    6501        # Villain default
    
    # Additional C2 ports
    3389        # RDP - often used for lateral movement
    5985        # WinRM HTTP
    5986        # WinRM HTTPS
    
    # High ports commonly used by RATs for evasion
    28035       # Custom RDP backdoors
    32467       # Custom RDP backdoors
    41578       # Custom RDP backdoors
    46892       # Custom RDP backdoors
)

# -----------------------------------------------------------------------------
# CRYPTO MINING PORTS - Cryptocurrency mining pool connections
# -----------------------------------------------------------------------------
CRYPTO_MINING_PORTS=(
    3333        # Stratum mining
    3334        # Stratum alternate
    4444        # Stratum (also Metasploit - dual use)
    5555        # Stratum alternate
    7777        # Stratum alternate
    8899        # Stratum alternate
    9999        # Stratum alternate
    14433       # Stratum TLS
    14444       # Stratum TLS
    45560       # Monero mining
    45700       # Monero mining
)

# -----------------------------------------------------------------------------
# DATA EXFILTRATION PORTS - Commonly abused for data theft
# -----------------------------------------------------------------------------
EXFIL_PORTS=(
    20          # FTP data (Emotet documented)
    21          # FTP control
    22          # SSH/SCP/SFTP
    69          # TFTP
    115         # SFTP (simple)
    443         # HTTPS (encrypted exfil)
    989         # FTPS data
    990         # FTPS control
    992         # Telnets
    993         # IMAPS
    995         # POP3S
    1194        # OpenVPN
    3128        # Squid proxy
    8080        # HTTP proxy
    8118        # Privoxy
)

# -----------------------------------------------------------------------------
# SUSPICIOUS USER AGENTS - Known malware/C2 user agent strings
# Sources: Threat intelligence, malware analysis reports
# -----------------------------------------------------------------------------
SUSPICIOUS_USER_AGENTS=(
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)"  # Cobalt Strike default
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"               # Common in older malware
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"  # Cobalt Strike
    "Java/1."                                                           # Java-based RATs
    "Python-urllib"                                                     # Python scripts/bots
    "curl/"                                                             # Scripted requests
    "Wget/"                                                             # Scripted downloads
    "PowerShell/"                                                       # PowerShell Empire, etc.
)

# -----------------------------------------------------------------------------
# TOR EXIT NODE DETECTION - Check against Tor exit node lists
# Note: Use live feeds for production - these are example ranges
# Sources: https://check.torproject.org/torbulkexitlist
# -----------------------------------------------------------------------------
TOR_CHECK_URLS=(
    "https://check.torproject.org/torbulkexitlist"
    "https://www.dan.me.uk/torlist/"
)

# -----------------------------------------------------------------------------
# KNOWN C2 DOMAINS - Placeholder for threat intelligence integration
# Note: Populate with your threat intelligence feed
# Sources: Custom threat intel, OSINT feeds, threat sharing platforms
# -----------------------------------------------------------------------------
C2_DOMAINS=(
)

# -----------------------------------------------------------------------------
# DNS TUNNELING PATTERNS - Suspicious DNS query patterns
# Sources: DNS tunneling detection research
# -----------------------------------------------------------------------------
DNS_TUNNELING_PATTERNS=(
    "^[a-f0-9]{20,}"        # Long hex strings
    "\.[a-z]{50,}\."        # Very long subdomains
    "[0-9]{10,}\."          # Long numeric strings
)

# -----------------------------------------------------------------------------
# MITRE ATT&CK TECHNIQUE REFERENCES
# -----------------------------------------------------------------------------
# T1571 - Non-Standard Port: Adversaries use unusual ports for C2
# T1219 - Remote Access Tools: Legitimate tools abused for access
# T1572 - Protocol Tunneling: DNS, HTTPS tunneling for C2
# T1071.001 - Application Layer Protocol: Web Protocols
# T1071.004 - Application Layer Protocol: DNS
# =============================================================================

# Export for Python access
export PCAP_FILE REPORT_DIR
export FILELESS_PCAP_FILE RAW_PCAP_FILE MONITOR_PCAP_FILE FILELESS_REPORT_DIR TIMESTAMP

# =============================================================================
# UTILITY FUNCTIONS (from Fileless.sh)
# =============================================================================

# Print banner (from Fileless.sh)
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    +===============================================================+
    |                                                               |
    |     + + ++  +    +  ++   +    |
    |    +==++==++====+++++    |  ||   |    |
    |    |+++   +++     ||   |    |
    |    +==|+===+ +==+   ++     +==||   |    |
    |    |  ||     +++ +    |  |+++    |
    |    +=+  +=++=+     +======++=+  +=+    +=+  +=+ +=====+     |
    |                                                               |
    |              Network C2 Hunter & Threat Detector             |
    |                    macOS Edition - v5.0                      |
    |                                                               |
    |            For MacBook Air M1 2020 (Apple Silicon)           |
    |                                                               |
    +===============================================================+
EOF
    echo -e "${NC}"
}

# Alert function for suspicious findings (from Fileless.sh)
alert() {
    local severity="$1"
    local category="$2"
    local message="$3"
    local alert_file="$FILELESS_REPORT_DIR/analysis/ALERTS.txt"
    
    local color=""
    case "$severity" in
        "CRITICAL") color="$RED" ;;
        "HIGH") color="$MAGENTA" ;;
        "MEDIUM") color="$YELLOW" ;;
        "LOW") color="$CYAN" ;;
        *) color="$NC" ;;
    esac
    
    echo -e "${color}[${severity}] [${category}] ${message}${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${severity}] [${category}] ${message}" >> "$alert_file"
    log "ALERT" "[$severity] [$category] $message"
}

# Terminal display function for analysis results (from Fileless.sh)
display_findings() {
    local title=$1
    local file=$2
    local max_lines=${3:-15}
    
    if [[ -f "$file" && -s "$file" ]]; then
        local line_count=$(wc -l < "$file")
        echo -e "\n${CYAN}+- $title ($line_count items found)${NC}"
        echo -e "${CYAN}${NC}"
        head -n "$max_lines" "$file" | while IFS= read -r line; do
            echo -e "${CYAN}${NC}  $line"
        done
        if [[ $line_count -gt $max_lines ]]; then
            echo -e "${CYAN}${NC}  ${YELLOW}... and $((line_count - max_lines)) more items${NC}"
            echo -e "${CYAN}${NC}  ${YELLOW}Full results saved to: $file${NC}"
        fi
        echo -e "${CYAN}+-${NC}"
    fi
}

# Display summary statistics (from Fileless.sh)
display_stats() {
    local category=$1
    local dir=$2
    
    if [[ -d "$dir" ]]; then
        local file_count=$(find "$dir" -type f 2>/dev/null | wc -l)
        local total_size=$(du -sh "$dir" 2>/dev/null | awk '{print $1}')
        echo -e "  ${GREEN}[+]${NC} $category: $file_count files ($total_size)"
        
        # List files
        find "$dir" -type f 2>/dev/null | while read -r file; do
            local size=$(ls -lh "$file" 2>/dev/null | awk '{print $5}')
            local basename=$(basename "$file")
            echo -e "    ${CYAN}->${NC} $basename ($size)"
        done
    fi
}

# Display suspicious findings in real-time (from Fileless.sh)
analyze_and_display() {
    local analysis_file=$1
    local pattern=$2
    local alert_msg=$3
    local severity=$4
    
    if [[ -f "$analysis_file" ]]; then
        local matches=$(grep -c "$pattern" "$analysis_file" 2>/dev/null || echo "0")
        if [[ $matches -gt 0 ]]; then
            echo -e "  ${YELLOW}[!]${NC}  Found $matches potential issues"
            grep "$pattern" "$analysis_file" 2>/dev/null | head -5 | while IFS= read -r line; do
                echo -e "     ${RED}->${NC} $line"
                alert "$severity" "DETECTION" "$alert_msg: $line"
            done
        fi
    fi
}

# Logging function
log() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"
    log "INFO" "Cleanup initiated"
    
    if [[ -n "$TCPDUMP_PIDS" ]]; then
        for pid in $TCPDUMP_PIDS; do
            if kill -0 "$pid" 2>/dev/null; then
                sudo kill "$pid" 2>/dev/null || true
            fi
        done
    fi
    sudo killall tcpdump 2>/dev/null || true
    
    log "INFO" "Cleanup complete"
    echo -e "${GREEN}[✓] Cleanup complete${NC}"
}

trap cleanup SIGINT SIGTERM EXIT

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}[*] Checking prerequisites...${NC}"
    log "INFO" "Checking prerequisites"
    
    for tool in tcpdump python3; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[!] Missing: $tool${NC}"
            log "ERROR" "Missing tool: $tool"
            exit 1
        fi
    done
    
    # Check for mergecap (optional but recommended)
    if ! command -v mergecap &> /dev/null; then
        echo -e "${YELLOW}[!] mergecap not found (install with: brew install wireshark)${NC}"
        log "WARN" "mergecap not available"
    fi
    
    # Check Python packages
    python3 -c "import dpkt, pandas" 2>/dev/null || {
        echo -e "${YELLOW}[*] Installing Python packages...${NC}"
        log "INFO" "Installing Python packages"
        pip3 install --user dpkt pandas 2>/dev/null
    }
    
    mkdir -p "$REPORT_DIR"
    echo -e "${GREEN}[✓] Prerequisites OK${NC}"
    log "INFO" "Prerequisites check passed"
}

# List available interfaces - macOS compatible
list_interfaces() {
    echo -e "\n${BLUE}[*] Available network interfaces: ${NC}"
    ifconfig -l | tr ' ' '\n' | while read iface; do
        local status=$(ifconfig "$iface" 2>/dev/null | grep "status:" | awk '{print $2}')
        local inet=$(ifconfig "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        if [[ -n "$status" ]]; then
            echo "$iface - $status ${inet:+($inet)}"
        else
            echo "$iface"
        fi
    done
}

# Capture from ALL interfaces simultaneously
start_capture_all_interfaces() {
    echo -e "\n${GREEN}[*] Starting capture on ALL interfaces for ${CAPTURE_DURATION}s...${NC}"
    log "INFO" "Starting multi-interface capture"
    
    # Get ALL interfaces (including virtual, loopback, VPN tunnels, etc.)
    local interfaces=($(ifconfig -l))
    local pids=()
    
    echo -e "${YELLOW}[*] Capturing on: ${interfaces[*]}${NC}"
    
    # Start tcpdump on each interface
    for iface in "${interfaces[@]}"; do
        local iface_pcap="/tmp/traffic_${iface}_$(date +%Y%m%d_%H%M%S).pcap"
        sudo tcpdump -i "$iface" -n -s 0 -w "$iface_pcap" 2>>"$LOG_FILE" &
        pids+=($!)
        echo -e "${GREEN}├── ${iface}: PID $! ${NC}"
    done
    
    # Also use pktap for system-wide capture (macOS specific)
    sudo tcpdump -i pktap -n -s 0 -w "${PCAP_FILE%.pcap}_pktap.pcap" 2>>"$LOG_FILE" &
    pids+=($!)
    echo -e "${GREEN}└── pktap (ALL): PID $!${NC}"
    
    TCPDUMP_PIDS="${pids[*]}"
    
    # Wait for capture duration
    for ((i=0; i<CAPTURE_DURATION; i+=10)); do
        printf "\r${YELLOW}[*] Progress: %d/%d seconds${NC}" "$i" "$CAPTURE_DURATION"
        sleep 10
    done
    
    # Stop all captures
    echo ""
    for pid in "${pids[@]}"; do
        sudo kill "$pid" 2>/dev/null || true
    done
    
    # Wait for processes to terminate
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    
    TCPDUMP_PIDS=""
    sleep 2
    
    # Merge all pcaps
    if command -v mergecap &> /dev/null; then
        echo -e "${YELLOW}[*] Merging capture files...${NC}"
        mergecap -w "$PCAP_FILE" /tmp/traffic_*_*.pcap 2>/dev/null || {
            echo -e "${YELLOW}[!] Merge failed, using largest file${NC}"
            cp "$(ls -S /tmp/traffic_*_*.pcap 2>/dev/null | head -1)" "$PCAP_FILE" 2>/dev/null || true
        }
    else
        cp "$(ls -S /tmp/traffic_*_*.pcap 2>/dev/null | head -1)" "$PCAP_FILE" 2>/dev/null || true
    fi
    
    local size=$(du -h "$PCAP_FILE" 2>/dev/null | cut -f1 || echo "0")
    echo -e "${GREEN}[✓] Multi-interface capture complete: $size${NC}"
    log "INFO" "Multi-interface capture complete: $size"
}

# Perform analysis
perform_analysis() {
    echo -e "\n${YELLOW}[*] Analyzing captured traffic...${NC}"
    log "INFO" "Starting analysis"
    
    if [[ ! -f "$PCAP_FILE" ]] || [[ ! -s "$PCAP_FILE" ]]; then
        echo -e "${RED}[!] No valid PCAP file to analyze${NC}"
        log "ERROR" "PCAP file missing or empty"
        return 1
    fi
    
    python3 << 'PYEND' || echo "Analysis error"
import sys
import os
import socket
import json
from collections import defaultdict, Counter
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

PCAP_FILE = os.environ.get('PCAP_FILE', '/tmp/traffic.pcap')
REPORT_DIR = os.environ.get('REPORT_DIR', '/tmp/report')

print("\n" + "="*60)
print("NETWORK TRAFFIC ANALYSIS REPORT")
print("="*60)
print(f"Timestamp: {datetime.now()}")
print(f"PCAP File: {PCAP_FILE}")
print("="*60)

try:
    import dpkt
    import pandas as pd
    
    # Data structures
    ips = set()
    ipv6_addresses = set()
    ports = defaultdict(int)
    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    connections = defaultdict(lambda: {'packets': 0, 'bytes': 0})
    timestamps = []
    
    total_packets = 0
    total_bytes = 0
    
    # Parse PCAP
    if not os.path.exists(PCAP_FILE):
        print(f"Error: PCAP file not found: {PCAP_FILE}")
        sys.exit(1)
    
    with open(PCAP_FILE, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        for ts, buf in pcap:
            total_packets += 1
            total_bytes += len(buf)
            timestamps.append(ts)
            
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                
                # Handle IPv4
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    
                    ips.add(src_ip)
                    ips.add(dst_ip)
                    src_ips[src_ip] += 1
                    dst_ips[dst_ip] += 1
                    
                    conn_key = f"{src_ip} -> {dst_ip}"
                    connections[conn_key]['packets'] += 1
                    connections[conn_key]['bytes'] += len(buf)
                    
                    # Protocol analysis
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        protocols['TCP'] += 1
                        tcp = ip.data
                        ports[tcp.dport] += 1
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        protocols['UDP'] += 1
                        udp = ip.data
                        ports[udp.dport] += 1
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        protocols['ICMP'] += 1
                    else:
                        protocols['Other'] += 1
                
                # Handle IPv6
                elif isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                    src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
                    dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                    
                    ipv6_addresses.add(src_ip)
                    ipv6_addresses.add(dst_ip)
                    src_ips[src_ip] += 1
                    dst_ips[dst_ip] += 1
                    protocols['IPv6'] += 1
                    
                    conn_key = f"{src_ip} -> {dst_ip}"
                    connections[conn_key]['packets'] += 1
                    connections[conn_key]['bytes'] += len(buf)
                    
            except Exception as e:
                pass
    
    # Print results
    print(f"\nTotal Packets: {total_packets:,}")
    print(f"Total Bytes: {total_bytes:,} ({total_bytes/1024/1024:.2f} MB)")
    print(f"Unique IPv4 Addresses: {len(ips)}")
    print(f"Unique IPv6 Addresses: {len(ipv6_addresses)}")
    
    # Bandwidth timeline
    if len(timestamps) >= 2:
        duration = timestamps[-1] - timestamps[0]
        if duration > 0:
            avg_bandwidth = (total_bytes * 8) / duration / 1000  # kbps
            print(f"Capture Duration: {duration:.1f} seconds")
            print(f"Average Bandwidth: {avg_bandwidth:.2f} kbps")
    
    print("\n" + "="*40)
    print("PROTOCOL DISTRIBUTION")
    print("="*40)
    for proto, count in protocols.most_common():
        pct = (count / total_packets * 100) if total_packets > 0 else 0
        print(f"{proto}: {count:,} ({pct:.1f}%)")
    
    print("\n" + "="*40)
    print("TOP SOURCE IPs")
    print("="*40)
    for ip, count in src_ips.most_common(10):
        print(f"{ip:45} : {count:,}")
    
    print("\n" + "="*40)
    print("TOP DESTINATION IPs")
    print("="*40)
    for ip, count in dst_ips.most_common(10):
        print(f"{ip:45} : {count:,}")
    
    print("\n" + "="*40)
    print("TOP DESTINATION PORTS")
    print("="*40)
    def get_service_name(port, protocol='tcp'):
        """Get service name for a port number from system services database."""
        try:
            return socket.getservbyport(port, protocol)
        except (OSError, socket.error):
            # Fallback for non-standard ports not in /etc/services
            return 'unknown'

    for port, count in sorted(ports.items(), key=lambda x: x[1], reverse=True)[:15]:
        service = get_service_name(port)
        print(f"Port {port:5} ({service:12}) : {count:,}")
    
    print("\n" + "="*40)
    print("TOP CONNECTIONS")
    print("="*40)
    for conn, data in sorted(connections.items(), key=lambda x: x[1]['bytes'], reverse=True)[:10]:
        print(f"{conn:50} : {data['packets']:,} pkts, {data['bytes']:,} bytes")
    
    # Export data
    print("\n" + "="*40)
    print("EXPORTING DATA")
    print("="*40)
    
    # Export IPv4 IPs
    with open(f"{REPORT_DIR}/ipv4.txt", 'w') as f:
        for ip in sorted(ips):
            f.write(f"{ip}\n")
    print(f"✓ IPv4 Addresses: {REPORT_DIR}/ipv4.txt")
    
    # Export IPv6 IPs
    with open(f"{REPORT_DIR}/ipv6.txt", 'w') as f:
        for ip in sorted(ipv6_addresses):
            f.write(f"{ip}\n")
    print(f"✓ IPv6 Addresses: {REPORT_DIR}/ipv6.txt")
    
    # Export combined IPs
    with open(f"{REPORT_DIR}/ips.txt", 'w') as f:
        for ip in sorted(ips):
            f.write(f"{ip}\n")
        for ip in sorted(ipv6_addresses):
            f.write(f"{ip}\n")
    print(f"✓ All IPs: {REPORT_DIR}/ips.txt")
    
    # Export as JSON
    summary = {
        'total_packets': total_packets,
        'total_bytes': total_bytes,
        'unique_ipv4': len(ips),
        'unique_ipv6': len(ipv6_addresses),
        'protocols': dict(protocols),
        'top_src_ips': dict(src_ips.most_common(20)),
        'top_dst_ips': dict(dst_ips.most_common(20)),
        'top_ports': dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:20])
    }
    
    with open(f"{REPORT_DIR}/summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"✓ Summary: {REPORT_DIR}/summary.json")
    
    # Export CSV
    if connections:
        csv_data = []
        for conn, data in connections.items():
            src, dst = conn.split(' -> ')
            csv_data.append({'source': src, 'destination': dst, 'packets': data['packets'], 'bytes': data['bytes']})
        
        df = pd.DataFrame(csv_data)
        csv_file = f"{REPORT_DIR}/connections.csv"
        df.to_csv(csv_file, index=False)
        print(f"✓ Connections: {csv_file}")
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    
except ImportError as e:
    print(f"Error: Missing module {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

PYEND
    
    echo -e "${GREEN}[✓] Analysis complete${NC}"
    log "INFO" "Analysis complete"
}

# Extract IPs from ALL pcap files - macOS compatible
extract_all_ips() {
    echo -e "\n${YELLOW}[*] Extracting IPs from ALL pcap files on system...${NC}"
    log "INFO" "Starting extraction of IPs from all pcap files"
    
    local all_ips_file="$REPORT_DIR/all_ips_from_pcaps.txt"
    local ipv4_regex='([0-9]{1,3}\.){3}[0-9]{1,3}'
    local ipv6_regex='([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|fe80:[0-9a-fA-F:]+'
    
    {
        # Extract from current capture
        if [[ -f "$PCAP_FILE" ]] && [[ -s "$PCAP_FILE" ]]; then
            tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | grep -oE "${ipv4_regex}|${ipv6_regex}"
        fi
        
        # Find ALL pcap files (multiple extensions, macOS compatible) using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "\.(pcap|pcapng|cap)$" | while read -r f; do
            if [[ "$f" != "$PCAP_FILE" ]]; then
                tcpdump -nn -r "$f" 2>/dev/null | grep -oE "${ipv4_regex}|${ipv6_regex}"
            fi
        done
        
    } | sort -u > "$all_ips_file"
    
    local ip_count=$(wc -l < "$all_ips_file" 2>/dev/null | xargs)
    echo -e "${GREEN}[✓] Extracted $ip_count unique IPs from pcap files${NC}"
    log "INFO" "Extracted $ip_count unique IPs from pcap files"
}

# COMPREHENSIVE IP EXTRACTION - ALL SOURCES
extract_all_network_evidence() {
    echo -e "\n${YELLOW}[*] COMPREHENSIVE IP EXTRACTION - macOS M1${NC}"
    local evidence_file="$REPORT_DIR/all_network_evidence.txt"
    local ip_regex='([0-9]{1,3}\.){3}[0-9]{1,3}'
    
    {
        echo "=== PCAP FILES ==="
        # All accessible pcap files using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "\.(pcap|pcapng|cap)$" | while read f; do
            echo "# From: $f"
            tcpdump -nn -r "$f" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        echo -e "\n=== ACTIVE CONNECTIONS ==="
        # All active network connections
        sudo lsof -i -n -P 2>/dev/null | grep -oE "$ip_regex"
        netstat -an 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== DNS CACHE ==="
        # DNS cache (requires dscacheutil)
        sudo dscacheutil -cachedump -entries Host 2>/dev/null | grep -oE "$ip_regex"
        # mDNSResponder logs
        sudo log show --predicate 'process == "mDNSResponder"' --last 24h 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== SYSTEM LOGS ==="
        # Unified logging system (ALL network-related)
        sudo log show --predicate 'eventMessage contains "IP" OR eventMessage contains "connect" OR eventMessage contains "socket"' --last 7d 2>/dev/null | grep -oE "$ip_regex"
        
        # Legacy logs if accessible
        sudo grep -rhoE "$ip_regex" /var/log/ 2>/dev/null || true
        
        echo -e "\n=== ARP CACHE ==="
        arp -an 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== ROUTING TABLE ==="
        netstat -rn 2>/dev/null | grep -oE "$ip_regex"
        route -n get default 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== FIREWALL LOGS ==="
        # macOS packet filter logs
        sudo pfctl -s all 2>/dev/null | grep -oE "$ip_regex"
        sudo log show --predicate 'process == "socketfilterfw"' --last 7d 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== BROWSER CACHES ==="
        # Safari using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/Safari/.*\.db$" | while read db; do
            strings "$db" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        # Chrome/Chromium using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/Chrome/.*(History|Cache)$" | while read f; do
            strings "$f" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        # Firefox using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/Firefox/.*\.sqlite$" | while read db; do
            strings "$db" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        echo -e "\n=== PROCESS MEMORY (Requires root) ==="
        # Extract IPs from running process memory
        for pid in $(ps -ax -o pid=); do
            sudo vmmap "$pid" 2>/dev/null | grep -oE "$ip_regex" || true
        done
        
        echo -e "\n=== APPLICATION LOGS ==="
        # Common app log locations using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/Logs/" | while read log; do
            sudo strings "$log" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        echo -e "\n=== VPN/PROXY CONFIGS ==="
        # VPN configurations using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/Preferences/.*\.plist$" | while read plist; do
            sudo plutil -p "$plist" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        echo -e "\n=== NETWORK EXTENSION LOGS ==="
        # Network extensions (VPNs, filters, proxies)
        sudo log show --predicate 'subsystem == "com.apple.networkextension"' --last 7d 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== LAUNCHD NETWORK SERVICES ==="
        # Services that might have network connections
        sudo launchctl list 2>/dev/null | while read -r line; do
            sudo launchctl print system/"$(echo $line | awk '{print $3}')" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        echo -e "\n=== KNOWN_HOSTS AND SSH ==="
        # SSH files using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/\.ssh/" | while read f; do
            sudo cat "$f" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        echo -e "\n=== CERTIFICATE STORES ==="
        # System certificates might contain IPs
        security dump-trust-settings 2>/dev/null | grep -oE "$ip_regex"
        security dump-keychain -d 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== CRASH REPORTS (May contain network state) ==="
        # Crash reports using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/DiagnosticReports/" | while read crash; do
            sudo strings "$crash" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        echo -e "\n=== PACKET FILTER STATE TABLE ==="
        # Active connections in pf
        sudo pfctl -s state 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== SYSTEM PROFILER NETWORK INFO ==="
        system_profiler SPNetworkDataType 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== SYSDIAGNOSE ARCHIVES (if exist) ==="
        # Sysdiagnose archives using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "sysdiagnose_.*\.tar\.gz$" | while read archive; do
            sudo tar -xzOf "$archive" 2>/dev/null | strings | grep -oE "$ip_regex"
        done
        
        echo -e "\n=== NETWORK INTERFACE STATISTICS ==="
        # Network interface stats and configurations
        ifconfig -a 2>/dev/null | grep -oE "$ip_regex"
        networksetup -listallhardwareports 2>/dev/null
        
        echo -e "\n=== HOSTS FILE ANALYSIS ==="
        # Check /etc/hosts for suspicious entries
        cat /etc/hosts 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== DNS RESOLVER CONFIGURATION ==="
        # DNS resolver settings
        scutil --dns 2>/dev/null | grep -oE "$ip_regex"
        cat /etc/resolv.conf 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== BLUETOOTH NETWORK CONNECTIONS ==="
        # Bluetooth network connections (potential exfiltration path)
        system_profiler SPBluetoothDataType 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== USB NETWORK DEVICES ==="
        # USB network devices (potential rogue devices)
        system_profiler SPUSBDataType 2>/dev/null | grep -iE "(network|ethernet|wifi)" | grep -oE "$ip_regex"
        
        echo -e "\n=== KERNEL NETWORK EXTENSIONS ==="
        # Kernel extensions related to networking using System path search
        kextstat 2>/dev/null | grep -iE "(network|socket|filter)"
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "\.kext$" | grep -iE "(network|socket|filter)"
        
        echo -e "\n=== RECENT NETWORK-RELATED FILE CHANGES ==="
        # Recent modifications to network config files using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "(hosts|resolv|network|socket)" | while read f; do
            if [[ -f "$f" ]]; then
                echo "FILE: $f"
                cat "$f" 2>/dev/null | grep -oE "$ip_regex"
            fi
        done
        
        echo -e "\n=== TIME MACHINE NETWORK DESTINATIONS ==="
        # Time Machine backup destinations (potential data exfiltration)
        tmutil destinationinfo 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== SHARING PREFERENCES ==="
        # Sharing settings (file sharing, screen sharing, etc.)
        sudo defaults read /Library/Preferences/com.apple.sharing.plist 2>/dev/null | grep -oE "$ip_regex"
        
        echo -e "\n=== QUARANTINE DATABASE ==="
        # Downloaded files with network origins using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "com\.apple\.LaunchServices\.QuarantineEventsV2$" | while read db; do
            sqlite3 "$db" "SELECT LSQuarantineDataURLString FROM LSQuarantineEvent;" 2>/dev/null | grep -oE "$ip_regex"
        done
        
        echo -e "\n=== APPLICATION FIREWALL RULES ==="
        # Application firewall configuration
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null
        sudo defaults read /Library/Preferences/com.apple.alf 2>/dev/null | grep -oE "$ip_regex"
        
    } | sort -u > "$evidence_file"
    
    local count=$(wc -l < "$evidence_file")
    echo -e "${GREEN}[✓] Extracted $count unique IPs from ALL sources${NC}"
    echo -e "${GREEN}    Evidence file: $evidence_file${NC}"
    log "INFO" "Extracted $count unique IPs from all sources"
}

# Detect suspicious DNS queries (common C2 indicator)
detect_suspicious_dns() {
    echo -e "\n${YELLOW}[*] Analyzing DNS patterns for C2 indicators...${NC}"
    log "INFO" "Starting DNS analysis"
    
    if [[ ! -f "$PCAP_FILE" ]] || [[ ! -s "$PCAP_FILE" ]]; then
        echo -e "${YELLOW}[!] No PCAP file available for DNS analysis${NC}"
        return 1
    fi
    
    # Extract DNS queries from packet capture
    tcpdump -nn -r "$PCAP_FILE" 'udp port 53' 2>/dev/null | \
        grep -oE '([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}' | \
        sort | uniq -c | sort -rn > "$REPORT_DIR/dns_queries.txt"
    
    # Look for long/suspicious domain names (DGA domains)
    awk '{print $2}' "$REPORT_DIR/dns_queries.txt" | \
        awk 'length($0) > 20' > "$REPORT_DIR/suspicious_long_domains.txt"
    
    local dga_count=$(wc -l < "$REPORT_DIR/suspicious_long_domains.txt" 2>/dev/null | xargs)
    echo -e "${GREEN}[✓] DNS analysis complete${NC}"
    echo -e "${GREEN}    Found $dga_count potentially suspicious domains${NC}"
    log "INFO" "DNS analysis complete: $dga_count suspicious domains"
}

# Extract all outbound connections
extract_outbound_connections() {
    echo -e "\n${YELLOW}[*] Extracting all outbound connections...${NC}"
    log "INFO" "Extracting outbound connections"
    
    # Get local IPs first
    local_ips=$(ifconfig | grep -oE 'inet ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}')
    
    sudo lsof -i -n -P | grep ESTABLISHED > "$REPORT_DIR/established_connections.txt"
    netstat -an | grep ESTABLISHED > "$REPORT_DIR/netstat_established.txt"
    
    local conn_count=$(wc -l < "$REPORT_DIR/established_connections.txt" 2>/dev/null | xargs)
    echo -e "${GREEN}[✓] Outbound connections saved${NC}"
    echo -e "${GREEN}    Active connections: $conn_count${NC}"
    log "INFO" "Extracted $conn_count outbound connections"
}

# Check for persistence mechanisms
check_persistence() {
    echo -e "\n${YELLOW}[*] Checking persistence mechanisms (LaunchAgents/Daemons)...${NC}"
    log "INFO" "Checking persistence mechanisms"
    
    local persistence_file="$REPORT_DIR/persistence_check.txt"
    
    {
        echo "=== USER LAUNCH AGENTS ==="
        # Launch agents using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/LaunchAgents/" | while read f; do
            echo "FILE: $f"
            sudo plutil -p "$f" 2>/dev/null | grep -E "(Program|ProgramArguments|Socket|KeepAlive)"
        done
        
        echo -e "\n=== SYSTEM LAUNCH DAEMONS ==="
        # Launch daemons using System path search
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/LaunchDaemons/" | while read f; do
            echo "FILE: $f"
            sudo plutil -p "$f" 2>/dev/null | grep -E "(Program|ProgramArguments|Socket|KeepAlive)"
        done
        
        echo -e "\n=== CRON JOBS ==="
        crontab -l 2>/dev/null
        sudo crontab -l 2>/dev/null
        
    } > "$persistence_file"
    
    echo -e "${GREEN}[✓] Persistence check complete${NC}"
    echo -e "${GREEN}    Report: $persistence_file${NC}"
    log "INFO" "Persistence check complete"
}

# Detect suspicious patterns for C2 activity
detect_suspicious_activity() {
    echo -e "\n${YELLOW}[*] Analyzing for suspicious C2 abuse patterns...${NC}"
    log "INFO" "Starting suspicious activity detection"
    
    local suspicious_report="$REPORT_DIR/suspicious_activity.txt"
    
    {
        echo "============================================"
        echo "SUSPICIOUS ACTIVITY REPORT"
        echo "Generated: $(date)"
        echo "============================================"
        echo ""
        
        # DNS Analysis
        echo "=== DNS QUERIES (Potential DGA Domains) ==="
        if [[ -f "$PCAP_FILE" ]] && [[ -s "$PCAP_FILE" ]]; then
            tcpdump -nn -r "$PCAP_FILE" 'udp port 53' 2>/dev/null | \
                grep -oE '([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}' | \
                awk 'length($0) > 20' | sort | uniq -c | sort -rn | head -20
        fi
        
        echo ""
        echo "=== OUTBOUND CONNECTIONS TO NON-STANDARD PORTS ==="
        if [[ -f "$PCAP_FILE" ]] && [[ -s "$PCAP_FILE" ]]; then
            tcpdump -nn -r "$PCAP_FILE" 'tcp[tcpflags] & (tcp-syn) != 0' 2>/dev/null | \
                grep -oE '\.[0-9]{1,5}: ' | sed 's/[\.:]//g' | \
                grep -vE '^(80|443|22|21|25|110|143|993|995|587|465)$' | \
                sort | uniq -c | sort -rn | head -20
        fi
        
        echo ""
        echo "=== ESTABLISHED CONNECTIONS (Active Now) ==="
        sudo lsof -i -n -P 2>/dev/null | grep ESTABLISHED | head -30
        
        echo ""
        echo "=== LISTENING PORTS (Potential Backdoors) ==="
        sudo lsof -i -n -P 2>/dev/null | grep LISTEN
        
        echo ""
        echo "=== PERSISTENCE MECHANISMS (LaunchAgents/Daemons) ==="
        echo "User LaunchAgents:"
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/LaunchAgents/" | grep -v "^total" | grep -v "^d"
        echo ""
        echo "System LaunchDaemons (modified in last 30 days):"
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/LaunchDaemons/" | while read f; do
            # Check if modified in last 30 days using stat
            if [[ -f "$f" ]]; then
                mod_time=$(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f" 2>/dev/null)
                current_time=$(date +%s)
                days_ago=$(( (current_time - mod_time) / 86400 ))
                if [[ $days_ago -lt 30 ]]; then
                    ls -la "$f" 2>/dev/null
                fi
            fi
        done
        
        echo ""
        echo "=== UNUSUAL CRON JOBS ==="
        echo "User crontab:"
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "/crontab$|/cron\."
        
    } > "$suspicious_report"
    
    echo -e "${GREEN}[✓] Suspicious activity analysis complete${NC}"
    echo -e "${GREEN}    Report: $suspicious_report${NC}"
    log "INFO" "Suspicious activity detection complete"
}

# Display help
show_help() {
    echo -e "${GREEN}"
    echo "Usage: $0 [CAPTURE_DURATION_SECONDS]"
    echo ""
    echo "macOS M1 Compatible Network Forensics & C2 Detection Tool"
    echo ""
    echo "Options:"
    echo "  CAPTURE_DURATION    Duration in seconds (default: 1000)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Features:"
    echo "  • Multi-interface packet capture (including pktap)"
    echo "  • Comprehensive IP extraction from ALL system sources"
    echo "  • C2 abuse detection patterns"
    echo "  • Persistence mechanism checking"
    echo "  • DNS analysis for DGA domains"
    echo "  • Active connection monitoring"
    echo ""
    echo "Examples:"
    echo "  $0              # Capture for 1000 seconds"
    echo "  $0 600          # Capture for 10 minutes"
    echo "  $0 3600         # Capture for 1 hour"
    echo ""
    echo "Requirements:"
    echo "  • Run with sudo (for tcpdump and system access)"
    echo "  • Terminal needs Full Disk Access (System Preferences)"
    echo "  • Python 3 with dpkt and pandas"
    echo -e "${NC}"
}

# Main
main() {
    # Check for help flag
    if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    # Check if running with sudo
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[!] This script needs sudo privileges for comprehensive capture${NC}"
        echo -e "${YELLOW}[!] Some features may not work without sudo${NC}"
        echo ""
    fi
    
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════╗"
    echo "║  Network Capture & Analysis Tool - macOS Edition ║"
    echo "║  C2 abuse Detection & Forensics v4.0           ║"
    echo "╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "INFO" "Script started"
    log "INFO" "Capture duration: ${CAPTURE_DURATION}s"
    log "INFO" "PCAP file: ${PCAP_FILE}"
    log "INFO" "Report directory: ${REPORT_DIR}"
    log "INFO" "Platform: macOS ($(uname -m))"
    
    check_prerequisites
    
    # Multi-interface capture
    start_capture_all_interfaces
    
    # Python analysis
    perform_analysis
    
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  STARTING COMPREHENSIVE FORENSIC EXTRACTION        ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
    
    # COMPREHENSIVE extraction
    extract_all_ips
    extract_all_network_evidence
    
    # C2 detection
    detect_suspicious_dns
    extract_outbound_connections
    check_persistence
    detect_suspicious_activity
    
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  COMPREHENSIVE FORENSIC COLLECTION COMPLETE        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${BLUE}[i] Generated Files: ${NC}"
    echo -e "    Reports: ${REPORT_DIR}/"
    echo -e "    PCAP: ${PCAP_FILE}"
    echo -e "    Log: ${LOG_FILE}"
    echo ""
    
    ls -lh "$REPORT_DIR"/ 2>/dev/null
    echo ""
    ls -lh "$PCAP_FILE" 2>/dev/null
    
    echo -e "\n${YELLOW}[i] Key Files: ${NC}"
    echo -e "    ${GREEN}all_network_evidence.txt${NC}    - All IPs from all sources"
    echo -e "    ${GREEN}all_ips_from_pcaps.txt${NC}      - IPs from pcap files"
    echo -e "    ${GREEN}dns_queries.txt${NC}             - DNS query analysis"
    echo -e "    ${GREEN}suspicious_long_domains.txt${NC} - Potential DGA domains"
    echo -e "    ${GREEN}established_connections.txt${NC} - Active connections"
    echo -e "    ${GREEN}persistence_check.txt${NC}       - Persistence mechanisms"
    echo -e "    ${GREEN}suspicious_activity.txt${NC}     - C2 abuse indicators"
    
    log "INFO" "Script completed successfully"
    echo -e "All evidence in: ${REPORT_DIR}/"
    
    echo -e "\n${YELLOW}[!] For even more comprehensive pcap extraction, run: ${NC}"
    echo -e "    ${BLUE}sudo find / -type f -path \"*/System/*\" 2>/dev/null | grep -E \"(.pcap)\" | while read f; do tcpdump -nn -r \"\$f\" 2>/dev/null | grep -oE '\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b'; done | sort -u > $REPORT_DIR/system_pcap_ips.txt${NC}"
}

main "$@"



#Run ={ sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "(.pcap)" | while read f; do tcpdump -nn -r "$f" 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'; done | sort -u } afterwards to get all.  It works best for me.
