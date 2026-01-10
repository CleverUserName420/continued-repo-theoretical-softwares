#!/bin/bash

# =============================================================================
# Network Traffic Capture, Analysis & C2/Fileless Malware Detection
# Version 5.0 - macOS Edition (M1/Apple Silicon Compatible)
# Converted for MacBook Air M1 2020
# =============================================================================

set -u  # Exit on undefined vars

# Initialize arrays to avoid unbound variable errors
DISCOVERED_INTERFACES=()

# Trap handler for cleanup
trap cleanup EXIT INT TERM

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
CAPTURE_DURATION=${1:-1000}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DESKTOP_DIR="$HOME/Desktop"
PCAP_FILE="$DESKTOP_DIR/PCAP_FILE_${TIMESTAMP}.pcap"
RAW_PCAP_FILE="$DESKTOP_DIR/RAW_PCAP_FILE_${TIMESTAMP}.pcap"
MONITOR_PCAP_FILE="$DESKTOP_DIR/MONITOR_PCAP_FILE_${TIMESTAMP}.pcap"
REPORT_DIR="$DESKTOP_DIR/REPORT_DIR_${TIMESTAMP}"
LOG_FILE="$DESKTOP_DIR/LOG_FILE_${TIMESTAMP}.log"
TCPDUMP_PIDS=()
MONITOR_INTERFACES=()
ORIGINAL_INTERFACE_STATES=()

# Capture settings - NO LIMITS
SNAPLEN=65535          # Maximum packet size (0 not supported on all platforms)
BUFFER_SIZE=256        # MB - maximum ring buffer
PACKET_COUNT=0         # 0 = unlimited packets
PROMISC_MODE=1         # Enable promiscuous mode

# =============================================================================
# COMPREHENSIVE C2/MALICIOUS NETWORK INDICATORS
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
export PCAP_FILE RAW_PCAP_FILE MONITOR_PCAP_FILE REPORT_DIR TIMESTAMP

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Print banner
print_banner() {
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           C2 Hunter v5.0 - macOS Edition                     ║"
    echo "║     Network Traffic Capture & Malware Detection              ║"
    echo "║           Fileless Malware & C2 Abuse Detection              ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

# Alert function for suspicious findings
alert() {
    local severity="$1"
    local category="$2"
    local message="$3"
    local alert_file="$REPORT_DIR/analysis/ALERTS.txt"
    
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

# Terminal display function for analysis results
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

# Display summary statistics
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

# Display suspicious findings in real-time
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

# Print banner
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

# =============================================================================
# PREREQUISITE CHECKS
# =============================================================================

check_prerequisites() {
    echo -e "${YELLOW}[*] Checking prerequisites...${NC}"
    log "INFO" "Checking prerequisites"
    
    local missing_tools=()
    local optional_tools=()
    
    # Check for required tools
    for tool in tcpdump ifconfig awk grep sed; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # Optional but recommended tools (macOS alternatives)
    for tool in tshark dumpcap nmap lsof sqlite3; do
        if ! command -v "$tool" &> /dev/null; then
            optional_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}[!] Missing required tools: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}[*] Install with: brew install ${missing_tools[*]}${NC}"
        log "ERROR" "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    if [[ ${#optional_tools[@]} -gt 0 ]]; then
        echo -e "${YELLOW}[!] Optional tools not found (some features disabled): ${optional_tools[*]}${NC}"
        echo -e "${YELLOW}[*] Install with: brew install wireshark nmap${NC}"
        log "WARN" "Optional tools not found: ${optional_tools[*]}"
    fi
    
    # Check for disk space (require at least 5GB free)
    local desktop_path="$DESKTOP_DIR"
    if [[ ! -d "$desktop_path" ]]; then
        mkdir -p "$desktop_path" 2>/dev/null || {
            echo -e "${RED}[!] Cannot create Desktop directory${NC}"
            exit 1
        }
    fi
    
    local free_space_kb=$(df -k "$desktop_path" | awk 'NR==2 {print $4}')
    local free_space_gb=$((free_space_kb / 1024 / 1024))
    
    echo -e "${CYAN}[*] Available disk space: ${free_space_gb}GB${NC}"
    
    if [[ $free_space_gb -lt 5 ]]; then
        echo -e "${YELLOW}[!] WARNING: Low disk space (${free_space_gb}GB available)${NC}"
        echo -e "${YELLOW}[!] Packet captures can be large. Recommended: 10GB+ free${NC}"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}[*] Aborted by user${NC}"
            exit 0
        fi
    fi
    
    # Check Python packages
    if command -v python3 &> /dev/null; then
        python3 -c "import dpkt, pandas" 2>/dev/null || {
            echo -e "${YELLOW}[*] Optional: Python packages not found (advanced analysis disabled)${NC}"
            log "INFO" "Python packages not available"
        }
    fi
    
    # Check for root/sudo
    if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        echo -e "${YELLOW}[!] This script requires sudo access${NC}"
        echo -e "${YELLOW}[!] You may be prompted for your password${NC}"
        # Test sudo access
        if ! sudo -v; then
            echo -e "${RED}[[X]] Failed to obtain sudo access${NC}"
            exit 1
        fi
    fi
    
    # Keep sudo alive in background
    ( while true; do sudo -n true; sleep 50; done 2>/dev/null ) &
    local sudo_keeper_pid=$!
    
    # Create report directory structure (same as Linux version)
    if ! mkdir -p "$REPORT_DIR"/{pcaps,logs,exports,analysis,c2_detection,persistence,memory,network_state} 2>/dev/null; then
        echo -e "${RED}[!] Failed to create report directories${NC}"
        exit 1
    fi
    
    if ! touch "$REPORT_DIR/analysis/ALERTS.txt" 2>/dev/null; then
        echo -e "${RED}[!] Failed to create alerts file${NC}"
        exit 1
    fi
    
    log "INFO" "Created report directory: $REPORT_DIR"
    
    echo -e "${GREEN}[[+]] Prerequisites OK${NC}"
    log "INFO" "Prerequisites check passed"
}

# =============================================================================
# NETWORK INTERFACE DISCOVERY (macOS specific)
# =============================================================================

discover_interfaces() {
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|                    DISCOVERING INTERFACES                        |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Discovering network interfaces"
    
    local all_interfaces=()
    
    # Method 1: networksetup (macOS specific)
    while IFS= read -r line; do
        if [[ "$line" =~ ^Device: ]]; then
            iface=$(echo "$line" | awk '{print $2}')
            [[ -n "$iface" ]] && all_interfaces+=("$iface")
        fi
    done < <(networksetup -listallhardwareports 2>/dev/null)
    
    # Method 2: ifconfig -l (macOS)
    for iface in $(ifconfig -l 2>/dev/null); do
        [[ -n "$iface" ]] && all_interfaces+=("$iface")
    done
    
    # Method 3: Parse ifconfig -a output
    while IFS= read -r line; do
        if [[ "$line" =~ ^[a-z] ]]; then
            iface=$(echo "$line" | cut -d':' -f1)
            [[ -n "$iface" ]] && all_interfaces+=("$iface")
        fi
    done < <(ifconfig -a 2>/dev/null)
    
    # Deduplicate - using bash 3.x compatible method
    DISCOVERED_INTERFACES=()
    if [ ${#all_interfaces[@]} -gt 0 ]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && DISCOVERED_INTERFACES+=("$line")
        done < <(printf '%s\n' "${all_interfaces[@]}" | sort -u)
    fi
    
    echo -e "${GREEN}[[+]] Found ${#DISCOVERED_INTERFACES[@]} interfaces:${NC}"
    
    if [ ${#DISCOVERED_INTERFACES[@]} -eq 0 ]; then
        echo -e "${RED}[!] No network interfaces found!${NC}"
        log "ERROR" "No network interfaces discovered"
        return
    fi
    
    for iface in "${DISCOVERED_INTERFACES[@]}"; do
        local status="DOWN"
        local ip_addr="No IP"
        local mac="No MAC"
        
        if ifconfig "$iface" 2>/dev/null | grep -q "status: active"; then
            status="UP"
        fi
        
        ip_addr=$(ifconfig "$iface" 2>/dev/null | grep "inet " | head -1 | awk '{print $2}')
        [[ -z "$ip_addr" ]] && ip_addr="No IP"
        
        mac=$(ifconfig "$iface" 2>/dev/null | grep "ether " | awk '{print $2}')
        [[ -z "$mac" ]] && mac="No MAC"
        
        echo -e "    ${CYAN}[$iface]${NC} Status: $status | IP: $ip_addr | MAC: $mac"
    done
    
    log "INFO" "Discovered ${#DISCOVERED_INTERFACES[@]} interfaces"
}

# =============================================================================
# ENABLE PROMISCUOUS MODE (macOS)
# =============================================================================

enable_promiscuous_mode() {
    echo -e "\n${YELLOW}[*] Enabling promiscuous mode on active interfaces...${NC}"
    log "INFO" "Enabling promiscuous mode"
    
    if [ ${#DISCOVERED_INTERFACES[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No interfaces to configure${NC}"
        log "WARN" "No interfaces found for promiscuous mode"
        return
    fi
    
    for iface in "${DISCOVERED_INTERFACES[@]}"; do
        if [[ "$iface" != "lo0" && "$iface" != "lo" ]]; then
            echo -e "    ${YELLOW}[*] Setting $iface to promiscuous mode...${NC}"
            # On macOS, promiscuous mode is handled by tcpdump automatically
            # But we can verify the interface is up
            sudo ifconfig "$iface" up 2>/dev/null || true
            
            if ifconfig "$iface" 2>/dev/null | grep -q "UP"; then
                echo -e "        ${GREEN}[[+]] $iface is ready for capture${NC}"
                log "INFO" "Interface $iface prepared for promiscuous mode"
            fi
        fi
    done
    
    echo -e "${GREEN}[[+]] Interfaces ready for promiscuous capture${NC}"
    log "INFO" "Promiscuous mode preparation complete"
}

# =============================================================================
# MONITOR MODE SETUP (macOS WiFi)
# =============================================================================

setup_monitor_mode() {
    echo -e "\n${YELLOW}[*] Checking for WiFi monitor mode capability...${NC}"
    log "INFO" "Checking monitor mode"
    
    # Find WiFi interface on macOS
    local wifi_iface=$(networksetup -listallhardwareports | grep -A 1 "Wi-Fi" | grep "Device:" | awk '{print $2}')
    
    if [[ -z "$wifi_iface" ]]; then
        echo -e "${YELLOW}[!] No WiFi interface found, skipping monitor mode${NC}"
        log "WARN" "No WiFi interface found"
        return
    fi
    
    echo -e "${CYAN}[*] WiFi interface found: $wifi_iface${NC}"
    echo -e "${YELLOW}[!] Note: macOS requires the wireless diagnostics tool for full monitor mode${NC}"
    echo -e "${YELLOW}[!] To enable: Option+Click WiFi icon > Open Wireless Diagnostics > Window > Sniffer${NC}"
    
    # We can still capture WiFi traffic in regular mode
    echo -e "${GREEN}[[+]] WiFi capture will proceed in regular mode${NC}"
    log "INFO" "WiFi capture configured"
}

# =============================================================================
# DATA COLLECTION MODULES (macOS adapted)
# =============================================================================

collect_network_layer_c2() {
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|               NETWORK LAYER C2 DETECTION                         |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Starting network layer C2 detection"
    
    local output_dir="$REPORT_DIR/c2_detection"
    
    # Active connections
    echo -e "${YELLOW}[*] Capturing active network connections...${NC}"
    netstat -an > "$output_dir/active_connections.txt" 2>&1 || true
    sudo lsof -i -P -n > "$output_dir/open_sockets.txt" 2>&1 || true
    
    # Display active connections summary
    if [[ -f "$output_dir/active_connections.txt" ]]; then
        local conn_count=$(grep -c "ESTABLISHED\|LISTEN" "$output_dir/active_connections.txt" 2>/dev/null || echo "0")
        echo -e "  ${GREEN}[+]${NC} Found $conn_count active connections"
        echo -e "\n  ${CYAN}Top 10 Active Connections:${NC}"
        grep "ESTABLISHED" "$output_dir/active_connections.txt" 2>/dev/null | head -10 | while IFS= read -r line; do
            echo -e "    ${CYAN}->${NC} $line"
        done
    fi
    
    # Open ports
    echo -e "\n${YELLOW}[*] Capturing listening ports...${NC}"
    netstat -an | grep LISTEN > "$output_dir/listening_ports.txt" 2>&1 || true
    sudo lsof -i -P -n | grep LISTEN > "$output_dir/listening_ports_lsof.txt" 2>&1 || true
    
    # Display listening ports
    if [[ -f "$output_dir/listening_ports.txt" ]]; then
        local port_count=$(wc -l < "$output_dir/listening_ports.txt")
        echo -e "  ${GREEN}[+]${NC} Found $port_count listening ports"
        echo -e "\n  ${CYAN}Listening Ports:${NC}"
        cat "$output_dir/listening_ports.txt" 2>/dev/null | while IFS= read -r line; do
            echo -e "    ${CYAN}->${NC} $line"
        done
    fi
    
    # ARP table
    echo -e "\n${YELLOW}[*] Capturing ARP table...${NC}"
    arp -a > "$output_dir/arp_table.txt" 2>&1 || true
    display_findings "ARP Table Entries" "$output_dir/arp_table.txt" 10
    
    # Routing table
    echo -e "\n${YELLOW}[*] Capturing routing table...${NC}"
    netstat -rn > "$output_dir/routing_table.txt" 2>&1 || true
    display_findings "Routing Table" "$output_dir/routing_table.txt" 15
    
    # DNS configuration
    echo -e "\n${YELLOW}[*] Capturing DNS configuration...${NC}"
    scutil --dns > "$output_dir/dns_config.txt" 2>&1 || true
    sudo dscacheutil -cachedump -entries Host > "$output_dir/dns_cache.txt" 2>&1 || true
    
    # Display DNS servers
    if [[ -f "$output_dir/dns_config.txt" ]]; then
        echo -e "\n  ${CYAN}DNS Servers in Use:${NC}"
        grep "nameserver\[" "$output_dir/dns_config.txt" 2>/dev/null | sort -u | head -10 | while IFS= read -r line; do
            echo -e "    ${CYAN}->${NC} $line"
        done
    fi
    
    # Check for suspicious ports
    echo -e "\n${YELLOW}[*] Checking for suspicious ports...${NC}"
    local suspicious_found=0
    
    if [ ${#SUSPICIOUS_PORTS[@]} -gt 0 ]; then
        for port in "${SUSPICIOUS_PORTS[@]}"; do
            if netstat -an 2>/dev/null | grep LISTEN | grep -q ":$port "; then
                alert "HIGH" "SUSPICIOUS_PORT" "Suspicious port $port is listening"
                suspicious_found=$((suspicious_found + 1))
            fi
        done
    fi
    
    if [[ $suspicious_found -eq 0 ]]; then
        echo -e "  ${GREEN}[+]${NC} No suspicious ports detected"
    else
        echo -e "  ${RED}[!]${NC}  Found $suspicious_found suspicious ports"
    fi
    
    # Check for C2 framework ports
    echo -e "\n${YELLOW}[*] Checking for C2 framework ports...${NC}"
    local c2_found=0
    
    if [ ${#C2_FRAMEWORKS_PORTS[@]} -gt 0 ]; then
        for port in "${C2_FRAMEWORKS_PORTS[@]}"; do
            if netstat -an 2>/dev/null | grep LISTEN | grep -q ":$port "; then
                alert "CRITICAL" "C2_PORT" "Known C2 framework port $port is listening"
                c2_found=$((c2_found + 1))
            fi
        done
    fi
    
    if [[ $c2_found -eq 0 ]]; then
        echo -e "  ${GREEN}[+]${NC} No C2 framework ports detected"
    else
        echo -e "  ${RED}[!]${NC}  Found $c2_found C2 framework ports"
    fi
    
    # Check for crypto mining ports
    echo -e "\n${YELLOW}[*] Checking for crypto mining ports...${NC}"
    local crypto_found=0
    
    if [ ${#CRYPTO_MINING_PORTS[@]} -gt 0 ]; then
        for port in "${CRYPTO_MINING_PORTS[@]}"; do
            if netstat -an 2>/dev/null | grep LISTEN | grep -q ":$port "; then
                alert "MEDIUM" "CRYPTO_MINING" "Crypto mining port $port is listening"
                crypto_found=$((crypto_found + 1))
            fi
        done
    fi
    
    if [[ $crypto_found -eq 0 ]]; then
        echo -e "  ${GREEN}[+]${NC} No crypto mining ports detected"
    else
        echo -e "  ${RED}[!]${NC}  Found $crypto_found crypto mining ports"
    fi
    
    # Network statistics
    echo -e "\n${YELLOW}[*] Gathering network statistics...${NC}"
    netstat -s > "$output_dir/network_stats.txt" 2>&1 || true
    echo -e "  ${GREEN}[+]${NC} Network statistics captured"
    
    # Check for DoH connections
    echo -e "\n${YELLOW}[*] Checking for DNS-over-HTTPS (DoH) connections...${NC}"
    local doh_found=0
    
    if [[ -f "$output_dir/active_connections.txt" ]] && [ ${#DOH_SERVERS[@]} -gt 0 ]; then
        for doh_ip in "${DOH_SERVERS[@]}"; do
            if grep -q "$doh_ip" "$output_dir/active_connections.txt" 2>/dev/null; then
                alert "MEDIUM" "DOH_CONNECTION" "DoH connection detected to $doh_ip (may be used to bypass DNS monitoring)"
                doh_found=$((doh_found + 1))
            fi
        done
    fi
    
    if [[ $doh_found -eq 0 ]]; then
        echo -e "  ${GREEN}[+]${NC} No DoH connections detected"
    else
        echo -e "  ${YELLOW}[!]${NC} Found $doh_found DoH connections"
    fi
    
    # Check for known C2 domains (requires DNS cache analysis)
    echo -e "\n${YELLOW}[*] Checking DNS cache for known C2 domains...${NC}"
    local c2_domain_found=0
    
    # Check if C2_DOMAINS array has elements
    if [ ${#C2_DOMAINS[@]} -eq 0 ]; then
        echo -e "  ${CYAN}[*]${NC} No C2 domain threat intelligence loaded (array is empty)"
        echo -e "  ${CYAN}[*]${NC} Populate C2_DOMAINS array for enhanced detection"
    elif [[ -f "$output_dir/dns_cache.txt" ]]; then
        for domain in "${C2_DOMAINS[@]}"; do
            if grep -qi "$domain" "$output_dir/dns_cache.txt" 2>/dev/null; then
                alert "CRITICAL" "C2_DOMAIN" "Known C2 domain found in DNS cache: $domain"
                c2_domain_found=$((c2_domain_found + 1))
            fi
        done
        
        if [[ $c2_domain_found -eq 0 ]]; then
            echo -e "  ${GREEN}[+]${NC} No known C2 domains in DNS cache"
        else
            echo -e "  ${RED}[!]${NC} Found $c2_domain_found known C2 domains"
        fi
    else
        echo -e "  ${YELLOW}[!]${NC} DNS cache file not found"
    fi
    
    # Analyze for unusual connections
    echo -e "\n${YELLOW}[*] Analyzing for unusual patterns...${NC}"
    if [[ -f "$output_dir/open_sockets.txt" ]]; then
        # Check for non-standard ports
        grep -E ":[0-9]{5}" "$output_dir/open_sockets.txt" 2>/dev/null | head -5 | while IFS= read -r line; do
            echo -e "  ${YELLOW}[!]${NC}  High port detected: $line"
        done
    fi
    
    echo -e "\n${GREEN}[[+]] Network layer C2 detection complete${NC}"
    log "INFO" "Network layer C2 detection complete"
}

collect_process_memory() {
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|              PROCESS MEMORY ANALYSIS                             |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Starting process memory analysis"
    
    local output_dir="$REPORT_DIR/memory"
    
    # Process list with full details
    echo -e "${YELLOW}[*] Capturing process information...${NC}"
    ps aux > "$output_dir/process_list.txt" 2>&1 || true
    ps aux | sort -k3 -r | head -20 > "$output_dir/top_cpu_processes.txt" 2>&1 || true
    ps aux | sort -k4 -r | head -20 > "$output_dir/top_memory_processes.txt" 2>&1 || true
    
    # Display top CPU consumers
    if [[ -f "$output_dir/top_cpu_processes.txt" ]]; then
        echo -e "\n  ${CYAN}Top 10 CPU Consumers:${NC}"
        head -11 "$output_dir/top_cpu_processes.txt" | tail -10 | while IFS= read -r line; do
            echo -e "    ${CYAN}->${NC} $line"
        done
    fi
    
    # Display top memory consumers
    if [[ -f "$output_dir/top_memory_processes.txt" ]]; then
        echo -e "\n  ${CYAN}Top 10 Memory Consumers:${NC}"
        head -11 "$output_dir/top_memory_processes.txt" | tail -10 | while IFS= read -r line; do
            echo -e "    ${CYAN}->${NC} $line"
        done
    fi
    
    # Processes with open network connections
    echo -e "\n${YELLOW}[*] Capturing network processes...${NC}"
    if command -v lsof &> /dev/null; then
        sudo lsof -i > "$output_dir/network_processes.txt" 2>&1 || true
        
        if [[ -f "$output_dir/network_processes.txt" ]]; then
            local net_proc_count=$(tail -n +2 "$output_dir/network_processes.txt" 2>/dev/null | wc -l)
            echo -e "  ${GREEN}[+]${NC} Found $net_proc_count processes with network activity"
            
            echo -e "\n  ${CYAN}Processes with Network Connections:${NC}"
            tail -n +2 "$output_dir/network_processes.txt" | awk '{print $1}' | sort -u | head -15 | while IFS= read -r proc; do
                local count=$(grep -c "^$proc " "$output_dir/network_processes.txt" 2>/dev/null || echo "0")
                echo -e "    ${CYAN}->${NC} $proc ($count connections)"
            done
        fi
    fi
    
    # Processes with open files
    echo -e "\n${YELLOW}[*] Capturing open files (this may take a moment)...${NC}"
    if command -v lsof &> /dev/null; then
        timeout 30 sudo lsof > "$output_dir/open_files.txt" 2>&1 || true
        if [[ -f "$output_dir/open_files.txt" ]]; then
            local open_files_count=$(wc -l < "$output_dir/open_files.txt")
            echo -e "  ${GREEN}[+]${NC} Captured $open_files_count open file handles"
        fi
    fi
    
    # Check for suspicious process names
    echo -e "\n${YELLOW}[*] Scanning for suspicious process names...${NC}"
    local suspicious_patterns=("nc" "ncat" "socat" "telnet" "meterpreter" "msf" "mimikatz" "beacon" "stager" "payload")
    local susp_proc_found=0
    for pattern in "${suspicious_patterns[@]}"; do
        if grep -iq "$pattern" "$output_dir/process_list.txt" 2>/dev/null; then
            matches=$(grep -i "$pattern" "$output_dir/process_list.txt" | head -3)
            if [[ -n "$matches" ]]; then
                echo -e "  ${RED}[!]${NC}  Potentially suspicious: processes matching '$pattern'"
                echo "$matches" | while IFS= read -r line; do
                    echo -e "     ${RED}->${NC} $line"
                    alert "HIGH" "SUSPICIOUS_PROCESS" "Found process matching suspicious pattern '$pattern': $line"
                done
                susp_proc_found=$((susp_proc_found + 1))
            fi
        fi
    done
    if [[ $susp_proc_found -eq 0 ]]; then
        echo -e "  ${GREEN}[+]${NC} No obviously suspicious process names detected"
    fi
    
    # Memory usage information
    echo -e "\n${YELLOW}[*] Capturing memory usage...${NC}"
    vm_stat > "$output_dir/vm_stats.txt" 2>&1 || true
    
    if [[ -f "$output_dir/vm_stats.txt" ]]; then
        echo -e "\n  ${CYAN}Memory Statistics:${NC}"
        grep -E "Pages free|Pages active|Pages inactive|Pages wired" "$output_dir/vm_stats.txt" 2>/dev/null | head -4 | while IFS= read -r line; do
            echo -e "    ${CYAN}->${NC} $line"
        done
    fi
    
    # System calls (using fs_usage for a short period)
    echo -e "\n${YELLOW}[*] Sampling network system calls (5 seconds)...${NC}"
    timeout 5 sudo fs_usage -w -f network > "$output_dir/fs_usage.txt" 2>&1 || true
    
    if [[ -f "$output_dir/fs_usage.txt" ]]; then
        local syscall_count=$(wc -l < "$output_dir/fs_usage.txt")
        echo -e "  ${GREEN}[+]${NC} Captured $syscall_count network system calls"
        
        echo -e "\n  ${CYAN}Most Active Network Processes (by syscalls):${NC}"
        awk '{print $2}' "$output_dir/fs_usage.txt" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while IFS= read -r line; do
            echo -e "    ${CYAN}->${NC} $line"
        done
    fi
    
    # Process tree
    echo -e "\n${YELLOW}[*] Capturing process tree...${NC}"
    pstree 2>/dev/null > "$output_dir/process_tree.txt" || ps axjf > "$output_dir/process_tree.txt" 2>&1 || true
    echo -e "  ${GREEN}[+]${NC} Process tree captured"
    
    # Check for processes running from temp directories
    echo -e "\n${YELLOW}[*] Checking for processes running from temporary locations...${NC}"
    local temp_proc_found=0
    if ps aux | grep -E "$DESKTOP_DIR/|/var$DESKTOP_DIR/|/private$DESKTOP_DIR/" | grep -v grep > "$output_dir/temp_processes.txt" 2>&1; then
        temp_proc_found=$(wc -l < "$output_dir/temp_processes.txt")
        if [[ $temp_proc_found -gt 0 ]]; then
            echo -e "  ${YELLOW}[!]${NC}  Found $temp_proc_found processes running from temp directories"
            head -5 "$output_dir/temp_processes.txt" | while IFS= read -r line; do
                echo -e "     ${YELLOW}->${NC} $line"
                alert "MEDIUM" "TEMP_PROCESS" "Process running from temp directory: $line"
            done
        fi
    fi
    if [[ $temp_proc_found -eq 0 ]]; then
        echo -e "  ${GREEN}[+]${NC} No processes running from temp directories"
    fi
    
    echo -e "\n${GREEN}[[+]] Process memory analysis complete${NC}"
    log "INFO" "Process memory analysis complete"
}

collect_persistence() {
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|            PERSISTENCE MECHANISM DETECTION                       |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Starting persistence detection"
    
    local output_dir="$REPORT_DIR/persistence"
    
    # Function to check and list directory contents
    check_directory() {
        local dir="$1"
        local description="$2"
        
        echo -e "\n${YELLOW}[*] Checking: $description${NC}"
        echo "=== $description ===" >> "$output_dir/all_persistence.txt"
        echo "Location: $dir" >> "$output_dir/all_persistence.txt"
        
        if [ -d "$dir" ]; then
            local count=$(ls -1 "$dir" 2>/dev/null | wc -l | tr -d ' ')
            echo -e "  ${GREEN}[+]${NC} Found $count items in $dir"
            echo "Status: Directory exists ($count items)" >> "$output_dir/all_persistence.txt"
            echo "" >> "$output_dir/all_persistence.txt"
            ls -la "$dir" 2>/dev/null >> "$output_dir/all_persistence.txt"
            echo "" >> "$output_dir/all_persistence.txt"
            
            # Display first few items to terminal
            if [ "$count" -gt 0 ]; then
                echo -e "  ${CYAN}Items found:${NC}"
                ls -1 "$dir" 2>/dev/null | head -5 | while IFS= read -r item; do
                    echo -e "    ${CYAN}->${NC} $item"
                done
                if [ "$count" -gt 5 ]; then
                    echo -e "    ${YELLOW}... and $((count - 5)) more${NC}"
                fi
                
                # Show content of plist files if any exist
                echo "--- Plist Details ---" >> "$output_dir/all_persistence.txt"
                for file in "$dir"/*.plist; do
                    if [ -f "$file" ]; then
                        echo "File: $(basename "$file")" >> "$output_dir/all_persistence.txt"
                        echo "  Label: $(defaults read "$file" Label 2>/dev/null || echo "N/A")" >> "$output_dir/all_persistence.txt"
                        echo "  Program: $(defaults read "$file" Program 2>/dev/null || echo "N/A")" >> "$output_dir/all_persistence.txt"
                        echo "  RunAtLoad: $(defaults read "$file" RunAtLoad 2>/dev/null || echo "N/A")" >> "$output_dir/all_persistence.txt"
                        echo "  KeepAlive: $(defaults read "$file" KeepAlive 2>/dev/null || echo "N/A")" >> "$output_dir/all_persistence.txt"
                        echo "" >> "$output_dir/all_persistence.txt"
                    fi
                done 2>/dev/null
            fi
        else
            echo -e "  ${YELLOW}[X]${NC} Directory does not exist"
            echo "Status: Directory does not exist" >> "$output_dir/all_persistence.txt"
            echo "" >> "$output_dir/all_persistence.txt"
        fi
        echo "---" >> "$output_dir/all_persistence.txt"
        echo "" >> "$output_dir/all_persistence.txt"
    }

    # System-wide Launch Daemons (run as root)
    {
    check_directory "/Library/LaunchDaemons" "System Launch Daemons"
    check_directory "/System/Library/LaunchDaemons" "Apple System Launch Daemons"

    # System-wide Launch Agents (run in user context)
    check_directory "/Library/LaunchAgents" "System Launch Agents"
    check_directory "/System/Library/LaunchAgents" "Apple System Launch Agents"

    # User-specific Launch Agents
    check_directory "$HOME/Library/LaunchAgents" "User Launch Agents (Current User)"

    # Check all user directories if running with appropriate permissions
    if [ -d "/Users" ]; then
        echo -e "\n${YELLOW}[*] Scanning all users' launch agents...${NC}"
        echo "=== All Users' Launch Agents ===" >> "$output_dir/all_persistence.txt"
        local user_count=0
        for user_dir in /Users/*; do
            if [ -d "$user_dir/Library/LaunchAgents" ]; then
                username=$(basename "$user_dir")
                user_count=$((user_count + 1))
                echo -e "  ${CYAN}->${NC} Found launch agents for user: $username"
                echo "User: $username" >> "$output_dir/all_persistence.txt"
                ls -la "$user_dir/Library/LaunchAgents" 2>/dev/null >> "$output_dir/all_persistence.txt"
                echo "" >> "$output_dir/all_persistence.txt"
            fi
        done
        echo -e "  ${GREEN}[+]${NC} Scanned $user_count user directories"
        echo "---" >> "$output_dir/all_persistence.txt"
        echo "" >> "$output_dir/all_persistence.txt"
    fi

    # Deprecated but still checked locations
    check_directory "/Library/StartupItems" "Legacy Startup Items (Deprecated)"
    check_directory "/System/Library/StartupItems" "Legacy System Startup Items (Deprecated)"

    # Additional locations
    check_directory "/private/var/root/Library/LaunchAgents" "Root User Launch Agents"
    check_directory "/Library/PrivilegedHelperTools" "Privileged Helper Tools"

    # Running launch services
    echo -e "\n${YELLOW}[*] Capturing currently running launch services...${NC}"
    echo "=== Currently Running Launch Services ===" >> "$output_dir/all_persistence.txt"
    echo "Using: launchctl list" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"
    launchctl list 2>/dev/null >> "$output_dir/all_persistence.txt"
    local service_count=$(launchctl list 2>/dev/null | wc -l)
    echo -e "  ${GREEN}[+]${NC} Captured $service_count running services"
    echo "" >> "$output_dir/all_persistence.txt"
    echo "---" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"

    # Bootstrap services (macOS 10.11+)
    echo -e "\n${YELLOW}[*] Checking bootstrap services...${NC}"
    echo "=== Bootstrap Services (GUI) ===" >> "$output_dir/all_persistence.txt"
    launchctl print gui/$(id -u) 2>/dev/null | grep -A 3 "services = {" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"
    echo "---" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"

    echo "=== Bootstrap Services (System) ===" >> "$output_dir/all_persistence.txt"
    launchctl print system 2>/dev/null | grep -A 3 "services = {" | head -20 >> "$output_dir/all_persistence.txt"
    echo "(Showing first 20 lines, system has many services...)" >> "$output_dir/all_persistence.txt"
    echo -e "  ${GREEN}[+]${NC} Bootstrap services captured"
    echo "" >> "$output_dir/all_persistence.txt"
    echo "---" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"

    # Check for disabled services
    echo -e "\n${YELLOW}[*] Checking disabled services...${NC}"
    echo "=== Disabled Services ===" >> "$output_dir/all_persistence.txt"
    launchctl print-disabled system 2>/dev/null >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"
    launchctl print-disabled gui/$(id -u) 2>/dev/null >> "$output_dir/all_persistence.txt"
    echo -e "  ${GREEN}[+]${NC} Disabled services captured"
    echo "" >> "$output_dir/all_persistence.txt"
    echo "---" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"

    # Search for any plist files that might be launch items
    echo -e "\n${YELLOW}[*] Searching for all launch-related plist files...${NC}"
    echo "=== Searching for Launch-Related Plist Files ===" >> "$output_dir/all_persistence.txt"
    echo "Searching in /Library and ~/Library..." >> "$output_dir/all_persistence.txt"
    find /Library -name "*.plist" -path "*/Launch*" 2>/dev/null | head -20 >> "$output_dir/all_persistence.txt"
    find "$HOME/Library" -name "*.plist" -path "*/Launch*" 2>/dev/null >> "$output_dir/all_persistence.txt"
    local plist_count=$(find /Library -name "*.plist" -path "*/Launch*" 2>/dev/null | wc -l)
    echo -e "  ${GREEN}[+]${NC} Found $plist_count launch-related plist files"
    echo "" >> "$output_dir/all_persistence.txt"
    echo "---" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"

    # Check for XPC services
    check_directory "/System/Library/XPCServices" "System XPC Services"
    check_directory "/Library/XPCServices" "Library XPC Services"
    check_directory "$HOME/Library/XPCServices" "User XPC Services"

    # Check for cron jobs
    echo -e "\n${YELLOW}[*] Checking cron jobs...${NC}"
    echo "=== Cron Jobs ===" >> "$output_dir/all_persistence.txt"
    echo "System crontab:" >> "$output_dir/all_persistence.txt"
    sudo crontab -l 2>/dev/null >> "$output_dir/all_persistence.txt" || echo "No system crontab" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"
    echo "User crontab:" >> "$output_dir/all_persistence.txt"
    crontab -l 2>/dev/null >> "$output_dir/all_persistence.txt" || echo "No user crontab" >> "$output_dir/all_persistence.txt"
    
    if sudo crontab -l 2>/dev/null | grep -q .; then
        echo -e "  ${YELLOW}[!]${NC}  System crontab has entries"
        alert "MEDIUM" "CRON_PERSISTENCE" "System crontab contains entries"
    else
        echo -e "  ${GREEN}[+]${NC} No system crontab"
    fi
    
    if crontab -l 2>/dev/null | grep -q .; then
        echo -e "  ${YELLOW}[!]${NC}  User crontab has entries"
    else
        echo -e "  ${GREEN}[+]${NC} No user crontab"
    fi
    
    echo "" >> "$output_dir/all_persistence.txt"
    echo "---" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"

    # Check /etc periodic scripts
    echo -e "\n${YELLOW}[*] Checking periodic scripts...${NC}"
    echo "=== Periodic Scripts ===" >> "$output_dir/all_persistence.txt"
    for period in daily weekly monthly; do
        echo "$period scripts:" >> "$output_dir/all_persistence.txt"
        ls -la "/etc/periodic/$period" 2>/dev/null >> "$output_dir/all_persistence.txt" || echo "None found" >> "$output_dir/all_persistence.txt"
        echo "" >> "$output_dir/all_persistence.txt"
        
        local period_count=$(ls -1 "/etc/periodic/$period" 2>/dev/null | wc -l)
        if [ "$period_count" -gt 0 ]; then
            echo -e "  ${GREEN}[+]${NC} Found $period_count $period scripts"
        fi
    done
    echo -e "  ${GREEN}[+]${NC} Periodic scripts captured"
    echo "---" >> "$output_dir/all_persistence.txt"
    echo "" >> "$output_dir/all_persistence.txt"
    } > "$output_dir/all_persistence.txt" 2>&1
    
    # Cron jobs (macOS still supports these)
    echo -e "${YELLOW}[*] Checking cron jobs...${NC}"
    crontab -l > "$output_dir/user_crontab.txt" 2>/dev/null || true
    sudo crontab -l > "$output_dir/root_crontab.txt" 2>/dev/null || true
    ls -la /etc/cron* > "$output_dir/system_cron.txt" 2>/dev/null || true
    
    # Login items
    echo -e "${YELLOW}[*] Checking login items...${NC}"
    osascript -e 'tell application "System Events" to get the name of every login item' > "$output_dir/login_items.txt" 2>&1 || true
    
    # User login scripts
    echo -e "${YELLOW}[*] Checking user login scripts...${NC}"
    {
        echo "=== ~/.zshrc ==="
        [[ -f ~/.zshrc ]] && cat ~/.zshrc 2>/dev/null
        echo ""
        echo "=== ~/.bash_profile ==="
        [[ -f ~/.bash_profile ]] && cat ~/.bash_profile 2>/dev/null
        echo ""
        echo "=== ~/.bashrc ==="
        [[ -f ~/.bashrc ]] && cat ~/.bashrc 2>/dev/null
        echo ""
        echo "=== ~/.profile ==="
        [[ -f ~/.profile ]] && cat ~/.profile 2>/dev/null
    } > "$output_dir/user_login_scripts.txt"
    
    # SSH configuration
    echo -e "${YELLOW}[*] Checking SSH configuration...${NC}"
    ls -la ~/.ssh/ > "$output_dir/ssh_config.txt" 2>/dev/null || true
    cat ~/.ssh/authorized_keys > "$output_dir/ssh_authorized_keys.txt" 2>/dev/null || true
    
    # Kernel extensions (deprecated but check anyway)
    echo -e "${YELLOW}[*] Checking kernel extensions...${NC}"
    kextstat > "$output_dir/kernel_extensions.txt" 2>&1 || true
    
    # System extensions (new macOS)
    echo -e "${YELLOW}[*] Checking system extensions...${NC}"
    systemextensionsctl list > "$output_dir/system_extensions.txt" 2>&1 || true
    
    echo -e "${GREEN}[[+]] Persistence detection complete${NC}"
    log "INFO" "Persistence detection complete"
}

collect_shell_abuse() {
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|                SHELL ABUSE DETECTION                             |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Starting shell abuse detection"
    
    local output_dir="$REPORT_DIR/logs"
    
    # Shell history files
    echo -e "${YELLOW}[*] Capturing shell histories...${NC}"
    {
        echo "=== Bash History ==="
        cat ~/.bash_history 2>/dev/null | tail -200 || echo "No bash history"
        echo ""
        echo "=== Zsh History ==="
        cat ~/.zsh_history 2>/dev/null | tail -200 || echo "No zsh history"
    } > "$output_dir/shell_history.txt"
    
    # Recent commands
    echo -e "${YELLOW}[*] Capturing recent commands...${NC}"
    history > "$output_dir/current_history.txt" 2>/dev/null || true
    
    # Environment variables
    echo -e "${YELLOW}[*] Capturing environment variables...${NC}"
    env > "$output_dir/environment_vars.txt" 2>/dev/null || true
    
    # Check for suspicious environment variables
    echo -e "${YELLOW}[*] Checking for suspicious environment variables...${NC}"
    if env | grep -iE "(DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH)" > /dev/null 2>&1; then
        alert "MEDIUM" "SUSPICIOUS_ENV" "Suspicious environment variables detected (DYLD_INSERT_LIBRARIES/DYLD_LIBRARY_PATH)"
    fi
    
    # Shell profiles
    echo -e "${YELLOW}[*] Checking shell profiles...${NC}"
    {
        echo "=== ~/.zshrc ==="
        [[ -f ~/.zshrc ]] && cat ~/.zshrc 2>/dev/null
        echo ""
        echo "=== ~/.bash_profile ==="
        [[ -f ~/.bash_profile ]] && cat ~/.bash_profile 2>/dev/null
        echo ""
        echo "=== ~/.bashrc ==="
        [[ -f ~/.bashrc ]] && cat ~/.bashrc 2>/dev/null
    } > "$output_dir/shell_profiles.txt"
    
    echo -e "${GREEN}[[+]] Shell abuse detection complete${NC}"
    log "INFO" "Shell abuse detection complete"
}

collect_kernel_analysis() {
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|                 KERNEL ANALYSIS                                  |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Starting kernel analysis"
    
    local output_dir="$REPORT_DIR/network_state"
    
    # Kernel version and info
    echo -e "${YELLOW}[*] Gathering kernel information...${NC}"
    {
        echo "=== Kernel Version ==="
        uname -a
        echo ""
        echo "=== System Info ==="
        system_profiler SPSoftwareDataType
        echo ""
        echo "=== Loaded Kernel Extensions ==="
        sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "(.kext)"
        echo ""
        echo "=== Kernel Boot Arguments ==="
        nvram boot-args 2>/dev/null || echo "Unable to read boot-args"
    } > "$output_dir/kernel_info.txt"
    
    # Kernel network parameters (sysctl on macOS)
    echo -e "${YELLOW}[*] Gathering kernel network parameters...${NC}"
    sysctl -a 2>/dev/null | grep -i net > "$output_dir/kernel_network_params.txt" 2>/dev/null || true
    
    # Network interface statistics
    echo -e "${YELLOW}[*] Gathering interface statistics...${NC}"
    if [ ${#DISCOVERED_INTERFACES[@]} -gt 0 ]; then
        for iface in "${DISCOVERED_INTERFACES[@]}"; do
            netstat -I "$iface" > "$output_dir/stats_$iface.txt" 2>/dev/null || true
        done
    else
        echo "No interfaces to gather statistics for" > "$output_dir/stats_none.txt"
    fi
    
    # IP forwarding status
    echo -e "${YELLOW}[*] Checking IP forwarding status...${NC}"
    sysctl net.inet.ip.forwarding > "$output_dir/ip_forwarding.txt" 2>/dev/null || true
    
    # System integrity
    echo -e "${YELLOW}[*] Checking system integrity...${NC}"
    csrutil status > "$output_dir/sip_status.txt" 2>&1 || true
    
    echo -e "${GREEN}[[+]] Kernel analysis complete${NC}"
    log "INFO" "Kernel analysis complete"
}

collect_network_config_abuse() {
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|           NETWORK CONFIGURATION ABUSE DETECTION                  |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Starting network config abuse detection"
    
    local output_dir="$REPORT_DIR/network_state"
    
    # Network configuration
    echo -e "${YELLOW}[*] Capturing network configuration...${NC}"
    {
        echo "=== Network Services ==="
        networksetup -listallnetworkservices
        echo ""
        echo "=== Active Network Service ==="
        for service in $(networksetup -listallnetworkservices | grep -v "*"); do
            echo "--- $service ---"
            networksetup -getinfo "$service" 2>/dev/null
        done
        echo ""
        echo "=== DNS Servers ==="
        networksetup -getdnsservers Wi-Fi 2>/dev/null
        networksetup -getdnsservers Ethernet 2>/dev/null
        echo ""
        echo "=== Proxies ==="
        networksetup -getwebproxy Wi-Fi 2>/dev/null
        networksetup -getsecurewebproxy Wi-Fi 2>/dev/null
        networksetup -getsocksfirewallproxy Wi-Fi 2>/dev/null
        echo ""
        echo "=== Routing Table ==="
        netstat -rn
        echo ""
        echo "=== DNS Resolution Config ==="
        scutil --dns
    } > "$output_dir/network_config.txt"
    
    # Firewall status
    echo -e "${YELLOW}[*] Checking firewall configuration...${NC}"
    {
        echo "=== Firewall Status ==="
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
        echo ""
        echo "=== Firewall Logging ==="
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode
        echo ""
        echo "=== Firewall Stealth Mode ==="
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
        echo ""
        echo "=== Firewall Applications ==="
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
        echo ""
        echo "=== PF Rules (Packet Filter) ==="
        sudo pfctl -s rules 2>/dev/null || echo "PF not enabled"
    } > "$output_dir/firewall_config.txt" 2>&1 || true
    
    # Hosts file
    echo -e "${YELLOW}[*] Checking hosts file...${NC}"
    cat /etc/hosts > "$output_dir/hosts_file.txt" 2>&1 || true
    
    # Network namespaces (limited on macOS)
    echo -e "${YELLOW}[*] Checking network interfaces details...${NC}"
    ifconfig -a > "$output_dir/ifconfig_all.txt" 2>&1 || true
    
    echo -e "${GREEN}[[+]] Network config abuse detection complete${NC}"
    log "INFO" "Network config abuse detection complete"
}

collect_browser_app_data() {
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|            BROWSER & APPLICATION DATA COLLECTION                 |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Starting browser/app data collection"
    
    local output_dir="$REPORT_DIR/exports"
    
    # Running applications
    echo -e "${YELLOW}[*] Capturing running applications...${NC}"
    {
        echo "=== Running Applications (ps) ==="
        ps aux | grep -i "\.app" | grep -v grep
        echo ""
        echo "=== All Running Processes ==="
        ps aux
        echo ""
        echo "=== Login Items ==="
        osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null
    } > "$output_dir/running_apps.txt" 2>&1 || true
    
    # Browser extensions (basic check)
    echo -e "${YELLOW}[*] Checking for browser data...${NC}"
    {
        echo "=== Chrome Extensions ==="
        if [[ -d ~/Library/Application\ Support/Google/Chrome/Default/Extensions/ ]]; then
            ls -la ~/Library/Application\ Support/Google/Chrome/Default/Extensions/ 2>/dev/null
        else
            echo "Chrome extensions directory not found"
        fi
        echo ""
        echo "=== Safari Extensions ==="
        if [[ -d ~/Library/Safari/Extensions/ ]]; then
            ls -la ~/Library/Safari/Extensions/ 2>/dev/null
        else
            echo "Safari extensions directory not found"
        fi
        echo ""
        echo "=== Firefox Addons ==="
        if [[ -d ~/Library/Application\ Support/Firefox/Profiles/ ]]; then
            find ~/Library/Application\ Support/Firefox/Profiles/ -name "extensions" -exec ls -la {} \; 2>/dev/null
        else
            echo "Firefox profiles directory not found"
        fi
    } > "$output_dir/browser_data.txt"
    
    # Browser history (Chrome/Chromium) - macOS path
    if [[ -d ~/Library/Application\ Support/Google/Chrome ]]; then
        echo -e "${YELLOW}[*] Extracting Chrome history...${NC}"
        if command -v sqlite3 &> /dev/null; then
            find ~/Library/Application\ Support/Google/Chrome -name "History" -exec sqlite3 {} "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000" \; > "$output_dir/chrome_history.txt" 2>/dev/null || true
        fi
    fi
    
    # Browser history (Firefox) - macOS path
    if [[ -d ~/Library/Application\ Support/Firefox ]]; then
        echo -e "${YELLOW}[*] Extracting Firefox history...${NC}"
        if command -v sqlite3 &> /dev/null; then
            find ~/Library/Application\ Support/Firefox/Profiles/ -name "places.sqlite" -exec sqlite3 {} "SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 1000" \; > "$output_dir/firefox_history.txt" 2>/dev/null || true
        fi
    fi
    
    # Safari history - macOS specific
    if [[ -f ~/Library/Safari/History.db ]]; then
        echo -e "${YELLOW}[*] Extracting Safari history...${NC}"
        if command -v sqlite3 &> /dev/null; then
            sqlite3 ~/Library/Safari/History.db "SELECT url, title, visit_time FROM history_visits INNER JOIN history_items ON history_visits.history_item = history_items.id ORDER BY visit_time DESC LIMIT 1000" > "$output_dir/safari_history.txt" 2>/dev/null || true
        fi
    fi
    
    echo -e "${GREEN}[[+]] Browser/app data collection complete${NC}"
    log "INFO" "Browser/app data collection complete"
}

# =============================================================================
# PACKET CAPTURE (macOS adapted)
# =============================================================================

start_capture() {
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|                    STARTING PACKET CAPTURE                       |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Starting packet capture"
    
    # Validate we have interfaces
    if [ ${#DISCOVERED_INTERFACES[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] WARNING: No interfaces discovered, attempting capture anyway${NC}"
        log "WARN" "No interfaces discovered, capture may fail"
    fi
    
    # Create pcaps directory with error checking
    if ! mkdir -p "$REPORT_DIR/pcaps" 2>/dev/null; then
        echo -e "${RED}[!] ERROR: Cannot create pcaps directory${NC}"
        log "ERROR" "Failed to create pcaps directory"
        return 1
    fi
    
    # Main capture on all interfaces
    # Note: macOS tcpdump uses slightly different syntax
    echo -e "${YELLOW}[*] Launching main packet capture...${NC}"
    sudo tcpdump \
        -i any \
        -n \
        -s "$SNAPLEN" \
        -w "$PCAP_FILE" \
        2>>"$LOG_FILE" &
    TCPDUMP_PIDS+=($!)
    echo -e "    ${GREEN}[[+]] Main capture started (PID: $!)${NC}"
    
    # Raw packet capture (backup)
    echo -e "${YELLOW}[*] Launching raw backup capture...${NC}"
    sudo tcpdump \
        -i any \
        -n \
        -s "$SNAPLEN" \
        -w "$RAW_PCAP_FILE" \
        2>>"$LOG_FILE" &
    TCPDUMP_PIDS+=($!)
    echo -e "    ${GREEN}[[+]] Raw capture started (PID: $!)${NC}"
    
    # ICMP capture for tunneling detection
    echo -e "${YELLOW}[*] Launching ICMP capture (tunneling detection)...${NC}"
    sudo tcpdump \
        -i any \
        -n \
        -s "$SNAPLEN" \
        -w "$REPORT_DIR/pcaps/icmp_${TIMESTAMP}.pcap" \
        icmp or icmp6 \
        2>>"$LOG_FILE" &
    TCPDUMP_PIDS+=($!)
    
    # DNS capture (port 53)
    echo -e "${YELLOW}[*] Launching DNS capture...${NC}"
    sudo tcpdump \
        -i any \
        -n \
        -s "$SNAPLEN" \
        -w "$REPORT_DIR/pcaps/dns_${TIMESTAMP}.pcap" \
        port 53 \
        2>>"$LOG_FILE" &
    TCPDUMP_PIDS+=($!)
    
    # DoH capture (HTTPS to known DoH servers)
    echo -e "${YELLOW}[*] Launching DoH capture...${NC}"
    local doh_filter=""
    
    if [ ${#DOH_SERVERS[@]} -gt 0 ]; then
        for server in "${DOH_SERVERS[@]}"; do
            if [[ -z "$doh_filter" ]]; then
                doh_filter="host $server"
            else
                doh_filter="$doh_filter or host $server"
            fi
        done
    else
        # If no DoH servers defined, just capture HTTPS traffic
        doh_filter="port 443"
    fi
    
    sudo tcpdump \
        -i any \
        -n \
        -s "$SNAPLEN" \
        -w "$REPORT_DIR/pcaps/doh_${TIMESTAMP}.pcap" \
        "$doh_filter" \
        2>>"$LOG_FILE" &
    TCPDUMP_PIDS+=($!)
    
    # Suspicious ports capture
    echo -e "${YELLOW}[*] Launching suspicious ports capture...${NC}"
    local port_filter=""
    
    if [ ${#SUSPICIOUS_PORTS[@]} -gt 0 ]; then
        for port in "${SUSPICIOUS_PORTS[@]}"; do
            if [[ -z "$port_filter" ]]; then
                port_filter="port $port"
            else
                port_filter="$port_filter or port $port"
            fi
        done
    else
        # If no suspicious ports defined, capture high ports
        port_filter="portrange 40000-65535"
    fi
    
    sudo tcpdump \
        -i any \
        -n \
        -s "$SNAPLEN" \
        -w "$REPORT_DIR/pcaps/suspicious_ports_${TIMESTAMP}.pcap" \
        "$port_filter" \
        2>>"$LOG_FILE" &
    TCPDUMP_PIDS+=($!)
    
    # Validate that capture processes started successfully
    echo -e "\n${YELLOW}[*] Validating packet capture processes...${NC}"
    sleep 2
    local failed_captures=0
    local active_captures=0
    
    if [ ${#TCPDUMP_PIDS[@]} -gt 0 ]; then
        for pid in "${TCPDUMP_PIDS[@]}"; do
            if ps -p $pid > /dev/null 2>&1; then
                active_captures=$((active_captures + 1))
            else
                failed_captures=$((failed_captures + 1))
                echo -e "  ${RED}[!]${NC} Capture process $pid failed to start"
                log "ERROR" "Capture process $pid failed"
            fi
        done
    fi
    
    if [[ $active_captures -eq 0 ]]; then
        echo -e "${RED}[!] ERROR: All capture processes failed to start${NC}"
        echo -e "${RED}[!] Check $LOG_FILE for details${NC}"
        log "ERROR" "All capture processes failed to start"
        exit 1
    elif [[ $failed_captures -gt 0 ]]; then
        echo -e "  ${YELLOW}[!]${NC} $failed_captures capture(s) failed, $active_captures running"
    else
        echo -e "  ${GREEN}[[+]]${NC} All $active_captures capture processes running successfully"
    fi
    
    echo -e "    ${GREEN}[[+]] Packet capture operational${NC}"
    log "INFO" "Packet captures validated: $active_captures active, $failed_captures failed"
}

# =============================================================================
# STOP PACKET CAPTURE
# =============================================================================

stop_capture() {
    echo -e "\n${YELLOW}[*] Stopping packet capture...${NC}"
    log "INFO" "Stopping packet capture"
    
    if [ ${#TCPDUMP_PIDS[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No capture processes to stop${NC}"
        return
    fi
    
    local stopped_count=0
    for pid in "${TCPDUMP_PIDS[@]}"; do
        if ps -p $pid > /dev/null 2>&1; then
            # Send TERM signal for graceful shutdown
            if sudo kill -TERM $pid 2>/dev/null; then
                stopped_count=$((stopped_count + 1))
                echo -e "  ${GREEN}[[+]]${NC} Stopped capture process (PID: $pid)"
                log "INFO" "Stopped capture process $pid"
            fi
        fi
    done
    
    # Wait for processes to finish writing
    echo -e "${YELLOW}[*] Waiting for capture files to be finalized...${NC}"
    sleep 3
    
    # Force kill any remaining processes
    for pid in "${TCPDUMP_PIDS[@]}"; do
        if ps -p $pid > /dev/null 2>&1; then
            sudo kill -KILL $pid 2>/dev/null
            echo -e "  ${YELLOW}[!]${NC} Force killed process (PID: $pid)"
        fi
    done
    
    echo -e "${GREEN}[[+]] All capture processes stopped ($stopped_count total)${NC}"
    log "INFO" "Stopped $stopped_count capture processes"
}

# =============================================================================
# CLEANUP FUNCTION
# =============================================================================

cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"
    log "INFO" "Starting cleanup"
    
    # Kill all tcpdump processes - check if array has elements
    if [ ${#TCPDUMP_PIDS[@]} -gt 0 ]; then
        echo -e "${YELLOW}[*] Stopping packet capture processes...${NC}"
        for pid in "${TCPDUMP_PIDS[@]}"; do
            if ps -p $pid > /dev/null 2>&1; then
                # Try graceful termination first
                if sudo kill -TERM $pid 2>/dev/null; then
                    echo -e "${YELLOW}[*] Sent TERM signal to PID: $pid${NC}"
                    # Wait briefly for process to finish
                    sleep 1
                    # Check if still running
                    if ps -p $pid > /dev/null 2>&1; then
                        # Force kill if still running
                        sudo kill -KILL $pid 2>/dev/null
                        echo -e "${YELLOW}[*] Force killed PID: $pid${NC}"
                    fi
                else
                    echo -e "${YELLOW}[*] Process $pid already terminated${NC}"
                fi
            fi
        done
        # Wait for all tcpdump processes to finish writing
        sleep 2
    fi
    
    # Restore interfaces to normal state if needed
    if [ ${#DISCOVERED_INTERFACES[@]} -gt 0 ]; then
        echo -e "${YELLOW}[*] Restoring network interfaces...${NC}"
        for iface in "${DISCOVERED_INTERFACES[@]}"; do
            if [[ "$iface" != "lo0" && "$iface" != "lo" ]]; then
                # Ensure interface is still up
                sudo ifconfig "$iface" up 2>/dev/null || true
            fi
        done
    fi
    
    # Kill the sudo keep-alive process if it exists
    pkill -f "sudo -n true; sleep 50" 2>/dev/null || true
    
    echo -e "${GREEN}[[+]] Cleanup complete${NC}"
    log "INFO" "Cleanup complete"
}

# =============================================================================
# GENERATE FINAL REPORT
# =============================================================================

generate_report() {
    # Stop packet capture before generating report
    stop_capture
    
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|                      GENERATING FINAL REPORT                     |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    log "INFO" "Generating final report"
    
    local report_file="$REPORT_DIR/REPORT_${TIMESTAMP}.txt"
    
    # Display real-time analysis summary to terminal
    echo -e "\n${CYAN}+==================================================================+${NC}"
    echo -e "${CYAN}|                    ANALYSIS SUMMARY                              |${NC}"
    echo -e "${CYAN}+==================================================================+${NC}"
    
    # Count files in each category
    echo -e "\n${YELLOW}[*] Data Collection Summary:${NC}"
    display_stats "C2 Detection" "$REPORT_DIR/c2_detection"
    display_stats "Memory Analysis" "$REPORT_DIR/memory"
    display_stats "Persistence" "$REPORT_DIR/persistence"
    display_stats "Network State" "$REPORT_DIR/network_state"
    display_stats "Logs" "$REPORT_DIR/logs"
    display_stats "Browser Data" "$REPORT_DIR/exports"
    display_stats "PCAP Files" "$REPORT_DIR/pcaps"
    
    # Alert summary
    echo -e "\n${YELLOW}[*] Security Alert Summary:${NC}"
    if [[ -s "$REPORT_DIR/analysis/ALERTS.txt" ]]; then
        local alert_count=$(wc -l < "$REPORT_DIR/analysis/ALERTS.txt" | tr -d ' ')
        local critical_count=$(grep -c "CRITICAL" "$REPORT_DIR/analysis/ALERTS.txt" 2>/dev/null | tr -d ' ' || echo "0")
        local high_count=$(grep -c "HIGH" "$REPORT_DIR/analysis/ALERTS.txt" 2>/dev/null | tr -d ' ' || echo "0")
        local medium_count=$(grep -c "MEDIUM" "$REPORT_DIR/analysis/ALERTS.txt" 2>/dev/null | tr -d ' ' || echo "0")
        local low_count=$(grep -c "LOW" "$REPORT_DIR/analysis/ALERTS.txt" 2>/dev/null | tr -d ' ' || echo "0")
        
        echo -e "  ${RED}[!]${NC}  Total Alerts: $alert_count"
        [[ "$critical_count" -gt 0 ]] 2>/dev/null && echo -e "    ${RED}[X]${NC} CRITICAL: $critical_count"
        [[ "$high_count" -gt 0 ]] 2>/dev/null && echo -e "    ${MAGENTA}[X]${NC} HIGH: $high_count"
        [[ "$medium_count" -gt 0 ]] 2>/dev/null && echo -e "    ${YELLOW}[!]${NC} MEDIUM: $medium_count"
        [[ "$low_count" -gt 0 ]] 2>/dev/null && echo -e "    ${CYAN}[i]${NC} LOW: $low_count"
        
        echo -e "\n  ${CYAN}Recent Alerts:${NC}"
        tail -10 "$REPORT_DIR/analysis/ALERTS.txt" | while IFS= read -r line; do
            echo -e "    ${YELLOW}->${NC} $line"
        done
    else
        echo -e "  ${GREEN}[+]${NC} No security alerts generated"
    fi
    
    # Network connections summary
    echo -e "\n${YELLOW}[*] Network Activity Summary:${NC}"
    if [[ -f "$REPORT_DIR/c2_detection/active_connections.txt" ]]; then
        local est_conn=$(grep -c "ESTABLISHED" "$REPORT_DIR/c2_detection/active_connections.txt" 2>/dev/null || echo "0")
        local listen_ports=$(grep -c "LISTEN" "$REPORT_DIR/c2_detection/active_connections.txt" 2>/dev/null || echo "0")
        echo -e "  ${GREEN}[+]${NC} Active Connections: $est_conn"
        echo -e "  ${GREEN}[+]${NC} Listening Ports: $listen_ports"
    fi
    
    # Process summary
    if [[ -f "$REPORT_DIR/memory/network_processes.txt" ]]; then
        local net_procs=$(tail -n +2 "$REPORT_DIR/memory/network_processes.txt" 2>/dev/null | wc -l)
        echo -e "  ${GREEN}[+]${NC} Processes with Network Activity: $net_procs"
    fi
    
    # PCAP files summary
    echo -e "\n${YELLOW}[*] Captured Traffic:${NC}"
    if [[ -f "$PCAP_FILE" ]]; then
        local pcap_size=$(ls -lh "$PCAP_FILE" 2>/dev/null | awk '{print $5}')
        echo -e "  ${GREEN}[+]${NC} Main PCAP: $pcap_size"
    fi

    local total_pcaps=$(find "$REPORT_DIR/pcaps" -name "*.pcap" 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  ${GREEN}[+]${NC} Total PCAP Files: $total_pcaps"

    # Analyze captured PCAP files for unique IPs and display summary
    if [[ "$total_pcaps" -gt 0 ]]; then
        echo -e "\n  ${YELLOW}[*] Analyzing PCAP captures...${NC}"
        local ip_output="$REPORT_DIR/analysis/unique_ips.txt"
        local temp_ips="$DESKTOP_DIR/temp_ips_${TIMESTAMP}.txt"
        
        # Extract IPs from all PCAP files
        > "$temp_ips"
        find "$REPORT_DIR/pcaps" / -type f -path "*/System/*" 2>/dev/null | grep -E "(.pcap)" | while read -r pcap_file; do
            tcpdump -nn -r "$pcap_file" 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' >> "$temp_ips"
        done
        
        # Deduplicate and save
        sort -u "$temp_ips" > "$ip_output"
        rm -f "$temp_ips"
        
        local ip_count
        ip_count=$(wc -l < "$ip_output" 2>/dev/null | tr -d ' ')
        
        if [[ "$ip_count" -gt 0 ]]; then
            echo -e "  ${GREEN}[+]${NC} Found $ip_count unique IPv4 addresses"
            echo -e "  ${CYAN}->${NC} Saved to: $ip_output"
            
            # Display first 10 IPs
            echo -e "\n  ${CYAN}Sample IPs (first 10):${NC}"
            head -10 "$ip_output" | while read ip; do
                echo -e "    ${YELLOW}*${NC} $ip"
            done
            
            if [[ "$ip_count" -gt 10 ]]; then
                echo -e "    ${YELLOW}... and $((ip_count - 10)) more${NC}"
            fi
        else
            echo -e "  ${YELLOW}[!]${NC} No IP addresses found in captures"
        fi
        
        # Show packet counts per PCAP
        echo -e "\n  ${CYAN}PCAP File Statistics:${NC}"
        find "$REPORT_DIR/pcaps" -name "*.pcap" 2>/dev/null | while read -r pcap_file; do
            local pcap_name=$(basename "$pcap_file")
            local packet_count=$(tcpdump -r "$pcap_file" 2>/dev/null | wc -l | tr -d ' ')
            local file_size=$(ls -lh "$pcap_file" | awk '{print $5}')
            echo -e "    ${GREEN}[+]${NC} $pcap_name: $packet_count packets ($file_size)"
        done
    else
        echo -e "  ${YELLOW}[!]${NC} No PCAP files captured"
    fi
    
    # Generate file report
    {
        echo "============================================================================="
        echo "Network Analysis Report - macOS Edition"
        echo "Generated: $(date)"
        echo "Duration: ${CAPTURE_DURATION} seconds"
        echo "System: $(uname -a)"
        echo "============================================================================="
        echo ""
        echo "PCAP Files:"
        echo "-----------"
        find "$REPORT_DIR/pcaps" -name "*.pcap" -ls 2>/dev/null
        echo ""
        echo "Main PCAP: $PCAP_FILE"
        echo "Raw PCAP: $RAW_PCAP_FILE"
        echo ""
        echo "============================================================================="
        echo "ALERTS SUMMARY"
        echo "============================================================================="
        if [[ -s "$REPORT_DIR/analysis/ALERTS.txt" ]]; then
            cat "$REPORT_DIR/analysis/ALERTS.txt"
        else
            echo "No alerts generated."
        fi
        echo ""
        echo "============================================================================="
        echo "ANALYSIS FILES"
        echo "============================================================================="
        echo "C2 Detection Files:"
        ls -lh "$REPORT_DIR/c2_detection/" 2>/dev/null || echo "  No C2 detection files"
        echo ""
        echo "Memory Analysis Files:"
        ls -lh "$REPORT_DIR/memory/" 2>/dev/null || echo "  No memory files"
        echo ""
        echo "Persistence Analysis Files:"
        ls -lh "$REPORT_DIR/persistence/" 2>/dev/null || echo "  No persistence files"
        echo ""
        echo "Network State Files:"
        ls -lh "$REPORT_DIR/network_state/" 2>/dev/null || echo "  No network state files"
        echo ""
        echo "Log Files:"
        ls -lh "$REPORT_DIR/logs/" 2>/dev/null || echo "  No log files"
        echo ""
        echo "Exported Data Files:"
        ls -lh "$REPORT_DIR/exports/" 2>/dev/null || echo "  No exported data"
        echo ""
        echo "============================================================================="
        echo "CAPTURED DATA LOCATIONS"
        echo "============================================================================="
        echo "Report Directory: $REPORT_DIR"
        echo ""
        echo "Subdirectories:"
        find "$REPORT_DIR" -type d | sed 's/^/  /'
        echo ""
        echo "============================================================================="
        echo "FILE COUNTS"
        echo "============================================================================="
        echo "Total files captured: $(find "$REPORT_DIR" -type f | wc -l)"
        echo ""
        echo "By category:"
        echo "  - PCAP files: $(find "$REPORT_DIR" -name "*.pcap" | wc -l)"
        echo "  - Text files: $(find "$REPORT_DIR" -name "*.txt" | wc -l)"
        echo "  - Log files: $(find "$REPORT_DIR" -name "*.log" | wc -l)"
        echo ""
        echo "============================================================================="
        echo "NEXT STEPS"
        echo "============================================================================="
        echo "1. Analyze PCAP files with Wireshark:"
        echo "   open -a Wireshark $PCAP_FILE"
        echo ""
        echo "2. Review analysis files in subdirectories:"
        echo "   - $REPORT_DIR/c2_detection/"
        echo "   - $REPORT_DIR/persistence/"
        echo "   - $REPORT_DIR/memory/"
        echo "   - $REPORT_DIR/network_state/"
        echo ""
        echo "3. Check for suspicious activity:"
        echo "   - Unusual ports in suspicious_ports_*.pcap"
        echo "   - DNS queries in dns_*.pcap"
        echo "   - DoH traffic in doh_*.pcap"
        echo ""
        echo "4. Review alerts:"
        echo "   cat $REPORT_DIR/analysis/ALERTS.txt"
        echo ""
    } > "$report_file"
    
    echo -e "    ${GREEN}[[+]] Report generated: $report_file${NC}"
    log "INFO" "Report generated: $report_file"
    
    # Generate comprehensive combined report
    echo -e "\n${YELLOW}[*] Generating comprehensive combined analysis report...${NC}"
    local combined_report="$DESKTOP_DIR/COMBINED_ANALYSIS_${TIMESTAMP}.txt"
    
    {
        echo "============================================================================="
        echo "COMPREHENSIVE NETWORK & MALWARE ANALYSIS REPORT"
        echo "============================================================================="
        echo "Generated: $(date)"
        echo "Duration: ${CAPTURE_DURATION} seconds"
        echo "System: $(uname -a)"
        echo "Hostname: $(hostname)"
        echo "User: $(whoami)"
        echo "Report Directory: $REPORT_DIR"
        echo "============================================================================="
        echo ""
        echo ""
        
        # C2 DETECTION SECTION
        echo "==========================================================================="
        echo "                       C2 & NETWORK DETECTION ANALYSIS"
        echo "==========================================================================="
        echo ""
        
        for file in "$REPORT_DIR/c2_detection"/*.txt; do
            if [[ -f "$file" ]]; then
                echo "-----------------------------------------------------------------------"
                echo "FILE: $(basename "$file")"
                echo "-----------------------------------------------------------------------"
                cat "$file"
                echo ""
                echo ""
            fi
        done
        
        # MEMORY ANALYSIS SECTION
        echo "==========================================================================="
        echo "                         PROCESS & MEMORY ANALYSIS"
        echo "==========================================================================="
        echo ""
        
        for file in "$REPORT_DIR/memory"/*.txt; do
            if [[ -f "$file" ]]; then
                echo "-----------------------------------------------------------------------"
                echo "FILE: $(basename "$file")"
                echo "-----------------------------------------------------------------------"
                cat "$file"
                echo ""
                echo ""
            fi
        done
        
        # PERSISTENCE ANALYSIS SECTION
        echo "==========================================================================="
        echo "                       PERSISTENCE MECHANISM ANALYSIS"
        echo "==========================================================================="
        echo ""
        
        for file in "$REPORT_DIR/persistence"/*.txt; do
            if [[ -f "$file" ]]; then
                echo "-----------------------------------------------------------------------"
                echo "FILE: $(basename "$file")"
                echo "-----------------------------------------------------------------------"
                cat "$file"
                echo ""
                echo ""
            fi
        done
        
        # NETWORK STATE SECTION
        echo "==========================================================================="
        echo "                           NETWORK STATE ANALYSIS"
        echo "==========================================================================="
        echo ""
        
        for file in "$REPORT_DIR/network_state"/*.txt; do
            if [[ -f "$file" ]]; then
                echo "-----------------------------------------------------------------------"
                echo "FILE: $(basename "$file")"
                echo "-----------------------------------------------------------------------"
                cat "$file"
                echo ""
                echo ""
            fi
        done
        
        # SHELL & LOG ANALYSIS SECTION
        echo "==========================================================================="
        echo "                         SHELL & LOG ANALYSIS"
        echo "==========================================================================="
        echo ""
        
        for file in "$REPORT_DIR/logs"/*.txt; do
            if [[ -f "$file" ]]; then
                echo "-----------------------------------------------------------------------"
                echo "FILE: $(basename "$file")"
                echo "-----------------------------------------------------------------------"
                cat "$file"
                echo ""
                echo ""
            fi
        done
        
        # BROWSER & APPLICATION DATA SECTION
        echo "==========================================================================="
        echo "                    BROWSER & APPLICATION DATA ANALYSIS"
        echo "==========================================================================="
        echo ""
        
        for file in "$REPORT_DIR/exports"/*.txt; do
            if [[ -f "$file" ]]; then
                echo "-----------------------------------------------------------------------"
                echo "FILE: $(basename "$file")"
                echo "-----------------------------------------------------------------------"
                cat "$file"
                echo ""
                echo ""
            fi
        done
        
        # PCAP ANALYSIS SECTION
        echo "==========================================================================="
        echo "                         PACKET CAPTURE ANALYSIS"
        echo "==========================================================================="
        echo ""
        
        if [[ -d "$REPORT_DIR/pcaps" ]]; then
            echo "PCAP Files Captured:"
            echo "-------------------"
            ls -lh "$REPORT_DIR/pcaps"/*.pcap 2>/dev/null || echo "No PCAP files found"
            echo ""
            echo ""
            
            # Extract unique IPs from all PCAPs
            echo "==========================================================================="
            echo "                    UNIQUE IP ADDRESSES FROM CAPTURES"
            echo "==========================================================================="
            echo ""
            
            local temp_ips="$DESKTOP_DIR/all_unique_ips_${TIMESTAMP}.txt"
            > "$temp_ips"
            
            for pcap in "$REPORT_DIR/pcaps"/*.pcap; do
                if [[ -f "$pcap" ]]; then
                    echo "Processing: $(basename "$pcap")"
                    tcpdump -nn -r "$pcap" 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' >> "$temp_ips"
                fi
            done
            
            if [[ -s "$temp_ips" ]]; then
                echo ""
                echo "IPv4 Addresses Found:"
                echo "--------------------"
                sort -u "$temp_ips" | while read ip; do
                    echo "  * $ip"
                done
                echo ""
                echo "Total Unique IPv4 Addresses: $(sort -u "$temp_ips" | wc -l | tr -d ' ')"
            else
                echo "No IP addresses extracted from PCAP files"
            fi
            
            rm -f "$temp_ips"
            echo ""
            echo ""
            
            # TCP/UDP Connection Summary
            echo "==========================================================================="
            echo "                      TCP/UDP CONNECTION SUMMARY"
            echo "==========================================================================="
            echo ""
            
            for pcap in "$REPORT_DIR/pcaps"/*.pcap; do
                if [[ -f "$pcap" ]]; then
                    echo "File: $(basename "$pcap")"
                    echo "  Packets: $(tcpdump -r "$pcap" 2>/dev/null | wc -l | tr -d ' ')"
                    echo "  TCP: $(tcpdump -r "$pcap" tcp 2>/dev/null | wc -l | tr -d ' ')"
                    echo "  UDP: $(tcpdump -r "$pcap" udp 2>/dev/null | wc -l | tr -d ' ')"
                    echo "  ICMP: $(tcpdump -r "$pcap" icmp 2>/dev/null | wc -l | tr -d ' ')"
                    echo ""
                fi
            done
        fi
        
        # ALERTS SECTION
        echo "==========================================================================="
        echo "                           SECURITY ALERTS"
        echo "==========================================================================="
        echo ""
        
        if [[ -f "$REPORT_DIR/analysis/ALERTS.txt" ]]; then
            cat "$REPORT_DIR/analysis/ALERTS.txt"
        else
            echo "No security alerts generated."
        fi
        
        echo ""
        echo ""
        echo "==========================================================================="
        echo "                              END OF REPORT"
        echo "==========================================================================="
        echo "Report saved to: $combined_report"
        echo "Individual files available in: $REPORT_DIR"
        echo "PCAP files for Wireshark analysis: $REPORT_DIR/pcaps/"
        echo ""
        
    } > "$combined_report"
    
    echo -e "    ${GREEN}[[+]] Comprehensive combined report saved to Desktop:${NC}"
    echo -e "    ${CYAN}-> $combined_report${NC}"
    log "INFO" "Comprehensive combined report generated: $combined_report"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Print banner
    print_banner
    
    echo -e "${GREEN}[*] C2 Hunter v5.0 - macOS Edition Starting...${NC}"
    echo -e "${CYAN}[*] Capture Duration: ${CAPTURE_DURATION} seconds${NC}"
    echo -e "${CYAN}[*] Report Directory: ${REPORT_DIR}${NC}"
    echo ""
    
    # Run prerequisite checks
    if ! check_prerequisites; then
        echo -e "${RED}[!] Prerequisite checks failed${NC}"
        exit 1
    fi
    
    # Discover and setup interfaces
    discover_interfaces
    
    # Check if we have any interfaces
    if [ ${#DISCOVERED_INTERFACES[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] WARNING: No network interfaces discovered${NC}"
        echo -e "${YELLOW}[!] Packet capture may not work properly${NC}"
        echo -e "${YELLOW}[!] Continuing with other analysis modules...${NC}"
    fi
    
    enable_promiscuous_mode
    setup_monitor_mode
    
    # Run all detection modules
    echo -e "\n${MAGENTA}+==================================================================+${NC}"
    echo -e "${MAGENTA}|                  RUNNING DETECTION MODULES                       |${NC}"
    echo -e "${MAGENTA}+==================================================================+${NC}"
    
    collect_network_layer_c2 || echo -e "${YELLOW}[!] Network layer C2 detection had errors${NC}"
    collect_process_memory || echo -e "${YELLOW}[!] Process memory collection had errors${NC}"
    collect_persistence || echo -e "${YELLOW}[!] Persistence detection had errors${NC}"
    collect_shell_abuse || echo -e "${YELLOW}[!] Shell abuse detection had errors${NC}"
    collect_kernel_analysis || echo -e "${YELLOW}[!] Kernel analysis had errors${NC}"
    collect_network_config_abuse || echo -e "${YELLOW}[!] Network config analysis had errors${NC}"
    collect_browser_app_data || echo -e "${YELLOW}[!] Browser data collection had errors${NC}"
    
    # Start packet capture
    if ! start_capture; then
        echo -e "${RED}[!] Packet capture failed to start${NC}"
        echo -e "${YELLOW}[!] Continuing with report generation from collected data...${NC}"
    else
        # Wait for capture duration only if capture started successfully
        echo -e "\n${GREEN}+==================================================================+${NC}"
        echo -e "${GREEN}|                    CAPTURE IN PROGRESS                           |${NC}"
        echo -e "${GREEN}+==================================================================+${NC}"
        echo -e "${YELLOW}[*] Capturing for ${CAPTURE_DURATION} seconds...${NC}"
        echo -e "${YELLOW}[*] Press Ctrl+C to stop early${NC}"
        echo ""
        
        # Progress indicator
        local elapsed=0
        local update_interval=10
        
        # Adjust update interval for short captures
        if [[ $CAPTURE_DURATION -lt 60 ]]; then
            update_interval=5
        fi
        
        while [[ $elapsed -lt $CAPTURE_DURATION ]]; do
            local remaining=$((CAPTURE_DURATION - elapsed))
            printf "\r${CYAN}[*] Time remaining: %d seconds...${NC}    " "$remaining"
            
            # Check if capture processes are still running
            local running_captures=0
            if [ ${#TCPDUMP_PIDS[@]} -gt 0 ]; then
                for pid in "${TCPDUMP_PIDS[@]}"; do
                    if ps -p $pid > /dev/null 2>&1; then
                        running_captures=$((running_captures + 1))
                    fi
                done
            fi
            
            if [[ $running_captures -eq 0 ]] && [[ ${#TCPDUMP_PIDS[@]} -gt 0 ]]; then
                echo ""
                echo -e "${RED}[!] All capture processes stopped unexpectedly${NC}"
                echo -e "${YELLOW}[!] Check $LOG_FILE for details${NC}"
                break
            fi
            
            sleep "$update_interval"
            elapsed=$((elapsed + update_interval))
        done
        echo ""
    fi
    
    # Generate final report
    if ! generate_report; then
        echo -e "${YELLOW}[!] Report generation had errors, but files may still be available${NC}"
    fi
    
    # Summary
    echo -e "\n${GREEN}+==================================================================+${NC}"
    echo -e "${GREEN}|                    CAPTURE COMPLETE                              |${NC}"
    echo -e "${GREEN}+==================================================================+${NC}"
    echo -e "${CYAN}[*] Reports saved to: $REPORT_DIR${NC}"
    
    if [[ -f "$PCAP_FILE" ]]; then
        echo -e "${CYAN}[*] Main PCAP file: $PCAP_FILE${NC}"
    fi
    
    if [[ -f "$REPORT_DIR/analysis/ALERTS.txt" ]]; then
        echo -e "${CYAN}[*] Alerts file: $REPORT_DIR/analysis/ALERTS.txt${NC}"
    fi
    
    if [[ -f "$REPORT_DIR/REPORT_${TIMESTAMP}.txt" ]]; then
        echo -e "${CYAN}[*] Full report: $REPORT_DIR/REPORT_${TIMESTAMP}.txt${NC}"
    fi
    
    local combined_report="$DESKTOP_DIR/COMBINED_ANALYSIS_${TIMESTAMP}.txt"
    if [[ -f "$combined_report" ]]; then
        echo -e "${GREEN}[*] Combined analysis report: $combined_report${NC}"
    fi
    echo ""
    
    # Count alerts
    if [[ -s "$REPORT_DIR/analysis/ALERTS.txt" ]]; then
        local alert_count=$(wc -l < "$REPORT_DIR/analysis/ALERTS.txt" | tr -d ' ')
        echo -e "${YELLOW}[!] Total alerts generated: $alert_count${NC}"
        echo -e "${YELLOW}[!] Review alerts file for potential threats${NC}"
        
        # Show severity breakdown
        if command -v grep &>/dev/null; then
            local critical=$(grep -c "CRITICAL" "$REPORT_DIR/analysis/ALERTS.txt" 2>/dev/null || echo "0")
            local high=$(grep -c "HIGH" "$REPORT_DIR/analysis/ALERTS.txt" 2>/dev/null || echo "0")
            local medium=$(grep -c "MEDIUM" "$REPORT_DIR/analysis/ALERTS.txt" 2>/dev/null || echo "0")
            local low=$(grep -c "LOW" "$REPORT_DIR/analysis/ALERTS.txt" 2>/dev/null || echo "0")
            
            # Remove any whitespace and ensure we have a valid number
            critical=$(echo "$critical" | tr -d ' ' | head -1)
            high=$(echo "$high" | tr -d ' ' | head -1)
            medium=$(echo "$medium" | tr -d ' ' | head -1)
            low=$(echo "$low" | tr -d ' ' | head -1)
            
            # Set to 0 if empty or not a number
            [[ -z "$critical" || ! "$critical" =~ ^[0-9]+$ ]] && critical=0
            [[ -z "$high" || ! "$high" =~ ^[0-9]+$ ]] && high=0
            [[ -z "$medium" || ! "$medium" =~ ^[0-9]+$ ]] && medium=0
            [[ -z "$low" || ! "$low" =~ ^[0-9]+$ ]] && low=0
            
            echo -e "${CYAN}[*] Alert Breakdown:${NC}"
            [[ $critical -gt 0 ]] && echo -e "    ${RED}CRITICAL: $critical${NC}"
            [[ $high -gt 0 ]] && echo -e "    ${MAGENTA}HIGH: $high${NC}"
            [[ $medium -gt 0 ]] && echo -e "    ${YELLOW}MEDIUM: $medium${NC}"
            [[ $low -gt 0 ]] && echo -e "    ${CYAN}LOW: $low${NC}"
        fi
    else
        echo -e "${GREEN}[[+]] No suspicious activity detected${NC}"
    fi
    
    echo ""
    
    if [[ -f "$PCAP_FILE" ]]; then
        echo -e "${YELLOW}[*] To analyze captures with Wireshark:${NC}"
        echo -e "${YELLOW}    open -a Wireshark \"$PCAP_FILE\"${NC}"
        echo ""
    fi
    
    echo -e "${GREEN}[[+]] Analysis complete!${NC}"
    log "INFO" "Capture and analysis complete"
}

# Run main function
main "$@"
