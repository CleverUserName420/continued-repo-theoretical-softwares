#!/bin/bash

# Enhanced Network Traffic Capture and Analysis Script - macOS Edition
# Version 4.0 - macOS M1 Compatible with C2/Malware Detection

set -u  # Exit on undefined vars

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CAPTURE_DURATION=${1:-1000}
PCAP_FILE="/tmp/traffic_$(date +%Y%m%d_%H%M%S).pcap"
REPORT_DIR="/tmp/network_analysis_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/tmp/netcap_$(date +%Y%m%d_%H%M%S).log"
TCPDUMP_PIDS=""

# Export for Python access
export PCAP_FILE REPORT_DIR

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
