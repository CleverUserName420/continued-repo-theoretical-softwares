#!/bin/bash

# Enhanced Network Traffic Capture and Analysis Script
# Version 3.0 - Complete with all fixes and enhancements

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
TCPDUMP_PID=""

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
    if [[ -n "$TCPDUMP_PID" ]] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        sudo kill "$TCPDUMP_PID" 2>/dev/null || true
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
            echo -e "${RED}[! ] Missing: $tool${NC}"
            log "ERROR" "Missing tool: $tool"
            exit 1
        fi
    done
    
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

# List available interfaces
list_interfaces() {
    echo -e "\n${BLUE}[*] Available network interfaces:${NC}"
    ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}'
}

# Start packet capture
start_capture() {
    echo -e "\n${GREEN}[*] Starting capture for ${CAPTURE_DURATION}s...${NC}"
    echo -e "Output: ${PCAP_FILE}"
    log "INFO" "Starting capture for ${CAPTURE_DURATION}s to ${PCAP_FILE}"
    
    list_interfaces
    
    sudo tcpdump -i any -n -w "$PCAP_FILE" 2>>"$LOG_FILE" &
    TCPDUMP_PID=$!
    
    sleep 2
    if !  kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        echo -e "${RED}[!] tcpdump failed - check $LOG_FILE for details${NC}"
        log "ERROR" "tcpdump failed to start"
        exit 1
    fi
    
    echo -e "${GREEN}[✓] Capturing (PID: $TCPDUMP_PID)${NC}"
    log "INFO" "tcpdump started with PID: $TCPDUMP_PID"
    
    # Progress counter
    for ((i=0; i<CAPTURE_DURATION; i+=10)); do
        printf "\r${YELLOW}[*] Progress: %d/%d seconds${NC}" "$i" "$CAPTURE_DURATION"
        sleep 10
    done
    
    echo ""
    sudo kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    TCPDUMP_PID=""
    
    sleep 1
    local size=$(du -h "$PCAP_FILE" 2>/dev/null | cut -f1)
    echo -e "${GREEN}[✓] Capture complete: $size${NC}"
    log "INFO" "Capture complete: $size"
}

# Perform analysis
perform_analysis() {
    echo -e "\n${YELLOW}[*] Analyzing...${NC}"
    log "INFO" "Starting analysis"
    
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
    port_names = {
        80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 53: 'DNS',
        25: 'SMTP', 21: 'FTP', 3306: 'MySQL', 5432: 'PostgreSQL',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 3389: 'RDP',
        23: 'Telnet', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS',
        995: 'POP3S', 587: 'SMTP-TLS', 465: 'SMTPS', 6379: 'Redis',
        27017: 'MongoDB', 5900: 'VNC', 1433: 'MSSQL', 1521: 'Oracle'
    }
    for port, count in sorted(ports.items(), key=lambda x: x[1], reverse=True)[:15]:
        service = port_names.get(port, 'unknown')
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

# Extract all IPs from all pcap files on system - NO FILTERS
extract_all_ips() {
    echo -e "\n${YELLOW}[*] Searching entire filesystem for pcap files (no filters)...${NC}"
    log "INFO" "Starting extraction of IPs from all pcap files - no path filters"
    
    local all_ips_file="$REPORT_DIR/all_ips.txt"
    local ipv4_regex='\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'
    local ipv6_regex='([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|fe80:[0-9a-fA-F:]+|::1|::[0-9a-fA-F]{1,4}'
    
    echo -e "${YELLOW}[*] Extracting IPs from ALL pcap files (including hidden, no exclusions)...${NC}"
    
    {
        # First, extract from current capture
        tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | grep -oE "${ipv4_regex}|${ipv6_regex}"
        
        # Find and extract from ALL pcap files - NO PATH EXCLUSIONS
        sudo find / -type f -regex ".*\.pcap$" 2>/dev/null | while read -r f; do
            # Skip current capture to avoid duplicates
            if [[ "$f" != "$PCAP_FILE" ]]; then
                tcpdump -nn -r "$f" 2>/dev/null | grep -oE "${ipv4_regex}|${ipv6_regex}"
            fi
        done
    } | sort -u > "$all_ips_file"
    
    local ip_count=$(wc -l < "$all_ips_file" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓] Extracted $ip_count unique IPs (IPv4 + IPv6) to: $all_ips_file${NC}"
    log "INFO" "Extracted $ip_count unique IPs to $all_ips_file"
    
    # Also create separate IPv4 and IPv6 files from all pcaps
    grep -E "^${ipv4_regex}$" "$all_ips_file" > "$REPORT_DIR/all_ipv4.txt" 2>/dev/null || true
    grep -vE "^${ipv4_regex}$" "$all_ips_file" > "$REPORT_DIR/all_ipv6.txt" 2>/dev/null || true
    
    local ipv4_count=$(wc -l < "$REPORT_DIR/all_ipv4.txt" 2>/dev/null || echo 0)
    local ipv6_count=$(wc -l < "$REPORT_DIR/all_ipv6.txt" 2>/dev/null || echo 0)
    
    echo -e "${GREEN}    ├── IPv4: $ipv4_count addresses${NC}"
    echo -e "${GREEN}    └── IPv6: $ipv6_count addresses${NC}"
}

# Display help
show_help() {
    echo -e "${GREEN}"
    echo "Usage: $0 [CAPTURE_DURATION_SECONDS]"
    echo ""
    echo "Options:"
    echo "  CAPTURE_DURATION    Duration in seconds (default: 1000)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0              # Capture for 1000 seconds"
    echo "  $0 600          # Capture for 10 minutes"
    echo "  $0 3600         # Capture for 1 hour"
    echo -e "${NC}"
}

# Main
main() {
    # Check for help flag
    if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════╗"
    echo "║ Nathan Adie's Network Capture &        ║"
    echo "║ Analysis Tool mk2                      ║"
    echo "╚════════════════════════════════════════╝"
    echo -e "${NC}"
    
    log "INFO" "Script started"
    log "INFO" "Capture duration: ${CAPTURE_DURATION}s"
    log "INFO" "PCAP file: ${PCAP_FILE}"
    log "INFO" "Report directory: ${REPORT_DIR}"
    
    check_prerequisites
    start_capture
    perform_analysis
    extract_all_ips
    
    echo -e "\n${GREEN}[✓] Done! ${NC}"
    echo -e "Reports: ${REPORT_DIR}/"
    echo -e "PCAP: ${PCAP_FILE}"
    echo -e "Log: ${LOG_FILE}"
    echo ""
    ls -lh "$REPORT_DIR"/ "$PCAP_FILE" 2>/dev/null || true
    
    log "INFO" "Script completed successfully"
}

main "$@"



#Run ={ sudo find / -type f -path "*/System/*" 2>/dev/null | grep -E "(.pcap)" | while read f; do tcpdump -nn -r "$f" 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'; done | sort -u } afterwards to get all. It works best for me.
