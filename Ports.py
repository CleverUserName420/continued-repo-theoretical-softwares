#!/usr/bin/env python3

"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║        ADVANCED CYBERSECURITY PORT SCANNER & VULNERABILITY ANALYZER       ║
║                          Professional Edition v2.0                        ║
║                                                                           ║
║  A comprehensive security assessment tool featuring:                     ║
║  • Multi-protocol port scanning (TCP/UDP/SYN)                           ║
║  • Vulnerability detection & CVE matching                               ║
║  • SSL/TLS security analysis                                            ║
║  • Web application enumeration                                          ║
║  • Service fingerprinting & version detection                           ║
║  • OS fingerprinting                                                    ║
║  • Network topology mapping                                             ║
║  • Comprehensive reporting (HTML/PDF/JSON/XML)                          ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import socket
import sys
import threading
import time
import json
import argparse
import re
import ssl
import struct
import random
import hashlib
import base64
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import os
import subprocess
import platform
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import ipaddress

# ============================================================================
# CONSTANTS AND CONFIGURATIONS
# ============================================================================

VERSION = "2.0.0"
BANNER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║     █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗   ║
║    ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗  ║
║    ███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║     █████╗  ██║  ██║  ║
║    ██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║     ██╔══╝  ██║  ██║  ║
║    ██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗███████╗██████╔╝  ║
║    ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═════╝   ║
║                                                                           ║
║          CYBERSECURITY PORT SCANNER & VULNERABILITY ANALYZER v2.0        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def colored(text, color):
        return f"{color}{text}{Colors.ENDC}"

# Risk levels
class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# Scan types
class ScanType(Enum):
    TCP_CONNECT = "TCP Connect"
    SYN_SCAN = "SYN Scan"
    UDP_SCAN = "UDP Scan"
    COMPREHENSIVE = "Comprehensive"
    STEALTH = "Stealth"

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ServiceInfo:
    port: int
    protocol: str
    service: str
    version: str = ""
    banner: str = ""
    risk_level: str = "LOW"
    vulnerabilities: List[str] = None
    ssl_info: Dict = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []

@dataclass
class VulnerabilityInfo:
    cve_id: str
    severity: str
    description: str
    affected_service: str
    affected_version: str
    cvss_score: float
    exploit_available: bool = False
    mitigation: str = ""

@dataclass
class SSLInfo:
    protocol_version: str
    cipher_suite: str
    certificate_info: Dict
    vulnerabilities: List[str]
    grade: str
    expiry_date: str

# ============================================================================
# COMPREHENSIVE SERVICE FINGERPRINTING DATABASE
# ============================================================================

class ServiceDatabase:
    """Comprehensive database of services, ports, and known vulnerabilities"""
    
    SERVICES = {
        # File Transfer
        20: {"name": "FTP-DATA", "description": "FTP Data Transfer", "risk": "HIGH"},
        21: {"name": "FTP", "description": "File Transfer Protocol", "risk": "CRITICAL"},
        69: {"name": "TFTP", "description": "Trivial File Transfer Protocol", "risk": "HIGH"},
        115: {"name": "SFTP", "description": "Simple File Transfer Protocol", "risk": "MEDIUM"},
        
        # Remote Access
        22: {"name": "SSH", "description": "Secure Shell", "risk": "HIGH"},
        23: {"name": "Telnet", "description": "Telnet (Unencrypted)", "risk": "CRITICAL"},
        513: {"name": "rlogin", "description": "Remote Login", "risk": "CRITICAL"},
        514: {"name": "rsh", "description": "Remote Shell", "risk": "CRITICAL"},
        3389: {"name": "RDP", "description": "Remote Desktop Protocol", "risk": "CRITICAL"},
        5900: {"name": "VNC", "description": "Virtual Network Computing", "risk": "HIGH"},
        5901: {"name": "VNC", "description": "VNC Display 1", "risk": "HIGH"},
        5902: {"name": "VNC", "description": "VNC Display 2", "risk": "HIGH"},
        
        # Email Services
        25: {"name": "SMTP", "description": "Simple Mail Transfer Protocol", "risk": "HIGH"},
        110: {"name": "POP3", "description": "Post Office Protocol v3", "risk": "MEDIUM"},
        143: {"name": "IMAP", "description": "Internet Message Access Protocol", "risk": "MEDIUM"},
        465: {"name": "SMTPS", "description": "SMTP over SSL", "risk": "MEDIUM"},
        587: {"name": "SMTP", "description": "SMTP Submission", "risk": "MEDIUM"},
        993: {"name": "IMAPS", "description": "IMAP over SSL", "risk": "LOW"},
        995: {"name": "POP3S", "description": "POP3 over SSL", "risk": "LOW"},
        
        # Web Services
        80: {"name": "HTTP", "description": "Hypertext Transfer Protocol", "risk": "MEDIUM"},
        443: {"name": "HTTPS", "description": "HTTP over SSL/TLS", "risk": "MEDIUM"},
        8000: {"name": "HTTP-Alt", "description": "Alternative HTTP", "risk": "MEDIUM"},
        8008: {"name": "HTTP-Alt", "description": "Alternative HTTP", "risk": "MEDIUM"},
        8080: {"name": "HTTP-Proxy", "description": "HTTP Proxy", "risk": "MEDIUM"},
        8443: {"name": "HTTPS-Alt", "description": "Alternative HTTPS", "risk": "MEDIUM"},
        8888: {"name": "HTTP-Alt", "description": "Alternative HTTP", "risk": "MEDIUM"},
        9090: {"name": "HTTP-Alt", "description": "Alternative HTTP", "risk": "MEDIUM"},
        
        # DNS
        53: {"name": "DNS", "description": "Domain Name System", "risk": "MEDIUM"},
        5353: {"name": "mDNS", "description": "Multicast DNS", "risk": "LOW"},
        
        # Directory Services
        389: {"name": "LDAP", "description": "Lightweight Directory Access Protocol", "risk": "HIGH"},
        636: {"name": "LDAPS", "description": "LDAP over SSL", "risk": "MEDIUM"},
        3268: {"name": "LDAP-GC", "description": "LDAP Global Catalog", "risk": "HIGH"},
        
        # Databases
        1433: {"name": "MS-SQL", "description": "Microsoft SQL Server", "risk": "CRITICAL"},
        1434: {"name": "MS-SQL-M", "description": "MS-SQL Monitor", "risk": "CRITICAL"},
        1521: {"name": "Oracle", "description": "Oracle Database", "risk": "CRITICAL"},
        3306: {"name": "MySQL", "description": "MySQL Database", "risk": "CRITICAL"},
        5432: {"name": "PostgreSQL", "description": "PostgreSQL Database", "risk": "CRITICAL"},
        5984: {"name": "CouchDB", "description": "CouchDB Database", "risk": "HIGH"},
        6379: {"name": "Redis", "description": "Redis Database", "risk": "CRITICAL"},
        7000: {"name": "Cassandra", "description": "Cassandra Database", "risk": "HIGH"},
        7001: {"name": "Cassandra", "description": "Cassandra JMX", "risk": "HIGH"},
        9042: {"name": "Cassandra", "description": "Cassandra CQL", "risk": "HIGH"},
        9200: {"name": "Elasticsearch", "description": "Elasticsearch", "risk": "CRITICAL"},
        9300: {"name": "Elasticsearch", "description": "Elasticsearch Transport", "risk": "CRITICAL"},
        27017: {"name": "MongoDB", "description": "MongoDB Database", "risk": "CRITICAL"},
        27018: {"name": "MongoDB", "description": "MongoDB Shard", "risk": "CRITICAL"},
        28017: {"name": "MongoDB", "description": "MongoDB Web Admin", "risk": "CRITICAL"},
        
        # Windows Services
        135: {"name": "MS-RPC", "description": "Microsoft RPC", "risk": "HIGH"},
        137: {"name": "NetBIOS-NS", "description": "NetBIOS Name Service", "risk": "MEDIUM"},
        138: {"name": "NetBIOS-DGM", "description": "NetBIOS Datagram", "risk": "MEDIUM"},
        139: {"name": "NetBIOS-SSN", "description": "NetBIOS Session", "risk": "HIGH"},
        445: {"name": "SMB", "description": "Server Message Block", "risk": "CRITICAL"},
        593: {"name": "MS-RPC-HTTP", "description": "MS RPC over HTTP", "risk": "HIGH"},
        
        # Network Services
        67: {"name": "DHCP", "description": "DHCP Server", "risk": "LOW"},
        68: {"name": "DHCP", "description": "DHCP Client", "risk": "LOW"},
        123: {"name": "NTP", "description": "Network Time Protocol", "risk": "LOW"},
        161: {"name": "SNMP", "description": "Simple Network Management", "risk": "HIGH"},
        162: {"name": "SNMP-Trap", "description": "SNMP Trap", "risk": "HIGH"},
        179: {"name": "BGP", "description": "Border Gateway Protocol", "risk": "MEDIUM"},
        520: {"name": "RIP", "description": "Routing Information Protocol", "risk": "MEDIUM"},
        521: {"name": "RIPng", "description": "RIP next generation", "risk": "MEDIUM"},
        
        # VPN/Tunneling
        500: {"name": "IKE", "description": "Internet Key Exchange", "risk": "MEDIUM"},
        1194: {"name": "OpenVPN", "description": "OpenVPN", "risk": "LOW"},
        1701: {"name": "L2TP", "description": "Layer 2 Tunneling Protocol", "risk": "MEDIUM"},
        1723: {"name": "PPTP", "description": "Point-to-Point Tunneling", "risk": "HIGH"},
        4500: {"name": "IPSec-NAT", "description": "IPSec NAT Traversal", "risk": "MEDIUM"},
        
        # Proxy/SOCKS
        1080: {"name": "SOCKS", "description": "SOCKS Proxy", "risk": "MEDIUM"},
        3128: {"name": "Squid", "description": "Squid Proxy", "risk": "MEDIUM"},
        8118: {"name": "Privoxy", "description": "Privoxy Proxy", "risk": "MEDIUM"},
        
        # Messaging/Collaboration
        1863: {"name": "MSNP", "description": "MSN Messenger", "risk": "LOW"},
        5222: {"name": "XMPP", "description": "XMPP/Jabber Client", "risk": "LOW"},
        5269: {"name": "XMPP-S2S", "description": "XMPP Server-to-Server", "risk": "LOW"},
        5280: {"name": "XMPP-BOSH", "description": "XMPP BOSH", "risk": "LOW"},
        
        # Monitoring/Management
        2049: {"name": "NFS", "description": "Network File System", "risk": "HIGH"},
        10000: {"name": "Webmin", "description": "Webmin Admin Panel", "risk": "HIGH"},
        19999: {"name": "Netdata", "description": "Netdata Monitoring", "risk": "MEDIUM"},
        
        # Application Servers
        4848: {"name": "GlassFish", "description": "GlassFish Admin", "risk": "HIGH"},
        7001: {"name": "WebLogic", "description": "Oracle WebLogic", "risk": "HIGH"},
        8009: {"name": "AJP", "description": "Apache JServ Protocol", "risk": "MEDIUM"},
        9000: {"name": "FastCGI", "description": "FastCGI", "risk": "MEDIUM"},
        
        # Game Servers
        25565: {"name": "Minecraft", "description": "Minecraft Server", "risk": "LOW"},
        27015: {"name": "Steam", "description": "Steam Game Server", "risk": "LOW"},
        
        # IoT/Embedded
        554: {"name": "RTSP", "description": "Real Time Streaming", "risk": "MEDIUM"},
        1883: {"name": "MQTT", "description": "MQTT Protocol", "risk": "MEDIUM"},
        8883: {"name": "MQTT-TLS", "description": "MQTT over TLS", "risk": "LOW"},
        
        # Printing
        515: {"name": "LPD", "description": "Line Printer Daemon", "risk": "MEDIUM"},
        631: {"name": "IPP", "description": "Internet Printing Protocol", "risk": "MEDIUM"},
        9100: {"name": "JetDirect", "description": "HP JetDirect", "risk": "MEDIUM"},
        
        # Enterprise
        50000: {"name": "SAP", "description": "SAP Application", "risk": "HIGH"},
        50070: {"name": "Hadoop", "description": "Hadoop NameNode", "risk": "HIGH"},
        8086: {"name": "InfluxDB", "description": "InfluxDB", "risk": "MEDIUM"},
    }
    
    # Known CVE database (simplified version)
    VULNERABILITIES = {
        "FTP": [
            {"cve": "CVE-2021-28151", "severity": "CRITICAL", "desc": "ProFTPD vulnerability", "cvss": 9.8},
            {"cve": "CVE-2020-7382", "severity": "HIGH", "desc": "Anonymous FTP access", "cvss": 7.5},
        ],
        "SSH": [
            {"cve": "CVE-2021-28041", "severity": "HIGH", "desc": "SSH username enumeration", "cvss": 7.5},
            {"cve": "CVE-2020-14145", "severity": "MEDIUM", "desc": "SSH observable discrepancy", "cvss": 5.9},
            {"cve": "CVE-2018-15473", "severity": "MEDIUM", "desc": "OpenSSH user enumeration", "cvss": 5.3},
        ],
        "Telnet": [
            {"cve": "CVE-2020-10188", "severity": "CRITICAL", "desc": "Telnet service vulnerability", "cvss": 9.8},
        ],
        "SMTP": [
            {"cve": "CVE-2020-28017", "severity": "CRITICAL", "desc": "Exim SMTP vulnerability", "cvss": 9.8},
            {"cve": "CVE-2019-10149", "severity": "CRITICAL", "desc": "Exim RCE vulnerability", "cvss": 9.8},
        ],
        "HTTP": [
            {"cve": "CVE-2021-41773", "severity": "CRITICAL", "desc": "Apache path traversal", "cvss": 9.8},
            {"cve": "CVE-2021-42013", "severity": "CRITICAL", "desc": "Apache RCE", "cvss": 9.8},
            {"cve": "CVE-2017-5638", "severity": "CRITICAL", "desc": "Apache Struts2 RCE", "cvss": 10.0},
        ],
        "SMB": [
            {"cve": "CVE-2020-0796", "severity": "CRITICAL", "desc": "SMBGhost", "cvss": 10.0},
            {"cve": "CVE-2017-0144", "severity": "CRITICAL", "desc": "EternalBlue", "cvss": 9.3},
            {"cve": "CVE-2017-0143", "severity": "CRITICAL", "desc": "EternalRomance", "cvss": 9.3},
        ],
        "RDP": [
            {"cve": "CVE-2019-0708", "severity": "CRITICAL", "desc": "BlueKeep", "cvss": 9.8},
            {"cve": "CVE-2020-0609", "severity": "CRITICAL", "desc": "RDP Gateway RCE", "cvss": 9.8},
        ],
        "MySQL": [
            {"cve": "CVE-2021-2471", "severity": "HIGH", "desc": "MySQL Server vulnerability", "cvss": 7.5},
            {"cve": "CVE-2020-14867", "severity": "CRITICAL", "desc": "MySQL privilege escalation", "cvss": 9.1},
        ],
        "MongoDB": [
            {"cve": "CVE-2020-7610", "severity": "CRITICAL", "desc": "MongoDB unauthenticated access", "cvss": 9.8},
            {"cve": "CVE-2019-2386", "severity": "HIGH", "desc": "MongoDB query injection", "cvss": 8.1},
        ],
        "Redis": [
            {"cve": "CVE-2021-32672", "severity": "HIGH", "desc": "Redis Lua sandbox escape", "cvss": 7.5},
            {"cve": "CVE-2022-0543", "severity": "CRITICAL", "desc": "Redis Lua RCE", "cvss": 10.0},
        ],
        "Elasticsearch": [
            {"cve": "CVE-2021-22145", "severity": "CRITICAL", "desc": "Elasticsearch RCE", "cvss": 9.8},
            {"cve": "CVE-2020-7009", "severity": "HIGH", "desc": "Elasticsearch arbitrary file read", "cvss": 7.5},
        ],
    }
    
    # Web application signatures
    WEB_SIGNATURES = {
        "WordPress": {
            "patterns": ["/wp-content/", "/wp-admin/", "/wp-login.php"],
            "vulnerabilities": ["CVE-2021-24762", "CVE-2021-24750"]
        },
        "Joomla": {
            "patterns": ["/administrator/", "/components/com_", "/index.php?option=com_"],
            "vulnerabilities": ["CVE-2020-11888", "CVE-2020-10238"]
        },
        "Drupal": {
            "patterns": ["/drupal/", "/sites/default/", "drupal.js"],
            "vulnerabilities": ["CVE-2018-7600", "CVE-2018-7602"]
        },
        "Apache": {
            "patterns": ["Server: Apache", "Apache/"],
            "vulnerabilities": ["CVE-2021-41773", "CVE-2021-42013"]
        },
        "Nginx": {
            "patterns": ["Server: nginx", "nginx/"],
            "vulnerabilities": ["CVE-2021-23017", "CVE-2019-9511"]
        },
        "Tomcat": {
            "patterns": ["Apache-Coyote", "Tomcat/"],
            "vulnerabilities": ["CVE-2021-42340", "CVE-2020-9484"]
        },
        "IIS": {
            "patterns": ["Server: Microsoft-IIS", "X-Powered-By: ASP.NET"],
            "vulnerabilities": ["CVE-2021-31166", "CVE-2020-0646"]
        },
    }
    
    @staticmethod
    def get_service_info(port: int) -> Dict:
        """Get service information for a port"""
        return ServiceDatabase.SERVICES.get(port, {
            "name": "Unknown",
            "description": f"Unknown service on port {port}",
            "risk": "INFO"
        })
    
    @staticmethod
    def get_vulnerabilities(service_name: str) -> List[Dict]:
        """Get known vulnerabilities for a service"""
        return ServiceDatabase.VULNERABILITIES.get(service_name, [])

# ============================================================================
# ADVANCED SCANNING ENGINE
# ============================================================================

class AdvancedPortScanner:
    """Advanced port scanning with multiple techniques and protocols"""
    
    def __init__(self, target: str, port_range: Optional[str] = None,
                 threads: int = 100, timeout: float = 2, verbose: bool = False,
                 scan_type: ScanType = ScanType.TCP_CONNECT):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.scan_type = scan_type
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.services = {}
        self.banners = {}
        self.os_fingerprint = {}
        self.lock = threading.Lock()
        
        if port_range:
            self.ports = self._parse_port_range(port_range)
        else:
            self.ports = self._get_comprehensive_ports()
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string"""
        ports = []
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))
    
    def _get_comprehensive_ports(self) -> List[int]:
        """Return comprehensive list of ports to scan"""
        # Top 1000 most common ports
        common_ports = list(ServiceDatabase.SERVICES.keys())
        
        # Add additional commonly used ports
        additional = list(range(8000, 8100)) + list(range(9000, 9100))
        
        return sorted(set(common_ports + additional))
    
    def scan_tcp_port(self, port: int) -> Dict:
        """TCP Connect scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                banner = self._grab_banner(sock, port)
                service_info = ServiceDatabase.get_service_info(port)
                
                sock.close()
                
                with self.lock:
                    self.open_ports.append(port)
                    if banner:
                        self.banners[port] = banner
                    self.services[port] = service_info
                
                if self.verbose:
                    self._print_port_status(port, "OPEN", service_info['name'], service_info['risk'])
                
                return {'port': port, 'status': 'open', 'banner': banner, 'service': service_info}
            else:
                with self.lock:
                    self.closed_ports.append(port)
                sock.close()
                return {'port': port, 'status': 'closed'}
                
        except socket.timeout:
            with self.lock:
                self.filtered_ports.append(port)
            return {'port': port, 'status': 'filtered'}
        except Exception as e:
            with self.lock:
                self.filtered_ports.append(port)
            return {'port': port, 'status': 'error', 'error': str(e)}
    
    def scan_udp_port(self, port: int) -> Dict:
        """UDP scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (self.target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                service_info = ServiceDatabase.get_service_info(port)
                
                with self.lock:
                    self.open_ports.append(port)
                    self.services[port] = service_info
                
                sock.close()
                return {'port': port, 'status': 'open', 'protocol': 'UDP', 'service': service_info}
            except socket.timeout:
                # No response means port is likely open or filtered
                sock.close()
                return {'port': port, 'status': 'open|filtered', 'protocol': 'UDP'}
                
        except Exception as e:
            return {'port': port, 'status': 'error', 'protocol': 'UDP', 'error': str(e)}
    
    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """Advanced banner grabbing with protocol-specific probes"""
        try:
            sock.settimeout(2)
            
            # HTTP/HTTPS probes
            if port in [80, 8000, 8008, 8080, 8443, 8888, 9090]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
            
            # SMTP probe
            elif port == 25:
                sock.send(b"EHLO scanner.local\r\n")
            
            # POP3 probe
            elif port == 110:
                sock.send(b"USER test\r\n")
            
            # IMAP probe
            elif port == 143:
                sock.send(b"A001 CAPABILITY\r\n")
            
            # FTP probe (usually sends banner automatically)
            elif port == 21:
                pass
            
            # SSH probe (usually sends banner automatically)
            elif port == 22:
                pass
            
            # MySQL probe
            elif port == 3306:
                pass  # MySQL sends greeting packet
            
            # SMTP submission
            elif port == 587:
                sock.send(b"EHLO scanner.local\r\n")
            
            # Redis probe
            elif port == 6379:
                sock.send(b"INFO\r\n")
            
            # MongoDB probe
            elif port == 27017:
                pass
            
            # Generic probe
            else:
                sock.send(b"\r\n")
            
            # Receive banner
            banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
            return banner[:1000] if banner else None
            
        except:
            return None
    
    def _print_port_status(self, port: int, status: str, service: str, risk: str):
        """Print colored port status"""
        risk_colors = {
            "CRITICAL": Colors.FAIL,
            "HIGH": Colors.WARNING,
            "MEDIUM": Colors.OKCYAN,
            "LOW": Colors.OKGREEN,
            "INFO": Colors.OKBLUE
        }
        
        color = risk_colors.get(risk, Colors.ENDC)
        print(f"{color}[+] Port {port:5d} ({service:15s}) - {status:8s} - {risk}{Colors.ENDC}")
    
    def scan(self) -> Dict:
        """Execute comprehensive port scan"""
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print(f"Starting {self.scan_type.value} Scan")
        print(f"Target: {self.target}")
        print(f"Ports: {len(self.ports)} ports")
        print(f"Threads: {self.threads}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            if self.scan_type == ScanType.UDP_SCAN:
                futures = {executor.submit(self.scan_udp_port, port): port for port in self.ports}
            else:
                futures = {executor.submit(self.scan_tcp_port, port): port for port in self.ports}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if not self.verbose and completed % 50 == 0:
                    progress = (completed / len(self.ports)) * 100
                    print(f"\r{Colors.OKCYAN}Progress: {progress:.1f}% ({completed}/{len(self.ports)}){Colors.ENDC}", end='', flush=True)
        
        if not self.verbose:
            print()
        
        elapsed = time.time() - start_time
        return self._generate_scan_report(elapsed)
    
    def _generate_scan_report(self, elapsed: float) -> Dict:
        """Generate detailed scan report"""
        threat_level = "LOW"
        critical_count = sum(1 for p in self.open_ports if self.services.get(p, {}).get('risk') == 'CRITICAL')
        high_count = sum(1 for p in self.open_ports if self.services.get(p, {}).get('risk') == 'HIGH')
        
        if critical_count > 0:
            threat_level = "CRITICAL"
        elif high_count > 0:
            threat_level = "HIGH"
        elif len(self.open_ports) > 10:
            threat_level = "MEDIUM"
        
        return {
            'timestamp': datetime.now().isoformat(),
            'target': self.target,
            'scan_type': self.scan_type.value,
            'total_ports_scanned': len(self.ports),
            'open_ports': sorted(self.open_ports),
            'open_port_details': [
                {
                    'port': port,
                    'service': self.services.get(port, {}).get('name', 'Unknown'),
                    'description': self.services.get(port, {}).get('description', ''),
                    'risk': self.services.get(port, {}).get('risk', 'INFO'),
                    'banner': self.banners.get(port, '')
                }
                for port in sorted(self.open_ports)
            ],
            'closed_ports': len(self.closed_ports),
            'filtered_ports': len(self.filtered_ports),
            'threat_level': threat_level,
            'scan_duration': elapsed,
            'critical_services': critical_count,
            'high_risk_services': high_count
        }

# ============================================================================
# VULNERABILITY SCANNER
# ============================================================================

class VulnerabilityScanner:
    """Advanced vulnerability detection and analysis"""
    
    def __init__(self, target: str, open_ports: List[int], services: Dict, banners: Dict):
        self.target = target
        self.open_ports = open_ports
        self.services = services
        self.banners = banners
        self.vulnerabilities = []
        self.recommendations = []
    
    def scan_vulnerabilities(self) -> Dict:
        """Comprehensive vulnerability scan"""
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("Starting Vulnerability Analysis")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        results = {
            'service_vulnerabilities': self._check_service_vulnerabilities(),
            'configuration_issues': self._check_configuration_issues(),
            'outdated_software': self._detect_outdated_software(),
            'security_headers': self._check_security_headers(),
            'ssl_vulnerabilities': self._check_ssl_vulnerabilities(),
            'recommendations': []
        }
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _check_service_vulnerabilities(self) -> List[Dict]:
        """Check for known service vulnerabilities"""
        vulnerabilities = []
        
        for port in self.open_ports:
            service_info = self.services.get(port, {})
            service_name = service_info.get('name', 'Unknown')
            
            # Check vulnerability database
            known_vulns = ServiceDatabase.get_vulnerabilities(service_name)
            
            for vuln in known_vulns:
                vulnerabilities.append({
                    'port': port,
                    'service': service_name,
                    'cve': vuln['cve'],
                    'severity': vuln['severity'],
                    'description': vuln['desc'],
                    'cvss_score': vuln['cvss']
                })
                
                if self.verbose:
                    severity_color = Colors.FAIL if vuln['severity'] == 'CRITICAL' else Colors.WARNING
                    print(f"{severity_color}[!] {vuln['cve']} - {service_name} on port {port}{Colors.ENDC}")
        
        return vulnerabilities
    
    def _check_configuration_issues(self) -> List[Dict]:
        """Check for common configuration issues"""
        issues = []
        
        # Check for unauthenticated services
        unauthenticated_services = [
            (21, "FTP", "Anonymous FTP access may be enabled"),
            (23, "Telnet", "Unencrypted remote access enabled"),
            (6379, "Redis", "Redis running without authentication"),
            (27017, "MongoDB", "MongoDB running without authentication"),
            (9200, "Elasticsearch", "Elasticsearch accessible without authentication")
        ]
        
        for port, service, description in unauthenticated_services:
            if port in self.open_ports:
                issues.append({
                    'type': 'Unauthenticated Service',
                    'port': port,
                    'service': service,
                    'severity': 'HIGH',
                    'description': description
                })
        
        # Check for unnecessary services
        if 23 in self.open_ports:
            issues.append({
                'type': 'Insecure Protocol',
                'port': 23,
                'service': 'Telnet',
                'severity': 'CRITICAL',
                'description': 'Telnet transmits data in cleartext'
            })
        
        if 21 in self.open_ports and 22 not in self.open_ports:
            issues.append({
                'type': 'Insecure Protocol',
                'port': 21,
                'service': 'FTP',
                'severity': 'HIGH',
                'description': 'FTP transmits credentials in cleartext. Use SFTP instead.'
            })
        
        return issues
    
    def _detect_outdated_software(self) -> List[Dict]:
        """Detect potentially outdated software from banners"""
        outdated = []
        
        for port, banner in self.banners.items():
            if not banner:
                continue
            
            # Check for version indicators
            version_patterns = [
                (r'Apache/(\d+\.\d+\.\d+)', 'Apache', 'HTTP Server'),
                (r'nginx/(\d+\.\d+\.\d+)', 'nginx', 'Web Server'),
                (r'OpenSSH[_\s](\d+\.\d+)', 'OpenSSH', 'SSH Server'),
                (r'Microsoft-IIS/(\d+\.\d+)', 'IIS', 'Web Server'),
                (r'PHP/(\d+\.\d+\.\d+)', 'PHP', 'Programming Language'),
            ]
            
            for pattern, software, type_name in version_patterns:
                match = re.search(pattern, banner)
                if match:
                    version = match.group(1)
                    outdated.append({
                        'port': port,
                        'software': software,
                        'version': version,
                        'type': type_name,
                        'banner': banner[:200]
                    })
        
        return outdated
    
    def _check_security_headers(self) -> Dict:
        """Check HTTP security headers"""
        results = {}
        
        http_ports = [p for p in self.open_ports if p in [80, 443, 8000, 8080, 8443, 8888]]
        
        for port in http_ports:
            try:
                url = f"http://{self.target}:{port}"
                if port in [443, 8443]:
                    url = f"https://{self.target}:{port}"
                
                request = urllib.request.Request(url, headers={'User-Agent': 'SecurityScanner/1.0'})
                
                # Disable SSL verification for testing
                context = ssl._create_unverified_context()
                
                with urllib.request.urlopen(request, timeout=5, context=context) as response:
                    headers = dict(response.headers)
                    
                    security_headers = {
                        'Strict-Transport-Security': False,
                        'X-Frame-Options': False,
                        'X-Content-Type-Options': False,
                        'Content-Security-Policy': False,
                        'X-XSS-Protection': False,
                        'Referrer-Policy': False
                    }
                    
                    for header in security_headers:
                        security_headers[header] = header in headers
                    
                    results[port] = {
                        'url': url,
                        'status_code': response.status,
                        'server': headers.get('Server', 'Unknown'),
                        'security_headers': security_headers,
                        'missing_headers': [h for h, present in security_headers.items() if not present]
                    }
            except Exception as e:
                results[port] = {'error': str(e)}
        
        return results
    
    def _check_ssl_vulnerabilities(self) -> Dict:
        """Check for SSL/TLS vulnerabilities"""
        ssl_results = {}
        
        ssl_ports = [p for p in self.open_ports if p in [443, 465, 587, 636, 993, 995, 8443]]
        
        for port in ssl_ports:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        protocol = ssock.version()
                        
                        # Check for weak protocols
                        weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
                        is_weak = protocol in weak_protocols
                        
                        # Certificate expiry
                        not_after = cert.get('notAfter', '')
                        
                        ssl_results[port] = {
                            'protocol': protocol,
                            'cipher': cipher,
                            'certificate': {
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'version': cert.get('version'),
                                'notAfter': not_after,
                            },
                            'weak_protocol': is_weak,
                            'grade': 'F' if is_weak else 'A'
                        }
            except Exception as e:
                ssl_results[port] = {'error': str(e)}
        
        return ssl_results
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check for critical issues
        if 23 in self.open_ports:
            recommendations.append("🔴 CRITICAL: Disable Telnet and use SSH instead")
        
        if 21 in self.open_ports:
            recommendations.append("🟠 HIGH: Disable FTP and use SFTP/SCP instead")
        
        if 445 in self.open_ports:
            recommendations.append("🟠 HIGH: Ensure SMB is properly secured and up-to-date (protect against EternalBlue)")
        
        if 3389 in self.open_ports:
            recommendations.append("🟠 HIGH: Secure RDP with strong passwords and consider using VPN (protect against BlueKeep)")
        
        # Database security
        db_ports = [3306, 5432, 1433, 6379, 27017, 9200]
        exposed_dbs = [p for p in db_ports if p in self.open_ports]
        if exposed_dbs:
            recommendations.append(f"🟠 HIGH: Database services exposed on ports {exposed_dbs}. Restrict access to trusted networks only.")
        
        # SSL/TLS recommendations
        ssl_vulns = results.get('ssl_vulnerabilities', {})
        for port, ssl_info in ssl_vulns.items():
            if isinstance(ssl_info, dict) and ssl_info.get('weak_protocol'):
                recommendations.append(f"🟡 MEDIUM: Port {port} uses weak SSL/TLS protocol. Upgrade to TLS 1.2 or higher.")
        
        # Security headers
        sec_headers = results.get('security_headers', {})
        for port, header_info in sec_headers.items():
            if isinstance(header_info, dict) and 'missing_headers' in header_info:
                missing = header_info['missing_headers']
                if missing:
                    recommendations.append(f"🟡 MEDIUM: Port {port} missing security headers: {', '.join(missing)}")
        
        # General recommendations
        if len(self.open_ports) > 20:
            recommendations.append("🟡 MEDIUM: Large number of open ports detected. Close unnecessary services.")
        
        recommendations.append("🟢 LOW: Regularly update all software and apply security patches")
        recommendations.append("🟢 LOW: Implement network segmentation and firewall rules")
        recommendations.append("🟢 LOW: Enable logging and monitoring for all critical services")
        
        return recommendations

# ============================================================================
# WEB APPLICATION SCANNER
# ============================================================================

class WebApplicationScanner:
    """Scan for web applications and common vulnerabilities"""
    
    def __init__(self, target: str, ports: List[int]):
        self.target = target
        self.ports = [p for p in ports if p in [80, 443, 8000, 8008, 8080, 8443, 8888, 9090]]
        self.findings = {}
    
    def scan(self) -> Dict:
        """Scan web applications"""
        if not self.ports:
            return {'message': 'No web ports found'}
        
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("Starting Web Application Scan")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        results = {}
        
        for port in self.ports:
            print(f"{Colors.OKCYAN}[*] Scanning web service on port {port}...{Colors.ENDC}")
            results[port] = self._scan_web_service(port)
        
        return results
    
    def _scan_web_service(self, port: int) -> Dict:
        """Scan individual web service"""
        result = {
            'technologies': [],
            'cms_detected': None,
            'directories': [],
            'security_issues': []
        }
        
        try:
            # Determine protocol
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{self.target}:{port}"
            
            # Create request with custom headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            request = urllib.request.Request(base_url, headers=headers)
            
            # Disable SSL verification for testing
            context = ssl._create_unverified_context()
            
            # Get homepage
            with urllib.request.urlopen(request, timeout=10, context=context) as response:
                content = response.read().decode('utf-8', errors='ignore')
                response_headers = dict(response.headers)
                
                # Detect technologies
                result['technologies'] = self._detect_technologies(content, response_headers)
                
                # Detect CMS
                result['cms_detected'] = self._detect_cms(content, base_url)
                
                # Check for common directories
                result['directories'] = self._check_common_directories(base_url, context)
                
                # Security checks
                result['security_issues'] = self._check_web_security(content, response_headers)
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _detect_technologies(self, content: str, headers: Dict) -> List[str]:
        """Detect web technologies"""
        technologies = []
        
        # Server header
        server = headers.get('Server', headers.get('server', ''))
        if server:
            technologies.append(f"Server: {server}")
        
        # X-Powered-By
        powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
        if powered_by:
            technologies.append(f"Powered-By: {powered_by}")
        
        # JavaScript frameworks
        frameworks = {
            'React': ['react.development.js', 'react.production.min.js', '_react'],
            'Angular': ['angular.js', 'angular.min.js', 'ng-'],
            'Vue.js': ['vue.js', 'vue.min.js', 'v-'],
            'jQuery': ['jquery.js', 'jquery.min.js'],
            'Bootstrap': ['bootstrap.css', 'bootstrap.min.css']
        }
        
        for framework, indicators in frameworks.items():
            if any(indicator in content.lower() for indicator in indicators):
                technologies.append(f"Framework: {framework}")
        
        return technologies
    
    def _detect_cms(self, content: str, base_url: str) -> Optional[str]:
        """Detect Content Management System"""
        for cms, signature in ServiceDatabase.WEB_SIGNATURES.items():
            if any(pattern in content for pattern in signature['patterns']):
                return cms
        
        return None
    
    def _check_common_directories(self, base_url: str, context) -> List[str]:
        """Check for common directories"""
        common_dirs = [
            '/admin', '/administrator', '/wp-admin', '/login', '/phpmyadmin',
            '/backup', '/.git', '/.env', '/config', '/api', '/dashboard'
        ]
        
        found_dirs = []
        
        for directory in common_dirs:
            try:
                url = base_url + directory
                request = urllib.request.Request(url, headers={'User-Agent': 'SecurityScanner/1.0'})
                
                with urllib.request.urlopen(request, timeout=3, context=context) as response:
                    if response.status in [200, 301, 302, 401, 403]:
                        found_dirs.append(f"{directory} (Status: {response.status})")
            except:
                pass
        
        return found_dirs
    
    def _check_web_security(self, content: str, headers: Dict) -> List[Dict]:
        """Check for common web security issues"""
        issues = []
        
        # Check for directory listing
        if 'Index of /' in content or 'Directory listing for' in content:
            issues.append({
                'type': 'Directory Listing',
                'severity': 'MEDIUM',
                'description': 'Directory listing is enabled'
            })
        
        # Check for default pages
        if 'Welcome to nginx!' in content or 'Apache2 Debian Default Page' in content:
            issues.append({
                'type': 'Default Page',
                'severity': 'LOW',
                'description': 'Default web server page detected'
            })
        
        # Check for exposed credentials
        if 'password' in content.lower() and ('admin' in content.lower() or 'root' in content.lower()):
            issues.append({
                'type': 'Potential Credential Exposure',
                'severity': 'HIGH',
                'description': 'Potential credentials found in source code'
            })
        
        # Check for comments with sensitive info
        if '<!--' in content and any(keyword in content.lower() for keyword in ['password', 'key', 'secret', 'token']):
            issues.append({
                'type': 'Sensitive Information in Comments',
                'severity': 'MEDIUM',
                'description': 'HTML comments may contain sensitive information'
            })
        
        return issues

# ============================================================================
# OS FINGERPRINTING
# ============================================================================

class OSFingerprint:
    """Operating System fingerprinting"""
    
    def __init__(self, target: str, open_ports: List[int], banners: Dict):
        self.target = target
        self.open_ports = open_ports
        self.banners = banners
    
    def fingerprint(self) -> Dict:
        """Attempt to fingerprint the operating system"""
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("Starting OS Fingerprinting")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        os_hints = []
        confidence = "LOW"
        
        # Check banners for OS information
        for port, banner in self.banners.items():
            if not banner:
                continue
            
            # Windows indicators
            if any(indicator in banner.lower() for indicator in ['windows', 'microsoft', 'win32', 'iis']):
                os_hints.append("Windows")
            
            # Linux indicators
            if any(indicator in banner.lower() for indicator in ['linux', 'ubuntu', 'debian', 'centos', 'red hat', 'fedora']):
                os_hints.append("Linux")
            
            # Unix indicators
            if any(indicator in banner.lower() for indicator in ['unix', 'bsd', 'freebsd', 'openbsd']):
                os_hints.append("Unix")
        
        # Check port combinations
        if 135 in self.open_ports and 445 in self.open_ports:
            os_hints.append("Windows")
            confidence = "MEDIUM"
        
        if 22 in self.open_ports and 80 in self.open_ports:
            os_hints.append("Linux/Unix")
            confidence = "LOW"
        
        # Count occurrences
        os_count = {}
        for hint in os_hints:
            os_count[hint] = os_count.get(hint, 0) + 1
        
        if os_count:
            likely_os = max(os_count, key=os_count.get)
            if os_count[likely_os] > 2:
                confidence = "MEDIUM"
            if os_count[likely_os] > 4:
                confidence = "HIGH"
        else:
            likely_os = "Unknown"
        
        return {
            'likely_os': likely_os,
            'confidence': confidence,
            'evidence': os_hints,
            'reasoning': f"Based on {len(os_hints)} indicators from banners and port combinations"
        }

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self, scan_data: Dict):
        self.scan_data = scan_data
        self.timestamp = datetime.now()
    
    def generate_html_report(self, filename: str = "security_report.html"):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - {self.scan_data.get('target', 'Unknown')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 4px solid #667eea;
            padding-bottom: 15px;
            margin-bottom: 30px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-left: 5px solid #667eea;
            padding-left: 15px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-box {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .stat-box h3 {{
            margin: 0 0 10px 0;
            color: #667eea;
        }}
        .stat-box .value {{
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #27ae60; font-weight: bold; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .vulnerability {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .recommendation {{
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Assessment Report</h1>
            <p><strong>Target:</strong> {self.scan_data.get('target', 'Unknown')}</p>
            <p><strong>Scan Date:</strong> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Threat Level:</strong> <span class="{self.scan_data.get('threat_level', 'LOW').lower()}">{self.scan_data.get('threat_level', 'LOW')}</span></p>
        </div>
        
        <div class="summary">
            <div class="stat-box">
                <h3>Ports Scanned</h3>
                <div class="value">{self.scan_data.get('total_ports_scanned', 0)}</div>
            </div>
            <div class="stat-box">
                <h3>Open Ports</h3>
                <div class="value">{len(self.scan_data.get('open_ports', []))}</div>
            </div>
            <div class="stat-box">
                <h3>Critical Services</h3>
                <div class="value critical">{self.scan_data.get('critical_services', 0)}</div>
            </div>
            <div class="stat-box">
                <h3>Vulnerabilities</h3>
                <div class="value high">{len(self.scan_data.get('vulnerabilities', {}).get('service_vulnerabilities', []))}</div>
            </div>
        </div>
        
        <h2>📊 Open Ports & Services</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Description</th>
                    <th>Risk Level</th>
                    <th>Banner</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for port_detail in self.scan_data.get('open_port_details', []):
            risk_class = port_detail.get('risk', 'LOW').lower()
            banner = port_detail.get('banner', '')[:100]
            html += f"""
                <tr>
                    <td>{port_detail.get('port')}</td>
                    <td>{port_detail.get('service')}</td>
                    <td>{port_detail.get('description', '')}</td>
                    <td><span class="{risk_class}">{port_detail.get('risk')}</span></td>
                    <td>{banner}</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
"""
        
        # Vulnerabilities section
        vulnerabilities = self.scan_data.get('vulnerabilities', {})
        service_vulns = vulnerabilities.get('service_vulnerabilities', [])
        
        if service_vulns:
            html += """
        <h2>🔍 Detected Vulnerabilities</h2>
"""
            for vuln in service_vulns:
                html += f"""
        <div class="vulnerability">
            <h3>{vuln.get('cve')} - <span class="{vuln.get('severity', 'MEDIUM').lower()}">{vuln.get('severity')}</span></h3>
            <p><strong>Service:</strong> {vuln.get('service')} (Port {vuln.get('port')})</p>
            <p><strong>CVSS Score:</strong> {vuln.get('cvss_score')}</p>
            <p><strong>Description:</strong> {vuln.get('description')}</p>
        </div>
"""
        
        # Recommendations
        recommendations = vulnerabilities.get('recommendations', [])
        if recommendations:
            html += """
        <h2>💡 Security Recommendations</h2>
"""
            for rec in recommendations:
                html += f"""
        <div class="recommendation">
            {rec}
        </div>
"""
        
        # OS Fingerprint
        os_info = self.scan_data.get('os_fingerprint', {})
        if os_info:
            html += f"""
        <h2>💻 Operating System Detection</h2>
        <p><strong>Likely OS:</strong> {os_info.get('likely_os', 'Unknown')}</p>
        <p><strong>Confidence:</strong> {os_info.get('confidence', 'LOW')}</p>
        <p><strong>Reasoning:</strong> {os_info.get('reasoning', 'No data')}</p>
"""
        
        html += f"""
        <div class="footer">
            <p>Report generated by Advanced Cybersecurity Port Scanner v{VERSION}</p>
            <p>© 2024 Security Assessment Tool</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        return json.dumps(self.scan_data, indent=2)
    
    def generate_text_report(self) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("SECURITY ASSESSMENT REPORT")
        lines.append("=" * 80)
        lines.append(f"Target: {self.scan_data.get('target', 'Unknown')}")
        lines.append(f"Scan Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Threat Level: {self.scan_data.get('threat_level', 'LOW')}")
        lines.append("=" * 80)
        lines.append("")
        
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Ports Scanned: {self.scan_data.get('total_ports_scanned', 0)}")
        lines.append(f"Open Ports: {len(self.scan_data.get('open_ports', []))}")
        lines.append(f"Critical Services: {self.scan_data.get('critical_services', 0)}")
        lines.append("")
        
        lines.append("OPEN PORTS & SERVICES")
        lines.append("-" * 80)
        for port_detail in self.scan_data.get('open_port_details', []):
            lines.append(f"Port {port_detail.get('port'):5d} - {port_detail.get('service'):15s} - {port_detail.get('risk')}")
        
        lines.append("")
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 80)
        for rec in self.scan_data.get('vulnerabilities', {}).get('recommendations', []):
            lines.append(f"• {rec}")
        
        return "\n".join(lines)

# ============================================================================
# NETWORK MAPPER
# ============================================================================

class NetworkMapper:
    """Network topology and relationship mapping"""
    
    def __init__(self, scan_results: List[Dict]):
        self.scan_results = scan_results
    
    def generate_network_map(self) -> Dict:
        """Generate network topology map"""
        network_map = {
            'hosts': [],
            'services': defaultdict(list),
            'risk_summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        for result in self.scan_results:
            target = result.get('target')
            threat_level = result.get('threat_level', 'LOW')
            
            network_map['hosts'].append({
                'ip': target,
                'open_ports': len(result.get('open_ports', [])),
                'threat_level': threat_level
            })
            
            # Categorize services
            for port_detail in result.get('open_port_details', []):
                service = port_detail.get('service')
                risk = port_detail.get('risk', 'LOW')
                
                network_map['services'][service].append({
                    'host': target,
                    'port': port_detail.get('port'),
                    'risk': risk
                })
                
                # Update risk summary
                network_map['risk_summary'][risk.lower()] += 1
        
        return network_map

# ============================================================================
# INTERACTIVE MENU SYSTEM
# ============================================================================

class InteractiveScanner:
    """Interactive menu-driven scanner interface"""
    
    def __init__(self):
        self.target = None
        self.scan_results = {}
    
    def show_banner(self):
        """Display banner"""
        print(Colors.colored(BANNER, Colors.HEADER))
        print(Colors.colored(f"Version {VERSION}", Colors.OKCYAN))
        print(Colors.colored("Professional Cybersecurity Assessment Tool\n", Colors.OKCYAN))
    
    def main_menu(self):
        """Display main menu"""
        while True:
            print(f"\n{Colors.HEADER}{'=' * 80}")
            print("MAIN MENU")
            print(f"{'=' * 80}{Colors.ENDC}\n")
            
            print("1. 🎯 Quick Scan (Common Ports)")
            print("2. 🔍 Comprehensive Scan (All Ports)")
            print("3. 🌐 Web Application Scan")
            print("4. 🔐 Vulnerability Assessment")
            print("5. 🛡️ Full Security Audit")
            print("6. 📊 Generate Report")
            print("7. ⚙️  Advanced Options")
            print("8. ❌ Exit")
            
            choice = input(f"\n{Colors.OKCYAN}Select option [1-8]: {Colors.ENDC}").strip()
            
            if choice == '1':
                self.quick_scan()
            elif choice == '2':
                self.comprehensive_scan()
            elif choice == '3':
                self.web_scan()
            elif choice == '4':
                self.vulnerability_scan()
            elif choice == '5':
                self.full_audit()
            elif choice == '6':
                self.generate_report()
            elif choice == '7':
                self.advanced_options()
            elif choice == '8':
                print(f"\n{Colors.OKGREEN}Thank you for using Advanced Security Scanner!{Colors.ENDC}\n")
                break
            else:
                print(f"{Colors.FAIL}Invalid option. Please try again.{Colors.ENDC}")
    
    def get_target(self) -> str:
        """Get target from user"""
        if self.target:
            use_existing = input(f"\n{Colors.OKCYAN}Use previous target ({self.target})? [Y/n]: {Colors.ENDC}").strip().lower()
            if use_existing != 'n':
                return self.target
        
        while True:
            target = input(f"\n{Colors.OKCYAN}Enter target IP address or hostname: {Colors.ENDC}").strip()
            if target:
                self.target = target
                return target
            print(f"{Colors.FAIL}Please enter a valid target.{Colors.ENDC}")
    
    def quick_scan(self):
        """Perform quick scan"""
        target = self.get_target()
        
        print(f"\n{Colors.OKGREEN}Starting Quick Scan...{Colors.ENDC}")
        
        scanner = AdvancedPortScanner(
            target=target,
            port_range=None,
            threads=100,
            timeout=2,
            verbose=True,
            scan_type=ScanType.TCP_CONNECT
        )
        
        results = scanner.scan()
        self.scan_results['port_scan'] = results
        
        self.display_scan_summary(results)
    
    def comprehensive_scan(self):
        """Perform comprehensive scan"""
        target = self.get_target()
        
        print(f"\n{Colors.OKGREEN}Starting Comprehensive Scan (this may take several minutes)...{Colors.ENDC}")
        
        scanner = AdvancedPortScanner(
            target=target,
            port_range="1-65535",
            threads=200,
            timeout=1,
            verbose=False,
            scan_type=ScanType.COMPREHENSIVE
        )
        
        results = scanner.scan()
        self.scan_results['port_scan'] = results
        
        self.display_scan_summary(results)
    
    def web_scan(self):
        """Perform web application scan"""
        if 'port_scan' not in self.scan_results:
            print(f"{Colors.WARNING}Please run a port scan first.{Colors.ENDC}")
            return
        
        target = self.target
        open_ports = self.scan_results['port_scan'].get('open_ports', [])
        
        web_scanner = WebApplicationScanner(target, open_ports)
        results = web_scanner.scan()
        
        self.scan_results['web_scan'] = results
        
        print(f"\n{Colors.OKGREEN}Web scan completed!{Colors.ENDC}")
    
    def vulnerability_scan(self):
        """Perform vulnerability assessment"""
        if 'port_scan' not in self.scan_results:
            print(f"{Colors.WARNING}Please run a port scan first.{Colors.ENDC}")
            return
        
        target = self.target
        port_data = self.scan_results['port_scan']
        
        vuln_scanner = VulnerabilityScanner(
            target=target,
            open_ports=port_data.get('open_ports', []),
            services={},
            banners={}
        )
        
        results = vuln_scanner.scan_vulnerabilities()
        self.scan_results['vulnerabilities'] = results
        
        print(f"\n{Colors.OKGREEN}Vulnerability scan completed!{Colors.ENDC}")
        print(f"Found {len(results.get('service_vulnerabilities', []))} potential vulnerabilities")
    
    def full_audit(self):
        """Perform full security audit"""
        target = self.get_target()
        
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("FULL SECURITY AUDIT")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        print("This will perform:")
        print("1. Comprehensive port scan")
        print("2. Service fingerprinting")
        print("3. Vulnerability assessment")
        print("4. Web application scan")
        print("5. OS fingerprinting")
        print("\nThis may take 10-20 minutes depending on the target.\n")
        
        confirm = input(f"{Colors.OKCYAN}Proceed? [Y/n]: {Colors.ENDC}").strip().lower()
        if confirm == 'n':
            return
        
        # Port scan
        print(f"\n{Colors.OKGREEN}[1/5] Running port scan...{Colors.ENDC}")
        scanner = AdvancedPortScanner(target=target, threads=150, verbose=False)
        port_results = scanner.scan()
        self.scan_results['port_scan'] = port_results
        
        # OS fingerprinting
        print(f"\n{Colors.OKGREEN}[2/5] Fingerprinting OS...{Colors.ENDC}")
        os_fp = OSFingerprint(target, port_results.get('open_ports', []), scanner.banners)
        os_results = os_fp.fingerprint()
        self.scan_results['os_fingerprint'] = os_results
        
        # Vulnerability scan
        print(f"\n{Colors.OKGREEN}[3/5] Scanning for vulnerabilities...{Colors.ENDC}")
        vuln_scanner = VulnerabilityScanner(
            target=target,
            open_ports=port_results.get('open_ports', []),
            services=scanner.services,
            banners=scanner.banners
        )
        vuln_results = vuln_scanner.scan_vulnerabilities()
        self.scan_results['vulnerabilities'] = vuln_results
        
        # Web scan
        print(f"\n{Colors.OKGREEN}[4/5] Scanning web applications...{Colors.ENDC}")
        web_scanner = WebApplicationScanner(target, port_results.get('open_ports', []))
        web_results = web_scanner.scan()
        self.scan_results['web_scan'] = web_results
        
        # Compile results
        print(f"\n{Colors.OKGREEN}[5/5] Compiling results...{Colors.ENDC}")
        
        # Merge all results
        full_results = {
            **port_results,
            'os_fingerprint': os_results,
            'vulnerabilities': vuln_results,
            'web_applications': web_results
        }
        
        self.scan_results = full_results
        
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("FULL AUDIT COMPLETED")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        self.display_full_audit_summary(full_results)
    
    def display_scan_summary(self, results: Dict):
        """Display scan summary"""
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("SCAN SUMMARY")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        print(f"Target: {results.get('target')}")
        print(f"Scan Duration: {results.get('scan_duration', 0):.2f} seconds")
        print(f"Total Ports Scanned: {results.get('total_ports_scanned', 0)}")
        print(f"Open Ports: {Colors.OKGREEN}{len(results.get('open_ports', []))}{Colors.ENDC}")
        print(f"Closed Ports: {results.get('closed_ports', 0)}")
        print(f"Filtered Ports: {results.get('filtered_ports', 0)}")
        
        threat_color = {
            'CRITICAL': Colors.FAIL,
            'HIGH': Colors.WARNING,
            'MEDIUM': Colors.OKCYAN,
            'LOW': Colors.OKGREEN
        }.get(results.get('threat_level', 'LOW'), Colors.ENDC)
        
        print(f"Threat Level: {threat_color}{results.get('threat_level', 'LOW')}{Colors.ENDC}")
        
        if results.get('open_port_details'):
            print(f"\n{Colors.HEADER}Open Ports:{Colors.ENDC}")
            for detail in results['open_port_details'][:10]:
                risk_color = {
                    'CRITICAL': Colors.FAIL,
                    'HIGH': Colors.WARNING,
                    'MEDIUM': Colors.OKCYAN,
                    'LOW': Colors.OKGREEN
                }.get(detail.get('risk', 'LOW'), Colors.ENDC)
                
                print(f"  {risk_color}Port {detail.get('port'):5d} - {detail.get('service'):15s} ({detail.get('risk')}){Colors.ENDC}")
    
    def display_full_audit_summary(self, results: Dict):
        """Display full audit summary"""
        print(f"📊 {Colors.BOLD}Scan Statistics:{Colors.ENDC}")
        print(f"   Ports Scanned: {results.get('total_ports_scanned', 0)}")
        print(f"   Open Ports: {len(results.get('open_ports', []))}")
        print(f"   Critical Services: {Colors.FAIL}{results.get('critical_services', 0)}{Colors.ENDC}")
        print(f"   High Risk Services: {Colors.WARNING}{results.get('high_risk_services', 0)}{Colors.ENDC}")
        
        os_info = results.get('os_fingerprint', {})
        if os_info:
            print(f"\n💻 {Colors.BOLD}OS Detection:{Colors.ENDC}")
            print(f"   Likely OS: {os_info.get('likely_os', 'Unknown')}")
            print(f"   Confidence: {os_info.get('confidence', 'LOW')}")
        
        vulns = results.get('vulnerabilities', {}).get('service_vulnerabilities', [])
        if vulns:
            print(f"\n🔍 {Colors.BOLD}Vulnerabilities:{Colors.ENDC}")
            print(f"   Total Found: {Colors.FAIL}{len(vulns)}{Colors.ENDC}")
            critical_vulns = [v for v in vulns if v.get('severity') == 'CRITICAL']
            if critical_vulns:
                print(f"   Critical: {Colors.FAIL}{len(critical_vulns)}{Colors.ENDC}")
        
        recommendations = results.get('vulnerabilities', {}).get('recommendations', [])
        if recommendations:
            print(f"\n💡 {Colors.BOLD}Top Recommendations:{Colors.ENDC}")
            for rec in recommendations[:5]:
                print(f"   {rec}")
    
    def generate_report(self):
        """Generate security report"""
        if not self.scan_results:
            print(f"{Colors.WARNING}No scan results available. Please run a scan first.{Colors.ENDC}")
            return
        
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("REPORT GENERATION")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        print("Select report format:")
        print("1. HTML (Interactive)")
        print("2. JSON (Machine-readable)")
        print("3. Text (Plain text)")
        print("4. All formats")
        
        choice = input(f"\n{Colors.OKCYAN}Select format [1-4]: {Colors.ENDC}").strip()
        
        report_gen = ReportGenerator(self.scan_results)
        
        if choice in ['1', '4']:
            html_report = report_gen.generate_html_report()
            filename = f"security_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(filename, 'w') as f:
                f.write(html_report)
            print(f"{Colors.OKGREEN}✓ HTML report saved: {filename}{Colors.ENDC}")
        
        if choice in ['2', '4']:
            json_report = report_gen.generate_json_report()
            filename = f"security_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                f.write(json_report)
            print(f"{Colors.OKGREEN}✓ JSON report saved: {filename}{Colors.ENDC}")
        
        if choice in ['3', '4']:
            text_report = report_gen.generate_text_report()
            filename = f"security_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(text_report)
            print(f"{Colors.OKGREEN}✓ Text report saved: {filename}{Colors.ENDC}")
    
    def advanced_options(self):
        """Advanced scanning options"""
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("ADVANCED OPTIONS")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        print("1. Custom Port Range Scan")
        print("2. UDP Port Scan")
        print("3. Multi-Target Scan")
        print("4. Stealth Scan")
        print("5. Back to Main Menu")
        
        choice = input(f"\n{Colors.OKCYAN}Select option [1-5]: {Colors.ENDC}").strip()
        
        if choice == '1':
            self.custom_port_scan()
        elif choice == '2':
            self.udp_scan()
        elif choice == '3':
            self.multi_target_scan()
        elif choice == '4':
            print(f"{Colors.WARNING}Stealth scan requires root privileges and is not implemented in basic mode.{Colors.ENDC}")
    
    def custom_port_scan(self):
        """Custom port range scan"""
        target = self.get_target()
        port_range = input(f"\n{Colors.OKCYAN}Enter port range (e.g., 1-1000 or 80,443,8080): {Colors.ENDC}").strip()
        
        if not port_range:
            print(f"{Colors.FAIL}Invalid port range.{Colors.ENDC}")
            return
        
        scanner = AdvancedPortScanner(
            target=target,
            port_range=port_range,
            threads=100,
            verbose=True
        )
        
        results = scanner.scan()
        self.scan_results['port_scan'] = results
        self.display_scan_summary(results)
    
    def udp_scan(self):
        """UDP port scan"""
        target = self.get_target()
        
        print(f"\n{Colors.WARNING}Note: UDP scanning is slower and less reliable than TCP scanning.{Colors.ENDC}")
        
        scanner = AdvancedPortScanner(
            target=target,
            port_range="53,67,68,69,123,161,162,514,520",
            threads=20,
            timeout=3,
            verbose=True,
            scan_type=ScanType.UDP_SCAN
        )
        
        results = scanner.scan()
        self.scan_results['udp_scan'] = results
        self.display_scan_summary(results)
    
    def multi_target_scan(self):
        """Scan multiple targets"""
        print(f"\n{Colors.OKCYAN}Enter targets (comma-separated or CIDR notation):{Colors.ENDC}")
        targets_input = input("Targets: ").strip()
        
        if not targets_input:
            print(f"{Colors.FAIL}No targets specified.{Colors.ENDC}")
            return
        
        # Parse targets
        targets = [t.strip() for t in targets_input.split(',')]
        
        print(f"\n{Colors.OKGREEN}Scanning {len(targets)} target(s)...{Colors.ENDC}\n")
        
        all_results = []
        
        for i, target in enumerate(targets, 1):
            print(f"\n{Colors.HEADER}[{i}/{len(targets)}] Scanning {target}...{Colors.ENDC}")
            
            scanner = AdvancedPortScanner(target=target, threads=100, verbose=False)
            results = scanner.scan()
            all_results.append(results)
            
            time.sleep(1)  # Be nice to the network
        
        # Generate network map
        mapper = NetworkMapper(all_results)
        network_map = mapper.generate_network_map()
        
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("MULTI-TARGET SCAN SUMMARY")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        for host in network_map['hosts']:
            threat_color = {
                'CRITICAL': Colors.FAIL,
                'HIGH': Colors.WARNING,
                'MEDIUM': Colors.OKCYAN,
                'LOW': Colors.OKGREEN
            }.get(host['threat_level'], Colors.ENDC)
            
            print(f"{threat_color}{host['ip']:20s} - {host['open_ports']:3d} open ports - {host['threat_level']}{Colors.ENDC}")
        
        self.scan_results['multi_target'] = all_results
        self.scan_results['network_map'] = network_map

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Advanced Cybersecurity Port Scanner & Vulnerability Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Interactive mode (no arguments)
  %(prog)s
  
  # Quick scan
  %(prog)s 192.168.1.1
  
  # Custom port range
  %(prog)s 192.168.1.1 -p 1-10000
  
  # Full audit with reports
  %(prog)s 192.168.1.1 --full-audit -o report
  
  # Multiple targets
  %(prog)s 192.168.1.1 192.168.1.2 192.168.1.3
  
  # Verbose output
  %(prog)s 192.168.1.1 -v
        '''
    )
    
    parser.add_argument('targets', nargs='*', help='Target IP address(es) to scan')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000 or 80,443,8080)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=2, help='Socket timeout in seconds (default: 2)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output filename (without extension)')
    parser.add_argument('--full-audit', action='store_true', help='Perform full security audit')
    parser.add_argument('--web-scan', action='store_true', help='Include web application scan')
    parser.add_argument('--vuln-scan', action='store_true', help='Include vulnerability scan')
    parser.add_argument('--format', choices=['html', 'json', 'text', 'all'], default='html',
                       help='Report format (default: html)')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    return parser.parse_args()

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # If no targets provided, run interactive mode
    if not args.targets:
        interactive = InteractiveScanner()
        interactive.show_banner()
        interactive.main_menu()
        return
    
    # Command-line mode
    print(Colors.colored(BANNER, Colors.HEADER))
    
    # Single target
    if len(args.targets) == 1:
        target = args.targets[0]
        
        if args.full_audit:
            # Full audit
            print(f"\n{Colors.OKGREEN}Starting Full Security Audit on {target}...{Colors.ENDC}\n")
            
            scanner = AdvancedPortScanner(
                target=target,
                port_range=args.ports,
                threads=args.threads,
                timeout=args.timeout,
                verbose=args.verbose
            )
            port_results = scanner.scan()
            
            os_fp = OSFingerprint(target, port_results.get('open_ports', []), scanner.banners)
            os_results = os_fp.fingerprint()
            
            vuln_scanner = VulnerabilityScanner(
                target=target,
                open_ports=port_results.get('open_ports', []),
                services=scanner.services,
                banners=scanner.banners
            )
            vuln_results = vuln_scanner.scan_vulnerabilities()
            
            # Compile results
            full_results = {
                **port_results,
                'os_fingerprint': os_results,
                'vulnerabilities': vuln_results
            }
            
            # Generate reports
            if args.output:
                report_gen = ReportGenerator(full_results)
                
                if args.format in ['html', 'all']:
                    html = report_gen.generate_html_report()
                    with open(f"{args.output}.html", 'w') as f:
                        f.write(html)
                    print(f"{Colors.OKGREEN}✓ HTML report saved: {args.output}.html{Colors.ENDC}")
                
                if args.format in ['json', 'all']:
                    json_report = report_gen.generate_json_report()
                    with open(f"{args.output}.json", 'w') as f:
                        f.write(json_report)
                    print(f"{Colors.OKGREEN}✓ JSON report saved: {args.output}.json{Colors.ENDC}")
                
                if args.format in ['text', 'all']:
                    text_report = report_gen.generate_text_report()
                    with open(f"{args.output}.txt", 'w') as f:
                        f.write(text_report)
                    print(f"{Colors.OKGREEN}✓ Text report saved: {args.output}.txt{Colors.ENDC}")
        else:
            # Basic scan
            scanner = AdvancedPortScanner(
                target=target,
                port_range=args.ports,
                threads=args.threads,
                timeout=args.timeout,
                verbose=args.verbose
            )
            results = scanner.scan()
            
            if args.output:
                with open(f"{args.output}.json", 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"{Colors.OKGREEN}Results saved to {args.output}.json{Colors.ENDC}")
    
    else:
        # Multiple targets
        print(f"\n{Colors.OKGREEN}Scanning {len(args.targets)} targets...{Colors.ENDC}\n")
        
        all_results = []
        for i, target in enumerate(args.targets, 1):
            print(f"\n{Colors.HEADER}[{i}/{len(args.targets)}] Scanning {target}...{Colors.ENDC}")
            
            scanner = AdvancedPortScanner(
                target=target,
                port_range=args.ports,
                threads=args.threads,
                timeout=args.timeout,
                verbose=args.verbose
            )
            results = scanner.scan()
            all_results.append(results)
            
            time.sleep(1)
        
        if args.output:
            with open(f"{args.output}.json", 'w') as f:
                json.dump(all_results, f, indent=2)
            print(f"\n{Colors.OKGREEN}Results saved to {args.output}.json{Colors.ENDC}")

# ============================================================================
# ENTRY POINT
# ============================================================================

# ============================================================================
# EXPLOIT DATABASE & METASPLOIT INTEGRATION
# ============================================================================

class ExploitDatabase:
    """Comprehensive exploit database with Metasploit integration"""
    
    EXPLOITS = {
        "CVE-2017-0144": {
            "name": "EternalBlue",
            "service": "SMB",
            "port": 445,
            "severity": "CRITICAL",
            "description": "Remote Code Execution vulnerability in SMBv1",
            "affected_versions": ["Windows 7", "Windows Server 2008", "Windows 10"],
            "metasploit_module": "exploit/windows/smb/ms17_010_eternalblue",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                "https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/"
            ],
            "mitigation": "Apply MS17-010 security update immediately",
            "exploitability": "High",
            "public_exploit": True
        },
        "CVE-2019-0708": {
            "name": "BlueKeep",
            "service": "RDP",
            "port": 3389,
            "severity": "CRITICAL",
            "description": "Remote Desktop Services Remote Code Execution",
            "affected_versions": ["Windows 7", "Windows Server 2008 R2"],
            "metasploit_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"
            ],
            "mitigation": "Apply Windows security updates, enable Network Level Authentication",
            "exploitability": "High",
            "public_exploit": True
        },
        "CVE-2021-41773": {
            "name": "Apache Path Traversal",
            "service": "HTTP",
            "port": 80,
            "severity": "CRITICAL",
            "description": "Path traversal vulnerability in Apache 2.4.49",
            "affected_versions": ["Apache 2.4.49"],
            "metasploit_module": "exploit/multi/http/apache_normalize_path_rce",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
            ],
            "mitigation": "Upgrade to Apache 2.4.51 or later",
            "exploitability": "High",
            "public_exploit": True
        },
        "CVE-2022-0543": {
            "name": "Redis Lua Sandbox Escape",
            "service": "Redis",
            "port": 6379,
            "severity": "CRITICAL",
            "description": "Lua sandbox escape leading to RCE",
            "affected_versions": ["Redis < 6.2.7", "Redis < 6.0.16"],
            "metasploit_module": "exploit/linux/redis/cve_2022_0543_lua_rce",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-0543"
            ],
            "mitigation": "Upgrade Redis, enable authentication, restrict network access",
            "exploitability": "High",
            "public_exploit": True
        },
        "CVE-2021-44228": {
            "name": "Log4Shell",
            "service": "Java Applications",
            "port": 8080,
            "severity": "CRITICAL",
            "description": "Remote Code Execution via JNDI injection in Log4j",
            "affected_versions": ["Log4j 2.0-beta9 to 2.14.1"],
            "metasploit_module": "exploit/multi/http/log4shell_header_injection",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
            ],
            "mitigation": "Upgrade to Log4j 2.17.0 or later",
            "exploitability": "Critical",
            "public_exploit": True
        },
        "CVE-2020-0796": {
            "name": "SMBGhost",
            "service": "SMB",
            "port": 445,
            "severity": "CRITICAL",
            "description": "Remote Code Execution in SMBv3",
            "affected_versions": ["Windows 10 1903", "Windows 10 1909", "Windows Server 1903/1909"],
            "metasploit_module": "exploit/windows/smb/cve_2020_0796_smbghost",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2020-0796"
            ],
            "mitigation": "Apply KB4551762 security update",
            "exploitability": "High",
            "public_exploit": True
        }
    }
    
    @staticmethod
    def check_exploits(service: str, port: int, version: str = "") -> List[Dict]:
        """Check for available exploits"""
        matching_exploits = []
        
        for cve, exploit_info in ExploitDatabase.EXPLOITS.items():
            if exploit_info['service'].lower() in service.lower() or exploit_info['port'] == port:
                matching_exploits.append({
                    'cve': cve,
                    **exploit_info
                })
        
        return matching_exploits
    
    @staticmethod
    def get_exploit_details(cve: str) -> Optional[Dict]:
        """Get detailed exploit information"""
        return ExploitDatabase.EXPLOITS.get(cve)
    
    @staticmethod
    def generate_metasploit_commands(exploits: List[Dict]) -> List[str]:
        """Generate Metasploit commands for found exploits"""
        commands = []
        
        for exploit in exploits:
            if 'metasploit_module' in exploit:
                commands.append(f"""
# Exploit: {exploit['name']} ({exploit['cve']})
use {exploit['metasploit_module']}
set RHOSTS <target_ip>
set RPORT {exploit['port']}
exploit
""")
        
        return commands

# ============================================================================
# COMPLIANCE CHECKER
# ============================================================================

class ComplianceChecker:
    """Check compliance with security standards (PCI-DSS, HIPAA, CIS, etc.)"""
    
    def __init__(self, scan_results: Dict):
        self.scan_results = scan_results
        self.findings = []
    
    def check_pci_dss(self) -> Dict:
        """Check PCI-DSS compliance"""
        findings = {
            'compliant': True,
            'issues': [],
            'recommendations': []
        }
        
        open_ports = self.scan_results.get('open_ports', [])
        
        # PCI-DSS Requirement 1: Install and maintain a firewall
        if len(open_ports) > 10:
            findings['compliant'] = False
            findings['issues'].append({
                'requirement': 'PCI-DSS 1.2',
                'description': 'Excessive open ports detected',
                'severity': 'HIGH',
                'details': f'{len(open_ports)} ports are open. Minimize exposed services.'
            })
        
        # PCI-DSS Requirement 2: Do not use vendor-supplied defaults
        if 23 in open_ports:  # Telnet
            findings['compliant'] = False
            findings['issues'].append({
                'requirement': 'PCI-DSS 2.3',
                'description': 'Insecure protocol detected',
                'severity': 'CRITICAL',
                'details': 'Telnet is enabled. Use SSH instead.'
            })
        
        # PCI-DSS Requirement 4: Encrypt transmission of cardholder data
        if 80 in open_ports and 443 not in open_ports:
            findings['issues'].append({
                'requirement': 'PCI-DSS 4.1',
                'description': 'Unencrypted web traffic',
                'severity': 'HIGH',
                'details': 'HTTP is enabled without HTTPS. Enable SSL/TLS.'
            })
        
        # Database security
        db_ports = [3306, 5432, 1433, 27017, 6379]
        exposed_dbs = [p for p in db_ports if p in open_ports]
        if exposed_dbs:
            findings['compliant'] = False
            findings['issues'].append({
                'requirement': 'PCI-DSS 1.3',
                'description': 'Database services exposed',
                'severity': 'CRITICAL',
                'details': f'Database ports {exposed_dbs} are accessible from external networks.'
            })
        
        return findings
    
    def check_hipaa(self) -> Dict:
        """Check HIPAA compliance"""
        findings = {
            'compliant': True,
            'issues': [],
            'recommendations': []
        }
        
        open_ports = self.scan_results.get('open_ports', [])
        
        # HIPAA requires encryption in transit
        if 23 in open_ports or 21 in open_ports:
            findings['compliant'] = False
            findings['issues'].append({
                'requirement': 'HIPAA 164.312(e)(1)',
                'description': 'Unencrypted transmission',
                'severity': 'CRITICAL',
                'details': 'Unencrypted protocols (Telnet/FTP) detected.'
            })
        
        # Access controls
        if 3389 in open_ports:  # RDP
            findings['issues'].append({
                'requirement': 'HIPAA 164.312(a)(1)',
                'description': 'Remote access service exposed',
                'severity': 'HIGH',
                'details': 'RDP should be protected with MFA and VPN.'
            })
        
        return findings
    
    def check_cis_benchmarks(self) -> Dict:
        """Check CIS Security Benchmarks"""
        findings = {
            'compliant': True,
            'issues': [],
            'score': 0
        }
        
        open_ports = self.scan_results.get('open_ports', [])
        total_checks = 10
        passed_checks = 0
        
        # CIS Control 4: Controlled Use of Administrative Privileges
        if 22 in open_ports:  # SSH
            passed_checks += 1
        
        # CIS Control 9: Limitation and Control of Network Ports
        if len(open_ports) < 20:
            passed_checks += 1
        
        # CIS Control 13: Data Protection
        if 443 in open_ports:  # HTTPS
            passed_checks += 1
        
        # Disable unnecessary services
        unnecessary = [23, 21, 513, 514]
        if not any(p in open_ports for p in unnecessary):
            passed_checks += 2
        
        findings['score'] = (passed_checks / total_checks) * 100
        findings['compliant'] = findings['score'] >= 70
        
        return findings
    
    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive compliance report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.scan_results.get('target'),
            'pci_dss': self.check_pci_dss(),
            'hipaa': self.check_hipaa(),
            'cis': self.check_cis_benchmarks()
        }
        
        return report

# ============================================================================
# NETWORK DISCOVERY & MAPPING
# ============================================================================

class NetworkDiscovery:
    """Advanced network discovery and topology mapping"""
    
    def __init__(self, network: str):
        self.network = network
        self.active_hosts = []
        self.network_topology = {}
    
    def ping_sweep(self, timeout: float = 1) -> List[str]:
        """Perform ping sweep to discover active hosts"""
        print(f"\n{Colors.HEADER}{'=' * 80}")
        print("Network Discovery - Ping Sweep")
        print(f"{'=' * 80}{Colors.ENDC}\n")
        
        active_hosts = []
        
        try:
            # Parse network
            network = ipaddress.ip_network(self.network, strict=False)
            total_hosts = network.num_addresses - 2  # Exclude network and broadcast
            
            print(f"Scanning {total_hosts} hosts in {self.network}...\n")
            
            for i, host in enumerate(network.hosts(), 1):
                if i % 10 == 0:
                    progress = (i / total_hosts) * 100
                    print(f"\rProgress: {progress:.1f}% ({i}/{total_hosts})", end='', flush=True)
                
                # Try to ping
                if platform.system().lower() == 'windows':
                    ping_cmd = f"ping -n 1 -w {int(timeout*1000)} {host}"
                else:
                    ping_cmd = f"ping -c 1 -W {int(timeout)} {host}"
                
                try:
                    result = subprocess.run(
                        ping_cmd.split(),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=timeout + 1
                    )
                    
                    if result.returncode == 0:
                        active_hosts.append(str(host))
                        print(f"\n{Colors.OKGREEN}[+] Host {host} is alive{Colors.ENDC}")
                except:
                    pass
            
            print(f"\n\nDiscovered {len(active_hosts)} active hosts")
            
        except Exception as e:
            print(f"{Colors.FAIL}Error during network discovery: {str(e)}{Colors.ENDC}")
        
        self.active_hosts = active_hosts
        return active_hosts
    
    def arp_scan(self) -> List[Dict]:
        """Perform ARP scan for local network discovery"""
        print(f"\n{Colors.OKCYAN}Performing ARP scan...{Colors.ENDC}")
        
        # This would typically use scapy or similar, but we'll simulate
        results = []
        
        for host in self.active_hosts:
            results.append({
                'ip': host,
                'mac': 'XX:XX:XX:XX:XX:XX',
                'vendor': 'Unknown'
            })
        
        return results
    
    def trace_route(self, target: str, max_hops: int = 30) -> List[Dict]:
        """Trace route to target"""
        print(f"\n{Colors.OKCYAN}Tracing route to {target}...{Colors.ENDC}")
        
        hops = []
        
        # Simplified traceroute
        for hop in range(1, min(max_hops + 1, 10)):
            hops.append({
                'hop': hop,
                'ip': f"192.168.{hop}.1",
                'rtt': f"{random.uniform(1, 50):.2f} ms"
            })
        
        return hops
    
    def generate_topology_map(self) -> Dict:
        """Generate network topology map"""
        topology = {
            'networks': {},
            'hosts': [],
            'connections': []
        }
        
        for host in self.active_hosts:
            topology['hosts'].append({
                'ip': host,
                'status': 'active',
                'services': []
            })
        
        return topology

# ============================================================================
# PLUGIN SYSTEM
# ============================================================================

class PluginSystem:
    """Extensible plugin system for custom scanners"""
    
    def __init__(self):
        self.plugins = {}
        self.plugin_directory = "/tmp/scanner_plugins"
    
    def register_plugin(self, name: str, plugin_class):
        """Register a plugin"""
        self.plugins[name] = plugin_class
        print(f"{Colors.OKGREEN}[+] Plugin registered: {name}{Colors.ENDC}")
    
    def load_plugins(self):
        """Load plugins from directory"""
        if not os.path.exists(self.plugin_directory):
            os.makedirs(self.plugin_directory)
        
        # This would dynamically load Python files from the plugin directory
        print(f"{Colors.OKCYAN}Loading plugins from {self.plugin_directory}...{Colors.ENDC}")
    
    def execute_plugin(self, name: str, *args, **kwargs):
        """Execute a plugin"""
        if name in self.plugins:
            plugin = self.plugins[name]
            return plugin.run(*args, **kwargs)
        else:
            print(f"{Colors.FAIL}Plugin not found: {name}{Colors.ENDC}")
            return None
    
    def list_plugins(self):
        """List available plugins"""
        print(f"\n{Colors.HEADER}Available Plugins:{Colors.ENDC}")
        for name in self.plugins:
            print(f"  • {name}")

# ============================================================================
# ADVANCED REPORTING WITH VISUALIZATION
# ============================================================================

class AdvancedReportGenerator:
    """Advanced reporting with charts and visualizations"""
    
    def __init__(self, scan_data: Dict):
        self.scan_data = scan_data
        self.timestamp = datetime.now()
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary"""
        summary = f"""
EXECUTIVE SUMMARY
=================

Assessment Date: {self.timestamp.strftime('%Y-%m-%d')}
Target: {self.scan_data.get('target', 'Unknown')}

OVERALL RISK RATING: {self.scan_data.get('threat_level', 'UNKNOWN')}

Key Findings:
- {len(self.scan_data.get('open_ports', []))} open ports discovered
- {self.scan_data.get('critical_services', 0)} critical services exposed
- {len(self.scan_data.get('vulnerabilities', {}).get('service_vulnerabilities', []))} potential vulnerabilities identified

Top Concerns:
"""
        
        # Add top concerns
        vulns = self.scan_data.get('vulnerabilities', {}).get('service_vulnerabilities', [])
        critical_vulns = [v for v in vulns if v.get('severity') == 'CRITICAL']
        
        for i, vuln in enumerate(critical_vulns[:5], 1):
            summary += f"{i}. {vuln.get('cve')} - {vuln.get('description')}\n"
        
        return summary
    
    def generate_risk_matrix(self) -> str:
        """Generate risk assessment matrix"""
        matrix = """
RISK ASSESSMENT MATRIX
======================

              Impact
            Low  Medium  High  Critical
Likelihood  ├────┼──────┼─────┼─────────┤
High        │ M  │  H   │  H  │    C    │
Medium      │ L  │  M   │  H  │    H    │
Low         │ L  │  L   │  M  │    M    │
Very Low    │ L  │  L   │  L  │    L    │

Legend: L=Low, M=Medium, H=High, C=Critical
"""
        return matrix
    
    def generate_detailed_html_report(self, filename: str = "detailed_report.html"):
        """Generate comprehensive HTML report with visualizations"""
        
        # Port distribution chart data
        port_data = []
        for port_detail in self.scan_data.get('open_port_details', []):
            port_data.append({
                'port': port_detail.get('port'),
                'service': port_detail.get('service'),
                'risk': port_detail.get('risk')
            })
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive Security Assessment - {self.scan_data.get('target', 'Unknown')}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0f0f23;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(102, 126, 234, 0.3);
        }}
        
        .header h1 {{
            color: white;
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .info-card {{
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }}
        
        .info-card h3 {{
            color: #fff;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        
        .info-card .value {{
            color: #fff;
            font-size: 1.8em;
            font-weight: bold;
        }}
        
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: #1a1a2e;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3);
            border: 1px solid #2a2a3e;
        }}
        
        .card h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.5em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }}
        
        .stat {{
            background: #0f0f23;
            padding: 15px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }}
        
        .stat-label {{
            color: #888;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        
        .stat-value {{
            color: #fff;
            font-size: 2em;
            font-weight: bold;
        }}
        
        .critical {{ color: #ff4757; }}
        .high {{ color: #ffa502; }}
        .medium {{ color: #ffd32a; }}
        .low {{ color: #26de81; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #2a2a3e;
        }}
        
        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}
        
        tr:hover {{
            background: rgba(102, 126, 234, 0.1);
        }}
        
        .vulnerability-card {{
            background: linear-gradient(135deg, #ff4757 0%, #ff6348 100%);
            padding: 20px;
            border-radius: 10px;
            margin: 10px 0;
            color: white;
        }}
        
        .vulnerability-card h3 {{
            margin-bottom: 10px;
        }}
        
        .recommendation {{
            background: linear-gradient(135deg, #26de81 0%, #20bf6b 100%);
            padding: 15px;
            border-radius: 10px;
            margin: 10px 0;
            color: white;
        }}
        
        .chart-container {{
            position: relative;
            height: 300px;
            margin: 20px 0;
        }}
        
        .section {{
            background: #1a1a2e;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 20px;
            border: 1px solid #2a2a3e;
        }}
        
        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }}
        
        .badge-critical {{
            background: #ff4757;
            color: white;
        }}
        
        .badge-high {{
            background: #ffa502;
            color: white;
        }}
        
        .badge-medium {{
            background: #ffd32a;
            color: #000;
        }}
        
        .badge-low {{
            background: #26de81;
            color: white;
        }}
        
        .timeline {{
            position: relative;
            padding-left: 30px;
        }}
        
        .timeline::before {{
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 2px;
            background: #667eea;
        }}
        
        .timeline-item {{
            position: relative;
            margin-bottom: 20px;
            padding-left: 20px;
        }}
        
        .timeline-item::before {{
            content: '';
            position: absolute;
            left: -36px;
            top: 0;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #667eea;
            border: 3px solid #0f0f23;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #888;
            margin-top: 40px;
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            
            .card, .section {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Comprehensive Security Assessment Report</h1>
            <div class="header-info">
                <div class="info-card">
                    <h3>Target</h3>
                    <div class="value">{self.scan_data.get('target', 'Unknown')}</div>
                </div>
                <div class="info-card">
                    <h3>Scan Date</h3>
                    <div class="value">{self.timestamp.strftime('%Y-%m-%d')}</div>
                </div>
                <div class="info-card">
                    <h3>Threat Level</h3>
                    <div class="value {self.scan_data.get('threat_level', 'LOW').lower()}">{self.scan_data.get('threat_level', 'LOW')}</div>
                </div>
                <div class="info-card">
                    <h3>Scan Duration</h3>
                    <div class="value">{self.scan_data.get('scan_duration', 0):.1f}s</div>
                </div>
            </div>
        </div>
        
        <div class="dashboard">
            <div class="card">
                <h2>📊 Statistics</h2>
                <div class="stat-grid">
                    <div class="stat">
                        <div class="stat-label">Ports Scanned</div>
                        <div class="stat-value">{self.scan_data.get('total_ports_scanned', 0)}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Open Ports</div>
                        <div class="stat-value">{len(self.scan_data.get('open_ports', []))}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label critical">Critical</div>
                        <div class="stat-value critical">{self.scan_data.get('critical_services', 0)}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label high">High Risk</div>
                        <div class="stat-value high">{self.scan_data.get('high_risk_services', 0)}</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>🎯 Risk Distribution</h2>
                <div class="chart-container">
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h2>🔍 Vulnerability Summary</h2>
                <div class="stat-grid">
                    <div class="stat">
                        <div class="stat-label">Total CVEs</div>
                        <div class="stat-value">{len(self.scan_data.get('vulnerabilities', {}).get('service_vulnerabilities', []))}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Exploitable</div>
                        <div class="stat-value critical">{sum(1 for v in self.scan_data.get('vulnerabilities', {}).get('service_vulnerabilities', []) if v.get('severity') == 'CRITICAL')}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🚨 Critical Findings</h2>
            <div class="timeline">
"""
        
        # Add vulnerabilities to timeline
        vulns = self.scan_data.get('vulnerabilities', {}).get('service_vulnerabilities', [])
        for vuln in vulns[:10]:
            html += f"""
                <div class="timeline-item">
                    <h3><span class="badge badge-{vuln.get('severity', 'medium').lower()}">{vuln.get('severity')}</span> {vuln.get('cve')}</h3>
                    <p><strong>Service:</strong> {vuln.get('service')} (Port {vuln.get('port')})</p>
                    <p><strong>CVSS Score:</strong> {vuln.get('cvss_score')}</p>
                    <p>{vuln.get('description')}</p>
                </div>
"""
        
        html += """
            </div>
        </div>
        
        <div class="section">
            <h2>🔓 Open Ports & Services</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Description</th>
                        <th>Risk Level</th>
                        <th>Banner</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for port_detail in self.scan_data.get('open_port_details', []):
            risk = port_detail.get('risk', 'LOW')
            html += f"""
                    <tr>
                        <td>{port_detail.get('port')}</td>
                        <td>{port_detail.get('service')}</td>
                        <td>{port_detail.get('description', '')}</td>
                        <td><span class="badge badge-{risk.lower()}">{risk}</span></td>
                        <td>{port_detail.get('banner', '')[:100]}</td>
                    </tr>
"""
        
        html += """
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>💡 Recommendations</h2>
"""
        
        for rec in self.scan_data.get('vulnerabilities', {}).get('recommendations', []):
            html += f"""
            <div class="recommendation">
                {rec}
            </div>
"""
        
        # JavaScript for charts
        html += """
        </div>
        
        <div class="footer">
            <p>Generated by Advanced Cybersecurity Port Scanner v2.0</p>
            <p>Confidential Security Assessment Report</p>
        </div>
    </div>
    
    <script>
        // Risk distribution chart
        const ctx = document.getElementById('riskChart').getContext('2d');
        const riskChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
"""
        
        # Calculate risk distribution
        critical = sum(1 for p in self.scan_data.get('open_port_details', []) if p.get('risk') == 'CRITICAL')
        high = sum(1 for p in self.scan_data.get('open_port_details', []) if p.get('risk') == 'HIGH')
        medium = sum(1 for p in self.scan_data.get('open_port_details', []) if p.get('risk') == 'MEDIUM')
        low = sum(1 for p in self.scan_data.get('open_port_details', []) if p.get('risk') == 'LOW')
        
        html += f"{critical}, {high}, {medium}, {low}"
        
        html += """],
                    backgroundColor: ['#ff4757', '#ffa502', '#ffd32a', '#26de81']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#e0e0e0'
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
"""
        
        return html

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

class ConfigurationManager:
    """Manage scanner configuration and profiles"""
    
    DEFAULT_CONFIG = {
        'scan_profiles': {
            'quick': {
                'threads': 100,
                'timeout': 1,
                'port_range': None,
                'comprehensive': False
            },
            'normal': {
                'threads': 150,
                'timeout': 2,
                'port_range': None,
                'comprehensive': False
            },
            'deep': {
                'threads': 200,
                'timeout': 3,
                'port_range': '1-65535',
                'comprehensive': True
            },
            'stealth': {
                'threads': 10,
                'timeout': 5,
                'port_range': None,
                'comprehensive': False
            }
        },
        'reporting': {
            'default_format': 'html',
            'include_exploits': True,
            'include_recommendations': True,
            'compliance_check': True
        },
        'network': {
            'max_retries': 3,
            'retry_delay': 1,
            'user_agent': 'SecurityScanner/2.0'
        }
    }
    
    def __init__(self, config_file: str = "scanner_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except:
                return self.DEFAULT_CONFIG.copy()
        return self.DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get_profile(self, profile_name: str) -> Dict:
        """Get scan profile"""
        return self.config.get('scan_profiles', {}).get(profile_name, self.DEFAULT_CONFIG['scan_profiles']['normal'])
    
    def create_profile(self, name: str, settings: Dict):
        """Create custom scan profile"""
        self.config['scan_profiles'][name] = settings
        self.save_config()
    
    def list_profiles(self) -> List[str]:
        """List available profiles"""
        return list(self.config.get('scan_profiles', {}).keys())

# ============================================================================
# THREAT INTELLIGENCE INTEGRATION
# ============================================================================

class ThreatIntelligence:
    """Integrate with threat intelligence feeds"""
    
    def __init__(self):
        self.threat_feeds = {
            'abuse_ip': 'https://api.abuseipdb.com/api/v2/check',
            'virustotal': 'https://www.virustotal.com/api/v3/ip_addresses/',
            'shodan': 'https://api.shodan.io/shodan/host/'
        }
    
    def check_ip_reputation(self, ip: str) -> Dict:
        """Check IP reputation"""
        reputation = {
            'ip': ip,
            'malicious': False,
            'score': 0,
            'reports': []
        }
        
        # Simplified reputation check
        # In production, would integrate with actual APIs
        
        return reputation
    
    def get_threat_actors(self, cve: str) -> List[str]:
        """Get known threat actors for CVE"""
        # Simplified - would integrate with real threat intel
        threat_actors = {
            'CVE-2017-0144': ['Shadow Brokers', 'APT Groups'],
            'CVE-2019-0708': ['Various APT Groups'],
            'CVE-2021-44228': ['State-sponsored actors', 'Ransomware gangs']
        }
        
        return threat_actors.get(cve, [])

# ============================================================================
# MAIN ENTRY POINT (UPDATED)
# ============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Scan interrupted by user.{Colors.ENDC}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}Error: {str(e)}{Colors.ENDC}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)
