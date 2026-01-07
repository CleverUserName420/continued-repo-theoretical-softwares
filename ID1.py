#!/usr/bin/env python3
"""
Enhanced Comprehensive IP & Domain Investigation Tool
Free public databases only - NO API KEYS REQUIRED
Data sources: WHOIS, IPInfo.io (free), IP2Location (free), BGP, DNS
"""

import subprocess
import json
import re
import sys
import time
from urllib.parse import urlparse, urlencode
from typing import Dict, List, Optional, Tuple
import urllib.request
import urllib.error
from datetime import datetime
import socket

class FreeIPInvestigator:
    """IP investigation using only free public databases"""
    
    def __init__(self):
        self.results = []
        self.whois_cache = {}
        self.ipinfo_cache = {}
        self.start_time = datetime.now()
        
    def extract_ip_or_domain(self, input_string: str) -> str:
        """Extract IP or domain from URL or return as-is"""
        input_string = input_string.strip()
        
        if '://' in input_string or input_string.startswith('www.'):
            if not input_string.startswith(('http://', 'https://')):
                input_string = 'http://' + input_string
            try:
                parsed = urlparse(input_string)
                return parsed.netloc or parsed.path.split('/')[0]
            except:
                return input_string
        
        return input_string.split('/')[0]
    
    def is_ip_address(self, value: str) -> bool:
        """Check if string is an IP address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return re.match(pattern, value) is not None
    
    def run_command(self, command: List[str], timeout: int = 30) -> Optional[str]:
        """Run shell command and return output"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout if result.returncode == 0 else result.stderr
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] Command took longer than {timeout}s"
        except FileNotFoundError:
            return f"[ERROR] Command not found: {command[0]}"
        except Exception as e:
            return f"[ERROR] {str(e)}"
    
    def fetch_json_url(self, url: str, headers: Optional[Dict] = None, timeout: int = 10) -> Optional[Dict]:
        """Fetch JSON from URL with error handling"""
        try:
            req = urllib.request.Request(url, headers=headers or {})
            req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)')
            
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode())
                return data
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}"}
        except urllib.error.URLError:
            return {"error": "URL unreachable"}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON"}
        except Exception as e:
            return {"error": str(e)}
    
    # ============= WHOIS LOOKUPS =============
    
    def whois_lookup(self, target: str) -> Optional[str]:
        """Perform WHOIS lookup with caching"""
        if target in self.whois_cache:
            return self.whois_cache[target]
        
        output = self.run_command(['whois', target])
        self.whois_cache[target] = output
        return output
    
    def extract_whois_fields(self, whois_output: str) -> Dict[str, str]:
        """Extract key fields from WHOIS output"""
        fields = {}
        patterns = {
            'Organization': r'(?:Organization|OrgName|org-name|organisation):\s*(.+?)(?:\n|$)',
            'Country': r'(?:Country|country):\s*([A-Z]{2})(?:\n|$)',
            'City': r'(?:City|city):\s*(.+?)(?:\n|$)',
            'State': r'(?:State|StateProv|state|Province):\s*(.+?)(?:\n|$)',
            'ASN': r'(?:ASN|aut-num|AS Number):\s*(AS?\d+)(?:\n|$)',
            'Owner': r'(?:Owner|person|role|Organisation Name):\s*(.+?)(?:\n|$)',
            'Network Name': r'(?:NetName|network-name|Network):\s*(.+?)(?:\n|$)',
            'CIDR': r'(?:CIDR|Netblock):\s*(.+?)(?:\n|$)',
            'Registrar': r'(?:Registrar|registrar-name):\s*(.+?)(?:\n|$)',
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, whois_output, re.IGNORECASE | re.MULTILINE)
            if match:
                fields[key] = match.group(1).strip()
        
        return fields
    
    # ============= GEOLOCATION - FREE SOURCES =============
    
    def ipinfo_lookup(self, ip: str) -> Optional[Dict]:
        """Get geolocation from IPInfo.io FREE tier"""
        if ip in self.ipinfo_cache:
            return self.ipinfo_cache[ip]
        
        # Free tier endpoint (no token needed)
        url = f"https://ipinfo.io/{ip}/json"
        data = self.fetch_json_url(url)
        self.ipinfo_cache[ip] = data
        return data
    
    def ip_api_lookup(self, ip: str) -> Optional[Dict]:
        """Get geolocation from ip-api.com (free tier - 45 req/min)"""
        url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,org,isp,lat,lon,timezone,as,reverse"
        return self.fetch_json_url(url)
    
    def geojs_lookup(self, ip: str) -> Optional[Dict]:
        """Get geolocation from geojs.io (unlimited free)"""
        url = f"https://get.geojs.io/geolocation/ip/{ip}.json"
        return self.fetch_json_url(url)
    
    def ipwhois_lookup(self, ip: str) -> Optional[Dict]:
        """Get detailed info from ipwhois.app (free, unlimited)"""
        url = f"https://ipwhois.app/json/{ip}"
        return self.fetch_json_url(url)
    
    def db_ip_lookup(self, ip: str) -> Optional[Dict]:
        """Get geolocation from db-ip.com (free tier)"""
        url = f"https://db-ip.com/api/v2/free/{ip}"
        return self.fetch_json_url(url)
    
    # ============= ASN/BGP INFORMATION =============
    
    def asn_lookup_ipinfo(self, ip: str) -> Optional[Dict]:
        """Get ASN from IPInfo"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            data = self.fetch_json_url(url)
            if data and 'asn' in data:
                return {
                    'asn': data['asn'],
                    'org': data.get('org', 'N/A'),
                    'country': data.get('country', 'N/A'),
                    'hostname': data.get('hostname', 'N/A'),
                }
        except:
            pass
        return None
    
    def bgp_lookup(self, ip: str) -> Optional[Dict]:
        """Get BGP/routing from ipwhois.app"""
        url = f"https://ipwhois.app/json/{ip}"
        return self.fetch_json_url(url)
    
    def asn_lookup_asnlookup(self, ip: str) -> Optional[Dict]:
        """Get ASN from asnlookup.com (free)"""
        url = f"https://asnlookup.com/api/v1/as/ip/{ip}"
        return self.fetch_json_url(url)
    
    # ============= DNS LOOKUPS =============
    
    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        output = self.run_command(['dig', '-x', ip, '+short'], timeout=10)
        return output.strip() if output and '[ERROR]' not in output else "No reverse DNS"
    
    def forward_dns_lookup(self, domain: str) -> Optional[str]:
        """Forward DNS lookup with all records"""
        output = self.run_command(['dig', domain, '+short'], timeout=10)
        return output.strip() if output else "No DNS records"
    
    def dns_mx_lookup(self, domain: str) -> Optional[str]:
        """Get MX records"""
        output = self.run_command(['dig', domain, 'MX', '+short'], timeout=10)
        return output.strip() if output else "No MX records"
    
    def dns_ns_lookup(self, domain: str) -> Optional[str]:
        """Get NS records"""
        output = self.run_command(['dig', domain, 'NS', '+short'], timeout=10)
        return output.strip() if output else "No NS records"
    
    # ============= NETWORK ANALYSIS =============
    
    def ping_test(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Test connectivity via ping"""
        output = self.run_command(['ping', '-c', '1', '-W', '2', ip], timeout=5)
        if output and '[ERROR]' not in output and 'TIMEOUT' not in output:
            return (True, output)
        return (False, output)
    
    def traceroute_test(self, ip: str) -> Optional[str]:
        """Perform limited traceroute"""
        output = self.run_command(['traceroute', '-m', '10', ip], timeout=30)
        return output if output else "Traceroute unavailable"
    
    def port_scan_check(self, ip: str) -> Dict[int, bool]:
        """Check common ports"""
        common_ports = {
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            25: 'SMTP',
            21: 'FTP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
        }
        
        open_ports = {}
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                open_ports[port] = (result == 0)
            except:
                open_ports[port] = False
        
        return open_ports
    
    # ============= THREAT ANALYSIS =============
    
    def analyze_threat_level(self, info: Dict) -> Tuple[str, List[str]]:
        """Determine threat level from available data"""
        threat_indicators = []
        score = 0
        
        # Geolocation analysis
        country = (info.get('country', '') or info.get('Country', '') or '').upper()
        if country in ['CN', 'RU', 'KP', 'IR', 'SY']:
            threat_indicators.append(f"High-risk country: {country}")
            score += 20
        
        # Organization analysis
        org = (info.get('org', '') or info.get('Organization', '') or '').lower()
        
        if any(x in org for x in ['military', 'defense', 'dod', 'pentagon', 'armed', 'forces', '.mil', 'mod.uk']):
            threat_indicators.append("!!! MILITARY/DEFENSE INFRASTRUCTURE !!!")
            score += 40
        
        if any(x in org for x in ['government', '.gov', 'state']):
            threat_indicators.append("Government network")
            score += 15
        
        if any(x in org for x in ['cloud', 'aws', 'azure', 'gcp', 'digitalocean']):
            threat_indicators.append("Cloud infrastructure (potential proxy)")
            score += 10
        
        if any(x in org for x in ['vpn', 'proxy', 'anonymizer', 'tor']):
            threat_indicators.append("Anonymization service")
            score += 20
        
        if any(x in org for x in ['hosting', 'datacenter', 'colo']):
            threat_indicators.append("Hosting/datacenter provider")
            score += 5
        
        # Reverse DNS analysis
        hostname = (info.get('hostname', '') or '').lower()
        if any(x in hostname for x in ['proxy', 'vpn', 'tor', 'spam', 'malware']):
            threat_indicators.append("Suspicious hostname")
            score += 15
        
        # Open ports
        open_ports = info.get('open_ports', {})
        suspicious_port_services = {
            25: 'SMTP (spam/malware relay)',
            53: 'DNS (potential resolver abuse)',
            3389: 'RDP (remote access)',
        }
        for port, service in suspicious_port_services.items():
            if open_ports.get(port):
                threat_indicators.append(f"Open port {port}: {service}")
                score += 5
        
        # Reachability (isolated networks less suspicious)
        if not info.get('reachable'):
            threat_indicators.append("Unreachable/filtered (secured network)")
            score -= 5
        
        # Determine threat level
        if score >= 40:
            return "🔴 CRITICAL", threat_indicators
        elif score >= 25:
            return "🟠 HIGH", threat_indicators
        elif score >= 15:
            return "🟡 MEDIUM", threat_indicators
        else:
            return "🟢 LOW", threat_indicators
    
    def check_military_networks(self, info: Dict) -> bool:
        """Check if IP belongs to military/defense infrastructure"""
        org = (info.get('org', '') or info.get('Organization', '') or '').lower()
        hostname = (info.get('hostname', '') or '').lower()
        
        military_keywords = [
            'military', 'defense', 'dod', 'pentagon', 'usaf', 'army', 'navy',
            'marines', 'coast guard', 'mod.uk', 'bundeswehr', 'mindef',
            'armed forces', 'af.mil', 'state.gov', 'jisc'
        ]
        
        for keyword in military_keywords:
            if keyword in org or keyword in hostname:
                return True
        
        return False
    
    # ============= MAIN INVESTIGATION =============
    
    def investigate_ip(self, ip: str, verbose: bool = True) -> Dict:
        """Comprehensive investigation using free sources"""
        if verbose:
            print(f"\n{'─' * 110}")
            print(f"Investigating: {ip}")
            print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"{'─' * 110}\n")
        
        result = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'whois': {},
            'geolocation': {},
            'dns': {},
            'asn': {},
            'connectivity': {},
            'threat_analysis': {},
            'military_network': False,
            'overall_threat_level': '?'
        }
        
        # ===== WHOIS LOOKUP =====
        if verbose:
            print("[*] Performing WHOIS lookup...")
        whois_data = self.whois_lookup(ip)
        if whois_data and '[ERROR]' not in whois_data:
            result['whois']['parsed'] = self.extract_whois_fields(whois_data)
            if verbose:
                print(f"✓ WHOIS retrieved")
                print(f"    Organization: {result['whois']['parsed'].get('Organization', 'N/A')}")
                print(f"    Country: {result['whois']['parsed'].get('Country', 'N/A')}")
                print(f"    ASN: {result['whois']['parsed'].get('ASN', 'N/A')}")
        
        # ===== GEOLOCATION (Multiple Free Sources) =====
        if verbose:
            print("\n[*] Retrieving geolocation from multiple free sources...")
        
        geolocation_sources = {
            'ipinfo': self.ipinfo_lookup(ip),
            'ip-api': self.ip_api_lookup(ip),
            'geojs': self.geojs_lookup(ip),
            'ipwhois': self.ipwhois_lookup(ip),
            'db-ip': self.db_ip_lookup(ip),
        }
        
        result['geolocation'] = {k: v for k, v in geolocation_sources.items() if v and 'error' not in v}
        
        if verbose:
            for source, data in result['geolocation'].items():
                if data and 'error' not in data:
                    city = data.get('city') or data.get('city_name') or 'N/A'
                    country = data.get('country') or data.get('country_name') or 'N/A'
                    org = data.get('org') or data.get('organisation_name') or 'N/A'
                    print(f"✓ {source:12}: {city}, {country} ({org})")
        
        # ===== ASN/BGP INFORMATION =====
        if verbose:
            print("\n[*] Looking up ASN and network information...")
        
        asn_sources = {
            'ipinfo': self.asn_lookup_ipinfo(ip),
            'ipwhois': self.bgp_lookup(ip),
        }
        
        result['asn'] = {k: v for k, v in asn_sources.items() if v and 'error' not in v}
        
        if verbose:
            for source, data in result['asn'].items():
                if data and 'error' not in data:
                    asn = data.get('asn') or data.get('AS Number') or 'N/A'
                    org = data.get('org') or data.get('organisation_name') or 'N/A'
                    print(f"✓ {source:12}: {asn} ({org})")
        
        # ===== DNS LOOKUPS =====
        if verbose:
            print("\n[*] Performing DNS lookups...")
        
        rdns = self.reverse_dns_lookup(ip)
        if rdns and rdns != "No reverse DNS":
            result['dns']['reverse'] = rdns
            if verbose:
                print(f"✓ Reverse DNS: {rdns}")
        
        # ===== NETWORK CONNECTIVITY =====
        if verbose:
            print("\n[*] Testing network connectivity...")
        
        reachable, ping_output = self.ping_test(ip)
        result['connectivity']['reachable'] = reachable
        if verbose:
            print(f"{'✓' if reachable else '✗'} Ping: {'Reachable' if reachable else 'Unreachable/filtered'}")
        
        # ===== PORT SCANNING =====
        if verbose:
            print("\n[*] Checking open ports...")
        
        open_ports = self.port_scan_check(ip)
        result['connectivity']['open_ports'] = {k: v for k, v in open_ports.items() if v}
        
        if verbose:
            if result['connectivity']['open_ports']:
                for port in result['connectivity']['open_ports'].keys():
                    print(f"✓ Port {port} is OPEN")
            else:
                print(f"✓ No common ports open")
        
        # ===== MILITARY/DEFENSE CHECK =====
        combined_info = {
            **result['whois'].get('parsed', {}),
            **result['geolocation'].get('ipinfo', {}),
            **result['asn'].get('ipinfo', {}),
            'open_ports': result['connectivity']['open_ports'],
            'reachable': result['connectivity']['reachable'],
        }
        
        result['military_network'] = self.check_military_networks(combined_info)
        if result['military_network'] and verbose:
            print(f"\n🚨 !!! MILITARY/DEFENSE/GOVERNMENT NETWORK DETECTED !!!")
        
        # ===== THREAT ANALYSIS =====
        if verbose:
            print("\n[*] Analyzing threat level...")
        
        threat_level, indicators = self.analyze_threat_level(combined_info)
        result['overall_threat_level'] = threat_level
        result['threat_analysis']['indicators'] = indicators
        
        if verbose:
            print(f"✓ Threat Level: {threat_level}")
            if indicators:
                for indicator in indicators:
                    print(f"    • {indicator}")
        
        return result
    
    def investigate_multiple(self, targets: List[str]) -> None:
        """Investigate multiple IPs"""
        print("=" * 110)
        print("FREE IP INVESTIGATION TOOL - NO API KEYS REQUIRED")
        print("Data Sources: WHOIS, IPInfo.io, IP-API, GeoJS, IPWHOIS, DB-IP, DNS, Network Analysis")
        print("=" * 110)
        print(f"\nStarting investigation of {len(targets)} target(s)...")
        print(f"Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        
        for i, target in enumerate(targets, 1):
            extracted = self.extract_ip_or_domain(target)
            print(f"\n[{i}/{len(targets)}] {target}")
            
            result = self.investigate_ip(extracted)
            self.results.append(result)
            
            if i < len(targets):
                time.sleep(1)  # Rate limiting
        
        self.print_summary()
        self.save_results()
    
    def print_summary(self) -> None:
        """Print summary table"""
        print(f"\n\n{'=' * 130}")
        print("INVESTIGATION SUMMARY")
        print(f"{'=' * 130}\n")
        
        print(f"{'IP':<18} {'Organization':<40} {'Country':<10} {'Threat':<15} {'Military':<12} {'Reachable':<10}")
        print(f"{'-' * 130}")
        
        for result in self.results:
            ip = result['ip']
            org = (result['whois'].get('parsed', {}).get('Organization', 'N/A') or
                   result['geolocation'].get('ipinfo', {}).get('org', 'N/A'))[:38]
            country = (result['geolocation'].get('ipinfo', {}).get('country', 'N/A') or
                      result['whois'].get('parsed', {}).get('Country', 'N/A'))
            threat = result['overall_threat_level']
            military = "YES 🚨" if result['military_network'] else "No"
            reachable = "Yes" if result['connectivity']['reachable'] else "No/Filtered"
            
            print(f"{ip:<18} {org:<40} {country:<10} {threat:<15} {military:<12} {reachable:<10}")
        
        print(f"\n{'=' * 130}")
        print(f"Total IPs: {len(self.results)}")
        military_count = sum(1 for r in self.results if r['military_network'])
        print(f"Military/Government: {military_count}")
        critical_count = sum(1 for r in self.results if '🔴' in r['overall_threat_level'])
        print(f"Critical threat: {critical_count}")
        print(f"Duration: {(datetime.now() - self.start_time).total_seconds():.2f}s")
    
    def save_results(self) -> None:
        """Save to JSON"""
        filename = f"ip_investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump({
                    'metadata': {
                        'timestamp': datetime.now().isoformat(),
                        'user': 'CleverUserName420',
                        'total_ips': len(self.results),
                    },
                    'results': self.results
                }, f, indent=2, default=str)
            print(f"\n✓ Results saved: {filename}")
        except Exception as e:
            print(f"\n✗ Error: {e}")

def main():
    print("=" * 110)
    print("FREE IP INVESTIGATION TOOL")
    print("=" * 110)
    print("\nNo API keys required - uses only free public sources!")
    print("\nOptions:")
    print("  1 = Enter custom IPs/domains")
    print("  2 = Use preset list (10 IPs)")
    print("  3 = Exit\n")
    
    choice = input("Select (1-3): ").strip()
    
    if choice == '1':
        print("\nEnter IPs/domains (one per line, empty to finish):\n")
        targets = []
        while True:
            line = input().strip()
            if not line:
                break
            targets.append(line)
    elif choice == '2':
        targets = [
            "201.253.240.121",
            "134.108.202.218",
            "35.137.206.133",
            "212.148.173.136",
            "171.78.186.241",
            "223.37.253.44",
            "155.136.159.245",
            "223.132.90.111",
            "89.56.231.210",
            "191.49.0.37"
        ]
    else:
        sys.exit(0)
    
    if targets:
        investigator = FreeIPInvestigator()
        investigator.investigate_multiple(targets)

if __name__ == "__main__":
    main()
