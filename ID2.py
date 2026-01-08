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
        
    def ipapi_co_lookup(self, ip: str) -> Optional[Dict]:
        """Get geolocation from ipapi.co (1000 requests/day free)"""
        url = f"https://ipapi.co/{ip}/json/"
        return self.fetch_json_url(url)
    
    def freegeoip_lookup(self, ip: str) -> Optional[Dict]:
        """Get geolocation from freegeoip.app"""
        url = f"https://freegeoip.app/json/{ip}"
        return self.fetch_json_url(url)
        
    def ipgeolocation_io(self, ip: str) -> Optional[Dict]:
        """IPGeolocation.io - 1000 free requests/day, no key"""
        url = f"https://api.ipgeolocation.io/ipgeo?ip={ip}"
        return self.fetch_json_url(url)
    
    def abstractapi_free(self, ip: str) -> Optional[Dict]:
        """AbstractAPI - 20,000 free requests/month, no key for basic"""
        url = f"https://ipgeolocation.abstractapi.com/v1/?ip_address={ip}"
        return self.fetch_json_url(url)
    
    def shodan_internetdb(self, ip: str) -> Optional[Dict]:
        """Shodan InternetDB - Completely free, no key, shows open ports"""
        url = f"https://internetdb.shodan.io/{ip}"
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
        
    def bgpview_lookup(self, ip: str) -> Optional[Dict]:
        """Get BGP/ASN info from BGPView (free API)"""
        url = f"https://api.bgpview.io/ip/{ip}"
        return self.fetch_json_url(url)
    
    def ripe_stat_lookup(self, ip: str) -> Optional[Dict]:
        """RIPE Stat data API (free)"""
        url = f"https://stat.ripe.net/data/whois/data.json?resource={ip}"
        return self.fetch_json_url(url)
    
    def rdap_lookup(self, ip: str) -> Optional[Dict]:
        """RDAP (modern WHOIS replacement) - ARIN"""
        url = f"https://rdap.arin.net/registry/ip/{ip}"
        return self.fetch_json_url(url)
        
    def team_cymru_asn(self, ip: str) -> Optional[str]:
        """Team Cymru IP to ASN - DNS-based query (free, reliable)"""
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            # Use DNS TXT record lookup
            result = self.run_command(['dig', '+short', query, 'TXT'], timeout=10)
            return result.strip().replace('"', '') if result else None
        except:
            return None
    
    def hurricane_bgp_lookup(self, asn: str) -> Optional[str]:
        """Hurricane Electric BGP Toolkit - Free BGP data"""
        if not asn:
            return None
        asn_clean = asn.replace('AS', '').strip()
        url = f"https://bgp.he.net/AS{asn_clean}"
        # Note: This returns HTML, would need parsing.  Placeholder for now.
        return f"View at: {url}"
    
    def peeringdb_lookup(self, asn: str) -> Optional[Dict]:
        """PeeringDB - Free network/peering info"""
        if not asn:
            return None
        asn_clean = asn.replace('AS', '').strip()
        url = f"https://www.peeringdb.com/api/net?asn={asn_clean}"
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
        
    def crtsh_lookup(self, domain: str) -> Optional[Dict]:
        """Certificate Transparency logs from crt.sh"""
        url = f"https://crt.sh/?q={domain}&output=json"
        return self.fetch_json_url(url)
    
    def passive_dns_lookup(self, domain: str) -> Optional[Dict]:
        """Passive DNS from ThreatCrowd"""
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        return self.fetch_json_url(url)
        
    def dnsdumpster_check(self, domain: str) -> Optional[str]:
        """DNSDumpster - Free subdomain enumeration (returns web URL)"""
        # API requires CSRF token, return web interface URL
        return f"https://dnsdumpster.com/?url={domain}"
    
    def securitytrails_free(self, domain: str) -> Optional[str]:
        """SecurityTrails - Limited free lookups (requires free account)"""
        # Free tier requires API key from account
        return f"https://securitytrails.com/domain/{domain}/dns"
    
    def urlscan_lookup(self, target: str) -> Optional[Dict]:
        """URLScan.io - Free scanning and API"""
        url = f"https://urlscan.io/api/v1/search/?q=ip:{target}"
        return self.fetch_json_url(url)
    
    def google_safebrowsing_check(self, url_to_check: str, api_key: str = None) -> Optional[Dict]:
        """Google Safe Browsing - Free with API key"""
        if not api_key:
            return {"error": "API key required (free from Google Cloud Console)"}
        
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "ip-investigator", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url_to_check}]
            }
        }
        
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode(),
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode())
        except:
            return {"error": "Request failed"}
    
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
    
    def port_scan_check(self, ip: str) -> Tuple[Dict[int, bool], int]:
        """Check common ports and return risk score"""
        # Port:  (Service, Risk Score)
        common_ports = {
            53: ('DNS', 2),
            80: ('HTTP', 1),
            443: ('HTTPS', 1),
            8080: ('HTTP-Proxy', 3),
            8443: ('HTTPS-Alt', 3),
            8000: ('HTTP-Alt', 2),
            
            # Remote Access (HIGH RISK)
            22: ('SSH', 5),
            23: ('Telnet', 10),
            3389: ('RDP', 8),
            5900: ('VNC', 8),
            5901: ('VNC-1', 8),
            
            # Email
            25: ('SMTP', 3),
            110: ('POP3', 2),
            143: ('IMAP', 2),
            465: ('SMTPS', 2),
            587: ('SMTP-Submission', 2),
            993: ('IMAPS', 2),
            995: ('POP3S', 2),
            
            # File Transfer
            21: ('FTP', 6),
            69: ('TFTP', 7),
            445: ('SMB', 9),
            139: ('NetBIOS', 7),
            
            # Databases (HIGH RISK if exposed)
            1433: ('MSSQL', 10),
            3306: ('MySQL', 10),
            5432: ('PostgreSQL', 10),
            27017: ('MongoDB', 10),
            6379: ('Redis', 10),
            9200: ('Elasticsearch', 9),
            5984: ('CouchDB', 9),
            
            # Network Services
            161: ('SNMP', 7),
            162: ('SNMP-Trap', 6),
            389: ('LDAP', 6),
            636: ('LDAPS', 5),
            
            # VPN & Proxy
            1194: ('OpenVPN', 4),
            1723: ('PPTP', 5),
            4500: ('IPSec-NAT', 4),
            500: ('IKE', 4),
            
            # Web Frameworks & Services
            3000: ('Node.js', 5),
            5000: ('Flask/Python', 5),
            8888: ('Jupyter/Alt-HTTP', 7),
            9000: ('PHP-FPM', 6),
            
            # Other Important
            111: ('RPC', 7),
            135: ('MS-RPC', 7),
            514: ('Syslog', 4),
            2049: ('NFS', 8),
            3128: ('Squid-Proxy', 4),
            6666: ('IRC', 5),
            
            # Containerization & Orchestration
            2375: ('Docker', 10),
            2376: ('Docker-TLS', 8),
            6443: ('Kubernetes', 9),
            10250: ('Kubelet', 9),
        }
        
        open_ports = {}
        total_risk = 0
        
        for port, (service, risk) in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                is_open = (result == 0)
                open_ports[port] = is_open
                
                if is_open:
                    total_risk += risk
            except:
                open_ports[port] = False
        
        return open_ports, total_risk
        
    def check_dnsbl(self, ip: str) -> Dict[str, bool]:
        """Check if IP is on DNS-based blacklists"""
        blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
            'psbl.surriel.com',
            'cbl.abuseat.org',
        ]
        
        results = {}
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        for bl in blacklists:
            try:
                socket.gethostbyname(f"{reversed_ip}.{bl}")
                results[bl] = True  # Listed
            except socket.gaierror:
                results[bl] = False  # Not listed
        
        return results
    
    def greynoise_community(self, ip: str) -> Optional[Dict]:
        """Check GreyNoise community API (free, no key for basic lookup)"""
        url = f"https://api.greynoise.io/v3/community/{ip}"
        return self.fetch_json_url(url)
    
    def alienvault_otx(self, ip: str) -> Optional[Dict]:
        """Check AlienVault OTX reputation (free)"""
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        return self.fetch_json_url(url)
    
    def threatcrowd_lookup(self, ip: str) -> Optional[Dict]:
        """ThreatCrowd free API"""
        url = f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}"
        return self.fetch_json_url(url)
    
    def bogon_check(self, ip: str) -> bool:
        """Check if IP is bogon/reserved"""
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_reserved or addr.is_loopback
        except:
            return False
    
    def carrier_lookup(self, ip: str) -> Optional[Dict]:
        """Detect mobile carrier if IP is cellular"""
        data = self.ip_api_lookup(ip)
        if data and 'error' not in data:
            return {
                'is_mobile': data.get('mobile', False),
                'is_proxy': data.get('proxy', False),
                'isp': data.get('isp', 'N/A')
            }
        return None
        
    def proxycheck_io(self, ip: str) -> Optional[Dict]:
        """ProxyCheck.io free tier (1000/day, no key)"""
        url = f"http://proxycheck.io/v2/{ip}?vpn=1&asn=1"
        return self.fetch_json_url(url)
    
    def iptoasn_lookup(self, ip: str) -> Optional[Dict]:
        """IP to ASN mapping (free database)"""
        url = f"https://api.iptoasn.com/v1/as/ip/{ip}"
        return self.fetch_json_url(url)
    
    def bigdatacloud_free(self, ip: str) -> Optional[Dict]:
        """BigDataCloud free geolocation (unlimited)"""
        url = f"https://api.bigdatacloud.net/data/ip-geolocation?ip={ip}&localityLanguage=en"
        return self.fetch_json_url(url)
        
    # Add missing method (around line 500):
    def sslbl_abuse_ch(self, ip: str) -> Optional[Dict]:
        """Check SSL Blacklist from abuse.ch"""
        try:
            url = f"https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as response:
                data = response.read().decode()
                return {'listed': ip in data}
        except:
            return None
    
    def ipdata_co_free(self, ip: str) -> Optional[Dict]:
        """IPData.co free tier (1500/day, no key)"""
        url = f"https://api.ipdata.co/{ip}?api-key=test"
        return self.fetch_json_url(url)
    
    def tor_exit_check(self, ip: str) -> bool:
        """Check if IP is Tor exit node"""
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = f"{reversed_ip}.80.ip-port.exitlist.torproject.org"
            socket.gethostbyname(query)
            return True
        except socket.gaierror:
            return False
    
    def spur_us_free(self, ip: str) -> Optional[Dict]:
        """Spur.us Context API (free tier)"""
        url = f"https://api.spur.us/v1/context/{ip}"
        return self.fetch_json_url(url)
    
    def ipinfo_abuse(self, ip: str) -> Optional[Dict]:
        """IPInfo.io Abuse Contact DB (free)"""
        url = f"https://ipinfo.io/{ip}/abuse"
        return self.fetch_json_url(url)
    
    def robtex_lookup(self, ip: str) -> Optional[Dict]:
        """Robtex free API"""
        url = f"https://freeapi.robtex.com/ipquery/{ip}"
        return self.fetch_json_url(url)
    
    def hackertarget_asn(self, ip: str) -> Optional[str]:
        """HackerTarget ASN lookup (free, no key)"""
        url = f"https://api.hackertarget.com/aslookup/?q={ip}"
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.read().decode().strip()
        except:
            return None
            
    def abuseipdb_check(self, ip: str, api_key: str = None) -> Optional[Dict]:
        """AbuseIPDB - 1000 free checks/day (requires free API key)"""
        if not api_key:
            return {"error": "Free API key required from abuseipdb.com"}
        
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {'Key': api_key, 'Accept': 'application/json'}
        return self.fetch_json_url(url, headers=headers)
    
    def ibm_xforce(self, ip: str) -> Optional[Dict]:
        """IBM X-Force Exchange - Free tier (requires free account)"""
        url = f"https://exchange.xforce.ibmcloud.com/api/ipr/{ip}"
        # Requires API key/password from free account
        return {"info": f"View at https://exchange.xforce.ibmcloud.com/ip/{ip}"}
    
    def maltiverse_lookup(self, ip: str) -> Optional[Dict]:
        """Maltiverse - Free threat intelligence API"""
        url = f"https://api.maltiverse.com/ip/{ip}"
        return self.fetch_json_url(url)
    
    def phishtank_check(self, url_to_check: str) -> Optional[Dict]:
        """Phishtank - Free phishing database"""
        api_url = "http://checkurl.phishtank.com/checkurl/"
        data = urlencode({
            'url': url_to_check,
            'format': 'json'
        }).encode()
        
        try:
            req = urllib.request.Request(api_url, data=data)
            req.add_header('User-Agent', 'phishtank/ip-investigator')
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode())
        except:
            return {"error": "Request failed"}
            
    def uceprotect_check(self, ip: str) -> bool:
        """UCEPROTECT - Additional DNSBL"""
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            socket.gethostbyname(f"{reversed_ip}.dnsbl-1.uceprotect.net")
            return True
        except socket.gaierror:
            return False
    
    def barracuda_reputation(self, ip: str) -> Optional[Dict]:
        """Barracuda Reputation - Free lookup"""
        url = f"http://barracudacentral.org/rbl/list-check?ip_address={ip}"
        # Returns HTML, would need scraping.  Return URL instead.
        return {"lookup_url": url}
    
    def mxtoolbox_blacklist(self, ip: str) -> Optional[str]:
        """MXToolbox - Multiple blacklist check"""
        return f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip}"
    
    def multirbl_check(self, ip: str) -> Optional[str]:
        """MultiRBL - Aggregated blacklist checker"""
        return f"http://multirbl.valli.org/lookup/{ip}.html"
    
    def emerging_threats_check(self, ip: str) -> Optional[bool]:
        """Emerging Threats - Check against free blocklists"""
        try:
            # ET Compromise IPs list
            url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as response:
                blocklist = response.read().decode()
                return ip in blocklist
        except:
            return None
    
    def spamhaus_drop_check(self, ip: str) -> Optional[bool]:
        """Spamhaus DROP/EDROP lists - Free downloadable"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            # Check DROP list
            url = "https://www.spamhaus.org/drop/drop.txt"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as response:
                drop_list = response.read().decode()
                
            for line in drop_list.split('\n'):
                if line.startswith(';') or not line.strip():
                    continue
                cidr = line.split(';')[0].strip()
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in network:
                        return True
                except:
                    continue
            return False
        except:
            return None
            
    def getipintel_check(self, ip: str, contact_email: str = "abuse@example.com") -> Optional[float]:
        """GetIPIntel - Free proxy/VPN detection"""
        url = f"http://check.getipintel.net/check.php?ip={ip}&contact={contact_email}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as response:
                score = float(response.read().decode().strip())
                return score  # 0-1, higher = more likely proxy/VPN
        except:
            return None
    
    def ipqualityscore_free(self, ip: str) -> Optional[Dict]:
        """IPQualityScore - Free tier available"""
        # Free tier has limited features without key
        url = f"https://www.ipqualityscore.com/api/json/ip/YOUR_KEY_HERE/{ip}"
        return {"info": "Requires free API key from ipqualityscore.com"}
    
    def vpnapi_lookup(self, ip: str) -> Optional[Dict]:
        """VPN API - Free VPN detection service"""
        url = f"https://vpnapi.io/api/{ip}"
        return self.fetch_json_url(url)
        
    def farsight_dnsdb_community(self, domain: str) -> Optional[str]:
        """Farsight DNSDB - Limited free community edition"""
        # Requires API key from free community account
        return {"info": "Requires free community API key from dnsdb.info"}
    
    def virustotal_lookup(self, ip: str, api_key: str = None) -> Optional[Dict]:
        """VirusTotal - Free API key, 4 requests/min"""
        if not api_key:
            return {"error": "Free API key required from virustotal.com"}
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': api_key}
        return self.fetch_json_url(url, headers=headers)
    
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
            53: 'DNS (potential resolver abuse)',
            80: 'HTTP (unencrypted web traffic)',
            443: 'HTTPS (encrypted web traffic)',
            8080: 'HTTP-Proxy (alternative web/proxy)',
            8443: 'HTTPS-Alt (alternative HTTPS)',
            8000: 'HTTP-Alt (development server)',
            
            # Remote Access (HIGH RISK)
            22: 'SSH (remote shell access)',
            23: 'Telnet (unencrypted remote access - CRITICAL)',
            3389: 'RDP (remote desktop access)',
            5900: 'VNC (remote desktop)',
            5901: 'VNC-1 (additional VNC instance)',
            
            # Email (SPAM/MALWARE RISK)
            25: 'SMTP (spam/malware relay)',
            110: 'POP3 (email retrieval)',
            143: 'IMAP (email access)',
            465: 'SMTPS (secure SMTP)',
            587: 'SMTP-Submission (email sending)',
            993: 'IMAPS (secure IMAP)',
            995: 'POP3S (secure POP3)',
            
            # File Transfer (DATA EXFILTRATION RISK)
            21: 'FTP (unencrypted file transfer)',
            69: 'TFTP (trivial file transfer - no auth)',
            445: 'SMB (file sharing - ransomware vector)',
            139: 'NetBIOS (legacy Windows file sharing)',
            
            # Databases (CRITICAL IF EXPOSED)
            1433: 'MSSQL (database - should NOT be public)',
            3306: 'MySQL (database - should NOT be public)',
            5432: 'PostgreSQL (database - should NOT be public)',
            27017: 'MongoDB (database - should NOT be public)',
            6379: 'Redis (in-memory database - should NOT be public)',
            9200: 'Elasticsearch (search engine - data exposure)',
            5984: 'CouchDB (database - should NOT be public)',
            
            # Network Services (ATTACK VECTORS)
            161: 'SNMP (network management - info disclosure)',
            162: 'SNMP-Trap (SNMP notifications)',
            389: 'LDAP (directory service - credential access)',
            636: 'LDAPS (secure LDAP)',
            
            # VPN & Proxy
            1194: 'OpenVPN (VPN service)',
            1723: 'PPTP (legacy VPN - vulnerable)',
            4500: 'IPSec-NAT (VPN/IPSec)',
            500: 'IKE (VPN key exchange)',
            
            # Web Frameworks & Services (DEVELOPMENT/MISCONFIGURATION)
            3000: 'Node.js (development server - may be exposed)',
            5000: 'Flask/Python (development server - may be exposed)',
            8888: 'Jupyter (notebook server - code execution risk)',
            9000: 'PHP-FPM (PHP processor)',
            
            # Other Important (LATERAL MOVEMENT)
            111: 'RPC (remote procedure call - attack vector)',
            135: 'MS-RPC (Microsoft RPC - lateral movement)',
            514: 'Syslog (log server)',
            2049: 'NFS (network file system - data access)',
            3128: 'Squid-Proxy (proxy server)',
            6666: 'IRC (chat server - botnet C&C)',
            
            # Containerization & Orchestration (CRITICAL)
            2375: 'Docker (container API - FULL HOST COMPROMISE)',
            2376: 'Docker-TLS (Docker with TLS)',
            6443: 'Kubernetes (cluster API - full cluster access)',
            10250: 'Kubelet (Kubernetes node - container access)',
        }
        for port, service in suspicious_port_services.items():
            if open_ports.get(port):
                threat_indicators.append(f"Open port {port}: {service}")
                score += 5
        
        # Reachability (isolated networks less suspicious)
        if not info.get('reachable'):
            threat_indicators.append("Unreachable/filtered (secured network)")
            score -= 5
            
        # Mobile IP with unusual open ports
        carrier_info = info.get('carrier', {})
        if carrier_info.get('is_mobile'):
            # Check for suspicious ports on mobile IPs
            if open_ports.get(21):  # FTP
                threat_indicators.append("Mobile IP with open FTP (unusual - possible compromise)")
                score += 10
            if open_ports.get(22):  # SSH
                threat_indicators.append("Mobile IP with open SSH (unusual configuration)")
                score += 8
            if open_ports.get(3389):  # RDP
                threat_indicators.append("Mobile IP with open RDP (highly suspicious)")
                score += 12
            if open_ports.get(445):  # SMB
                threat_indicators.append("Mobile IP with open SMB (likely compromised)")
                score += 15
            
        # Tor exit node
        if info.get('tor_exit'):
            threat_indicators.append("Tor exit node detected")
            score += 25
        
        # Proxy/VPN detection
        proxycheck = info.get('proxycheck', {})
        if proxycheck and proxycheck.get('proxy') == 'yes':
            threat_indicators.append("Proxy/VPN service (ProxyCheck)")
            score += 15
        
        # Spur.us anonymization
        spur = info.get('spur', {})
        if spur.get('anonymous'):
            threat_indicators.append("Anonymization service (Spur.us)")
            score += 15
        
        # DNSBL listings
        dnsbl = info.get('dnsbl', {})
        listed_count = sum(1 for v in dnsbl.values() if v)
        if listed_count > 0:
            threat_indicators.append(f"Listed on {listed_count} DNS blacklist(s)")
            score += listed_count * 5
        
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
            'ipapi.co':  self.ipapi_co_lookup(ip),
            'freegeoip': self.freegeoip_lookup(ip),
            'bigdatacloud': self.bigdatacloud_free(ip),
            'ipdata': self.ipdata_co_free(ip),
            'ipgeolocation.io': self.ipgeolocation_io(ip),
            'abstractapi':  self.abstractapi_free(ip),
            'shodan':  self.shodan_internetdb(ip),
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
            'bgpview': self.bgpview_lookup(ip),
            'ripe': self.ripe_stat_lookup(ip),
            'rdap':  self.rdap_lookup(ip),
            'iptoasn': self.iptoasn_lookup(ip),
            'robtex': self.robtex_lookup(ip),
            'team_cymru': self.team_cymru_asn(ip),
        }
        
        result['asn'] = {k: v for k, v in asn_sources.items() if v and 'error' not in str(v).lower()}

        
        if verbose:
            for source, data in result['asn'].items():
                if not data or 'error' in str(data):
                    continue
                    
                # Handle string responses
                if isinstance(data, str):
                    print(f"✓ {source:12}: {data}")
                    continue
                
                # Handle dict responses
                if isinstance(data, dict):
                    asn = (data.get('asn') or
                           data.get('AS Number') or
                           data.get('as_number') or
                           data.get('announced') or
                           'N/A')
                    
                    org = (data.get('org') or
                           data.get('organisation_name') or
                           data.get('name') or
                           data.get('as_name') or
                           'N/A')
                    
                    print(f"✓ {source:12}: {asn} ({org})")
                else:
                    # Fallback for unexpected types
                    print(f"✓ {source:12}: {str(data)[:60]}")
        
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

        open_ports, port_risk = self.port_scan_check(ip)

        # Store port information with service names
        port_info = {}
        common_ports = {
            53: ('DNS', 2),
            80: ('HTTP', 1),
            443: ('HTTPS', 1),
            8080: ('HTTP-Proxy', 3),
            8443: ('HTTPS-Alt', 3),
            8000: ('HTTP-Alt', 2),
            
            # Remote Access (HIGH RISK)
            22: ('SSH', 5),
            23: ('Telnet', 10),
            3389: ('RDP', 8),
            5900: ('VNC', 8),
            5901: ('VNC-1', 8),
            
            # Email
            25: ('SMTP', 3),
            110: ('POP3', 2),
            143: ('IMAP', 2),
            465: ('SMTPS', 2),
            587: ('SMTP-Submission', 2),
            993: ('IMAPS', 2),
            995: ('POP3S', 2),
            
            # File Transfer
            21: ('FTP', 6),
            69: ('TFTP', 7),
            445: ('SMB', 9),
            139: ('NetBIOS', 7),
            
            # Databases (HIGH RISK if exposed)
            1433: ('MSSQL', 10),
            3306: ('MySQL', 10),
            5432: ('PostgreSQL', 10),
            27017: ('MongoDB', 10),
            6379: ('Redis', 10),
            9200: ('Elasticsearch', 9),
            5984: ('CouchDB', 9),
            
            # Network Services
            161: ('SNMP', 7),
            162: ('SNMP-Trap', 6),
            389: ('LDAP', 6),
            636: ('LDAPS', 5),
            
            # VPN & Proxy
            1194: ('OpenVPN', 4),
            1723: ('PPTP', 5),
            4500: ('IPSec-NAT', 4),
            500: ('IKE', 4),
            
            # Web Frameworks & Services
            3000: ('Node.js', 5),
            5000: ('Flask/Python', 5),
            8888: ('Jupyter/Alt-HTTP', 7),
            9000: ('PHP-FPM', 6),
            
            # Other Important
            111: ('RPC', 7),
            135: ('MS-RPC', 7),
            514: ('Syslog', 4),
            2049: ('NFS', 8),
            3128: ('Squid-Proxy', 4),
            6666: ('IRC', 5),
            
            # Containerization & Orchestration
            2375: ('Docker', 10),
            2376: ('Docker-TLS', 8),
            6443: ('Kubernetes', 9),
            10250: ('Kubelet', 9),
        }

        # Build detailed port information for open ports
        for port, is_open in open_ports.items():
            if is_open:
                service, risk = common_ports. get(port, ('Unknown', 0))
                port_info[port] = {'service': service, 'risk':  risk}

        result['connectivity']['open_ports'] = port_info
        result['connectivity']['port_risk_score'] = port_risk

        if verbose:
            if port_info:
                print(f"✓ Found {len(port_info)} open port(s):")
                # Sort by risk (highest first), then by port number
                sorted_ports = sorted(port_info.items(), key=lambda x: (-x[1]['risk'], x[0]))
                
                for port, info in sorted_ports:
                    service = info['service']
                    risk = info['risk']
                    
                    # Color-code by risk level
                    if risk >= 9:
                        risk_indicator = "🔴 CRITICAL"
                    elif risk >= 7:
                        risk_indicator = "🟠 HIGH"
                    elif risk >= 4:
                        risk_indicator = "🟡 MEDIUM"
                    else:
                        risk_indicator = "🟢 LOW"
                    
                    print(f"    • Port {port: >5} | {service:<20} | Risk: {risk: >2}/10 {risk_indicator}")
                
                # Display total risk score
                if port_risk >= 30:
                    risk_level = "🔴 CRITICAL"
                elif port_risk >= 20:
                    risk_level = "🟠 HIGH"
                elif port_risk >= 10:
                    risk_level = "🟡 MEDIUM"
                else:
                    risk_level = "🟢 LOW"
                
                print(f"\n    Total Port Risk Score: {port_risk} ({risk_level})")
            else:
                print(f"✓ No common ports open (or all filtered)")
                
        if verbose:
            print("\n[*] Checking reputation databases...")
        
        # Bogon check
        if self.bogon_check(ip):
            if verbose:
                print(f"⚠️  WARNING: IP is private/reserved/bogon")
            result['threat_analysis']['bogon'] = True
        
        # DNSBL checks
        dnsbl_results = self.check_dnsbl(ip)
        result['threat_analysis']['dnsbl'] = dnsbl_results
        if verbose:
            listed_count = sum(1 for v in dnsbl_results.values() if v)
            if listed_count > 0:
                listed_on = [bl for bl, listed in dnsbl_results.items() if listed]
                print(f"⚠️  Listed on {listed_count}/{len(dnsbl_results)} blacklists:  {', '.join(listed_on)}")
            else:
                print(f"✓ Not listed on any blacklists")
        
        # GreyNoise
        greynoise = self.greynoise_community(ip)
        if greynoise and 'error' not in greynoise:
            result['threat_analysis']['greynoise'] = greynoise
            if verbose:
                noise = greynoise.get('noise', False)
                riot = greynoise.get('riot', False)
                print(f"✓ GreyNoise: Noise={noise}, RIOT={riot}")
        
        # AlienVault OTX
        otx = self.alienvault_otx(ip)
        if otx and 'error' not in otx:
            result['threat_analysis']['alienvault'] = otx
            if verbose:
                pulse_count = otx.get('pulse_info', {}).get('count', 0)
                if pulse_count > 0:
                    print(f"⚠️  AlienVault: {pulse_count} threat pulses")
                else:
                    print(f"✓ AlienVault: No threats")
        
        # ThreatCrowd
        threatcrowd = self.threatcrowd_lookup(ip)
        if threatcrowd and 'error' not in threatcrowd:
            result['threat_analysis']['threatcrowd'] = threatcrowd
            if verbose:
                votes = threatcrowd.get('votes', 0)
                if votes < 0:
                    print(f"⚠️  ThreatCrowd: Negative reputation ({votes} votes)")
                    
        # Maltiverse threat intelligence
        maltiverse = self.maltiverse_lookup(ip)
        if maltiverse and 'error' not in maltiverse:
            result['threat_analysis']['maltiverse'] = maltiverse
            if verbose:
                classification = maltiverse.get('classification', 'unknown')
                if classification != 'unknown':
                    print(f"⚠️  Maltiverse:  {classification}")
        
        # URLScan intelligence
        urlscan = self.urlscan_lookup(ip)
        if urlscan and 'error' not in urlscan:
            result['threat_analysis']['urlscan'] = urlscan
            if verbose:
                total = urlscan.get('total', 0)
                if total > 0:
                    print(f"ℹ️  URLScan: {total} results found")
        
        # Emerging Threats check
        et_listed = self.emerging_threats_check(ip)
        if et_listed is not None:
            result['threat_analysis']['emerging_threats'] = et_listed
            if verbose and et_listed:
                print(f"⚠️  Listed on Emerging Threats blocklist")
        
        # Spamhaus DROP check
        drop_listed = self.spamhaus_drop_check(ip)
        if drop_listed is not None:
            result['threat_analysis']['spamhaus_drop'] = drop_listed
            if verbose and drop_listed:
                print(f"🚨 Listed on Spamhaus DROP list (hijacked/illegal)")
        
        # SSL Blacklist
        sslbl = self.sslbl_abuse_ch(ip)
        if sslbl:
            result['threat_analysis']['ssl_blacklist'] = sslbl
            if verbose and sslbl.get('listed'):
                print(f"⚠️  SSL Blacklist:  Malicious SSL certificate detected")
        
        # GetIPIntel proxy detection
        getipintel = self.getipintel_check(ip)
        if getipintel is not None:
            result['threat_analysis']['getipintel'] = getipintel
            if verbose:
                if getipintel > 0.99:
                    print(f"🔀 GetIPIntel: VPN/Proxy CONFIRMED ({getipintel:.2f})")
                elif getipintel > 0.95:
                    print(f"⚠️  GetIPIntel: Likely VPN/Proxy ({getipintel:.2f})")
                else:
                    print(f"✓ GetIPIntel: Clean ({getipintel:.2f})")
        
        # VPN API check
        vpnapi = self.vpnapi_lookup(ip)
        if vpnapi and 'error' not in vpnapi:
            result['threat_analysis']['vpnapi'] = vpnapi
            if verbose:
                is_vpn = vpnapi.get('security', {}).get('vpn', False)
                is_proxy = vpnapi.get('security', {}).get('proxy', False)
                if is_vpn or is_proxy:
                    print(f"🔀 VPN API: {'VPN' if is_vpn else 'Proxy'} detected")
        
        # UCEPROTECT additional DNSBL
        uceprotect = self.uceprotect_check(ip)
        if uceprotect:
            result['threat_analysis']['uceprotect'] = True
            if verbose:
                print(f"⚠️  UCEPROTECT: Listed")
        
        # Team Cymru for additional verification
        cymru_asn = self.team_cymru_asn(ip)
        if cymru_asn:
            result['asn']['team_cymru_txt'] = cymru_asn
            if verbose:
                print(f"✓ Team Cymru:  {cymru_asn.split('|')[0].strip() if '|' in cymru_asn else cymru_asn}")
        
        # Carrier detection
        carrier = self.carrier_lookup(ip)
        if carrier:
            result['connectivity']['carrier'] = carrier
            if verbose and carrier.get('is_mobile'):
                print(f"📱 Mobile/Cellular IP detected")
            if verbose and carrier.get('is_proxy'):
                print(f"🔀 Proxy detected")
                
        # Proxy/VPN detection
        proxycheck = self.proxycheck_io(ip)
        if proxycheck and 'error' not in proxycheck:
            result['threat_analysis']['proxycheck'] = proxycheck
            if verbose:
                ip_data = proxycheck.get(ip, {})
                is_proxy = ip_data.get('proxy', 'no')
                proxy_type = ip_data.get('type', 'N/A')
                if is_proxy == 'yes':
                    print(f"🔀 ProxyCheck: Proxy/VPN detected (Type: {proxy_type})")
                else:
                    print(f"✓ ProxyCheck: Not a proxy")
        
        # Tor exit node check
        is_tor = self.tor_exit_check(ip)
        if is_tor:
            result['threat_analysis']['tor_exit'] = True
            if verbose:
                print(f"🧅 TOR EXIT NODE DETECTED")
        elif verbose:
            print(f"✓ Not a Tor exit node")
        
        # Spur.us intelligence
        spur = self.spur_us_free(ip)
        if spur and 'error' not in spur:
            result['threat_analysis']['spur'] = spur
            if verbose:
                if spur.get('anonymous'):
                    print(f"⚠️  Spur.us: Anonymous/VPN detected")
                if spur.get('vpn'):
                    print(f"⚠️  Spur.us: VPN service detected")
                if not spur.get('anonymous') and not spur.get('vpn'):
                    print(f"✓ Spur.us: Clean IP")
        
        # Abuse contact information
        abuse = self.ipinfo_abuse(ip)
        if abuse and 'error' not in abuse:
            result['threat_analysis']['abuse_contact'] = abuse
            if verbose:
                abuse_email = abuse.get('email', 'N/A')
                abuse_name = abuse.get('name', 'N/A')
                print(f"ℹ️  Abuse Contact: {abuse_name} ({abuse_email})")
        
        # HackerTarget ASN lookup (additional verification)
        hackertarget = self.hackertarget_asn(ip)
        if hackertarget and '[ERROR]' not in hackertarget:
            result['asn']['hackertarget'] = hackertarget
            if verbose:
                print(f"✓ HackerTarget ASN: {hackertarget.split()[0] if hackertarget else 'N/A'}")
        
        # ===== MILITARY/DEFENSE CHECK =====
        combined_info = {
            **result['whois'].get('parsed', {}),
            **result['geolocation'].get('ipinfo', {}),
            **result['asn'].get('ipinfo', {}),
            'open_ports': result['connectivity']['open_ports'],
            'reachable': result['connectivity']['reachable'],
            'tor_exit': result['threat_analysis'].get('tor_exit', False),
            'proxycheck': result['threat_analysis'].get('proxycheck', {}),
            'spur': result['threat_analysis'].get('spur', {}),
            'dnsbl': result['threat_analysis'].get('dnsbl', {}),
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
