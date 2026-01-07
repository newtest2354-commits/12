import os
import re
import json
import base64
import hashlib
import socket
import pickle
import threading
import concurrent.futures
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import time
import logging
import maxminddb
import ipaddress
import dns.resolver

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigParser:
    def __init__(self):
        self.lock = threading.Lock()
    
    def extract_domain_from_url(self, url):
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                netloc = parsed.netloc
                if '@' in netloc:
                    netloc = netloc.split('@')[-1]
                if ':' in netloc:
                    netloc = netloc.split(':')[0]
                return netloc
        except:
            pass
        return ''
    
    def parse_vmess(self, config_str):
        try:
            base64_part = config_str[8:]
            # استفاده از urlsafe_decode برای پشتیبانی بهتر
            padding_needed = len(base64_part) % 4
            if padding_needed:
                base64_part += '=' * (4 - padding_needed)
            config_data = json.loads(base64.urlsafe_b64decode(base64_part.encode()).decode('utf-8', errors='ignore'))
            
            address = config_data.get('add', '')
            host = config_data.get('host', '')
            sni = config_data.get('sni', '')
            
            target_host = address
            if host and self.is_domain(host):
                target_host = host
            elif sni and self.is_domain(sni):
                target_host = sni
            
            return {
                'protocol': 'vmess',
                'host': address,
                'port': int(config_data.get('port', 0)),
                'target_host': target_host,
                'raw': config_str,
                'sni': sni,
                'ps': config_data.get('ps', '')
            }
        except Exception as e:
            logger.debug(f"Failed to parse vmess config: {e}")
            return None
    
    def parse_vless(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            host, port_str = host_port.split(':')
            port = int(port_str.split('?')[0]) if '?' in port_str else int(port_str)
            
            query_params = parse_qs(parsed.query)
            sni = ''
            host_param = ''
            
            if 'sni' in query_params:
                sni = query_params['sni'][0]
            elif 'host' in query_params:
                host_param = query_params['host'][0]
            
            target_host = host
            if sni and self.is_domain(sni):
                target_host = sni
            elif host_param and self.is_domain(host_param):
                target_host = host_param
            
            return {
                'protocol': 'vless',
                'host': host,
                'port': port,
                'target_host': target_host,
                'raw': config_str,
                'sni': sni,
                'host_param': host_param
            }
        except Exception as e:
            logger.debug(f"Failed to parse vless config: {e}")
            return None
    
    def parse_trojan(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            host, port_str = host_port.split(':')
            port = int(port_str.split('#')[0]) if '#' in port_str else int(port_str)
            
            query_params = parse_qs(parsed.query)
            sni = ''
            
            if 'sni' in query_params:
                sni = query_params['sni'][0]
            
            target_host = host
            if sni and self.is_domain(sni):
                target_host = sni
            
            return {
                'protocol': 'trojan',
                'host': host,
                'port': port,
                'target_host': target_host,
                'raw': config_str,
                'sni': sni
            }
        except Exception as e:
            logger.debug(f"Failed to parse trojan config: {e}")
            return None
    
    def parse_ss(self, config_str):
        try:
            parts = config_str.split('#', 1)
            base_part = parts[0][5:]
            
            if '@' not in base_part:
                # استفاده از urlsafe_decode برای پشتیبانی بهتر
                decoded_bytes = base64.urlsafe_b64decode(base_part + '==')
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if '@' in decoded:
                    method_pass, server_part = decoded.split('@', 1)
                else:
                    return None
            else:
                encoded_method_pass, server_part = base_part.split('@', 1)
                
            server, port_str = server_part.split(':', 1)
            port = int(port_str)
            
            return {
                'protocol': 'ss',
                'host': server,
                'port': port,
                'target_host': server,
                'raw': config_str
            }
        except Exception as e:
            logger.debug(f"Failed to parse ss config: {e}")
            return None
    
    def parse_hysteria(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            host, port_str = host_port.split(':')
            port = int(port_str)
            
            # استخراج پارامترهای مهم از query
            query_params = parse_qs(parsed.query)
            sni = query_params.get('sni', [''])[0]
            host_param = query_params.get('host', [''])[0]
            
            target_host = host
            if sni and self.is_domain(sni):
                target_host = sni
            elif host_param and self.is_domain(host_param):
                target_host = host_param
            
            return {
                'protocol': 'hysteria',
                'host': host,
                'port': port,
                'target_host': target_host,
                'raw': config_str,
                'sni': sni,
                'host_param': host_param
            }
        except Exception as e:
            logger.debug(f"Failed to parse hysteria config: {e}")
            return None
    
    def parse_tuic(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            host, port_str = host_port.split(':')
            port = int(port_str)
            
            # استخراج پارامترهای مهم از query
            query_params = parse_qs(parsed.query)
            sni = query_params.get('sni', [''])[0]
            host_param = query_params.get('host', [''])[0]
            
            target_host = host
            if sni and self.is_domain(sni):
                target_host = sni
            elif host_param and self.is_domain(host_param):
                target_host = host_param
            
            return {
                'protocol': 'tuic',
                'host': host,
                'port': port,
                'target_host': target_host,
                'raw': config_str,
                'sni': sni,
                'host_param': host_param
            }
        except Exception as e:
            logger.debug(f"Failed to parse tuic config: {e}")
            return None
    
    def parse_wireguard(self, config_str):
        try:
            parsed = urlparse(config_str)
            params = parsed.query
            host = ''
            
            for param in params.split('&'):
                if param.startswith('address='):
                    host = param[8:].split(':')[0]
                    break
            
            return {
                'protocol': 'wireguard',
                'host': host,
                'port': 51820,
                'target_host': host,
                'raw': config_str
            }
        except Exception as e:
            logger.debug(f"Failed to parse wireguard config: {e}")
            return None
    
    def is_ip_address(self, host):
        if not host:
            return False
        
        try:
            ipaddress.ip_address(host)
            return True
        except:
            return False
    
    def is_domain(self, host):
        if not host:
            return False
        
        if self.is_ip_address(host):
            return False
        
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$'
        if re.match(domain_pattern, host):
            return True
        
        if '.' in host and not self.is_ip_address(host):
            return True
        
        return False
    
    def resolve_domain(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3  # کاهش timeout برای سرعت بیشتر
            resolver.lifetime = 3
            
            ipv4_addresses = []
            ipv6_addresses = []
            
            try:
                answers = resolver.resolve(domain, 'A')
                ipv4_addresses = [str(r) for r in answers]
            except:
                pass
            
            try:
                answers = resolver.resolve(domain, 'AAAA')
                ipv6_addresses = [str(r) for r in answers]
            except:
                pass
            
            return ipv4_addresses + ipv6_addresses
        except:
            return []
    
    def parse_config(self, config_str):
        config_str = config_str.strip()
        
        if config_str.startswith('vmess://'):
            return self.parse_vmess(config_str)
        elif config_str.startswith('vless://'):
            return self.parse_vless(config_str)
        elif config_str.startswith('trojan://'):
            return self.parse_trojan(config_str)
        elif config_str.startswith('ss://'):
            return self.parse_ss(config_str)
        elif config_str.startswith('hysteria://') or config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
            return self.parse_hysteria(config_str)
        elif config_str.startswith('tuic://'):
            return self.parse_tuic(config_str)
        elif config_str.startswith('wireguard://'):
            return self.parse_wireguard(config_str)
        
        return None

class GeoIPClassifier:
    def __init__(self):
        self.country_db = None
        self.asn_db = None
        self.ipapi_cache = {}
        self.cache_file = 'geoip_cache.pkl'
        self.lock = threading.Lock()
        
        self.cdn_asns = {
            '13335', '209242', '16509', '15169', '8075', 
            '54113', '19527', '14618', '40065', '14061',
            '63949', '8987', '55080', '268843', '394699',
            '395747', '136764', '18717', '22822', '46489'
        }
        
        self.datacenter_asns = {
            '24940', '16276', '51167', '14061', '395747',
            '46606', '20473', '55770', '13890', '60068',
            '60781', '36352', '204601', '22612', '63949',
            '393560', '202425', '203020', '197540', '133752'
        }
        
        self.load_databases()
        self.load_cache()
    
    def load_databases(self):
        try:
            if os.path.exists('GeoLite2-Country.mmdb'):
                self.country_db = maxminddb.open_database('GeoLite2-Country.mmdb')
                logger.info("GeoLite2-Country database loaded")
            else:
                logger.warning("GeoLite2-Country.mmdb not found, using fallback")
        
        except Exception as e:
            logger.error(f"Failed to load GeoLite2-Country: {e}")
        
        try:
            if os.path.exists('GeoLite2-ASN.mmdb'):
                self.asn_db = maxminddb.open_database('GeoLite2-ASN.mmdb')
                logger.info("GeoLite2-ASN database loaded")
            else:
                logger.warning("GeoLite2-ASN.mmdb not found, using fallback")
        
        except Exception as e:
            logger.error(f"Failed to load GeoLite2-ASN: {e}")
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    self.ipapi_cache = pickle.load(f)
        except:
            self.ipapi_cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.ipapi_cache, f)
        except:
            pass
    
    def get_asn_info(self, ip):
        if not self.asn_db:
            return None, None, None
        
        try:
            result = self.asn_db.get(ip)
            if result:
                asn = result.get('autonomous_system_number')
                org = result.get('autonomous_system_organization', '')
                return asn, org, None
        except:
            pass
        
        return None, None, None
    
    def get_country_from_db(self, ip):
        if not self.country_db:
            return None
        
        try:
            result = self.country_db.get(ip)
            if result:
                country = result.get('country', {}).get('iso_code')
                return country
        except:
            pass
        
        return None
    
    def is_anycast_asn(self, asn, org):
        if not asn:
            return False
        
        org_lower = org.lower() if org else ''
        
        anycast_indicators = [
            'anycast', 'cloudflare', 'akamai', 'fastly',
            'edge network', 'cdn', 'content delivery'
        ]
        
        for indicator in anycast_indicators:
            if indicator in org_lower:
                return True
        
        return False
    
    def classify_ip_type(self, ip, asn, org):
        if not ip:
            return 'UNKNOWN'
        
        if not asn:
            return 'UNKNOWN'
        
        asn_str = str(asn)
        
        if asn_str in self.cdn_asns:
            if self.is_anycast_asn(asn, org):
                return 'CDN'
            else:
                return 'FIXED_IP'
        
        if asn_str in self.datacenter_asns:
            return 'FIXED_IP'
        
        org_lower = org.lower() if org else ''
        
        cdn_keywords = ['cloudflare', 'akamai', 'fastly', 'cloudfront', 
                       'google edge', 'azure edge', 'aws cloudfront']
        
        datacenter_keywords = ['hetzner', 'ovh', 'digitalocean', 'vultr',
                              'linode', 'contabo', 'leaseweb', 'ionos',
                              'serverius', 'choopa', 'psychz', 'data center',
                              'hosting', 'server', 'vps', 'dedicated']
        
        for keyword in cdn_keywords:
            if keyword in org_lower:
                return 'CDN'
        
        for keyword in datacenter_keywords:
            if keyword in org_lower:
                return 'FIXED_IP'
        
        return 'UNKNOWN'
    
    def get_country_by_ipapi(self, ip):
        try:
            with self.lock:
                if ip in self.ipapi_cache:
                    return self.ipapi_cache[ip]
            
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,countryCode,as,asname,isp,org", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result = {
                        'country': data.get('countryCode', 'UNKNOWN'),
                        'asn': data.get('as', ''),
                        'org': data.get('org', data.get('isp', ''))
                    }
                    with self.lock:
                        self.ipapi_cache[ip] = result
                    return result
        except Exception as e:
            logger.debug(f"IP-API failed for {ip}: {e}")
        
        return {'country': 'UNKNOWN', 'asn': '', 'org': ''}
    
    def analyze_ip(self, ip):
        # اولویت با ip-api به دلیل به‌روزرسانی بهتر
        ipapi_result = self.get_country_by_ipapi(ip)
        country = ipapi_result['country']
        asn_str = ipapi_result['asn']
        org = ipapi_result['org']
        
        # استفاده از MaxMind به عنوان fallback
        if self.country_db and (not country or country == 'UNKNOWN'):
            country_from_db = self.get_country_from_db(ip)
            if country_from_db:
                country = country_from_db
        
        asn = None
        if asn_str and asn_str.startswith('AS'):
            try:
                asn = int(asn_str[2:])
            except:
                asn = None
        
        if not asn and self.asn_db:
            asn_from_db, org_from_db, _ = self.get_asn_info(ip)
            if asn_from_db:
                asn = asn_from_db
            if not org and org_from_db:
                org = org_from_db
        
        if asn:
            ip_type = self.classify_ip_type(ip, asn, org)
        else:
            ip_type = 'UNKNOWN'
        
        return {
            'country': country if country else 'UNKNOWN',
            'asn': asn,
            'org': org if org else '',
            'ip_type': ip_type
        }

class CountryClassifier:
    def __init__(self, max_workers=30):
        self.parser = ConfigParser()
        self.geoip = GeoIPClassifier()
        self.max_workers = max_workers
        self.results_lock = threading.Lock()
        self.results = {}
        self.stats = {
            'total': 0,
            'ip_based': 0,
            'domain_based': 0,
            'cdn_ip': 0,
            'fixed_ip': 0,
            'unknown_ip': 0,
            'by_country': {},
            'by_protocol': {},
            'by_ip_type': {}
        }
        # برای ذخیره اطلاعات کامل هر کانفیگ
        self.full_info = {}
    
    def process_single_config(self, config_str):
        try:
            parsed = self.parser.parse_config(config_str)
            if not parsed:
                return None
            
            target_host = parsed.get('target_host', '')
            if not target_host:
                return None
            
            is_ip = self.parser.is_ip_address(target_host)
            
            if not is_ip:
                resolved_ips = self.parser.resolve_domain(target_host)
                
                if resolved_ips:
                    best_ip = None
                    best_ip_type = 'UNKNOWN'
                    country = 'UNKNOWN'
                    
                    for ip in resolved_ips[:3]:  # بررسی حداکثر 3 IP
                        ip_info = self.geoip.analyze_ip(ip)
                        
                        if ip_info['ip_type'] == 'FIXED_IP':
                            best_ip = ip
                            best_ip_type = 'FIXED_IP'
                            country = ip_info['country']
                            break
                        elif ip_info['ip_type'] == 'CDN' and not best_ip:
                            best_ip = ip
                            best_ip_type = 'CDN'
                            country = ip_info['country']
                    
                    if best_ip:
                        return {
                            'config': config_str,
                            'parsed': parsed,
                            'ip': best_ip,
                            'country': country,
                            'is_ip': True,
                            'target_host': target_host,
                            'ip_type': best_ip_type,  # ذخیره ip_type
                            'resolved_from_domain': True
                        }
                
                return {
                    'config': config_str,
                    'parsed': parsed,
                    'ip': None,
                    'country': 'DOMAIN',
                    'is_ip': False,
                    'target_host': target_host,
                    'ip_type': 'DOMAIN',  # ذخیره ip_type
                    'resolved_from_domain': False
                }
            
            ip_info = self.geoip.analyze_ip(target_host)
            
            return {
                'config': config_str,
                'parsed': parsed,
                'ip': target_host,
                'country': ip_info['country'],
                'is_ip': True,
                'target_host': target_host,
                'ip_type': ip_info['ip_type'],  # ذخیره ip_type
                'resolved_from_domain': False
            }
        except Exception as e:
            logger.debug(f"Failed to process config: {e}")
            return None
    
    def process_configs(self, configs):
        logger.info(f"Processing {len(configs)} configurations...")
        
        self.results = {}
        self.full_info = {}
        self.stats = {
            'total': len(configs),
            'ip_based': 0,
            'domain_based': 0,
            'cdn_ip': 0,
            'fixed_ip': 0,
            'unknown_ip': 0,
            'by_country': {},
            'by_protocol': {},
            'by_ip_type': {}
        }
        
        unique_configs = []
        seen = set()
        
        for config in configs:
            config_hash = hashlib.md5(config.encode()).hexdigest()
            if config_hash not in seen:
                seen.add(config_hash)
                unique_configs.append(config)
        
        logger.info(f"After deduplication: {len(unique_configs)} unique configs")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_config = {executor.submit(self.process_single_config, config): config for config in unique_configs}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_config):
                completed += 1
                if completed % 100 == 0:
                    logger.info(f"Processed {completed}/{len(unique_configs)} configs")
                
                result = future.result()
                if result:
                    config_str = future_to_config[future]
                    with self.results_lock:
                        # ذخیره اطلاعات کامل برای استفاده بعدی
                        self.full_info[config_str] = result
                        
                        if result['is_ip']:
                            self.stats['ip_based'] += 1
                            
                            ip_type = result['ip_type']
                            if ip_type == 'CDN':
                                self.stats['cdn_ip'] += 1
                            elif ip_type == 'FIXED_IP':
                                self.stats['fixed_ip'] += 1
                            else:
                                self.stats['unknown_ip'] += 1
                            
                            self.stats['by_ip_type'][ip_type] = self.stats['by_ip_type'].get(ip_type, 0) + 1
                        else:
                            self.stats['domain_based'] += 1
                            self.stats['by_ip_type']['DOMAIN'] = self.stats['by_ip_type'].get('DOMAIN', 0) + 1
                        
                        country = result['country']
                        protocol = result['parsed']['protocol']
                        
                        if country not in self.results:
                            self.results[country] = {}
                        
                        if protocol not in self.results[country]:
                            self.results[country][protocol] = []
                        
                        self.results[country][protocol].append(result['config'])
                        
                        self.stats['by_country'][country] = self.stats['by_country'].get(country, 0) + 1
                        self.stats['by_protocol'][protocol] = self.stats['by_protocol'].get(protocol, 0) + 1
        
        self.geoip.save_cache()
        
        return {
            'results': self.results,
            'stats': self.stats,
            'full_info': self.full_info  # اضافه کردن اطلاعات کامل
        }
    
    def save_results(self, results, output_dir='configs/country'):
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # ذخیره بر اساس کشور و پروتکل
        for country, protocols in results['results'].items():
            if country == 'DOMAIN':
                continue
                
            country_dir = os.path.join(output_dir, country)
            os.makedirs(country_dir, exist_ok=True)
            
            all_country_configs = []
            
            for protocol, configs in protocols.items():
                if configs:
                    protocol_file = os.path.join(country_dir, f"{protocol}.txt")
                    content = f"# {country} - {protocol.upper()} Configurations\n"
                    content += f"# Updated: {timestamp}\n"
                    content += f"# Count: {len(configs)}\n"
                    content += f"# Country Code: {country}\n\n"
                    content += "\n".join(configs)
                    
                    with open(protocol_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    all_country_configs.extend(configs)
            
            if all_country_configs:
                all_file = os.path.join(country_dir, "all.txt")
                content = f"# All Configurations for {country}\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(all_country_configs)}\n"
                content += f"# Country Code: {country}\n\n"
                content += "\n".join(all_country_configs)
                
                with open(all_file, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        # ذخیره کانفیگ‌های مبتنی بر دامنه
        if 'DOMAIN' in results['results']:
            domain_dir = os.path.join(output_dir, 'DOMAIN')
            os.makedirs(domain_dir, exist_ok=True)
            
            domain_configs = []
            for protocol, configs in results['results']['DOMAIN'].items():
                domain_configs.extend(configs)
            
            if domain_configs:
                domain_file = os.path.join(domain_dir, "all.txt")
                content = f"# Domain-Based Configurations\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(domain_configs)}\n"
                content += "# Note: These configs use domain names instead of IP addresses\n\n"
                content += "\n".join(domain_configs)
                
                with open(domain_file, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        # ساختار جدید: ذخیره بر اساس IP Type
        ip_type_dir = os.path.join(output_dir, 'by_iptype')
        os.makedirs(ip_type_dir, exist_ok=True)
        
        ip_type_summary = {}
        # جمع‌آوری آمار دقیق IP Type
        for config_str, config_info in results['full_info'].items():
            ip_type = config_info.get('ip_type', 'UNKNOWN')
            if ip_type not in ip_type_summary:
                ip_type_summary[ip_type] = []
            ip_type_summary[ip_type].append(config_str)
        
        # ذخیره کانفیگ‌ها بر اساس IP Type
        for ip_type, configs in ip_type_summary.items():
            if configs:
                ip_type_file = os.path.join(ip_type_dir, f"{ip_type}.txt")
                content = f"# {ip_type} Configurations\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Count: {len(configs)}\n"
                content += f"# IP Type: {ip_type}\n\n"
                content += "\n".join(configs)
                
                with open(ip_type_file, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        # ذخیره خلاصه جامع
        summary_file = os.path.join(output_dir, "summary.txt")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"# Country Classification Summary\n")
            f.write(f"# Updated: {timestamp}\n\n")
            f.write(f"Total configs processed: {results['stats']['total']}\n")
            f.write(f"IP-based configs: {results['stats']['ip_based']}\n")
            f.write(f"  - Fixed IP (Datacenter): {results['stats']['fixed_ip']}\n")
            f.write(f"  - CDN IP: {results['stats']['cdn_ip']}\n")
            f.write(f"  - Unknown IP: {results['stats']['unknown_ip']}\n")
            f.write(f"Domain-based configs: {results['stats']['domain_based']}\n\n")
            
            f.write("IP-Based Configs by Country:\n")
            ip_countries = {k: v for k, v in results['stats']['by_country'].items() if k != 'DOMAIN'}
            for country, count in sorted(ip_countries.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {country}: {count}\n")
            
            f.write("\nBy Protocol:\n")
            for protocol, count in sorted(results['stats']['by_protocol'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {protocol}: {count}\n")
            
            f.write("\nBy IP Type:\n")
            for ip_type, count in sorted(results['stats']['by_ip_type'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {ip_type}: {count}\n")
            
            # اضافه کردن آمار دقیق IP Type از ip_type_summary
            f.write("\nDetailed IP Type Summary:\n")
            for ip_type, configs in sorted(ip_type_summary.items(), key=lambda x: len(x[1]), reverse=True):
                f.write(f"  {ip_type}: {len(configs)} configs\n")
        
        # ذخیره آمار به صورت JSON
        stats_file = os.path.join(output_dir, "stats.json")
        with open(stats_file, 'w', encoding='utf-8') as f:
            # اضافه کردن ip_type_summary به stats
            full_stats = results['stats'].copy()
            full_stats['detailed_ip_type'] = {k: len(v) for k, v in ip_type_summary.items()}
            json.dump(full_stats, f, indent=2)
        
        logger.info(f"Results saved to {output_dir}")

def read_all_configs():
    configs = []
    
    combined_file = 'configs/combined/all.txt'
    if os.path.exists(combined_file):
        try:
            with open(combined_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        configs.append(line)
        except:
            pass
    
    if not configs:
        sources = [
            'configs/telegram/all.txt',
            'configs/github/all.txt'
        ]
        
        for filepath in sources:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                configs.append(line)
                except:
                    pass
    
    return configs

def main():
    print("=" * 60)
    print("IP-BASED COUNTRY CONFIG CLASSIFIER")
    print("=" * 60)
    
    try:
        configs = read_all_configs()
        if not configs:
            logger.error("No configurations found to process")
            return
        
        logger.info(f"Found {len(configs)} configurations")
        
        classifier = CountryClassifier(max_workers=30)
        start_time = time.time()
        
        results = classifier.process_configs(configs)
        
        elapsed_time = time.time() - start_time
        
        classifier.save_results(results)
        
        print(f"\n✅ CLASSIFICATION COMPLETE")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Total configs: {results['stats']['total']}")
        print(f"IP-based configs: {results['stats']['ip_based']}")
        print(f"  - Fixed IP (Datacenter): {results['stats']['fixed_ip']}")
        print(f"  - CDN IP: {results['stats']['cdn_ip']}")
        print(f"  - Unknown IP: {results['stats']['unknown_ip']}")
        print(f"Domain-based configs: {results['stats']['domain_based']}")
        
        print(f"\n📊 IP-Based Configs by Country:")
        ip_countries = {k: v for k, v in results['stats']['by_country'].items() if k != 'DOMAIN'}
        top_countries = sorted(ip_countries.items(), key=lambda x: x[1], reverse=True)[:15]
        
        for country, count in top_countries:
            print(f"  {country}: {count} configs")
        
        print(f"\n📊 By IP Type:")
        for ip_type, count in sorted(results['stats']['by_ip_type'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {ip_type}: {count} configs")
        
        print(f"\n📁 Output saved to: configs/country/")
        print("=" * 60)
        
    except Exception as e:
        logger.error(f"Error in main: {e}")

if __name__ == "__main__":
    main()
