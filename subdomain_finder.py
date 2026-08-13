# -*- coding: utf-8 -*-
import socket
import ssl
import threading
import time
import os
import sys
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# ЦВЕТА
# ============================================================
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'

def print_banner():
    print(f"""{Colors.CYAN}
    ╔══════════════════════════════════════════════╗
    ║       SUBDOMAIN ENUMERATOR v2.0              ║
    ║   DNS Bruteforce + Passive Sources + HTTP    ║
    ╚══════════════════════════════════════════════╝
    {Colors.RESET}""")

# ============================================================
# БАЗА ПОДДОМЕНОВ (400+ слов)
# ============================================================
DEFAULT_SUBDOMAINS = [
    # --- Админки и панели управления ---
    'admin', 'administrator', 'adm', 'adminpanel', 'adminpanel2',
    'backend', 'back', 'cms', 'control', 'controlpanel', 'cp',
    'cpanel', 'dashboard', 'manage', 'manager', 'management',
    'moderator', 'panel', 'root', 'siteadmin', 'sysadmin',
    'webadmin', 'webmaster', 'whm', 'webmin', 'plesk', 'isp',

    # --- Почта ---
    'mail', 'mail2', 'mail3', 'mailadmin', 'email', 'emails',
    'webmail', 'webmail2', 'smtp', 'smtp2', 'imap', 'imap4',
    'pop', 'pop3', 'mx', 'mx1', 'mx2', 'mailhost', 'owa',
    'outlook', 'autodiscover', 'mta', 'relay',

    # --- FTP и файлы ---
    'ftp', 'ftp2', 'ftps', 'sftp', 'files', 'file', 'filemanager',
    'download', 'downloads', 'dl', 'upload', 'uploads', 'ul',
    'storage', 'store', 'static', 'static1', 'static2', 'assets',
    'media', 'media2', 'cdn', 'cdn1', 'cdn2', 'cdn3',

    # --- Разработка ---
    'dev', 'dev2', 'dev3', 'development', 'developer', 'developers',
    'test', 'test2', 'test3', 'testing', 'tst', 'stage', 'staging',
    'sandbox', 'demo', 'beta', 'alpha', 'preview', 'experimental',
    'lab', 'labs', 'playground', 'prototype', 'poc',

    # --- API ---
    'api', 'api2', 'api3', 'api-dev', 'api-test', 'api-stage',
    'rest', 'restapi', 'graphql', 'ws', 'websocket', 'socket',
    'services', 'service', 'soap', 'xml', 'json',

    # --- Приложения ---
    'app', 'apps', 'app2', 'app3', 'application', 'applications',
    'mobile', 'm', 'ios', 'android', 'desktop', 'client',

    # --- Базы данных ---
    'db', 'db2', 'database', 'databases', 'mysql', 'mysql2',
    'postgres', 'postgresql', 'pgsql', 'redis', 'mongo', 'mongodb',
    'elastic', 'elasticsearch', 'es', 'sql', 'data', 'datastore',
    'cassandra', 'couchdb', 'neo4j', 'oracle',

    # --- Мониторинг ---
    'monitor', 'monitoring', 'mon', 'status', 'health', 'healthcheck',
    'metrics', 'grafana', 'kibana', 'prometheus', 'nagios', 'zabbix',
    'icinga', 'sensu', 'datadog', 'newrelic', 'check',

    # --- Логи ---
    'logs', 'log', 'logging', 'logstash', 'syslog', 'audit',
    'auditlog', 'tracer', 'trace',

    # --- Безопасность ---
    'secure', 'security', 'sec', 'ssl', 'tls', 'cert', 'certs',
    'vpn', 'vpn2', 'openvpn', 'wireguard', 'wg', 'auth', 'auth2',
    'login', 'sso', 'saml', 'oauth', 'oauth2', 'ldap', 'radius',
    'firewall', 'fw', 'ids', 'ips', 'waf',

    # --- Сеть ---
    'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'dns3',
    'router', 'switch', 'gateway', 'gw', 'proxy', 'proxy1', 'proxy2',
    'lb', 'loadbalancer', 'haproxy', 'nginx', 'traefik', 'envoy',
    'nat', 'dmz', 'vlan',

    # --- Удаленный доступ ---
    'remote', 'rdp', 'rdweb', 'rdgateway', 'ts', 'terminal',
    'terminal server', 'citrix', 'xenapp', 'xendesktop', 'vdi',
    'vmware', 'horizon', 'workspace',

    # --- Офисные инструменты ---
    'jira', 'jira2', 'confluence', 'wiki', 'docs', 'doc',
    'documentation', 'kb', 'knowledge', 'faq', 'help', 'helpdesk',
    'support', 'ticket', 'tickets', 'servicedesk', 'itsm',
    'trello', 'redmine', 'trac', 'mantis', 'bugzilla',
    'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo',
    'repos', 'repository', 'gitea', 'gogs',

    # --- CI/CD ---
    'jenkins', 'ci', 'cd', 'build', 'deploy', 'deployment',
    'docker', 'docker2', 'k8s', 'kubernetes', 'rancher', 'swarm',
    'registry', 'harbor', 'nexus', 'artifactory',

    # --- Магазин ---
    'shop', 'store', 'cart', 'checkout', 'pay', 'payment',
    'payments', 'billing', 'invoice', 'invoices', 'order',
    'orders', 'catalog', 'products', 'product', 'price',

    # --- Пользователи ---
    'account', 'accounts', 'user', 'users', 'profile', 'profiles',
    'member', 'members', 'client', 'clients', 'customer', 'customers',
    'partner', 'partners', 'my', 'dashboard', 'signin', 'signup',
    'register', 'registration', 'join', 'login', 'logon',

    # --- Контент ---
    'blog', 'blog2', 'news', 'newsletter', 'press', 'media',
    'gallery', 'images', 'img', 'image', 'video', 'videos',
    'stream', 'streaming', 'live', 'tv', 'radio', 'podcast',
    'magazine', 'journal',

    # --- Поиск ---
    'search', 'search2', 'find', 'analytics', 'stats', 'statistics',
    'stat', 'tracker', 'tracking', 'pixel', 'matomo', 'piwik',

    # --- Резервное копирование ---
    'backup', 'backups', 'bak', 'backup2', 'replica', 'mirror',
    'snapshot', 'snapshots', 'archive', 'archives',

    # --- Старые версии ---
    'old', 'old2', 'new', 'new2', 'v1', 'v2', 'v3', 'v4', 'v5',
    'www2', 'www3', 'site2', 'web2', 'old-site', 'oldsite',
    'legacy', 'archive',

    # --- CRM/ERP ---
    'crm', 'crm2', 'erp', 'sap', 'salesforce', 'bitrix', 'amo',
    'zoho', 'sugarcrm', 'suitecrm',

    # --- VoIP/Связь ---
    'sip', 'sip2', 'voip', 'phone', 'phones', 'chat', 'messenger',
    'jabber', 'xmpp', 'rocket', 'rocketchat', 'slack', 'mattermost',
    'teams', 'zoom', 'meet', 'webinar', 'conf', 'conference',
    'jitsi', 'bbb',

    # --- Разное ---
    'info', 'about', 'contact', 'contactus', 'feedback', 'survey',
    'poll', 'event', 'events', 'calendar', 'time', 'ntp',
    'print', 'printer', 'scan', 'scanner', 'camera', 'cam',
    'webcam', 'door', 'access', 'badge',
    'vnc', 'vpn', 'terminal', 'console', 'shell',
    'map', 'maps', 'gis', 'geo', 'location',
    'ads', 'ad', 'banner', 'banners', 'pub',
    'affiliate', 'aff', 'partner', 'partners',
    'staging2', 'staging3', 'test4', 'test5',
    'dev4', 'dev5', 'dev6', 'uat', 'qa', 'qc',
    'preprod', 'production', 'prod', 'prod2',
]

# ============================================================
# HTTP КЛИЕНТ С НОРМАЛЬНОЙ ОБРАБОТКОЙ
# ============================================================
class HTTPClient:
    """HTTP клиент с retry, редиректами, обработкой ошибок"""
    
    def __init__(self, timeout=5, max_retries=2):
        self.timeout = timeout
        self.session = self._create_session(max_retries)
    
    def _create_session(self, max_retries):
        session = requests.Session()
        
        # Стратегия повторных попыток
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=50, pool_maxsize=50)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Заголовки
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def check(self, hostname, port=80, use_ssl=False, path='/'):
        """Проверяет HTTP/HTTPS на поддомене"""
        scheme = 'https' if use_ssl else 'http'
        url = f"{scheme}://{hostname}{path}"
        
        result = {
            'status_code': None,
            'server': '',
            'title': '',
            'redirect': '',
            'content_type': '',
            'content_length': 0,
            'headers': {},
            'error': None,
            'final_url': '',
            'redirect_chain': []
        }
        
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            result['status_code'] = resp.status_code
            result['final_url'] = resp.url
            result['content_type'] = resp.headers.get('Content-Type', '')
            result['content_length'] = int(resp.headers.get('Content-Length', 0))
            
            # Сервер
            result['server'] = resp.headers.get('Server', '')
            if not result['server']:
                result['server'] = resp.headers.get('X-Powered-By', '')
            
            # Заголовки
            result['headers'] = dict(resp.headers)
            
            # Редиректы
            if resp.history:
                result['redirect_chain'] = [r.url for r in resp.history]
                result['redirect'] = resp.url
            
            # Title страницы
            if 'text/html' in result['content_type'].lower():
                title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result['title'] = title_match.group(1).strip()[:200]
                    
        except requests.exceptions.SSLError as e:
            result['error'] = f'SSL Error'
        except requests.exceptions.ConnectionError as e:
            result['error'] = 'Connection refused'
        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
        except requests.exceptions.TooManyRedirects:
            result['error'] = 'Too many redirects'
        except Exception as e:
            result['error'] = str(e)[:100]
        
        return result


# ============================================================
# ПАССИВНЫЙ ПОИСК
# ============================================================
class PassiveSources:
    """Поиск поддоменов в открытых источниках"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def crt_sh(self, domain):
        """Certificate Transparency логи crt.sh"""
        found = set()
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower().lstrip('*.')
                        if name.endswith(f".{domain}") and name != domain:
                            sub = name.replace(f".{domain}", '').strip('.')
                            if sub and '*' not in sub:
                                found.add(sub)
        except Exception:
            pass
        
        return list(found)
    
    def alienvault_otx(self, domain):
        """AlienVault OTX passive DNS"""
        found = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '').lower()
                    if hostname.endswith(f".{domain}"):
                        sub = hostname.replace(f".{domain}", '').strip('.')
                        if sub and '*' not in sub:
                            found.add(sub)
        except Exception:
            pass
        
        return list(found)
    
    def urlscan_io(self, domain):
        """urlscan.io search"""
        found = set()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            
            if resp.status_code == 200:
                data = resp.json()
                for result in data.get('results', []):
                    page = result.get('page', {})
                    hostname = page.get('domain', '').lower()
                    if hostname.endswith(f".{domain}"):
                        sub = hostname.replace(f".{domain}", '').strip('.')
                        if sub and '*' not in sub:
                            found.add(sub)
        except Exception:
            pass
        
        return list(found)
    
    def search_all(self, domain):
        """Запуск всех пассивных источников"""
        all_found = set()
        
        print(f"\n{Colors.BOLD}[*] Пассивный поиск:{Colors.RESET}")
        
        # crt.sh
        print(f"    crt.sh...", end=' ')
        crt = self.crt_sh(domain)
        all_found.update(crt)
        print(f"{Colors.GREEN}{len(crt)}{Colors.RESET}")
        
        # AlienVault
        print(f"    AlienVault OTX...", end=' ')
        otx = self.alienvault_otx(domain)
        all_found.update(otx)
        print(f"{Colors.GREEN}{len(otx)}{Colors.RESET}")
        
        # urlscan.io
        print(f"    urlscan.io...", end=' ')
        us = self.urlscan_io(domain)
        all_found.update(us)
        print(f"{Colors.GREEN}{len(us)}{Colors.RESET}")
        
        total = len(all_found)
        print(f"\n    {Colors.BOLD}Всего из пассивных источников: {Colors.GREEN}{total}{Colors.RESET}")
        
        return list(all_found)


# ============================================================
# СКАНЕР ПОДДОМЕНОВ
# ============================================================
class SubdomainFinder:
    
    def __init__(self, domain, wordlist=None, threads=50, timeout=3.0,
                 check_http=True, use_passive=True):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.check_http = check_http
        self.use_passive = use_passive
        
        self.wordlist = wordlist if wordlist else DEFAULT_SUBDOMAINS
        self.http_client = HTTPClient(timeout=timeout) if check_http else None
        self.passive_sources = PassiveSources(timeout=10) if use_passive else None
        
        self.results = []
        self.lock = threading.Lock()
        self.found_count = 0
    
    def resolve_domain(self, subdomain):
        """Разрешает поддомен в IP"""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return ip
        except socket.gaierror:
            return None
    
    def check_subdomain(self, subdomain):
        """Проверяет один поддомен"""
        ip = self.resolve_domain(subdomain)
        
        if ip is None:
            return None
        
        result = {
            'subdomain': subdomain,
            'fqdn': f"{subdomain}.{self.domain}",
            'ip': ip,
            'http': None,
            'https': None,
            'source': 'dns_bruteforce'
        }
        
        if self.check_http and self.http_client:
            # HTTP
            http_result = self.http_client.check(result['fqdn'], port=80, use_ssl=False)
            if http_result['status_code']:
                result['http'] = http_result
            
            # HTTPS
            https_result = self.http_client.check(result['fqdn'], port=443, use_ssl=True)
            if https_result['status_code']:
                result['https'] = https_result
        
        with self.lock:
            self.found_count += 1
        
        return result
    
    def run(self):
        """Запускает поиск поддоменов"""
        start_time = time.time()
        
        print(f"\n{Colors.BOLD}┌─── Поиск поддоменов ───{Colors.RESET}")
        print(f"│ Домен      : {Colors.GREEN}{self.domain}{Colors.RESET}")
        print(f"│ Словарь    : {len(self.wordlist)} слов")
        print(f"│ Потоков    : {self.threads}")
        print(f"│ HTTP check : {'Да' if self.check_http else 'Нет'}")
        print(f"│ Пассивный  : {'Да' if self.use_passive else 'Нет'}")
        print(f"{'─' * 50}")
        
        # Пассивный поиск
        passive_subs = []
        if self.use_passive and self.passive_sources:
            passive_subs = self.passive_sources.search_all(self.domain)
        
        # Объединяем словарь с пассивными находками
        all_to_check = list(dict.fromkeys(self.wordlist + passive_subs))
        
        print(f"\n{Colors.BOLD}[*] Активный перебор ({len(all_to_check)} поддоменов)...{Colors.RESET}")
        
        results = []
        completed = 0
        total = len(all_to_check)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_sub = {}
            
            for subdomain in all_to_check:
                future = executor.submit(self.check_subdomain, subdomain)
                future_to_sub[future] = subdomain
            
            for future in as_completed(future_to_sub):
                subdomain = future_to_sub[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self._print_result(result)
                except Exception:
                    pass
                
                if completed % 100 == 0 or completed == total:
                    elapsed = time.time() - start_time
                    percent = 100 * completed // total
                    bar_len = 25
                    filled = bar_len * completed // total
                    bar = '█' * filled + '░' * (bar_len - filled)
                    print(f"\r{Colors.CYAN}[{bar}] {percent}% | {completed}/{total} | "
                          f"Найдено: {self.found_count} | {elapsed:.1f}с{Colors.RESET}", end='')
        
        print()
        
        self.results = results
        elapsed = time.time() - start_time
        
        return results, elapsed
    
    def _print_result(self, result):
        """Выводит найденный поддомен"""
        with self.lock:
            # Выбираем лучший HTTP результат
            http_info = result.get('https') or result.get('http')
            
            status_str = ""
            if http_info:
                code = http_info['status_code']
                if code == 200:
                    status_str = f"{Colors.GREEN}[200 OK]{Colors.RESET}"
                elif code in [301, 302, 307, 308]:
                    status_str = f"{Colors.YELLOW}[{code} Redirect]{Colors.RESET}"
                elif code == 401:
                    status_str = f"{Colors.YELLOW}[401 Auth]{Colors.RESET}"
                elif code == 403:
                    status_str = f"{Colors.RED}[403 Forbidden]{Colors.RESET}"
                elif code == 404:
                    status_str = f"{Colors.RED}[404]{Colors.RESET}"
                elif code == 500:
                    status_str = f"{Colors.RED}[500 Error]{Colors.RESET}"
                else:
                    status_str = f"{Colors.YELLOW}[{code}]{Colors.RESET}"
            
            server_info = ""
            if http_info and http_info.get('server'):
                server_info = f" ─ {Colors.BLUE}{http_info['server']}{Colors.RESET}"
            
            title_info = ""
            if http_info and http_info.get('title'):
                title_info = f"\n    └─ {Colors.WHITE}{http_info['title'][:100]}{Colors.RESET}"
            
            redirect_info = ""
            if http_info and http_info.get('redirect_chain'):
                chain = ' → '.join([urlparse(u).netloc for u in http_info['redirect_chain'][-3:]])
                redirect_info = f"\n    └─ {Colors.YELLOW}→ {chain}{Colors.RESET}"
            
            source_info = ""
            if result.get('source') == 'passive':
                source_info = f" {Colors.MAGENTA}[passive]{Colors.RESET}"
            
            print(f"\n  {Colors.GREEN}●{Colors.RESET} {Colors.BOLD}{result['fqdn']}{Colors.RESET} "
                  f"({result['ip']}) {status_str}{server_info}{source_info}"
                  f"{title_info}{redirect_info}")


def save_results(results, domain, elapsed):
    """Сохраняет результаты в TXT и JSON"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"subdomains_{domain.replace('.', '_')}_{timestamp}"
    
    # TXT
    txt_file = f"{filename}.txt"
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write(f"ОТЧЕТ О ПОИСКЕ ПОДДОМЕНОВ\n")
        f.write(f"Домен        : {domain}\n")
        f.write(f"Дата/время   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Длительность : {elapsed:.1f}с\n")
        f.write(f"Найдено      : {len(results)}\n")
        f.write("=" * 70 + "\n\n")
        
        # Группировка по статус-коду
        groups = defaultdict(list)
        for r in results:
            http_info = r.get('https') or r.get('http')
            code = http_info['status_code'] if http_info else 'N/A'
            groups[str(code)].append(r)
        
        for code, items in sorted(groups.items()):
            f.write(f"\n{'─' * 60}\n")
            f.write(f"HTTP {code} — {len(items)} поддоменов\n")
            f.write(f"{'─' * 60}\n")
            
            for r in items:
                http_info = r.get('https') or r.get('http')
                f.write(f"\n  {r['fqdn']} ({r['ip']})\n")
                
                if http_info:
                    if http_info.get('server'):
                        f.write(f"  Сервер      : {http_info['server']}\n")
                    if http_info.get('title'):
                        f.write(f"  Заголовок   : {http_info['title']}\n")
                    if http_info.get('content_type'):
                        f.write(f"  Content-Type: {http_info['content_type']}\n")
                    if http_info.get('content_length'):
                        f.write(f"  Размер      : {http_info['content_length']} байт\n")
                    if http_info.get('redirect_chain'):
                        f.write(f"  Редирект    : {' -> '.join(http_info['redirect_chain'])}\n")
                    if http_info.get('final_url'):
                        f.write(f"  Финальный URL: {http_info['final_url']}\n")
    
    # JSON
    json_file = f"{filename}.json"
    json_data = []
    for r in results:
        entry = {
            'fqdn': r['fqdn'],
            'ip': r['ip'],
            'subdomain': r['subdomain'],
            'source': r.get('source', 'dns_bruteforce')
        }
        
        http_info = r.get('https') or r.get('http')
        if http_info:
            entry['http'] = {
                'status_code': http_info['status_code'],
                'server': http_info['server'],
                'title': http_info['title'],
                'content_type': http_info['content_type'],
                'content_length': http_info['content_length'],
                'final_url': http_info['final_url'],
                'redirect_chain': http_info['redirect_chain']
            }
        
        json_data.append(entry)
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    return txt_file, json_file


def show_menu():
    print(f"\n{Colors.BOLD}Выберите действие:{Colors.RESET}")
    print(f"  {Colors.GREEN}1{Colors.RESET}. Быстрый поиск (60 слов)")
    print(f"  {Colors.GREEN}2{Colors.RESET}. Полный поиск (400+ слов)")
    print(f"  {Colors.GREEN}3{Colors.RESET}. Только пассивный поиск (без перебора)")
    print(f"  {Colors.GREEN}4{Colors.RESET}. Только перебор (без пассивного)")
    print(f"  {Colors.GREEN}5{Colors.RESET}. Только DNS (без HTTP проверки)")
    print(f"  {Colors.GREEN}6{Colors.RESET}. Свой словарь + пассивный поиск")
    print(f"  {Colors.GREEN}0{Colors.RESET}. Выход")


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    while True:
        show_menu()
        choice = input(f"\n  {Colors.CYAN}Ваш выбор →{Colors.RESET} ").strip()
        
        if choice == '0':
            print(f"\n{Colors.YELLOW}[*] Выход...{Colors.RESET}")
            break
        
        domain = input(f"\n{Colors.BOLD}Введите домен:{Colors.RESET} ").strip().lower()
        if not domain:
            print(f"{Colors.RED}[!] Домен не введен{Colors.RESET}")
            continue
        
        wordlist = None
        threads = 50
        check_http = True
        use_passive = True
        
        if choice == '1':
            wordlist = DEFAULT_SUBDOMAINS[:60]
            threads = 80
        elif choice == '2':
            wordlist = DEFAULT_SUBDOMAINS
            threads = 50
        elif choice == '3':
            wordlist = []
            check_http = True
            use_passive = True
        elif choice == '4':
            wordlist = DEFAULT_SUBDOMAINS
            use_passive = False
        elif choice == '5':
            wordlist = DEFAULT_SUBDOMAINS
            check_http = False
            use_passive = False
            threads = 150
        elif choice == '6':
            filepath = input(f"  Путь к файлу со словарем: ").strip()
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    wordlist = [line.strip().lower() for line in f if line.strip()]
                print(f"  {Colors.GREEN}[+] Загружено слов: {len(wordlist)}{Colors.RESET}")
            else:
                print(f"  {Colors.RED}[!] Файл не найден{Colors.RESET}")
                continue
        else:
            print(f"{Colors.RED}[!] Неверный выбор{Colors.RESET}")
            continue
        
        print(f"\n{Colors.YELLOW}╔═══ Подтверждение ═══╗{Colors.RESET}")
        print(f"{Colors.YELLOW}║ Домен      : {domain}{Colors.RESET}")
        print(f"{Colors.YELLOW}║ Слов       : {len(wordlist) if wordlist else 0}{Colors.RESET}")
        print(f"{Colors.YELLOW}║ Пассивный  : {'Да' if use_passive else 'Нет'}{Colors.RESET}")
        print(f"{Colors.YELLOW}║ HTTP check : {'Да' if check_http else 'Нет'}{Colors.RESET}")
        print(f"{Colors.YELLOW}╚══════════════════════╝{Colors.RESET}")
        confirm = input(f"  Начать? (y/n): ").strip().lower()
        
        if confirm not in ['y', 'yes', 'д', 'да']:
            continue
        
        try:
            finder = SubdomainFinder(
                domain=domain,
                wordlist=wordlist,
                threads=threads,
                timeout=3.0,
                check_http=check_http,
                use_passive=use_passive
            )
            
            results, elapsed = finder.run()
            
            # Итоги
            print(f"\n{Colors.BOLD}{'═' * 50}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Поиск завершен!{Colors.RESET}")
            print(f"[+] Найдено поддоменов: {Colors.GREEN}{len(results)}{Colors.RESET}")
            print(f"[+] Время: {elapsed:.1f} секунд")
            
            if results:
                # Статистика
                with_200 = 0
                with_redirect = 0
                with_error = 0
                servers = set()
                
                for r in results:
                    http_info = r.get('https') or r.get('http')
                    if http_info:
                        code = http_info['status_code']
                        if code == 200:
                            with_200 += 1
                        elif code in [301, 302, 307, 308]:
                            with_redirect += 1
                        elif code and code >= 400:
                            with_error += 1
                        if http_info.get('server'):
                            servers.add(http_info['server'])
                
                print(f"\n{Colors.BOLD}Статистика:{Colors.RESET}")
                print(f"  Доступны (200 OK)    : {Colors.GREEN}{with_200}{Colors.RESET}")
                print(f"  Редиректы            : {Colors.YELLOW}{with_redirect}{Colors.RESET}")
                print(f"  Ошибки (4xx/5xx)     : {Colors.RED}{with_error}{Colors.RESET}")
                if servers:
                    print(f"  Серверы              : {Colors.BLUE}{', '.join(sorted(servers))}{Colors.RESET}")
                
                save = input(f"\n{Colors.CYAN}Сохранить результаты? (y/n): {Colors.RESET}").strip().lower()
                if save in ['y', 'yes', 'д', 'да']:
                    txt_file, json_file = save_results(results, domain, elapsed)
                    print(f"{Colors.GREEN}[+] Сохранено:{Colors.RESET}")
                    print(f"    TXT: {txt_file}")
                    print(f"    JSON: {json_file}")
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Прервано пользователем{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Ошибка: {e}{Colors.RESET}")
            import traceback
            traceback.print_exc()
        
        input(f"\n{Colors.CYAN}Нажмите Enter чтобы продолжить...{Colors.RESET}")
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()

if __name__ == '__main__':
    main()