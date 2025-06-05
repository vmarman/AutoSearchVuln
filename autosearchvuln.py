#!/usr/bin/env python3

import os, re, json, subprocess, tempfile, shutil
from pathlib import Path
import requests, openai
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

OPENAI_MODEL = "gpt-4o"
console = Console(record=True)
SSL_PORTS = {"443", "8443", "465", "993", "995", "587", "636", "990", "992", "994"}

CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
RCE_RX = re.compile(r"(remote code execution|execuci[oó]n remota|buffer overflow|arbitrary code|shellcode|RCE|ejecuci[oó]n de c[oó]digo|command execution|shell access|obtain shell|gain shell)", re.I)
DOS_RX = re.compile(r"\b(do[sn]|denegaci[oó]n de servicio|crash|hang|DoS)\b", re.I)

def extrae_puerto(banner):
    m = re.search(r"(\d+)/tcp", banner)
    return m.group(1) if m else ""

def keyword(banner: str) -> str:
    for k in ("samba", "apache", "openssh", "rpcbind", "mod_ssl", "mysql",
              "postgres", "ftp", "proftpd", "ssh", "http", "webmin"):
        if k in banner.lower():
            return k
    # Si no se encuentra, intenta extraer el nombre antes de ':'
    if ':' in banner:
        return banner.split(':')[0].lower()
    return banner.split()[0].lower()

def token(ver: str) -> str:
    m = re.search(r"\d+\.\d+(?:\.\d+)?", ver)
    return m.group(0) if m else ver.split()[0]

def dedup(lines):
    seen, out = set(), []
    for l in lines:
        m = CVE_RX.search(l)
        if m:
            cv = m.group(0).upper()
            if cv in seen:
                continue
            seen.add(cv)
        out.append(l)
    return out

def nmap_os_detection(target):
    try:
        out = subprocess.check_output(["nmap", "-O", target], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if line.strip().startswith("OS details:"):
                return line.strip().replace("OS details:", "").strip()
            if "Running:" in line:
                return line.strip().replace("Running:", "").strip()
    except Exception:
        pass
    return "Desconocido"

def nmap_scan(tgt):
    console.print(f"[bold cyan]▶ nmap {tgt} – descubriendo servicios…[/]")
    out = subprocess.check_output(["nmap", "-sV", "-p-", "--open", "--min-rate", "500", tgt], text=True)
    return [l.strip() for l in out.splitlines() if "/tcp" in l and "open" in l]

def is_http_service(banner, port):
    http_keywords = ["http", "apache", "nginx", "webmin", "tomcat", "glassfish", "jetty", "iis"]
    banner_l = banner.lower()
    if any(kw in banner_l for kw in http_keywords):
        return True
    return port in {"80", "8080", "8000", "8008", "8180", "8888", "443"}

def show_services(banners):
    console.rule("[bold blue]Servicios detectados")
    for b in banners:
        port = extrae_puerto(b)
        kw = keyword(b)
        console.print(f"[cyan]{kw}:{port}[/] → [white]{b}[/]")

def run_dirb(target, port, wordlist="/usr/share/wordlists/dirb/common.txt"):
    if not shutil.which("dirb"):
        console.print("[yellow]⚠ dirb no encontrado en PATH.[/]")
        return []
    url = f"http://{target}:{port}/"
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
    tf.close()
    cmd = ["dirb", url, wordlist, "-o", tf.name]
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        urls = set()
        for line in open(tf.name):
            line = line.strip()
            if line.startswith('+ '):
                url_found = line.split()[1]
                urls.add(url_found)
            elif line.startswith('==> DIRECTORY:'):
                url_found = line.split('==> DIRECTORY:')[1].strip()
                if not url_found.endswith('/'):
                    url_found += '/'
                urls.add(url_found)
        os.unlink(tf.name)
        return sorted(urls)
    except Exception as e:
        console.print(f"[yellow]⚠ dirb: error inesperado en {url}: {e}[/]")
        os.unlink(tf.name)
        return []

def html_filename(args, target):
    for opt in ("full", "dirb", "nuclei", "ssh", "ssl"):
        if getattr(args, opt, False):
            return f"reporte_{opt}_{target}.html"
    return f"reporte_{target}.html"

def filtra_banners(banners, args):
    if args.full:
        return banners
    elif args.nuclei:
        return [b for b in banners if is_http_service(b, extrae_puerto(b))]
    elif args.ssl:
        return [b for b in banners if (
            extrae_puerto(b) in SSL_PORTS or "ssl" in b.lower() or "https" in b.lower()
        )]
    elif args.ssh:
        return [b for b in banners if keyword(b) in ["ssh", "openssh"]]
    elif args.dirb:
        return [b for b in banners if is_http_service(b, extrae_puerto(b))]
    else:
        return banners

def msf_version(kw, tgt, port):
    MSF_SCAN = {
        "samba": "auxiliary/scanner/smb/smb_version",
        "ssh": "auxiliary/scanner/ssh/ssh_version",
        "http": "auxiliary/scanner/http/http_version",
        "rpcbind": "auxiliary/scanner/rpc/rpcinfo",
    }
    RX_VERSION = {
        "samba": re.compile(r"Samba\s+([\d\.]+[a-z]?)", re.I),
        "ssh": re.compile(r"OpenSSH[/\s-]+([\d\.p]+)", re.I),
        "http": re.compile(r"Apache[/\s]+([\d\.]+)", re.I),
    }
    mod = MSF_SCAN.get(kw)
    rx = RX_VERSION.get(kw)
    if not mod or not rx:
        return None
    out = subprocess.getoutput(f"msfconsole -q -x 'use {mod}; set RHOSTS {tgt}; set RPORT {port}; run; exit'")
    m = rx.search(out)
    return m.group(1) if m else None

def searchsploit(kw, ver):
    tok = token(ver)
    try:
        js = json.loads(subprocess.check_output(["searchsploit", "--json", f"{kw} {tok}"], text=True))
    except Exception:
        return {"rce": [], "critica": []}
    rce, crit = [], []
    for it in js.get("RESULTS_EXPLOIT", []):
        title = it["Title"]
        path = it["Path"].lower()
        url = f"https://www.exploit-db.com/exploits/{it['EDB-ID']}"
        poc = f"/usr/share/exploitdb/{it['Path']}"
        line = f"{title}: {url} (PoC: {poc})"
        (rce if "/remote/" in path or RCE_RX.search(title.lower()) else crit).append(line)
    return {"rce": rce, "critica": crit}

def scrape_edb(kw, ver):
    tok = token(ver)
    try:
        html = requests.get(f"https://www.exploit-db.com/search?description={kw}+{tok}",
                            timeout=10, headers={"User-Agent": "Mozilla/5.0"}).text
        soup = BeautifulSoup(html, "html.parser")
        res = []
        for tr in soup.find_all("tr"):
            tds = tr.find_all("td")
            if len(tds) < 5:
                continue
            title = tds[4].text.strip()
            if kw in title.lower() and tok in title:
                link = "https://www.exploit-db.com" + tds[4].find("a")["href"]
                res.append(f"{title}: {link}")
        return res
    except Exception:
        return []

def ask_llm(banner):
    try:
        rsp = openai.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=0,
            messages=[
                {"role": "system", "content": "Eres un analista de ciberseguridad."},
                {"role": "user", "content": f"""Devuelve MARKDOWN con:
1. RCE – CVE
2. Otras críticas (DoS/infoleak) – CVE
3. Advertencias – CVE
Servicio: {banner}"""}
            ]
        )
        return [l for l in rsp.choices[0].message.content.splitlines() 
                if l.lstrip().startswith("-") and CVE_RX.search(l)]
    except Exception:
        return []

def is_valid_for_os(detail, so_info):
    detail_l = detail.lower()
    so = so_info.lower()
    if "windows" in detail_l and "linux" in so:
        return False
    if "linux" in detail_l and "windows" in so:
        return False
    return True

def enrich_with_searchsploit(lines, ss_rce, ss_crit, so_info):
    enriched = []
    all_ss = ss_rce + ss_crit
    for l in lines:
        m = CVE_RX.search(l)
        if m:
            cve = m.group(0).upper()
            url, poc = None, None
            for s in all_ss:
                if cve in s and is_valid_for_os(s, so_info):
                    url_match = re.search(r'(https?://[^\s]+)', s)
                    poc_match = re.search(r'\(PoC: ([^)]+)\)', s)
                    if url_match:
                        url = url_match.group(1)
                    if poc_match:
                        poc = poc_match.group(1)
                    break
            extra = ""
            if url and url not in l:
                extra += f" [ExploitDB: {url}]"
            if poc and poc not in l:
                extra += f" [PoC: {poc}]"
            enriched.append(l.strip() + extra)
        else:
            enriched.append(l)
    return enriched

def run_sslyze_or_testssl(target, port):
    if shutil.which("sslyze"):
        try:
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
            tf.close()
            subprocess.check_call(["sslyze", f"{target}:{port}", f"--json_out={tf.name}"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(tf.name) as f:
                data = json.load(f)
            os.unlink(tf.name)
            return [f"[SSL] {x}" for x in data.get("accepted_cipher_suites", [])]
        except Exception as e:
            return [f"[SSL] Error: {e}"]
    return ["[SSL] Herramienta no encontrada"]

def analizar(banner, tgt, prog, tk, args, so_info):
    port = extrae_puerto(banner)
    kw = keyword(banner)
    ver = msf_version(kw, tgt, port) or token(banner)
    rce, crit, adv = [], [], []
    if args.ssl and port not in SSL_PORTS and "ssl" not in banner.lower():
        return {"port": port, "banner": banner, "rce": [], "crit": [], "adv": []}
    ss = searchsploit(kw, ver)
    web = scrape_edb(kw, ver)
    llm = ask_llm(banner)
    for l in llm + web:
        if not is_valid_for_os(l, so_info):
            continue
        if RCE_RX.search(l):
            rce.append(l)
        elif DOS_RX.search(l):
            crit.append(l)
        else:
            adv.append(l)
    rce = enrich_with_searchsploit(rce, ss["rce"], ss["critica"], so_info)
    crit = enrich_with_searchsploit(crit, ss["rce"], ss["critica"], so_info)
    adv = enrich_with_searchsploit(adv, ss["rce"], ss["critica"], so_info)
    for s in ss["rce"]:
        if is_valid_for_os(s, so_info) and s not in rce:
            rce.append(s)
    for s in ss["critica"]:
        if is_valid_for_os(s, so_info) and s not in crit:
            crit.append(s)
    for s in web:
        if is_valid_for_os(s, so_info) and s not in rce:
            rce.append(s)
    if args.ssl or args.full:
        adv += run_sslyze_or_testssl(tgt, port)
    return {
        "port": port,
        "banner": f"{kw} {ver}" if ver else kw,
        "rce": dedup(rce),
        "crit": dedup(crit),
        "adv": dedup(adv)
    }

def show(s):
    t=Table(title=f"[bold]{s['banner']}[/] (puerto {s['port']})", show_lines=True)
    t.add_column("Gravedad",style="bold",no_wrap=True)
    t.add_column("Detalle")
    for l in s["rce"]: t.add_row("[red]RCE[/]",l)
    for l in s["crit"]: t.add_row("[yellow]Crítica[/]",l)
    for l in s["adv"]: t.add_row("[cyan]Advertencia[/]",l)
    if not (s["rce"] or s["crit"] or s["adv"]):
        t.add_row("[green]OK[/]","Sin vulnerabilidades con CVE conocidas")
    console.print(t); console.rule()

def main():
    import argparse
    parser = argparse.ArgumentParser(description="AutoSearchVuln - Busqueda de Vulnerabilidades")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--ssh", action="store_true")
    parser.add_argument("--nuclei", action="store_true")
    parser.add_argument("--dirb", action="store_true")
    parser.add_argument("--ssl", action="store_true")
    parser.add_argument("--html", action="store_true")
    args = parser.parse_args()

    so_info = nmap_os_detection(args.target)
    banners = nmap_scan(args.target)
    banners_filtrados = filtra_banners(banners, args)

    console.rule(f"[bold blue]Sistema operativo detectado: {so_info}")
    show_services(banners_filtrados)

    inventory = []
    inventory.append(f"nmap -sV -p- --open --min-rate 500 {args.target}")
    for b in banners_filtrados:
        port = extrae_puerto(b)
        kw = keyword(b)
        if args.dirb or args.full:
            if is_http_service(b, port):
                inventory.append(f"dirb http://{args.target}:{port}/ /usr/share/wordlists/dirb/common.txt -o ...")
        if args.nuclei or args.full:
            if is_http_service(b, port):
                inventory.append(f"nuclei -u http://{args.target}:{port}")
        if args.ssh or args.full:
            if kw in ["ssh", "openssh"]:
                inventory.append(f"ssh-audit {args.target}:{port}")
        if args.ssl or args.full:
            if port in SSL_PORTS or "ssl" in b.lower() or "https" in b.lower():
                inventory.append(f"sslyze {args.target}:{port} --json_out=...")

    console.rule("[bold blue]Inventario de comandos a ejecutar")
    for cmd in inventory:
        console.print(f"[white]{cmd}[/]")

    # DIRB: solo mostrar y exportar URLs encontradas
    if args.dirb:
        dirb_urls = []
        for b in banners_filtrados:
            port = extrae_puerto(b)
            urls = run_dirb(args.target, port)
            for url in urls:
                dirb_urls.append(f"{args.target}:{port} {url}")
        if dirb_urls:
            console.rule("[bold green]Resumen DIRB")
            t = Table(title="URLs detectadas por dirb", show_lines=True)
            t.add_column("IP:Puerto")
            t.add_column("URL")
            for line in sorted(dirb_urls):
                ipport, url = line.split(" ", 1)
                t.add_row(ipport, url)
            console.print(t)
            if args.html:
                name = html_filename(args, args.target)
                Path(name).write_text(console.export_html(inline_styles=True), encoding="utf8")
                console.print(f"[bold magenta]🡒 Informe guardado: {name} (modo: dirb)[/]")
        else:
            console.print("[yellow]No se encontraron URLs con dirb.[/]")
        return

    # Resto de modos igual que antes
    resultados = []
    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TextColumn("{task.description}"),
        TextColumn("[cyan]{task.fields[servicio]}")
    ) as prog:
        tk = prog.add_task("Analizando servicios...", total=len(banners_filtrados), servicio="")
        for banner in banners_filtrados:
            kw = keyword(banner)
            port = extrae_puerto(banner)
            prog.update(tk, servicio=f"{kw}:{port}")
            resultados.append(analizar(banner, args.target, prog, tk, args, so_info))
            prog.advance(tk)

    console.rule("[bold green]Resumen por servicio")
    for res in resultados:
        show(res)

    if args.html and resultados:
        name = html_filename(args, args.target)
        modo = name.replace(f"reporte_", "").replace(f"_{args.target}.html", "")
        Path(name).write_text(console.export_html(inline_styles=True), encoding="utf8")
        console.print(f"[bold magenta]🡒 Informe guardado: {name} (modo: {modo})[/]")

if __name__ == "__main__":
    openai.api_key = os.getenv("OPENAI_API_KEY")
    main()

