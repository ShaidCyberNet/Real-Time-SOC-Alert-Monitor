import json
import time
import requests
import glob
import os
import re
from collections import defaultdict, Counter
from threading import Thread, Lock
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rich.live import Live
from rich.table import Table
from rich.console import Console, Group
from rich.panel import Panel
from rich.align import Align
from subprocess import run

ALERT_DIR = "alerts"
BAN_THRESHOLD = 20
VT_API_KEY = "YOUR_VT_API_KEY_HERE"  # Replace with your VirusTotal API key
WHITELIST = set(["127.0.0.1", "192.168.1.1"])

# Tracking structures
IP_HITS = Counter()
IP_SCORES = defaultdict(int)
COUNTRY_SCORES = Counter()
SEVERITY = {}
TRIAGE = {}
GEO = {}

# Thread lock for shared data
lock = Lock()

console = Console()
os.makedirs(ALERT_DIR, exist_ok=True)

BAD_COUNTRIES = ["russia", "iran", "china", "north korea"]
MAL_KEYWORDS = [
    "reverse shell", "curl http", "nc -e", "powershell", "bash -i", "cmd.exe"
]


def vt_score(ip):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        res = requests.get(url, headers=headers, timeout=8)
        if res.status_code == 200:
            data = res.json()
            return data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except Exception:
        return 0
    return 0


def get_country(ip):
    if ip in GEO:
        return GEO[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=5)
        country = r.json().get("country", "?")
        GEO[ip] = country.lower()
        return GEO[ip]
    except Exception:
        return "?"


def parse_alert(data):
    ip = data.get("ip", "?")
    desc = data.get("desc", "?").lower()
    country = get_country(ip)

    vt = vt_score(ip)
    severity = (
        "malicious"
        if vt > 3 or any(k in desc for k in MAL_KEYWORDS)
        else "suspicious"
        if vt
        else "info"
    )

    score = vt * 3
    if country in BAD_COUNTRIES:
        score += 5

    with lock:
        IP_HITS[ip] += 1
        IP_SCORES[ip] += score
        COUNTRY_SCORES[country] += score
        SEVERITY[ip] = severity
        TRIAGE[ip] = "investigate" if score >= BAN_THRESHOLD or severity == "malicious" else "review"

    return ip, score, country, severity


class AlertHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith(".json"):
            return
        try:
            with open(event.src_path) as f:
                content = f.read().strip()
                if not content:
                    return
                data = json.loads(content)  # <-- fixed here
            ip, score, country, severity = parse_alert(data)
            run(
                [
                    "notify-send",
                    f"ALERT: {ip}",
                    f"{severity.upper()} | {TRIAGE[ip]} | {country} | score={score}",
                ]
            )
        except Exception as e:
            console.log(f"[red]Error processing alert:[/red] {e}")


def build_table():
    with lock:
        top_ips = IP_HITS.most_common(10)
        table = Table(title="[bold red]Real-Time SOC Feed", expand=True)
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Hits", justify="right")
        table.add_column("Score", justify="right")
        table.add_column("Severity", style="red")
        table.add_column("Triage", style="yellow")
        table.add_column("Country", style="green")

        for ip, hits in top_ips:
            table.add_row(
                ip,
                str(hits),
                f"{IP_SCORES[ip]:.1f}",
                SEVERITY.get(ip, "-").upper(),
                TRIAGE.get(ip, "-").upper(),
                GEO.get(ip, "-").upper(),
            )
    return table


def build_country_panel():
    with lock:
        top_countries = COUNTRY_SCORES.most_common(5)
        text = "\n".join([f"{c.upper()}: {s:.1f}" for c, s in top_countries])
    return Panel(text, title="Top Countries", style="magenta")


def main():
    observer = Observer()
    observer.schedule(AlertHandler(), ALERT_DIR, recursive=False)
    observer.start()

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while True:
                time.sleep(1)
                table = build_table()
                panel = build_country_panel()
                group = Group(table, panel)
                live.update(Align.center(group))
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
