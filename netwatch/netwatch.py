#!/usr/bin/env python3

import json
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime

import psutil
from psutil._ntuples import sconn
from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

BANNER = r"""
 ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
 ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
 ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
 ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
"""

STATUS_STYLE = {
    "ESTABLISHED": "bold green",
    "LISTEN": "bold cyan",
    "TIME_WAIT": "yellow",
    "CLOSE_WAIT": "bold yellow",
    "SYN_SENT": "bold magenta",
    "SYN_RECV": "magenta",
    "FIN_WAIT1": "dim yellow",
    "FIN_WAIT2": "dim yellow",
    "LAST_ACK": "dim red",
    "CLOSING": "dim red",
    "CLOSE": "dim white",
    "NONE": "dim white",
}

RISK_PORTS = {
    21: ("FTP", "red"),
    22: ("SSH", "yellow"),
    23: ("Telnet", "bold red"),
    25: ("SMTP", "yellow"),
    53: ("DNS", "cyan"),
    80: ("HTTP", "white"),
    443: ("HTTPS", "green"),
    3306: ("MySQL", "bold yellow"),
    3389: ("RDP", "bold red"),
    5432: ("PostgreSQL", "bold yellow"),
    8080: ("HTTP-Alt", "white"),
    8443: ("HTTPS-Alt", "green"),
    27017: ("MongoDB", "bold yellow"),
    6379: ("Redis", "bold yellow"),
}

_PRIVATE_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.2",
    "172.3",
    "192.168.",
    "127.",
    "::1",
    "fe80",
)



def port_displ(port: int | None) -> tuple[tuple[str,str], str]:
    if not port:
        return ("—", None), 'dim white'
    name, style = None, "white"
    if port in RISK_PORTS:
        name, style = RISK_PORTS[port]
    return (str(port), name), style


def _is_external(ip: str) -> bool:
    if not ip or ip in ("0.0.0.0", "::"):
        return False
    return not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


# Base risk score per port (higher = more dangerous)
_PORT_SCORE: dict[int, int] = {
    23: 4,
    21: 4,  # Telnet, FTP — plaintext & legacy
    3389: 3,  # RDP — remote desktop, high-value target
    22: 2,
    25: 2,  # SSH, SMTP
    3306: 2,
    5432: 2,  # MySQL, PostgreSQL
    27017: 2,
    6379: 2,  # MongoDB, Redis
    80: 1,
    8080: 1,  # HTTP — unencrypted
    443: 0,
    8443: 0,  # HTTPS — encrypted
    53: 0,  # DNS — normal
}

_SUSPICIOUS_PATHS = (
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/var/folders/",
    "Downloads/",
    "Desktop/",
)

_NEW_TTL = 4.0  # seconds a connection stays flagged as NEW
_OLD_TTL = 4.0  # seconds a connection stays flagged as OLD


processes = {} #some connections could have same pid
_geo_cache: dict[str, str] = {}
_geo_lock = threading.Lock()
seen_conns: dict[tuple, Conn] = {}

class Conn():
    time_seen: float
    time_end: float | None = None
    name: str
    path: str
    is_suspicious: bool
    risk_label: str
    risk_style: str
    key: tuple
    hostname: str | None = None
    new: bool
    old: bool

    def __new__(cls, conn:sconn, ts:float):
        key = cls._conn_key(conn)
        if key in seen_conns:
            i = seen_conns[key]
            if i.time_end != None: i.abort_closing(ts)
            if ts - i.time_seen > _NEW_TTL: i.new = False
            return i
        
        i = seen_conns[key] = super().__new__(cls)
        i.new = True
        i.old = False
        i.time_seen = ts
        return i

    def __init__(self, conn:sconn, ts:float):
        for k, v in conn._asdict().items():
            setattr(self, k, v)
        self.key = self._conn_key()


        if (t := processes.get(self.pid)) == None:
            t = processes[self.pid] = self.get_proc_info()
        self.name, self.path, self.is_suspicious = t
        self.risk_label, self.risk_style = self.calc_risk()


    def _conn_key(conn) -> tuple:
        la = (conn.laddr.ip, conn.laddr.port) if conn.laddr else None
        ra = (conn.raddr.ip, conn.raddr.port) if conn.raddr else None
        return (la, ra, conn.pid)


    def get_proc_info(self) -> tuple[str, str, bool]:  ## ── Process path validation
        """Returns (display_name, exe_path, is_suspicious)."""
        pid = self.pid
        if pid is None:
            return "—", "", False
        try:
            p = psutil.Process(pid)
            exe = p.exe()
            suspicious = any(s in exe for s in _SUSPICIOUS_PATHS)
            return p.name(), exe, suspicious
        except psutil.NoSuchProcess:
            return "—", "", False
        except psutil.AccessDenied:
            return "?", "", False
    

    def calc_risk(conn) -> tuple[str, str]:
        """Return (label, rich_style) — HIGH / MED / LOW."""
        rip = conn.raddr.ip if conn.raddr else ""
        rport = conn.raddr.port if conn.raddr else 0
        laddr = conn.laddr
        status = getattr(conn, "status", "NONE") or "NONE"

        effective_port = rport or (laddr.port if laddr else 0)
        score = _PORT_SCORE.get(effective_port, 1)

        if _is_external(rip) and status == "ESTABLISHED":
            score += 1
        if status == "LISTEN" and laddr and laddr.ip in ("0.0.0.0", "::"):
            score += 1
        if status == "SYN_SENT" and _is_external(rip):
            score += 1
        if conn.is_suspicious:
            score += 2  # process running from temp/downloads dir is inherently suspicious

        if score >= 4:
            return "● HIGH", "bold red"
        if score >= 2:
            return "◆ MED", "bold yellow"
        return "○ LOW", "dim green"
    

    def get_geo(self) -> str:  ## ── GeoIP
        if not self.raddr: return r"[dim]—[/dim]"
        ip = self.raddr.ip
        def _fetch_geo(ip: str) -> None:
            try:
                url = f"http://ip-api.com/json/{ip}?fields=country,countryCode"
                with urllib.request.urlopen(url, timeout=10) as r:
                    d = json.loads(r.read())
                    result = f"{d.get('countryCode','?')}  {d.get('country','?')}"
            except Exception: # todo
                result = "?"
            with _geo_lock:
                _geo_cache[ip] = result

        if not ip or not _is_external(ip):
            return r"[dim]local[/dim]"
        
        with _geo_lock:
            cached = _geo_cache.get(ip)
            if cached: return cached
            _geo_cache[ip] = "…"
        threading.Thread(target=_fetch_geo, args=(ip,), daemon=True).start()
        return "…"
    

    def close(self, time):
        if not self.time_end:
            self.time_end = time
            self.old = True
        else:
            if time - self.time_end > _OLD_TTL:
                del seen_conns[self.key] #suicide
    
    def abort_closing(self, time):
        self.time_end = None
        self.time_seen = time
        self.old = False
    

    def resolve_host(self, timeout: float = 0.4) -> str:
        if self.hostname: return self.hostname
        if not self.raddr.ip or self.raddr.ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
            return self.raddr.p
        try:
            socket.setdefaulttimeout(timeout)
            name = socket.gethostbyaddr(self.raddr.ip)[0]
            self.hostname = name
            return name
        except Exception:
            return self.raddr.ip



#region ── Connections update ────────────────────────────────────────────────────

_seen_lock = threading.Lock()

def update(connections: list[sconn]) -> tuple[set, set]:
    """updates seen_conns list with current connections"""
    now = time.time()
    
    active_conns = []

    with _seen_lock:
        for c in connections:
            active_conns.append(Conn(c, now).key)
        for k in list(seen_conns):
            if k not in active_conns:
                seen_conns[k].close(now)

def get_connections() -> tuple[list[sconn], bool]:
    """Returns connections, falling back to per-process scan on permission error."""
    try:
        return psutil.net_connections(kind="inet"), True
    except psutil.AccessDenied:
        conns = []
        for proc in psutil.process_iter(["pid"]):
            try:
                for c in proc.net_connections(kind="inet"):
                    conns.append(
                        sconn(
                            c.fd, c.family, c.type, c.laddr, c.raddr, c.status, proc.pid
                        )
                    )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        return conns, False

#endregion

#region ── Console Interface ────────────────────────────────────────────────────

def build_header() -> Panel:
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    hostname = socket.gethostname()
    local_ip = get_primary_ip()
    pub_ip = get_public_ip()
    ssid = get_wifi_ssid()
    gateway = get_default_gateway()
    dns = get_dns_servers()
    nio = psutil.net_io_counters()

    vpn_label, vpn_style = get_vpn_status()

    def field(label: str, value: str, val_style: str = "white") -> str:
        return f"[bold bright_green]{label}[/]  [{val_style}]{value}[/]"

    # VPN banner — full width, colour-coded
    vpn_row = Align.center(
        f"[bold bright_green]VPN[/]  [{vpn_style}]{vpn_label}[/]"
        + (
            "   [dim](⚠ on public wifi without VPN your traffic is exposed)[/]"
            if "NONE" in vpn_label
            else ""
        )
    )

    row1 = "   ".join(
        [
            field("HOST", hostname),
            field("LOCAL IP", local_ip),
            field("PUBLIC IP", pub_ip),
        ]
    )
    row2 = "   ".join(
        [
            field("WIFI", ssid),
            field("GATEWAY", gateway),
            field("DNS", dns),
        ]
    )
    row3 = "   ".join(
        [
            field("TIME", now),
            field("↑ SENT", fmt_bytes(nio.bytes_sent)),
            field("↓ RECV", fmt_bytes(nio.bytes_recv)),
        ]
    )

    border = "bold red" if "NONE" in vpn_label else "bright_cyan"
    body = "\n".join([str(vpn_row), row1, row2, row3])
    return Panel(
        Align.center(body),
        border_style=border,
        style="on black",
        title="[bold bright_cyan]SYSTEM[/]",
    )

def build_table(resolve: bool, fpid: int) -> Table:
    #connections.sort()

    table = Table(
        box=box.HEAVY_HEAD,
        border_style="bright_black",
        header_style="bold bright_cyan",
        show_lines=True,
        title=f"[bold bright_cyan]ACTIVE CONNECTIONS[/]  [dim]{datetime.now().strftime('%H:%M:%S')}[/]",
        title_style="bold",
        caption=f"[dim]{len(seen_conns)} connection(s) found[/]",
    )
    table.add_column("№", style="dim", width=4, justify="right")
    table.add_column("FLAGS", width=5, justify="center")
    table.add_column("RISK", width=8)
    table.add_column("PROTO", style="bright_white", width=6)
    table.add_column("STATUS", width=12)
    table.add_column("LOCAL", style="bright_white", min_width=20)
    table.add_column("REMOTE", min_width=24)
    table.add_column("COUNTRY", min_width=16)
    table.add_column("PORT", width=18)
    table.add_column("PROCESS", min_width=16)
    table.add_column("PID", style="dim", width=7, justify="right")

    i = 0
    for conn in seen_conns.values():
        if fpid and conn.pid != fpid: continue
        i += 1

        laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
        rip = conn.raddr.ip if conn.raddr else ""
        rport = conn.raddr.port if conn.raddr else None

        if resolve and rip:
            rhost = conn.resolve_host(rip)
            remote_display = f"{rhost}\n[dim]{rip}[/dim]" if rhost != rip else rip
        else:
            remote_display = rip or "[dim]—[/dim]"

        status = getattr(conn, "status", "NONE") or "NONE"
        status_txt = Text(status, style=STATUS_STYLE.get(status, "white"))
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

        # port
        port_txt = Text()
        port, port_style = port_displ(rport)
        port_txt.append(port[0], port_style)
        if port[1]: port_txt.append('\n'+port[1], 'dim '+port_style)
        

        # Process info with path validation
        proc_display = Text()
        if conn.is_suspicious:
            proc_display.append("⚠ ", style="bold red")
        proc_display.append(
            conn.name, style="bold red" if conn.is_suspicious else "bright_magenta"
        )

        # GeoIP
        country_txt = Text.from_markup(conn.get_geo())

        # Risk (elevated if suspicious path)
        risk_txt = Text(conn.risk_label, style=conn.risk_style)

        # New-connection flag
        flags = Text()
        if conn.new:
            flags.append("★", style="bold yellow")
        if conn.is_suspicious:
            flags.append("⚠", style="bold red")
        if conn.old:
            flags.append("⏳", style="bold red")

        row_style = "on grey7" if conn.new else ""
        table.add_row(
            str(i),
            flags,
            risk_txt,
            proto,
            status_txt,
            laddr_str,
            remote_display,
            country_txt,
            port_txt,
            proc_display,
            str(conn.pid),
            style=row_style,
        )

    return table

def build_stats() -> Panel:
    connections = seen_conns.values()
    status_counts: dict[str, int] = {}
    proc_counts: dict[str, int] = {}
    risk_counts = {"HIGH": 0, "MED": 0, "LOW": 0}

    for c in connections:
        s = getattr(c, "status", "NONE") or "NONE"
        status_counts[s] = status_counts.get(s, 0) + 1
        proc_counts[c.name] = proc_counts.get(c.name, 0) + 1
        key = c.risk_label.split()[-1]
        risk_counts[key] = risk_counts.get(key, 0) + 1

    status_lines = [
        f"  [{STATUS_STYLE.get(s, 'white')}]{s:<14}[/] [bold]{n:>3}[/]"
        for s, n in sorted(status_counts.items(), key=lambda x: -x[1])
    ]
    proc_lines = [
        f"  [bright_magenta]{name:<18}[/] [bold]{cnt:>3}[/]"
        for name, cnt in sorted(proc_counts.items(), key=lambda x: -x[1])[:6]
    ]
    risk_lines = [
        f"  [bold red]● HIGH          [/] [bold]{risk_counts['HIGH']:>3}[/]",
        f"  [bold yellow]◆ MED           [/] [bold]{risk_counts['MED']:>3}[/]",
        f"  [dim green]○ LOW           [/] [bold]{risk_counts['LOW']:>3}[/]",
    ]

    body = "\n".join(
        [
            "[bold bright_cyan]RISK SUMMARY[/]",
            *risk_lines,
            "",
            "[bold bright_cyan]BY STATUS[/]",
            *status_lines,
            "",
            "[bold bright_cyan]TOP PROCESSES[/]",
            *proc_lines,
        ]
    )
    return Panel(
        body,
        title="[bold bright_cyan]STATISTICS[/]",
        border_style="bright_black",
        padding=(0, 1),
    )

#endregion

# region ── System info helpers ────────────────────────────────────────────────────

def get_vpn_status() -> tuple[str, str]:
    ifaces = list(psutil.net_if_addrs().keys())
    active = [
        i for i in ifaces if i.startswith(("utun", "tun", "ppp", "tap", "ipsec", "wg"))
    ]
    if active:
        return f"● ACTIVE  ({active[0]})", "bold green"
    return "✗ NONE", "bold red"


_pub_ip_cache: dict = {"value": "fetching...", "ts": 0.0}
_pub_ip_lock = threading.Lock()


def _fetch_public_ip() -> None:
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=4) as r:
            ip = r.read().decode().strip()
    except Exception:
        ip = "unavailable"
    with _pub_ip_lock:
        _pub_ip_cache.update({"value": ip, "ts": time.time()})


def get_public_ip() -> str:
    now = time.time()
    with _pub_ip_lock:
        stale = now - _pub_ip_cache["ts"] > 60
    if stale:
        with _pub_ip_lock:
            _pub_ip_cache["ts"] = now  # prevent duplicate fetches
        threading.Thread(target=_fetch_public_ip, daemon=True).start()
    return _pub_ip_cache["value"]


def get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "unknown"
    finally:
        s.close()

ENC = 'oem'

def get_wifi_ssid() -> str:
    try:
        airport = (
            "/System/Library/PrivateFrameworks/Apple80211.framework"
            "/Versions/Current/Resources/airport"
        )
        out = subprocess.run(
            [airport, "-I"], capture_output=True, text=True, timeout=2, encoding=ENC
        ).stdout
        for line in out.splitlines():
            if " SSID:" in line:
                return line.split("SSID:")[1].strip()
    except FileNotFoundError:
        out = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=2, encoding=ENC
        ).stdout
        ssid = re.fullmatch(r"[\S\s]*[^B]SSID:(.+)[^.][\S\s]*", out)
        if ssid: return ssid.group(1)
    except Exception:
        pass
    return "—"


def get_default_gateway() -> str:
    try:
        out = subprocess.run(
            ["route", "get", "default"], capture_output=True, text=True, timeout=2, encoding=ENC
        ).stdout
        for line in out.splitlines():
            if "gateway:" in line:
                return line.split("gateway:")[1].strip()
    except Exception:
        pass
    return "—"


def get_dns_servers() -> str:
    try:
        servers: list[str] = []
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    servers.append(line.split()[1])
        return "  ".join(servers[:3]) if servers else "—"
    except Exception:
        return "—"


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"

# endregion


def run(fpid: int, resolve: bool = False) -> None:
    conns, is_root =  get_connections()

    console.print(
        Panel(
            Align.center(Text(BANNER, style="bold bright_cyan")),
            border_style="bright_cyan",
            subtitle="[dim]Network Connection Monitor  |  Ctrl+C to stop[/]",
            padding=(0, 0),
        )
    )

    if not is_root:
        console.print(
            Panel(
                "[yellow]Running without root — some processes may be hidden.[/]",
                border_style="yellow",
                padding=(0, 1),
            )
        )

    try:
        with Live(console=console, refresh_per_second=5, screen=False) as live:
            while True:
                conns, _ = get_connections()
                update(conns)
                live.update(
                    Group(
                        build_header(),
                        build_table(resolve=resolve, fpid=fpid),
                        build_stats(),
                    )
                )
                time.sleep(0.15)
    except KeyboardInterrupt:
        console.print("\n[bold bright_cyan]Scan terminated.[/]")


def main() -> None:
    threading.Thread(target=_fetch_public_ip, daemon=True).start()
    pid = None
    if '--process' in sys.argv:
        try:
            pid = sys.argv[sys.argv.index('--process')+1]
            pid = int(pid)
        except IndexError:
            console.print("\n[bold bright_cyan]Missing arg[/]")
            return
        except ValueError:
            console.print("\n[bold bright_cyan]Wrong pid[/]")
            return
    run(resolve="--resolve" in sys.argv, fpid=pid)


if __name__ == "__main__":
    main()
