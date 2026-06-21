#!/usr/bin/env python3

import re
import socket
import sys
import time
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
from rich.layout import Layout
from connections import seen_conns, update
from constants import *
from sysinfo import *

console = Console()


def port_displ(port: int | None) -> tuple[tuple[str,str], str]:
    if not port:
        return ("—", None), 'dim white'
    name, style = None, "white"
    if port in RISK_PORTS:
        name, style = RISK_PORTS[port]
    return (str(port), name), style



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
            field("↑ SENT", _fmt_bytes(nio.bytes_sent)),
            field("↓ RECV", _fmt_bytes(nio.bytes_recv)),
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


F = 1

def build_table(resolve: bool, fpid: int, maxrow=None) -> Table:
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
        if maxrow and i >= maxrow:break
        laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
        rip = conn.raddr.ip if conn.raddr else ""
        rport = conn.raddr.port if conn.raddr else None

        if resolve:
            rhost = conn.hostname()
            if not rhost: remote_display = "[dim]—[/dim]"
            else: remote_display = f"{rhost}"+(f"\n[dim]{rip}[/dim]" if resolve == 2 else "")  if rhost != '—' else rip
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

        row_style = "on grey7" if i == F else ""
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


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"


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
        with Live(console=console) as live:
            while True:
                conns, _ = get_connections()
                update(conns)
                layout = Layout()
                layout.update(build_table(resolve=resolve, fpid=fpid))

                render_map = layout.render(console, console.options)
                
                s = str(render_map[layout].render)
                r = r"[\s\S]*\[Segment\('├(?:─+┼)+─+┤?', Style\(color=Color\('bright_black', ColorType\.STANDARD, number=8\)\)\)(?:, Segment\(' +'\))?\], \[Segment\('\│', Style\(color=Color\('bright_black', ColorType\.STANDARD, number=8\)\)\), Segment\(' +', Style\(dim=True\)\), Segment\(' +(\d{1,4})', Style\(dim=True\)\), Segment\(' +', Style\(dim=True\)\), Segment\('\│', Style\(color=Color\('bright_black', ColorType\.STANDARD, number=8\)\)\)"
                max_row = int(re.findall(r,s)[-1])

                live.update(build_table(resolve=resolve, fpid=fpid, maxrow=max_row))

                time.sleep(1)

    except KeyboardInterrupt:
        console.print("\n[bold bright_cyan]Scan terminated.[/]")


def main() -> None:
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
    r = 0
    if "--resolve" in sys.argv:
        r = 1
    elif "--resolve-adv" in sys.argv:
        r = 2
    run(resolve=r, fpid=pid)


if __name__ == "__main__":
    main()
