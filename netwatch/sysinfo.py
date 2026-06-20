import re
import socket
import subprocess
import threading
import time
import urllib.request
import psutil
from constants import *

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