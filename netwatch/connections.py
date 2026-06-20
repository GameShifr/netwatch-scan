import json
import socket
import threading
import time
import urllib.request
import psutil
from psutil._ntuples import sconn
from constants import *

processes = {} #some connections could have same pid
_geo_cache: dict[str, str] = {}
_geo_lock = threading.Lock()
_seen_lock = threading.Lock()
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
    _hostname: str | None = None
    hostname_lock = threading.Lock()
    new: bool
    old: bool

    def __new__(cls, conn:sconn, ts:float):
        key = cls._conn_key(conn)
        if key in seen_conns:
            i = seen_conns[key]
            if i.time_end != None: i.abort_closing(ts)
            if ts - i.time_seen > NEW_TTL: i.new = False
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
            suspicious = any(s in exe for s in SUSPICIOUS_PATHS)
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
        score = PORT_SCORE.get(effective_port, 1)

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
            if time - self.time_end > OLD_TTL:
                del seen_conns[self.key] #suicide
    
    def abort_closing(self, time):
        self.time_end = None
        self.time_seen = time
        self.old = False
    

    def hostname(self) -> str:
        def resolve_host(self: Conn):
            try:
                socket.setdefaulttimeout(5)
                name = socket.gethostbyaddr(self.raddr.ip)[0]
            except Exception:
                name = '—'
            with self.hostname_lock:
                self._hostname = name

        with self.hostname_lock:
            if self._hostname: return self._hostname
            if not self.raddr:
                self._hostname = None
            elif self.raddr.ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                self._hostname = r"[dim]localhost[/dim]"
            else:
                threading.Thread(target=resolve_host, args=(self,), daemon=True).start()
                self._hostname = "…"
            return self._hostname
            


def update(connections: list[sconn]) -> tuple[set, set]:
    """updates connections list with current connections"""
    now = time.time()
    
    active_conns = []

    with _seen_lock:
        for c in connections:
            active_conns.append(Conn(c, now).key)
        for k in list(seen_conns):
            if k not in active_conns:
                seen_conns[k].close(now)

def _is_external(ip: str) -> bool:
    if not ip or ip in ("0.0.0.0", "::"):
        return False
    return not any(ip.startswith(p) for p in PRIVATE_PREFIXES)
