

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

PRIVATE_PREFIXES = (
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

# Base risk score per port (higher = more dangerous)
PORT_SCORE: dict[int, int] = {
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

SUSPICIOUS_PATHS = (
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/var/folders/",
    "Downloads/",
    "Desktop/",
)

NEW_TTL = 4.0  # seconds a connection stays flagged as NEW
OLD_TTL = 4.0  # seconds a connection stays flagged as OLD

ENC = 'oem'
