class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    pass

BANNER = f"""{Color.GREEN}
 ██████╗ ██████╗ ███████╗███╗   ██╗██████╗  ██████╗ ██████╗ ████████╗███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║██████╔╝██║   ██║██████╔╝   ██║   ███████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║
╚██████╔╝██║     ███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║   ██║   ███████║
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
   Common Ports Scanner
{Color.RESET}"""

COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB", 6667: "IRC", 9200: "Elasticsearch", 11211: "Memcached"
}

VULNERABILITIES = {
    "FTP": ["Anonymous FTP access", "FTP Bounce attack", "Cleartext transmission"],
    "SSH": ["Weak encryption algorithms", "SSH protocol version 1", "Brute-force attacks"],
    "Telnet": ["Clear text transmission", "Lack of encryption", "Man-in-the-middle attacks"],
    "SMTP": ["Open relay", "SMTP command injection", "Email spoofing"],
    "DNS": ["DNS cache poisoning", "DNS amplification", "Zone transfer vulnerabilities"],
    "HTTP": ["SQL injection", "Cross-site scripting (XSS)", "CSRF", "Directory traversal"],
    "POP3": ["Clear text authentication", "POP3 buffer overflow", "Man-in-the-middle attacks"],
    "IMAP": ["IMAP authentication weakness", "IMAP buffer overflow", "Cleartext transmission"],
    "HTTPS": ["SSL/TLS vulnerabilities", "Heartbleed", "POODLE", "BEAST"],
    "SMB": ["EternalBlue", "SMBGhost", "SMBleed"],
    "MySQL": ["SQL injection", "Weak authentication", "Privilege escalation"],
    "RDP": ["BlueKeep", "DejaBlue", "Brute-force attacks"],
    "PostgreSQL": ["SQL injection", "Weak authentication", "Privilege escalation"],
    "VNC": ["Weak authentication", "Unencrypted communication", "Man-in-the-middle attacks"],
    "Redis": ["Unauthenticated access", "Remote code execution", "Data exposure"],
    "MongoDB": ["Unauthenticated access", "Data exposure", "NoSQL injection"],
    "Elasticsearch": ["Unauthenticated access", "Remote code execution", "Data exposure"],
    "Memcached": ["Unauthenticated access", "Data exposure", "DDoS amplification"]
}