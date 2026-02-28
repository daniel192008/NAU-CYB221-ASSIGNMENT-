import argparse
import psutil
import socket
from typing import Optional, Tuple, List


def get_process_name(pid: Optional[int]) -> Optional[str]:
    try:
        if pid is None:
            return None
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def get_service_name(port: int, proto: str) -> str:
    # Common port-to-service mappings
    services = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
        123: "NTP", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        27017: "MongoDB", 6379: "Redis"
    }
    return services.get(port, "Unknown")


def get_exposure(ip: str) -> str:
    # Check for localhost
    if ip in ("127.0.0.1", "::1", "localhost"):
        return "Localhost"
    
    # Check for bind-all addresses
    if ip in ("0.0.0.0", "::", "::ffff:0.0.0.0"):
        return "All Interfaces"
    
    # Check for private IPv4 ranges
    if (ip.startswith("10.") or 
        ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or
        ip.startswith("172.19.") or ip.startswith("172.20.") or ip.startswith("172.21.") or
        ip.startswith("172.22.") or ip.startswith("172.23.") or ip.startswith("172.24.") or
        ip.startswith("172.25.") or ip.startswith("172.26.") or ip.startswith("172.27.") or
        ip.startswith("172.28.") or ip.startswith("172.29.") or ip.startswith("172.30.") or
        ip.startswith("172.31.") or
        ip.startswith("192.168.")):
        return "Private"
    
    # Check for IPv6 link-local (fe80::)
    if ip.startswith("fe80:"):
        return "Private"
    
    return "Public"


def scan_listening() -> List[Tuple[str, str, int, int, str, str, str]]:
    results: List[Tuple[str, str, int, int, str, str, str]] = []

    # TCP - filter for LISTEN
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN:
                proto = "TCP"
                ip = conn.laddr[0]
                port = conn.laddr[1]
                service = get_service_name(port, proto)
                exposure = get_exposure(ip)
                pid = conn.pid
                pname = get_process_name(pid) or "N/A"
                results.append((proto, ip, port, pid, pname, service, exposure))
    except Exception:
        pass

    # UDP - sockets with a local address
    try:
        for conn in psutil.net_connections(kind="udp"):
            if conn.laddr:
                proto = "UDP"
                ip = conn.laddr[0]
                port = conn.laddr[1]
                service = get_service_name(port, proto)
                exposure = get_exposure(ip)
                pid = conn.pid
                pname = get_process_name(pid) or "N/A"
                results.append((proto, ip, port, pid, pname, service, exposure))
    except Exception:
        pass

    def key(item):
        proto, ip, port, pid, pname, service, exposure = item
        return (proto, port)

    results.sort(key=key)
    return results


def main():
    parser = argparse.ArgumentParser(description="List listening TCP/UDP ports with service names and exposure")
    parser.add_argument("--no-resolve", action="store_true", help="don't resolve PIDs to process names")
    args = parser.parse_args()

    rows = scan_listening()

    header = "{:<5} | {:<18} | {:<6} | {:<14} | {:<14} | {:<8} | {}".format('Proto', 'IP Address', 'Port', 'Service', 'Exposure', 'PID', 'Process')
    print(header)
    print("-" * 115)
    for proto, ip, port, pid, pname, service, exposure in rows:
        pid_display = str(pid) if pid is not None else "N/A"
        if args.no_resolve:
            pname_display = "N/A"
        else:
            pname_display = pname
        print("{:<5} | {:<18} | {:<6} | {:<14} | {:<14} | {:<8} | {}".format(proto, ip, port, service, exposure, pid_display, pname_display))


if __name__ == "__main__":
    main()
