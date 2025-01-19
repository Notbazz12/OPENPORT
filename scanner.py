from typing import List, Tuple
import socket
import concurrent.futures
from .constants import Color
from .advanced import apply_advanced_settings
import random
import time

@apply_advanced_settings
def scan_ports(targets: List[str], timeout: float = 1.0, max_threads: int = 100, **kwargs) -> List[Tuple[str, int, str, List[str]]]:
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    blacklist = kwargs.get('blacklist', [])
    evade_ids = kwargs.get('evade_ids', False)
    scan_speed = kwargs.get('scan_speed', timeout)
    enable_fuzzing = kwargs.get('enable_fuzzing', False)

    def scan_port(ip: str, port: int) -> Tuple[str, int, str, List[str]] or None:
        if f"{ip}:{port}" in blacklist or str(port) in blacklist:
            return None

        if evade_ids:
            time.sleep(random.uniform(0.5, 2.0))

        try:
            with socket.create_connection((ip, port), timeout=scan_speed):
                service = socket.getservbyport(port)
                vulnerabilities = check_vulnerabilities(ip, port, service)
                print(f"{Color.GREEN}[+] {ip}:{port} está abierto ({service}){Color.RESET}")

                if enable_fuzzing:
                    fuzz_result = fuzz_service(ip, port, service)
                    vulnerabilities.extend(fuzz_result)

                return (ip, port, service, vulnerabilities)
        except (socket.timeout, ConnectionRefusedError):
            return None
        except Exception as e:
            print(f"{Color.RED}[-] Error escaneando {ip}:{port}: {str(e)}{Color.RESET}")
            return None

    for target in targets:
        print(f"\n{Color.CYAN}Escaneando {target}...{Color.RESET}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(scan_port, target, port) for port in common_ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

    return open_ports

def check_vulnerabilities(ip: str, port: int, service: str) -> List[str]:
    vulnerabilities = []
    
    # Ejemplo de verificación de vulnerabilidades conocidas
    if service == 'ftp' and port == 21:
        vulnerabilities.append("Posible FTP anónimo habilitado")
    elif service == 'ssh' and port == 22:
        vulnerabilities.append("Verificar versión de SSH para vulnerabilidades conocidas")
    elif service in ['http', 'https'] and port in [80, 443]:
        vulnerabilities.append("Comprobar versión del servidor web y vulnerabilidades comunes")

    return vulnerabilities

def fuzz_service(ip: str, port: int, service: str) -> List[str]:
    fuzz_results = []

    if service in ['http', 'https']:
        common_paths = ['/admin', '/login', '/wp-admin', '/phpmyadmin']
        for path in common_paths:
            try:
                with socket.create_connection((ip, port), timeout=1.0):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((ip, port))
                    request = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                    sock.sendall(request.encode())
                    response = sock.recv(1024).decode()
                    if "200 OK" in response:
                        fuzz_results.append(f"Posible directorio sensible encontrado: {path}")
            except Exception:
                pass

    return fuzz_results

# Puedes agregar más funciones auxiliares aquí según sea necesario