from .constants import Color
from typing import List, Tuple
import shodan
import socket
import ipaddress
import os
import requests

def save_results(output_format: str, output_file: str, open_ports: List[Tuple[str, int, str, List[str]]]) -> None:
    if output_format == 'json':
        import json
        with open(output_file, 'w') as f:
            json.dump(open_ports, f, indent=2)
        print(f"\n{Color.CYAN}✅ Resultados guardados en {output_file} en formato JSON.{Color.RESET}")
    elif output_format == 'csv':
        import csv
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Puerto', 'Servicio', 'Vulnerabilidades'])
            for ip, port, service, vulns in open_ports:
                writer.writerow([ip, port, service, ', '.join(vulns)])
        print(f"\n{Color.CYAN}✅ Resultados guardados en {output_file} en formato CSV.{Color.RESET}")
    elif output_format == 'txt':
        with open(output_file, 'w') as f:
            for ip, port, service, vulns in open_ports:
                f.write(f"IP: {ip}, Puerto: {port}, Servicio: {service}\n")
                f.write(f"Vulnerabilidades: {', '.join(vulns)}\n\n")
        print(f"\n{Color.CYAN}✅ Resultados guardados en {output_file} en formato TXT.{Color.RESET}")

def check_for_updates():
    try:
        response = requests.get("https://api.github.com/repos/Notbazz12/openports/releases/latest")
        latest_version = response.json()["tag_name"]
        print(f"{Color.CYAN}Última versión: {latest_version}{Color.RESET}")
        # Aquí puedes comparar con la versión actual e informar si hay una actualización disponible
    except Exception as e:
        print(f"{Color.YELLOW}No se pudo comprobar actualizaciones: {e}{Color.RESET}")

def scan_local_network():
    local_ip = socket.gethostbyname(socket.gethostname())
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)

    print(f"Escaneando red local: {network}")
    for ip in network.hosts():
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            print(f"Dispositivo encontrado: {ip} ({hostname})")
        except socket.herror:
            print(f"Dispositivo encontrado: {ip} (nombre de host no resuelto)")

def get_shodan_info(api_key: str, ip: str):
    api = shodan.Shodan(api_key)
    try:
        results = api.host(ip)
        print(f"IP: {results['ip_str']}")
        print(f"Organización: {results.get('org', 'N/A')}")
        print(f"Sistema Operativo: {results.get('os', 'N/A')}")
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"Nombre de host: {hostname}")
        except socket.herror:
            print("Nombre de host: No se pudo resolver")

        for item in results['data']:
            print(f"Puerto: {item['port']}")
            print(f"Banner: {item['data']}")
        
        if 'hostnames' in results:
            print(f"Nombres de host: {', '.join(results['hostnames'])}")
        if 'domains' in results:
            print(f"Dominios: {', '.join(results['domains'])}")
        if 'location' in results:
            location = results['location']
            print(f"Ubicación: {location.get('city', 'N/A')}, {location.get('country_name', 'N/A')}")
        
    except shodan.APIError as e:
        print(f"Error de API Shodan: {e}")
    except Exception as e:
        print(f"Ocurrió un error inesperado: {e}")

def get_current_user():
    """Devuelve el usuario actual del sistema."""
    try:
        username = os.getlogin()
        return username
    except Exception as e:
        print(f"Error al obtener el usuario actual: {str(e)}")
        return None