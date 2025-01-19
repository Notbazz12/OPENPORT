from .scanner import scan_ports
from .constants import Color
from .utils import check_for_updates, scan_local_network, get_shodan_info, save_results

def interactive_menu():
    while True:
        print(f"\n{Color.CYAN}=== Menú Interactivo de OpenPorts ==={Color.RESET}")
        print("1. Escanear puertos")
        print("2. Comprobar actualizaciones")
        print("3. Escanear red local")
        print("4. Obtener información de Shodan")
        print("5. Salir")
        
        choice = input("Ingrese su elección (1-5): ")
        
        if choice == '1':
            targets = input("Ingrese IP(s) objetivo separadas por espacio: ").split()
            timeout = float(input("Ingrese timeout (predeterminado 1.0): ") or 1.0)
            max_threads = int(input("Ingrese máximo de hilos (predeterminado 100): ") or 100)
            open_ports = scan_ports(targets, timeout, max_threads)
            print("\nResultados del escaneo:")
            for ip, port, service, vulns in open_ports:
                print(f"IP: {ip}, Puerto: {port}, Servicio: {service}")
                print(f"Vulnerabilidades: {', '.join(vulns)}")
            
            save = input("¿Desea guardar los resultados? (s/n): ").lower()
            if save == 's':
                output_format = input("Ingrese formato de salida (json/csv/txt): ")
                output_file = input("Ingrese nombre del archivo de salida: ")
                save_results(output_format, output_file, open_ports)
        
        elif choice == '2':
            check_for_updates()
        
        elif choice == '3':
            scan_local_network()
        
        elif choice == '4':
            api_key = input("Ingrese su clave API de Shodan: ")
            ip = input("Ingrese la IP a buscar: ")
            get_shodan_info(api_key, ip)
        
        elif choice == '5':
            print("Saliendo...")
            break
        
        else:
            print(f"{Color.RED}Elección inválida. Por favor, intente de nuevo.{Color.RESET}")