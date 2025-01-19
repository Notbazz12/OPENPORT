from openports.menu import interactive_menu
from openports.constants import Color, BANNER
import argparse
import time
from openports.utils import check_for_updates, scan_local_network, get_shodan_info, save_results
from openports.scanner import scan_ports
from openports.advanced import advanced_options

def main():
    print(BANNER)
    print(f"{Color.MAGENTA}Creado por Notbanzz12{Color.RESET}")
    print(f"{Color.BLUE}https://github.com/Notbazz12{Color.RESET}\n")

    parser = argparse.ArgumentParser(description="Escanea puertos abiertos comunes y vulnerabilidades potenciales.",
    epilog='Ejemplo de uso: python3 -m openports <objetivos> -t 3 -o json -f resultados_escaneo.json')
    parser.add_argument("targets", nargs='*', help="Direcciones IP, nombres de host o archivos con objetivos a escanear")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Tiempo de espera de conexión en segundos (por defecto: 1 segundo).")
    parser.add_argument("-o", "--output", choices=['csv', 'txt', 'json'], help="Formato de salida para los resultados.")
    parser.add_argument("-f", "--output-file", help="Archivo para guardar los resultados. (ej., resultados.json)")
    parser.add_argument("-m", "--max-threads", type=int, default=100, help="Número máximo de hilos a usar (por defecto: 100)")
    parser.add_argument("-u", "--check-updates", action="store_true", help="Comprobar actualizaciones")
    parser.add_argument("-i", "--interactive", action="store_true", help="Ejecutar en modo interactivo")
    parser.add_argument("--advanced", action="store_true", help="Habilita el modo avanzado con opciones personalizables.")

    args = parser.parse_args()

    if args.check_updates:
        check_for_updates()

    if args.interactive:
        interactive_menu()
    elif args.targets:
        start_time = time.time()
        try:
            advanced_settings = {}
            if args.advanced:
                advanced_settings = advanced_options()

            open_ports = scan_ports(args.targets, args.timeout, max_threads=args.max_threads, **advanced_settings)
            if args.output and args.output_file:
                save_results(args.output, args.output_file, open_ports)
        except KeyboardInterrupt:
            print(f"\n{Color.RED}Escaneo interrumpido por el usuario. Saliendo...{Color.RESET}")
        finally:
            end_time = time.time()
            print(f"\n{Color.CYAN}Escaneo completado en {end_time - start_time:.2f} segundos.{Color.RESET}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()