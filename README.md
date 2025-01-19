# OpenPorts

OpenPorts es una herramienta de escaneo de puertos y detección de vulnerabilidades con capacidades de explotación.

## Características

- Escaneo de puertos comunes en múltiples objetivos
- Detección de servicios y vulnerabilidades potenciales
- Capacidad de ejecutar exploits contra vulnerabilidades detectadas
- Soporte para exploits de Python y Metasploit
- Múltiples formatos de salida (CSV, TXT, JSON)

## Requisitos

- Python 3.6+
- Metasploit Framework (para exploits de Metasploit)

## Instalación

1. Clona este repositorio:
2. git clone https://github.com/Notbazz12/OPENPORT.git
3. Navega al directorio del proyecto:
4.  Instala las dependencias:

5.  ## Uso python3 -m pip install --upgrade -r requirements.txt
6.  Como usar: python3 OPENPORT.py (IP) 

7.  
Opciones:
- `-t, --timeout`: Tiempo de espera para la conexión (por defecto: 1 segundo)
- `-o, --output`: Formato de salida (csv, txt, json)
- `-f, --output-file`: Archivo para guardar los resultados
- `-m, --max-threads`: Número máximo de hilos a usar (por defecto: 100)
- `-u, --check-updates`: Comprobar actualizaciones

Ejemplo:


## Advertencia

Esta herramienta debe usarse solo en sistemas para los que tienes permiso explícito. El uso no autorizado de esta herramienta puede ser ilegal.

## Contribuir

Las contribuciones son bienvenidas. Por favor, abre un issue para discutir los cambios propuestos o crea un pull request.

## Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo `LICENSE` para más detalles.
