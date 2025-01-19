# OpenPorts beta 2.0

OpenPorts es una herramienta de escaneo de puertos y detección de vulnerabilidades escrita en Python.

## Características

- Escaneo de puertos comunes
- Detección básica de vulnerabilidades
- Modo interactivo
- Escaneo de red local
- Integración con Shodan
- Opciones avanzadas de escaneo

- ## Descripcion
- La versión Beta 2.0 lleva OPENPORT al siguiente nivel con características avanzadas diseñadas para profesionales de la ciberseguridad y entusiastas técnicos. Estas son las mejoras y nuevas funcionalidades:

 Detección Avanzada de Servicios y Sistemas Operativos:

Identifica automáticamente el sistema operativo (Windows, Linux, etc.) de las máquinas escaneadas.
Captura banners de servicios con soporte para técnicas de banner grabbing.
Soporte para Puertos UDP:

Ahora puedes escanear puertos UDP críticos como DNS, NTP, y SNMP, ampliando el alcance de tus auditorías de red.
Integración con Bases de Datos de Vulnerabilidades:

Busca vulnerabilidades conocidas en tiempo real usando Exploit-DB y CVE Details.
Genera un informe que muestra las posibles vulnerabilidades asociadas con los servicios detectados.
Generación de Reportes Detallados:

Exporta los resultados en formato PDF con tablas y gráficos visuales.
Compatible con herramientas como matplotlib para análisis más detallado.
Monitoreo en Tiempo Real:

Introduce un modo de monitoreo continuo que detecta cambios en la red, como nuevos servicios abiertos o IPs conectadas.
Modo Avanzado para Usuarios Expertos:

Configuración personalizada de:
Listas negras para evitar ciertos rangos de IP.
Técnicas de evasión para evitar detecciones por IDS/IPS.
Velocidad ajustable del escaneo.
Optimización de Rendimiento:

Mejora en la gestión de hilos para escaneos más rápidos y estables.
Soporte para redes con grandes cantidades de hosts.
Interfaz Más Amigable:

Mejoras en el menú interactivo, con opciones explicativas y accesibles para nuevos usuarios.
Colores optimizados para facilitar la lectura.

## Instalación

1. Clona este repositorio:
2. git clone https://github.com/Notbazz12/OPENPORT.git
3. Navega al directorio del proyecto:
4.  Instala las dependencias:

5.  ## Uso python3 -m pip install --upgrade -r requirements.txt
6.  Abre una consola de comandos y ejecuta ese comando de python en la carpeta no dentro 
7.  ## python -m openports -i
8.  ##python -m openports --help
    ## Opciones avanzadas

OpenPorts incluye varias opciones avanzadas como:

- Evasión de IDS
- Lista negra de puertos
- Ajuste de velocidad de escaneo
- Fuzzing básico de servicios

Consulta la documentación completa para más detalles sobre estas características.

## Contribuir

Las contribuciones son bienvenidas. Por favor, abre un issue para discutir cambios mayores antes de hacer un pull request.

## Licencia

[MIT](https://choosealicense.com/licenses/mit/)
9.  
Opciones:
- `-t, --timeout`: Tiempo de espera para la conexión (por defecto: 1 segundo)
- `-o, --output`: Formato de salida (csv, txt, json)
- `-f, --output-file`: Archivo para guardar los resultados
- `-m, --max-threads`: Número máximo de hilos a usar (por defecto: 100)
- `-u, --check-updates`: Comprobar actualizaciones

## Advertencia

Esta herramienta debe usarse solo en sistemas para los que tienes permiso explícito. El uso no autorizado de esta herramienta puede ser ilegal.

## Contribuir

Las contribuciones son bienvenidas. Por favor, abre un issue para discutir los cambios propuestos o crea un pull request.

## Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo `LICENSE` para más detalles.
