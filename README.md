Escáner de Red con Python, Flask y Nmap

Este proyecto es una aplicación web que permite escanear una red local, detectar dispositivos activos y mostrar su estado en una tabla con indicadores de color (verde = activo, gris = desconectado).

Requisitos

Python 3

Instalar dependencias:

pip install flask python-nmap


Nmap instalado

Windows: instalar desde https://nmap.org

Linux:

sudo apt install nmap

Cómo ejecutar

Ejecuta el archivo:

python app.py


Abre en el navegador:

http://127.0.0.1:5000

¿Qué hace el sistema?

Detecta automáticamente la red local (por ejemplo 192.168.0.0/24).

Usa Nmap para encontrar dispositivos activos.

Muestra:

IP

MAC

Hostname

Estado (verde o gris)

Marca dispositivos nuevos y conserva los que se desconectaron.

Uso desde la interfaz web

En el campo CIDR, escribe el rango (ej: 192.168.1.0/24).

Presiona Escanear ahora para iniciar el análisis.

Presiona Limpiar lista para borrar los resultados visibles.

Funcionamiento interno (resumen)

/scan ejecuta un escaneo Nmap con -sn.

Se guarda un registro en memoria para saber cuáles están activos o desconectados.

El frontend actualiza la tabla en cada escaneo.
