import os
import re
import sys
from pathlib import Path

classDir = os.path.join(os.path.dirname(__file__), "../app")
sys.path.append(classDir)

from classes import escaneo

mainDescription = "Búsqueda de vulnerabilidades de tipo CSRF"

def returnDesc():
    return mainDescription

resultados = []

def buscar_vulnerabilidades_csrf_con_linea(ruta_directorio):
    # Patrones para detectar inicio de métodos y métodos que manejan solicitudes POST
    inicio_metodo = re.compile(r'public\s+.*\(')
    maneja_post = re.compile(r'@PostMapping|@RequestMapping\(.*method\s*=\s*RequestMethod.POST.*\)')
    # Patrón para buscar referencias a tokens CSRF
    tiene_csrf = re.compile(r'csrfToken|CsrfToken')

    #resultados = []

    # Recorrer todos los archivos Java en el directorio
    for archivo_java in Path(ruta_directorio).rglob('*.java'):

        maneja_post_anterior = False
        metodo_vulnerable = False
        numero_linea_vulnerable = 0
        nombre_metodo = ''

        with open(archivo_java, 'r', encoding='utf-8') as archivo:
            for numero_linea, linea in enumerate(archivo, 1):
                # Si la línea actual maneja POST, marcarla para verificar si el próximo método es vulnerable
                if maneja_post.search(linea):
                    maneja_post_anterior = True
                    numero_linea_vulnerable = numero_linea
                    continue

                # Si encontramos el inicio de un método y la línea anterior indicaba que maneja POST
                if inicio_metodo.search(linea) and maneja_post_anterior:
                    # Suponemos que es vulnerable hasta que se demuestre lo contrario
                    metodo_vulnerable = True
                    nombre_metodo = linea

                # Si dentro de este posible método vulnerable encontramos un token CSRF, ya no es considerado vulnerable
                if metodo_vulnerable and tiene_csrf.search(linea):
                    metodo_vulnerable = False

                # Al encontrar el final de un método, verificamos si fue marcado como vulnerable
                if linea.strip() == '}' and metodo_vulnerable:
                    #lineas_vulnerables.append(numero_linea_vulnerable)
                    resultados.append(
                                escaneo('CSRF', archivo.name, str(numero_linea_vulnerable) , nombre_metodo , 'Función sin protección CSRF',
                                        'Use medidas de protección adecuadas', 'Media'))
                    metodo_vulnerable = False  # Resetear para el próximo método

                # Resetear la señal de maneja POST para la próxima iteración
                maneja_post_anterior = False

    return resultados

def execVulCheck(javaPath):
    resultados = buscar_vulnerabilidades_csrf_con_linea(javaPath)

    return resultados