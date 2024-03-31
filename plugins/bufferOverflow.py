import os
import re
import sys


classDir = os.path.join(os.path.dirname(__file__), "../app")
sys.path.append(classDir)

from classes import escaneo

mainDescription = "Busqueda de posible desbordamiento de pila"


def analizar_java(archivo_java):
    """Analiza un archivo Java y encuentra las declaraciones de métodos."""
    with open(archivo_java, 'r') as archivo:
        contenido = archivo.read()

    # Expresión regular simple para encontrar declaraciones de métodos
    patron_metodo = re.compile(r'public|protected|private|static\s+\w+\s+(\w+)\(')

    metodos = patron_metodo.findall(contenido)

    return metodos

def returnDesc():
    return mainDescription

def execVulCheck(javaPath):
    #buscar_vulnerabilidades(javaPath)

    patrones = [
        # Busqueda de bufferoverflow
        r"System\.arraycopy",
        r"BufferedReader",
        r"BufferedWriter",
        r"StringBuffer",
        r"StringBuilder",
        r"StringTokenizer",
        r"CharArrayReader",
        r"CharArrayWriter",
    ]

    # Compilar una expresión regular simple
    regex = re.compile('|'.join(patrones), re.IGNORECASE)

    # Lista para almacenar los resultados encontrados
    resultados = []

    # Iterar sobre todos los archivos en el directorio
    for raiz, dirs, archivos in os.walk(javaPath):
        for nombre_archivo in archivos:
            if nombre_archivo.endswith('.java'):
                # Construir la ruta completa al archivo
                ruta_completa = os.path.join(raiz, nombre_archivo)

                # Abrir y leer el archivo línea por línea
                with open(ruta_completa, 'r', encoding='utf-8') as archivo:
                    numero_linea = 0
                    for linea in archivo:
                        numero_linea += 1
                        # Buscar todas las coincidencias con la expresión regular en la línea actual
                        coincidencias = regex.findall(linea)
                        if coincidencias:
                            for coincidencia in coincidencias:
                                # Añadir los resultados a la lista
                                # Incluyendo el nombre del archivo, ruta completa, número de línea y la línea de código
                                resultados.append(escaneo('checkPasswords', nombre_archivo, numero_linea, linea.strip(),'Posible desbirdamiento de pila en: '+coincidencia,'Cambiel el código', 'Media'))

    return resultados