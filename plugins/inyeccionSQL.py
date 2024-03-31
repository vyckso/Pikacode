import os
import re
import sys

classDir = os.path.join(os.path.dirname(__file__), "../app")
sys.path.append(classDir)

from classes import escaneo

mainDescription = "Búsqueda de inyecciones SQL en el código"

def returnDesc():
    return mainDescription

def execVulCheck(javaPath):
    patrones = [
        #sentecias SQL más comunes
        r"union",
        r"select",
        r"where",
        r"insert",
        r"update",
        r"delete",
        r"order by",
        r"group by",
        r"having",
        #Sentencias java más comunes
        r"PreparedStatement",
        r"executeQuery",
        r"executeUpdate",
        r"createStatement",
    ]

    # Compilar una expresión regular simple para buscar potenciales contraseñas

    regex = re.compile('|'.join(patrones), re.IGNORECASE)

    # Compilar una expresión regular simple para buscar potenciales contraseñas
    #regex = re.compile(r"(union|select|from|where|insert|update|delete|order by|group by|having|PreparedStatement|executeQuery|executeUpdate|createStatement)\s+[^\n]+?\+")

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
                                resultados.append(escaneo('inyeccionSQL', nombre_archivo, numero_linea, linea.strip(),'Posible inyección SQL - Uso de '+coincidencia,'Use consultas parametrizadas', 'Media'))
                                #resultados.append({
                                #    'archivo': nombre_archivo,
                                #    'ruta': ruta_completa,
                                #    'linea': numero_linea,
                                #    'codigo': linea.strip(),
                                #    'variable': coincidencia[0],
                                #    'posible_contraseña': coincidencia[1]
                                #})

    return resultados