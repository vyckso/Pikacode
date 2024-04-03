import os
import re
import sys


classDir = os.path.join(os.path.dirname(__file__), "../app")
sys.path.append(classDir)

from classes import escaneo

mainDescription = "Busqueda de posible desbordamiento de pila"

#Lista para almacenar los resultados encontrados
resultados = []

def busca_overFlow_exp_reg(javaPath):
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
                                resultados.append(escaneo('bufferOverflow', nombre_archivo, numero_linea, linea.strip(),
                                                          'Posible desbirdamiento de pila en: ' + coincidencia,
                                                          'Cambie el código', 'Media'))


def extraer_codigo_funcion(nombre_archivo, nombre_funcion):
    # Abrir el archivo Java para leer
    with open(nombre_archivo, 'r') as archivo:
        codigo = archivo.read()

    # Construir la expresión regular para encontrar la función
    # Busca la definición de la función seguida de cualquier cosa hasta la próxima llave de cierre que no esté seguida de otra llave de cierre
    regex = r"(\b" + re.escape(nombre_funcion) + r"\b.*?\{)([^{}]*((\{[^{}]*\}[^{}]*)*))"

    # Buscar todas las coincidencias en el código
    matches = re.findall(regex, codigo, re.DOTALL)

    if matches:
        # Asumimos que solo hay una definición de la función
        # Concatenamos el grupo 1 y 2 del match para obtener toda la definición de la función
        #return matches[0][0] + matches[0][1]
        return matches[0][1]
    else:
        return "Función no encontrada."

def analizar_java_recursivo(javaPath):
    """Analiza un archivo Java y encuentra las declaraciones de métodos."""
    prevMethod = ''
    for raiz, dirs, archivos in os.walk(javaPath):
        for nombre_archivo in archivos:
            if nombre_archivo.endswith('.java'):

                with open(raiz + '\\' + nombre_archivo, 'r') as file:
                    content = file.read()

                    # Remover comentarios de una línea y bloques de comentarios para evitar falsos positivos
                    content_no_comments = re.sub(r'//.*|/\*[\s\S]*?\*/', '', content)

                    # Buscar todas las definiciones de métodos
                    method_defs = re.findall(
                        r'\b(public|protected|private|static|\s)*\s+[\w<>\[\]]+\s+(\w+)\s*\((?:[\w\s,<>\[\]].*?)?\)\s*\{',
                        content_no_comments)

                    method_names = {method_name for _, method_name in method_defs}

                    for method_name in method_names:

                        #Extraemos el código del método
                        methodCode = extraer_codigo_funcion(raiz + '\\' + nombre_archivo, method_name)


                        # Crear una expresión regular para buscar llamadas a este método
                        method_call_pattern = re.compile(r'\b' + re.escape(method_name) + r'\s*\(')

                        # Buscar llamadas al método dentro del codigo del método
                        if method_call_pattern.findall(methodCode):
                            resultados.append(escaneo('bufferOverflow', nombre_archivo, '', 'Función ' + method_name,
                                                      'El método ' + method_name + ' parece ser recursivo en ' + nombre_archivo + '.',
                                                      'Evite llamadas recursivas', 'Media'))



#return metodos

def returnDesc():
    return mainDescription

def execVulCheck(javaPath):

    analizar_java_recursivo(javaPath)
    busca_overFlow_exp_reg(javaPath)

    return resultados