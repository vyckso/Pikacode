"""
    Herramienta Pikacode para el descubrimiento de vulnerabilidades Java en código sin compilar

    * Paquetes requeridos (instalación con pip) agrparse, tabulate, packaging

    - Añadimos timeout, definido en la variable timeout en segundos, para la ejecución de los plugins


"""


import argparse
import os
import importlib
import sys
from tabulate import tabulate
import multiprocessing
from multiprocessing import Queue

classDir = os.path.join(os.path.dirname(__file__), "./app")
sys.path.append(classDir)

#directorio de los plugins para los plugins
pluginsPath = "./plugins"
extension = '.py'
timeout = 10 #Definimos el timeout para ejecución de plugin en segundos

#Definimos una clase para la gestión de errores
class appError(Exception):
    def __init__(self, mensaje):
        super().__init__(mensaje)

#DEfinimos una clase para los colores de la consola
class bcolors:
    HEADER = "\033[34m"
    OK_BLUE = "\033[94m"
    OK_CYAN = "\033[96m"
    OK_GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

def ejecutar_plugin(queue, plugin_name, repository):
    vulModule = 'plugins.' + plugin_name
    vulFunction = 'execVulCheck'

    # Importar el módulo dinámicamente
    modulo = importlib.import_module(vulModule)

    # Obtener la función del módulo
    funcion = getattr(modulo, vulFunction)

    # Ejecutar la función y colocar el resultado en la cola
    resultado = funcion(repository)
    queue.put((plugin_name, resultado))

def ejecutaPlugins(args):
    ficherosPython = [os.path.splitext(archivo)[0] for archivo in os.listdir(pluginsPath) if
                      archivo.endswith(extension)]

    # print(ficherosPython)

    resultadosFuncion = []

    processes = []
    queue = Queue()

    for optionsSelected in args.plugins:

        if optionsSelected not in ficherosPython:
            print(f"{bcolors.WARNING}Se ha seleccionado un escaneo inexistente - {optionsSelected}")
            raise appError("Se ha seleccionado un escaneo inexistente")

        # Crear un proceso para cada plugin
        process = multiprocessing.Process(target=ejecutar_plugin, args=(queue, optionsSelected, args.repository))
        process.start()
        processes.append(process)

        # Esperar a que todos los procesos terminen
        for process in processes:
            process.join(timeout)
            if process.is_alive():
                print(f"{bcolors.WARNING}Terminando el plugin {optionsSelected} que excedió el tiempo de espera de {timeout} segundos.{bcolors.ENDC}")
                process.terminate()
                process.join()

        # Recopilar resultados
        while not queue.empty():
            plugin_name, resultado = queue.get()
            resultadosFuncion.extend(resultado)

        # cabeceras = ['Tipo de escaneo', 'Número de linea', 'Código Java', 'Error', 'Remediación', 'Severidad']

        # cabeceras = resultadosFuncion[0].keys()
    tablaMostrar = []

    if not resultadosFuncion:
        print(f"{bcolors.WARNING}No hay resultados que mostrar para los plugins seleccionados: ")
        print(args.plugins)
        print(f"{bcolors.ENDC}")

    for scan in resultadosFuncion:
        # print(scan)
        tablaMostrar.append(
            {"Tipo de escaneo": scan.tipoEscaneo, "Fichero": scan.fichero, "Numero de línea": scan.nmLineaCodigo,
             "Código Java": scan.lineaCodigo, "Error": scan.error, "Remediación": scan.remediacion,
             "Severidad": scan.severidad})

    print(tabulate(tablaMostrar, headers="keys", tablefmt="grid"))

def ejecutaTodosPlugins(args):
    ficherosPython = [os.path.splitext(archivo)[0] for archivo in os.listdir(pluginsPath) if
                      archivo.endswith(extension)]

    resultadosFuncion = []
    processes = []
    queue = Queue()

    # TODO: Validar la estructura del plugin (Clase base + validacion de tiempos ejecucion + nmArchivos)
    for ficheros in ficherosPython:
        if ficheros != '__init__':

            # Crear un proceso para cada plugin
            process = multiprocessing.Process(target=ejecutar_plugin, args=(queue, ficheros, args.repository))
            process.start()
            processes.append(process)

            # Esperar a que todos los procesos terminen
            for process in processes:
                process.join(timeout)
                if process.is_alive():
                    print(
                        f"{bcolors.WARNING}Terminando el plugin {ficheros} que excedió el tiempo de espera de {timeout} segundos.{bcolors.ENDC}")
                    process.terminate()
                    process.join()

            # Recopilar resultados
            while not queue.empty():
                plugin_name, resultado = queue.get()
                resultadosFuncion.extend(resultado)


            """vulModule = 'plugins.' + ficheros
            vulFunction = 'execVulCheck'

            # Importar el módulo dinámicamente
            modulo = importlib.import_module(vulModule)

            # Obtener la función del módulo
            funcion = getattr(modulo, vulFunction)"""

        #resultadosFuncion.extend(funcion(args.repository))

    tablaMostrar = []

    for scan in resultadosFuncion:
        # print(scan)
        tablaMostrar.append(
            {"Tipo de escaneo": scan.tipoEscaneo, "Fichero": scan.fichero, "Numero de línea": scan.nmLineaCodigo,
             "Código Java": scan.lineaCodigo, "Error": scan.error, "Remediación": scan.remediacion,
             "Severidad": scan.severidad})

    print(tabulate(tablaMostrar, headers="keys", tablefmt="grid"))

def listaPlugins():
    print(f"{bcolors.OK_CYAN}Listado de plugins disponibles:{bcolors.ENDC}")
    ficherosPython = [os.path.splitext(archivo)[0] for archivo in os.listdir(pluginsPath) if
                      archivo.endswith(extension)]

    for ficheros in ficherosPython:
        if ficheros != '__init__':
            vulModule = 'plugins.' + ficheros
            vulFunction = 'returnDesc'

            # Importar el módulo dinámicamente
            modulo = importlib.import_module(vulModule)

            # Obtener la función del módulo
            funcion = getattr(modulo, vulFunction)

            print(f"{bcolors.OK_CYAN}Módulo: {ficheros} - Descripción: {funcion()}{bcolors.ENDC}")


def main():
    # Crear el parser
    parser = argparse.ArgumentParser(description='Busqueda de vulnerabilidades en código Java sin compilar')

    #Definimos los parámetros aceptados por la aplicación
    #Parámetro repository - Ruta a los fuentes Java
    parser.add_argument(
        "-r",
        "--repository",
        help="JAVA repository",
        #required=True,
        dest="repository",
    )

    #Parámetro list - Lista los plugins disponibles
    parser.add_argument(
        "-l",
        "--list",
        action='store_true',
        help="List plugins"
    )

    parser.add_argument(
        "-p",
        "--plugins",
        nargs='+',
        help="Plugins (Option -l list all available plugins) - 'all' executes all plugins ",
        #required=True,
        dest="plugins",
    )

    print(
        f"{bcolors.HEADER}░▒▓███████▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░ {bcolors.ENDC}")
    print(
        f"{bcolors.HEADER}░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        {bcolors.ENDC}")
    print(
        f"{bcolors.HEADER}░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        {bcolors.ENDC}")
    print(
        f"{bcolors.HEADER}░▒▓███████▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░   {bcolors.ENDC}")
    print(
        f"{bcolors.HEADER}░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        {bcolors.ENDC}")
    print(
        f"{bcolors.HEADER}░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        {bcolors.ENDC}")
    print(
        f"{bcolors.HEADER}░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░ {bcolors.ENDC}")

    print(f"CI Vulnerability tool for JAVA repositories by {bcolors.HEADER}Pilar Gonzalez and Victor Prada - Campus Ciberseguridad - ENIIT{bcolors.ENDC}")
    print()

    # Analizar los argumentos pasados al programa
    args = parser.parse_args()

    if args.list is True:
        listaPlugins()
    else:
        if args.repository is not None and args.plugins is not None:
            print(f"[{bcolors.OK_GREEN}Repositorio seleccionado{bcolors.ENDC}] {args.repository}")
            for plugin in args.plugins:
                print(f"[{bcolors.OK_GREEN}Scanner seleccionado{bcolors.ENDC}] {plugin}")
            if 'all' in args.plugins:
                ejecutaTodosPlugins(args)
            else:
                ejecutaPlugins(args)
        else:
            print(f"{bcolors.WARNING}No se ha seleccionado ninguna opción valida{bcolors.ENDC}")
            print(f"{bcolors.WARNING}Para la ejecución de la aplicación los parámetros -r y -p son obligatorios{bcolors.ENDC}")
            raise appError("No se han seleccionado opciones correctas")

if __name__ == "__main__":
    try:
        main()
    except appError as e:
        print(f"{bcolors.FAIL}Error en la ejecución de la aplicación")
