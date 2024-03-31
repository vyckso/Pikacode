import os
import sys
import time

from xml.etree import ElementTree as ET

classDir = os.path.join(os.path.dirname(__file__), "../app")
sys.path.append(classDir)

from classes import escaneo
import utils

mainDescription = "Búsqueda de vulnerabilidad log4j CVE-2021-44228"

resultados = []

#vulnerable_versions = ['2.0-beta9', '2.14.1'] #Se definen versiones inicial y final
vulnerable_versions = ['1.0-beta9', '2.14.1'] #Se definen versiones inicial y final

def returnDesc():
    return mainDescription

def find_vulnerable_log4j_in_pom(file_path):
    """Busca log4j vulnerables en archivos pom.xml"""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        namespaces = {'m': 'http://maven.apache.org/POM/4.0.0'}
        for dependency in root.findall(".//m:dependency", namespaces):
            groupId = dependency.find('m:groupId', namespaces)
            artifactId = dependency.find('m:artifactId', namespaces)
            version = dependency.find('m:version', namespaces)
            if groupId is not None and artifactId is not None and version is not None:
                if "log4j" in groupId.text and "log4j-core" in artifactId.text:
                    version_text = version.text
                    if utils.is_version_in_range(version_text,vulnerable_versions[0], vulnerable_versions[1]):
                        print(f"Encontrado en {file_path}: {version_text}")
                        resultados.append(escaneo('log4J', artifactId, 'N/A', version_text,
                                                  'Posible vulnerabilidad Log4j en: ' + file_path,
                                                  'Use versiones sin la vulnerabilidad', 'Alta - CVE-2021-44228'))
                        # Aquí podrías añadir una comprobación específica de la versión
    except ET.ParseError:
        print(f"Error al analizar XML: {file_path}")

def find_vulnerable_log4j_in_gradle(file_path):
    """Busca log4j vulnerables en archivos build.gradle"""
    with open(file_path, 'r') as file:
        for line in file:
            if 'log4j-core' in line:
                #print(f"Posible dependencia vulnerable encontrada en {file_path}: {line.strip()}")
                resultados.append(escaneo('log4J', file, 'N/A', line.strip(),
                                          'Posible vulnerabilidad Log4j en: ' + file_path,
                                          'Use versiones sin la vulnerabilidad', 'Alta - CVE-2021-44228'))

def find_vulnerable_log4j_in_jar(file, file_path):
    if file.startswith('log4j') and file.endswith('.jar'):
        nombre_sin_extension, extension = os.path.splitext(file)
        version = nombre_sin_extension.split('-')[1]
        if utils.is_version_in_range(version, vulnerable_versions[0], vulnerable_versions[1]):
            #print(f'Archivo vulnerable encontrado: {os.path.join(root, file)}')
            resultados.append(escaneo('log4J', file, 'N/A', 'N/A',
                                      'Posible vulnerabilidad Log4j en: ' + file_path,
                                      'Use versiones sin la vulnerabilidad', 'Alta - CVE-2021-44228'))

def search_directory_for_java_projects(directory):
    """Busca archivos pom.xml y build.gradle en el directorio especificado"""
    #time.sleep(15) #Prueba para confirmar timeout
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file == "pom.xml":
                find_vulnerable_log4j_in_pom(os.path.join(root, file))
            elif file == "build.gradle":
                find_vulnerable_log4j_in_gradle(os.path.join(root, file))
            elif file.startswith('log4j') and file.endswith('.jar'):
                find_vulnerable_log4j_in_jar(file, os.path.join(root, file))

def execVulCheck(javaPath):
    search_directory_for_java_projects(javaPath)
    if resultados:
        return resultados