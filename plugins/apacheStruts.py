import os
import re
import sys

classDir = os.path.join(os.path.dirname(__file__), "../app")
sys.path.append(classDir)

from classes import escaneo

vulnerable_versions = ['2.3.31', '2.5.10']

mainDescription = "Busca la vulnerabilidad Apache Struts CVE-2017-5638"

def returnDesc():
    return mainDescription

def execVulCheck(javaPath):
    # Lista para almacenar los resultados encontrados
    resultados = []

    for root, dirs, files in os.walk(javaPath):
        for file in files:
            if 'struts' in file and file.endswith('.jar'):
                for version in vulnerable_versions:
                    if version in file:
                        print(f'Archivo vulnerable encontrado: {os.path.join(root, file)}')
                        resultados.append(escaneo('apacheStructs', file, 'N/A', version,
                                                  'Posible vulnerabilidad Sructs en: ' + file,
                                                  'Use versiones sin la vulnerabilidad (from 2.5.11)', 'Alta - CVE-2017-5638'))

    return resultados