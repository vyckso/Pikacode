import os
import re
import sys

classDir = os.path.join(os.path.dirname(__file__), "../app")
sys.path.append(classDir)

from classes import escaneo
import utils

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
                nombre_sin_extension, extension = os.path.splitext(file)
                version = nombre_sin_extension.split('-')[1]
                if utils.is_version_in_range(version, vulnerable_versions[0], vulnerable_versions[1]):
                        resultados.append(escaneo('apacheStructs', file, 'N/A', version,
                                                  'Posible vulnerabilidad Sructs en: ' + file,
                                                  'Use versiones sin la vulnerabilidad (from 2.5.11)', 'Alta - CVE-2017-5638'))

    return resultados