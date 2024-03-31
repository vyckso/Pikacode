from packaging import version


def is_version_in_range(version_str, start_version, end_version):
    """
    Verifica si la versión dada se encuentra dentro del rango especificado.

    Parámetros:
    - version_str (str): La versión a comprobar.
    - start_version (str): La versión inicial del rango.
    - end_version (str): La versión final del rango.

    Ejemplo de uso
    - print(is_version_in_range("2.14.0", "2.0-beta9", "2.14.1"))  # Devolverá True
    - print(is_version_in_range("2.15.0", "2.0-beta9", "2.14.1"))  # Devolverá False

    Retorna:
    - bool: True si version_str está dentro del rango [start_version, end_version], False en caso contrario.
    """
    # Convertir las versiones de cadena a objetos Version para comparación
    v = version.parse(version_str)
    start_v = version.parse(start_version)
    end_v = version.parse(end_version)

    return start_v <= v <= end_v