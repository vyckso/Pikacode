class escaneo: #Seguir Convenciones nombres python
    def __init__(self, tipoEscaneo, fichero, nmLineaCodigo, lineaCodigo, error, remediacion, severidad):
        self.tipoEscaneo = tipoEscaneo
        self.fichero = fichero
        self.nmLineaCodigo = nmLineaCodigo
        self.lineaCodigo = lineaCodigo
        self.error = error
        self.remediacion = remediacion
        self.severidad = severidad

    def __repr__(self):
        return f"escaneo('{self.tipoEscaneo}', '{self.nmLineaCodigo}', '{self.lineaCodigo}', '{self.error}', '{self.remediacion}', '{self.severidad}')"