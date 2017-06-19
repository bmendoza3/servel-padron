# servel-padron
Crea archivos CSV a partir de los PDF publicados por el Servicio Electoral chileno con el padrón electoral.

## Dependencias  
  Código desarrollado en Línux. Utiliza *pdftotext* para convertir los archivos PDF a texto plano
  Requiere Python 2.x. Si no es el binario por defecto, cambiar `python` por `python2`
  
## Uso:

  - Para convertir un solo archivo .pdf a .csv:
    ```
    python luxuryParser.py -c <nombre_archivo.pdf>
    ```
  - Para convertir uno o más archivos .txt (ya procesados por *pdftotext*) a .csv:
    ```
    python luxuryParser.py -p <nombre_archivo.txt> <nombre_archivo2.txt> <...>
    ```
  - Para convertir todos los archivos .pdf de una carpeta  a .csv (ignora los archivos .pdf que tengan el mismo nombre que un archivo .csv preexistente):
    ```
    python batch_parse.py
    ```
