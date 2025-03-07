# Usa la imagen base de Python
FROM python:3.9

# Establece el directorio de trabajo
WORKDIR /app

# Copia el archivo principal de la aplicación
COPY main.py ./

# Instala FastAPI y Uvicorn directamente en la imagen
RUN pip install --no-cache-dir fastapi uvicorn PyJWT

# Expone el puerto 8080 para Cloud Run
EXPOSE 8080

# Comando para ejecutar la aplicación
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
