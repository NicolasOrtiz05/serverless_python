from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt  # PyJWT
import uvicorn

# Crear instancia de la aplicación FastAPI con OpenAPI personalizado
app = FastAPI(
    title="API de Autenticación y Roles",
    description="API con autenticación JWT que distingue entre compradores y vendedores.",
    version="1.0.0"
)

# Configuración del esquema de autenticación en OpenAPI
security = HTTPBearer()

# Claves quemadas para los usuarios
SECRET_KEY = ""
USERS_DB = {
    "buyer1": {"password": "buyerpass", "role": "buyer"},
    "seller1": {"password": "sellerpass", "role": "seller"},
}

def generate_jwt(username: str, role: str):
    """Genera un token JWT sin firmar."""
    payload = {"sub": username, "role": role}
    return jwt.encode(payload, SECRET_KEY, algorithm=None)  # Sin firma

def decode_jwt(token: str):
    """Decodifica un JWT sin firma."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Middleware para extraer el usuario desde el JWT."""
    token = credentials.credentials
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=403, detail="Token inválido")
    return payload

@app.post("/", tags=["Autenticación"], summary="Autentica a un usuario y devuelve un token JWT")
def login(data: dict):
    """Endpoint de autenticación: devuelve un JWT."""
    username, password = data.get("username"), data.get("password")
    user = USERS_DB.get(username)

    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    token = generate_jwt(username, user["role"])
    return {"token": token}

@app.get("/public/data", tags=["Datos"], summary="Endpoint accesible para compradores y vendedores")
def public_data(user: dict = Depends(get_current_user)):
    """Datos accesibles para ambos roles."""
    return {"message": "Datos accesibles para ambos roles"}

@app.get("/buyer/data", tags=["Compradores"], summary="Endpoint accesible solo para compradores")
def buyer_data(user: dict = Depends(get_current_user)):
    """Datos exclusivos para compradores."""
    if user["role"] != "buyer":
        raise HTTPException(status_code=403, detail="Acceso denegado")
    return {"message": "Datos exclusivos para compradores"}

@app.get("/seller/data", tags=["Vendedores"], summary="Endpoint accesible solo para vendedores")
def seller_data(user: dict = Depends(get_current_user)):
    """Datos exclusivos para vendedores."""
    if user["role"] != "seller":
        raise HTTPException(status_code=403, detail="Acceso denegado")
    return {"message": "Datos exclusivos para vendedores"}


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = app.openapi()
    openapi_schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method["security"] = [{"bearerAuth": []}]
    app.openapi_schema = openapi_schema
    return openapi_schema

app.openapi = custom_openapi  

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
