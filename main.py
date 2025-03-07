from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt  # PyJWT
import uvicorn

app = FastAPI(title="API con autenticación JWT sin firma.", description=
              """
Samuel Espitia Cruz
Edwin Alejandro Gutirrez
Nicolas Stiven Ortiz Corrtes
              """,version="1.0.0")

# Secret para firmar el JWT
SECRET_KEY = ""

# Usuarios quemados 
USERS_DB = {
    "buyer1": {"password": "buyerpass", "role": "buyer"},
    "seller1": {"password": "sellerpass", "role": "seller"},
}

# Configuración del esquema de autenticación
security = HTTPBearer()

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

@app.post("/", tags=["Autenticación"], summary="Login")
def login(data: dict):
    """Endpoint de autenticación: devuelve un JWT."""
    username, password = data.get("username"), data.get("password")
    user = USERS_DB.get(username)

    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    token = generate_jwt(username, user["role"])
    return {"token": token}

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Middleware para extraer el usuario desde el JWT."""
    payload = decode_jwt(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=403, detail="Token inválido")
    return payload

@app.get("/public/data", tags=["Datos"], summary="Public Data")
def public_data(user: dict = Depends(get_current_user)):
    """Endpoint accesible para compradores y vendedores."""
    return {"message": "Datos accesibles para ambos roles"}

@app.get("/buyer/data", tags=["Compradores"], summary="Buyer Data")
def buyer_data(user: dict = Depends(get_current_user)):
    """Endpoint solo para compradores."""
    if user["role"] != "buyer":
        raise HTTPException(status_code=403, detail="Acceso denegado")
    return {"message": "Datos exclusivos para compradores"}

@app.get("/seller/data", tags=["Vendedores"], summary="Seller Data")
def seller_data(user: dict = Depends(get_current_user)):
    """Endpoint solo para vendedores."""
    if user["role"] != "seller":
        raise HTTPException(status_code=403, detail="Acceso denegado")
    return {"message": "Datos exclusivos para vendedores"}

if __name__ == "_main_":
    uvicorn.run(app, host="0.0.0.0", port=8080)