from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError
from datetime import datetime, timedelta
from fastapi import HTTPException, Request
from database import usuarios
from bson import ObjectId
import os
from dotenv import load_dotenv, find_dotenv

# Carga .env
load_dotenv(find_dotenv())

# SECRET obligatoria
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY no configurada. Define SECRET_KEY en tu .env o entorno.")

ALGORITHM = "HS256"

def generar_token(usuario_id, role, exp_minutes: int = 30):
    payload = {
        "sub": str(usuario_id),
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=exp_minutes)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

async def validar_token(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token no proporcionado")

    token = auth.split(" ", 1)[1].strip()

    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except JWTError:
        raise HTTPException(status_code=403, detail="Token inválido")

    # No exponer el hash de contraseña
    usuario = usuarios.find_one({"_id": ObjectId(data["sub"])}, {"password": 0})
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    usuario["_id"] = str(usuario["_id"])
    return usuario
