from fastapi import APIRouter, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from database import usuarios, oauth_clients, oauth_codes
from bson import ObjectId
from datetime import datetime, timedelta
import secrets, hashlib, base64
import bcrypt
from auth import generar_token
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/oauth/authorize")
async def authorize_get_redirect():
    return RedirectResponse(url="/static/index.html", status_code=302)

# Índice TTL para que los authorization codes expiren solos
try:
    oauth_codes.create_index("expires_at", expireAfterSeconds=0)
except Exception:
    pass

def _base64url_sha256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
#3 valida credenciales
@router.post("/oauth/authorize")
async def authorize_post(
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(None),
    code_challenge: str = Form(None),
    code_challenge_method: str = Form(None)  # recibido, aunque no se usa
):
    # 1) Autenticar usuario
    user = usuarios.find_one({"username": username})
    if not user or not bcrypt.checkpw(password.encode(), user["password"]):
        return HTMLResponse(content="<h3>Credenciales incorrectas</h3>", status_code=401)

    # 2) Validar cliente y redirect_uri registrados
    client = oauth_clients.find_one({"client_id": client_id})
    if not client or client.get("redirect_uri") != redirect_uri:
        raise HTTPException(status_code=400, detail="client_id o redirect_uri inválidos")

    # 3) Generar code de corto plazo (5 min) y guardar con PKCE
    code = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(minutes=5)
    oauth_codes.insert_one({
        "code": code,
        "user_id": str(user["_id"]),
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "expires_at": expires
    })

    # 4) Redirigir al callback con code + state
    redirect = f"{redirect_uri}?code={code}"
    if state:
        redirect += f"&state={state}"
    return RedirectResponse(url=redirect, status_code=303)  

# 5=== Canje code -> access_token (valida PKCE) ===
@router.post("/oauth/token")
async def token_endpoint(
    grant_type: str = Form(...),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(None),
    code_verifier: str = Form(None)
):
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="grant_type no soportado")

    # 1) Buscar code
    code_doc = oauth_codes.find_one({"code": code})
    if not code_doc:
        raise HTTPException(status_code=400, detail="Código inválido o ya usado")

    # 2) Verificar expiración 
    if code_doc.get("expires_at") and code_doc["expires_at"] < datetime.utcnow():
        oauth_codes.delete_one({"code": code})
        raise HTTPException(status_code=400, detail="Código expirado")

    # 3) Validar cliente y redirect_uri
    if code_doc["client_id"] != client_id or code_doc["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="client_id o redirect_uri no coinciden")

    # 4) PKCE (calcula el code_verifier  y compara con code_challenge )
    if code_doc.get("code_challenge"):
        if not code_verifier:
            raise HTTPException(status_code=400, detail="code_verifier requerido")
        computed = _base64url_sha256(code_verifier)
        if computed != code_doc["code_challenge"]:
            raise HTTPException(status_code=400, detail="Verificación PKCE fallida")

    # 5) Emitir token y borrar el code 
    user = usuarios.find_one({"_id": ObjectId(code_doc["user_id"])})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    oauth_codes.delete_one({"code": code})
    access_token = generar_token(str(user["_id"]), user["role"])
    return JSONResponse({"access_token": access_token, "token_type": "bearer", "expires_in": 1800})
