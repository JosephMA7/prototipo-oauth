from fastapi import FastAPI, Depends, HTTPException, Body
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from database import usuarios, tareas, notas  # colecciones de Mongo
from models import UserLogin, UserCreate
from auth import generar_token, validar_token
from oauth import router as oauth_router

import bcrypt
import os

app = FastAPI()

# CORS: en producción restringe orígenes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,  
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def root():
    return RedirectResponse(url="/oauth/authorize?client_id=edu_client", status_code=307)

# Sirve favicon si existe para evitar 404 del navegador
@app.get("/favicon.ico")
def favicon():
    fpath = os.path.join(STATIC_DIR, "favicon.ico")
    if os.path.exists(fpath):
        return FileResponse(fpath)
    return ("", 204)

# === Rutas OAuth (Authorization Code + PKCE) ===
app.include_router(oauth_router)

# === Endpoints ===
@app.post("/login")
async def login(datos: UserLogin):
    user = usuarios.find_one({"username": datos.username})
    if not user or not bcrypt.checkpw(datos.password.encode(), user["password"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    token = generar_token(str(user["_id"]), user["role"])
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
async def me(usuario=Depends(validar_token)):
    return {"usuario": usuario["username"], "rol": usuario["role"]}

def rol_requerido(rol_permitido):
    async def wrapper(usuario=Depends(validar_token)):
        if usuario["role"] != rol_permitido:
            raise HTTPException(status_code=403, detail="No autorizado")
        return usuario
    return wrapper

@app.get("/usuarios")
async def listar_usuarios(usuario=Depends(rol_requerido("admin"))):
    usuarios_lista = usuarios.find({}, {"password": 0})
    resultado = []
    for u in usuarios_lista:
        u["_id"] = str(u["_id"])
        resultado.append(u)
    return resultado

@app.post("/crear_usuario")
async def crear_usuario(data: UserCreate, usuario=Depends(rol_requerido("admin"))):
    if usuarios.find_one({"username": data.username}):
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    password_cifrada = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt())
    nuevo = {"username": data.username, "password": password_cifrada, "role": data.role}
    usuarios.insert_one(nuevo)
    return {"msg": "Usuario creado exitosamente"}

@app.post("/subir_tarea")
async def subir_tarea(info: dict = Body(...), usuario=Depends(rol_requerido("profesor"))):
    info["profesor"] = usuario["username"]
    tareas.insert_one(info)
    return {"msg": "Tarea guardada exitosamente"}

@app.get("/estudiantes")
async def ver_estudiantes(usuario=Depends(rol_requerido("profesor"))):
    estudiantes = usuarios.find({"role": "estudiante"}, {"password": 0})
    resultado = []
    for est in estudiantes:
        est["_id"] = str(est["_id"])
        resultado.append(est)
    return resultado

@app.get("/mis_notas")
async def ver_mis_notas(usuario=Depends(rol_requerido("estudiante"))):
    resultados = notas.find({"estudiante": usuario["username"]})
    salida = []
    for nota in resultados:
        nota["_id"] = str(nota["_id"])
        salida.append(nota)
    return salida

@app.post("/notas")
async def agregar_nota(request: dict, usuario=Depends(rol_requerido("profesor"))):
    notas.insert_one(request)  # usa la colección importada, no la sobrescribas
    return {"mensaje": "Nota registrada correctamente"}
