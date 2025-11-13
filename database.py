from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "jwt_tesis")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

usuarios = db["usuarios"]
tareas = db["tareas"]
notas = db["notas"]
oauth_clients = db["oauth_clients"]
oauth_codes = db["oauth_codes"]
