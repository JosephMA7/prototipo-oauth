from database import oauth_clients
from datetime import datetime

client = {
    "client_id": "edu_client",
    "name": "Frontend SPA - Plataforma Educativa",
    "redirect_uri": "http://localhost:8000/static/oauth_callback.html",
    "confidential": False,
    "created_at": datetime.utcnow()
}

oauth_clients.insert_one(client)
print("Cliente registrado: edu_client")
