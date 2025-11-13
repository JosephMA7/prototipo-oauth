from database import usuarios
import bcrypt

username = input("Nombre de usuario: ")
password_plana = input("Contraseña: ")
rol = input("Rol (admin, profesor, estudiante): ")

password_cifrada = bcrypt.hashpw(password_plana.encode("utf-8"), bcrypt.gensalt())

nuevo_usuario = {
    "username": username,
    "password": password_cifrada,
    "role": rol
}

usuarios.insert_one(nuevo_usuario)
print("Usuario insertado correctamente.")
