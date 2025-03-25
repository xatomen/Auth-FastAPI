
from fastapi.security import OAuth2PasswordBearer
from models import UserModel
import jwt

# Función para hashear la contraseña
def hash_password(password: str):
    return jwt.encode({"password": password},"secret",algorithm="HS256")

# Definimos el esquema de autenticación
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")