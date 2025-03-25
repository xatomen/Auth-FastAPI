from pydantic import BaseModel

# Definimos el modelo de usuario
class UserModel(BaseModel):
    username: str
    email: str
    password_hash: str