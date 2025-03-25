# Router de autenticación

# Importamos configruación de la base de datos
from database import *

# Importamos el modelo de usuario desde la base de datos
from models import UserModel

# Importamos la lógica de seguridad
from security import *

# Importamos las librerías necesarias
from fastapi import APIRouter, Depends, HTTPException
from models import UserModel
import datetime

# Instanciamos el router
router = APIRouter()

# Crear usuario
@router.post("/create-user", tags=["Auth"])
def create_user(user: UserModel, db: Session = Depends(get_db)):
    # Verificar si el nombre de usuario ya existe
    existing_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Verificar si el correo electrónico ya existe
    existing_email = db.query(UserDB).filter(UserDB.email == user.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")
    # Si no existe, creamos el usuario
    new_user = UserDB(
        username=user.username,
        email=user.email,
        password_hash=hash_password(user.password_hash),
        created_at=datetime.datetime.now(),
        is_admin=False
        )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# Inicio de sesión
@router.post("/login", tags=["Auth"])
def login(user: UserModel, db: Session = Depends(get_db)):
    # Buscamos el usuario en la base de datos
    user_db = db.query(UserDB).filter(UserDB.username == user.username).first()
    # Si el usuario no existe, no autorizaoms
    if not user_db:
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Si la contraseña no coincide, no autorizamos
    if user_db.password_hash != hash_password(user.password_hash):
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Si todo está bien, generamos el token y lo devolvemos
    token_data = {
        "sub": user_db.username,
        "exp": datetime.datetime.now() + datetime.timedelta(minutes=1)
        }
    token = jwt.encode(token_data, "secret", algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}
