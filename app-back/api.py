from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
import jwt
from decouple import Config, RepositoryEnv
from decouple import config

# Importamos sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Time, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
import datetime

# Configuramos la base de datos mysql

config = Config(RepositoryEnv(".env"))

DB_USER = config("DB_USER")
DB_PASSWORD = config("DB_PASSWORD")
DB_HOST = config("DB_HOST")
DB_PORT = config("DB_PORT")
DB_NAME = config("DB_NAME")

SQLALCHEMY_DATABASE_URL = f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Definimos las tablas de la base de datos
Base = declarative_base()

class UserDB(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, nullable=False)

# Definimos el modelo de usuario
class UserModel(BaseModel):
    username: str
    email: str
    password_hash: str

# Función para conectarse a la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Función para hashear la contraseña
def hash_password(password: str):
    return jwt.encode({"password": password},"secret",algorithm="HS256")

# Definimos el esquema de autenticación
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Instanciamos la clase FastAPI
app = FastAPI()

# Crear usuario
@app.post("/create-user")
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
@app.post("/login")
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

# Plantilla de un endpoint seguro
@app.get("/secure-endpoint")
def secure(token: str = Depends(oauth2_scheme)):
    try:
        # Verificamos el token
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        
        ## -------- Acá va la lógica de negocios -------- ##
        
        # Por ejemplo: Mostrar información del usuario
        
        # Accedemos a la base de datos y retornamos toda la información del usuario (exceptuando la contraseña)
        
        db = SessionLocal()
        user_db = db.query(UserDB).filter(UserDB.username == payload["sub"]).first()
        return {
            "username": user_db.username,
            "email": user_db.email,
            "created_at": user_db.created_at,
            "is_admin": user_db.is_admin
        }
        
        ## ---------------------------------------------- ##

    # Si el token expiró, devolvemos un error
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    # Si el token es inválido, devolvemos un error
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")