# Router de ejemplo

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

# Plantilla de un endpoint seguro
@router.get("/secure-endpoint", tags=["Template"])
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