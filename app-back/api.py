from fastapi import FastAPI

from routers.auth import auth
from routers.template import template

# Instanciamos la clase FastAPI
app = FastAPI()

# Incluimos las rutas de autenticación
app.include_router(auth.router)
app.include_router(template.router)