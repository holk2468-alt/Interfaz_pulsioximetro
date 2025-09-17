from fastapi import FastAPI
from app.routes import router

app = FastAPI()

@app.get("/")
def root():
    return {"mensaje": "API del Sistema Médico funcionando 🚀"}

# Montar todas las rutas
app.include_router(router)



