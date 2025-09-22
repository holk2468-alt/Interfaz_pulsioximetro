from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import router

app = FastAPI()

# Configuración de CORS para permitir solicitudes desde el frontend en Vercel
origins = [
    "http://localhost:3000",
    "https://interfaz-pulsioximetro.onrender.com",
    "https://frontend-pulsioximetro.vercel.app"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"mensaje": "API del Sistema Médico funcionando 🚀"}

app.include_router(router)
