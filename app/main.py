from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import router

app = FastAPI()

# La configuración de CORS debe ir aquí, justo después de app = FastAPI()
origins = [
    "http://localhost:3000",
    "https://interfaz-pulsioximetro.onrender.com"
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
