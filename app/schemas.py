from pydantic import BaseModel, Field
from datetime import datetime, date
from typing import Optional

class PacienteRegister(BaseModel):
    nombre: str
    apellido: str
    cedula: str
    password: str
    fecha_nacimiento: date
    genero: str = Field(..., pattern="^(M|F)$")

class UsuarioUpdate(BaseModel):
    nombre: Optional[str]
    apellido: Optional[str]
    password: Optional[str]
    fecha_nacimiento: Optional[date]
    genero: Optional[str] = Field(None, pattern="^(M|F)$")
    rol: Optional[str]

class MedicionUpdate(BaseModel):
    ritmo_cardiaco: Optional[int]
    spo2: Optional[int]
    fecha_hora: Optional[datetime]

class AlertaUpdate(BaseModel):
    leida: bool
