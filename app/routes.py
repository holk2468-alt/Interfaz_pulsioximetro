from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.database import supabase
from app.auth import verify_password, create_access_token, decode_token, hash_password

from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional

router = APIRouter()

# OAuth2 para Swagger
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- MODELO PARA REGISTRO ---
from pydantic import BaseModel, EmailStr, validator

class RegisterPaciente(BaseModel):
    nombre: str
    correo: EmailStr
    password: str
    cedula: str

    @validator("cedula")
    def validar_cedula(cls, v):
        if not v.isdigit():
            raise ValueError("La cédula solo puede contener números")
        return v



# -----------------------
# REGISTRO PARA PACIENTES
# -----------------------
@router.post("/register_paciente")
async def register_paciente(new_paciente: PacienteRegister):
    existing = supabase.table("usuarios").select("cedula").eq("cedula", new_paciente.cedula).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Cédula ya registrada")

    # El resto de tu lógica de registro
    data_to_insert = new_paciente.model_dump()
    password_to_hash = data_to_insert.pop("password")
    data_to_insert["password_hash"] = hash_password(password_to_hash)
    data_to_insert["rol"] = "paciente"

    supabase.table("usuarios").insert(data_to_insert).execute()
    return {"mensaje": "Usuario registrado exitosamente como paciente"}
# -----------------------
# LOGIN
# -----------------------
@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        cedula = int(form_data.username)
    except ValueError:
        raise HTTPException(status_code=400, detail="La cédula debe ser numérica")

    result = supabase.table("usuarios").select("*").eq("cedula", cedula).execute()
    if not result.data:
        raise HTTPException(status_code=400, detail="Usuario no encontrado")
    
    user = result.data[0]
    if not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")
    
    access_token = create_access_token({"sub": user["cedula"], "rol": user["rol"]})
    return {"access_token": access_token, "token_type": "bearer"}


# -----------------------
# OBTENER USUARIOS
# -----------------------
@router.get("/usuarios")
async def get_usuarios(
    token: str = Depends(oauth2_scheme),
    cedula: str = None,
    genero: str = None,
    fecha_nacimiento_min: str = None,
    fecha_nacimiento_max: str = None,
    rol: str = None,
):
    usuario_token = decode_token(token)
    if not usuario_token:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol_usuario = usuario_token["rol"]
    cedula_usuario = str(usuario_token["sub"])

    # Inicializa la consulta a la tabla "usuarios"
    query = supabase.table("usuarios").select("cedula", "nombre", "apellido", "fecha_nacimiento", "genero", "rol")

    # Lógica de permisos
    if rol_usuario == "paciente":
        if cedula and cedula != cedula_usuario:
            raise HTTPException(status_code=403, detail="No autorizado a ver este usuario")
        query = query.eq("cedula", cedula_usuario)

    elif rol_usuario == "medico":
        if cedula:
            if cedula == cedula_usuario:
                query = query.eq("cedula", cedula_usuario)
            else:
                # Paso 1: Intentamos obtener el rol del usuario buscado.
                # Si falla, significa que la cédula no existe.
                try:
                    target_user_result = supabase.table("usuarios").select("rol").eq("cedula", cedula).single().execute()
                    target_rol = target_user_result.data.get("rol")
                except:
                    raise HTTPException(status_code=404, detail="Usuario no encontrado.")
                
                # Paso 2: Si el usuario existe, validamos los permisos.
                if target_rol in ["medico", "admin"]:
                    raise HTTPException(status_code=403, detail="No tiene permiso para buscar a este tipo de usuario.")
                
                # Paso 3: Si es un paciente, se procede con la búsqueda.
                query = query.eq("cedula", cedula)
        else:
            query = query.or_(f"rol.eq.paciente, cedula.eq.{cedula_usuario}")
            
    elif rol_usuario == "admin":
        if cedula:
            # Para el admin, solo verificamos si el usuario existe
            try:
                supabase.table("usuarios").select("cedula").eq("cedula", cedula).single().execute()
            except:
                raise HTTPException(status_code=404, detail="Usuario no encontrado.")
            query = query.eq("cedula", cedula)
        
    else:
        raise HTTPException(status_code=403, detail="Rol de usuario no válido")

    # Filtros adicionales
    if rol_usuario in ["medico", "admin"]:
        if genero:
            query = query.eq("genero", genero)
        if fecha_nacimiento_min:
            query = query.gte("fecha_nacimiento", fecha_nacimiento_min)
        if fecha_nacimiento_max:
            query = query.lte("fecha_nacimiento", fecha_nacimiento_max)
        if rol:
            if rol_usuario == "medico" and rol != "paciente":
                raise HTTPException(status_code=403, detail="Un médico solo puede filtrar por el rol de 'paciente'.")
            elif rol_usuario == "admin":
                query = query.eq("rol", rol)
        
    query = query.order("cedula")
    result = query.execute()
    filas = result.data or []

    # Se ajusta la respuesta final
    if not filas:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if rol_usuario == "paciente":
        return {"usuario": filas[0]}
    else:
        return {"usuarios": filas}
        
# -----------------------
# CREAR USUARIOS
# -----------------------
@router.post("/usuarios")
async def create_usuario(new_user: dict, token: str = Depends(oauth2_scheme)):
    usuario = decode_token(token)
    if not usuario:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol_actual = usuario["rol"]

    if rol_actual == "paciente" or (rol_actual == "medico" and new_user.get("rol") != "paciente"):
        raise HTTPException(status_code=403, detail="No autorizado para crear este usuario")

    existing = supabase.table("usuarios").select("*").eq("cedula", new_user["cedula"]).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Cédula ya registrada")

    new_user["password_hash"] = hash_password(new_user.pop("password"))
    supabase.table("usuarios").insert(new_user).execute()
    return {"mensaje": "Usuario creado exitosamente"}


# -----------------------
# ACTUALIZAR USUARIO
# -----------------------
@router.put("/usuarios/{cedula_actualizar}")
async def update_usuario(cedula_actualizar: str, datos: dict, token: str = Depends(oauth2_scheme)):
    usuario = decode_token(token)
    if not usuario:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol_actual = usuario["rol"]
    cedula = usuario["sub"]

    if rol_actual == "paciente" and cedula != cedula_actualizar:
        raise HTTPException(status_code=403, detail="No autorizado")

    if rol_actual == "medico":
        result = supabase.table("usuarios").select("rol").eq("cedula", cedula_actualizar).execute()
        if not result.data:
            raise HTTPException(status_code=404, detail="Usuario a actualizar no encontrado")
        rol_target = result.data[0]["rol"]
        if cedula_actualizar != cedula and rol_target != "paciente":
            raise HTTPException(status_code=403, detail="No autorizado para actualizar este usuario")
        if "rol" in datos:
            raise HTTPException(status_code=403, detail="No autorizado para cambiar el rol de un usuario")

    if rol_actual == "paciente" and "rol" in datos:
        raise HTTPException(status_code=403, detail="No autorizado para cambiar el rol de un usuario")

    if "cedula" in datos:
        nueva_cedula = datos["cedula"]
        existente = supabase.table("usuarios").select("*").eq("cedula", nueva_cedula).execute().data
        if existente and existente[0]["cedula"] != cedula_actualizar:
            raise HTTPException(status_code=400, detail="La cédula que intenta asignar ya está registrada")

    if "password" in datos:
        datos["password_hash"] = hash_password(datos.pop("password"))

    supabase.table("usuarios").update(datos).eq("cedula", cedula_actualizar).execute()
    return {"mensaje": "Usuario actualizado exitosamente"}


# -----------------------
# ELIMINAR USUARIO
# -----------------------
@router.delete("/usuarios/{cedula_eliminar}")
async def delete_usuario(cedula_eliminar: int, token: str = Depends(oauth2_scheme)):
    usuario = decode_token(token)
    if not usuario:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol_actual = usuario["rol"]
    if rol_actual != "admin":
        raise HTTPException(status_code=403, detail="No autorizado")

    # Paso 1: Verificar si el usuario existe
    result = supabase.table("usuarios").select("cedula").eq("cedula", cedula_eliminar).execute()
    
    # Paso 2: Si la lista de datos está vacía, el usuario no existe.
    if not result.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Paso 3: Si el usuario existe, se procede con la eliminación
    supabase.table("usuarios").delete().eq("cedula", cedula_eliminar).execute()
    return {"mensaje": "Usuario eliminado exitosamente"}


# -----------------------
# ACTUALIZAR MEDICIONES
# -----------------------
@router.put("/mediciones/{id}")
async def update_medicion(id: int, datos: dict, token: str = Depends(oauth2_scheme)):
    usuario = decode_token(token)
    if not usuario:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol = usuario["rol"]
    cedula = usuario["sub"]

    if rol == "paciente":
        raise HTTPException(status_code=403, detail="No autorizado para actualizar mediciones")

    campos_prohibidos = ["id", "cedula_paciente"]
    for campo in campos_prohibidos:
        if campo in datos:
            raise HTTPException(status_code=400, detail=f"No se puede actualizar el campo '{campo}'")

    result = supabase.table("mediciones").select("*").eq("id", id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Medición no encontrada")

    medicion = result.data[0]

    if rol == "medico":
        if medicion["cedula_paciente"] != cedula and supabase.table("usuarios").select("rol").eq("cedula", medicion["cedula_paciente"]).execute().data[0]["rol"] != "paciente":
            raise HTTPException(status_code=403, detail="No autorizado para actualizar esta medición")

    campos_permitidos = ["ritmo_cardiaco", "spo2", "fecha_hora"]
    datos_filtrados = {k: v for k, v in datos.items() if k in campos_permitidos}

    if not datos_filtrados:
        raise HTTPException(status_code=400, detail="No hay campos válidos para actualizar")

    supabase.table("mediciones").update(datos_filtrados).eq("id", id).execute()
    return {"mensaje": "Medición actualizada exitosamente"}


# -----------------------
# ELIMINAR MEDICIONES
# -----------------------
@router.delete("/mediciones/{id}")
async def delete_medicion(id: int, token: str = Depends(oauth2_scheme)):
    usuario = decode_token(token)
    if not usuario:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol_actual = usuario["rol"]
    if rol_actual != "admin":
        raise HTTPException(status_code=403, detail="No autorizado para eliminar registros")

    result = supabase.table("mediciones").select("id").eq("id", id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Medición no encontrada")

    supabase.table("mediciones").delete().eq("id", id).execute()
    return {"mensaje": f"Medición con id {id} eliminada exitosamente"}


# -----------------------
# CONSULTAR MEDICIONES
# -----------------------
@router.get("/mediciones")
async def get_mediciones(
    token: str = Depends(oauth2_scheme),
    cedula: str = None,
    rol: str = None,
    fecha_min: str = None,
    fecha_max: str = None,
    spo2_min: int = None,
    spo2_max: int = None,
    ritmo_min: int = None,
    ritmo_max: int = None,
):
    usuario = decode_token(token)
    if not usuario:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol_usuario = usuario["rol"]
    cedula_usuario = usuario["sub"]

    usuarios_all = supabase.table("usuarios").select("cedula", "rol").execute().data or []

    if rol_usuario == "paciente":
        cedulas_validas = [cedula_usuario]
        if rol:
            raise HTTPException(status_code=403, detail="No autorizado a filtrar por rol")
    elif rol_usuario == "medico":
        pacientes = [str(u["cedula"]) for u in usuarios_all if u["rol"] == "paciente"]
        cedulas_validas = pacientes + [str(cedula_usuario)]
        if rol:
            raise HTTPException(status_code=403, detail="No autorizado a filtrar por rol")
    elif rol_usuario == "admin":
        cedulas_validas = [str(u["cedula"]) for u in usuarios_all]
        if rol and rol not in ["paciente", "medico", "admin"]:
            raise HTTPException(status_code=400, detail="Rol inválido para filtrar")
    else:
        raise HTTPException(status_code=403, detail="Rol de usuario no válido")

    query = supabase.table("mediciones").select("*")

    if cedula:
        if rol_usuario == "paciente":
            raise HTTPException(status_code=403, detail="No autorizado a filtrar por cédula")
        if cedula not in cedulas_validas:
            raise HTTPException(status_code=403, detail="No autorizado a ver este paciente")
        query = query.eq("cedula_paciente", cedula)
    else:
        query = query.in_("cedula_paciente", cedulas_validas)

    if rol and rol_usuario == "admin":
        cedulas_filtradas_por_rol = [str(u["cedula"]) for u in usuarios_all if u["rol"] == rol]
        if not cedulas_filtradas_por_rol:
            return {"mediciones": []}
        query = query.in_("cedula_paciente", cedulas_filtradas_por_rol)

    if fecha_min:
        if len(fecha_min) == 10:
            fecha_min += "T00:00:00"
        query = query.gte("fecha_hora", fecha_min)
    if fecha_max:
        if len(fecha_max) == 10:
            fecha_max += "T23:59:59"
        query = query.lte("fecha_hora", fecha_max)
    
    if spo2_min is not None:
        query = query.gte("spo2", spo2_min)
    if spo2_max is not None:
        query = query.lte("spo2", spo2_max)

    if ritmo_min is not None:
        query = query.gte("ritmo_cardiaco", ritmo_min)
    if ritmo_max is not None:
        query = query.lte("ritmo_cardiaco", ritmo_max)

    result = query.execute()
    filas = result.data or []

    filas.sort(key=lambda x: x["fecha_hora"], reverse=True)
    filas.sort(key=lambda x: x["cedula_paciente"])

    return {"mediciones": filas}

# -----------------------
# CONSULTAR ALERTAS
# -----------------------
@router.get("/alertas")
async def get_alertas(
    token: str = Depends(oauth2_scheme),
    cedula: str = None,
    tipo_alerta: str = None,
    fecha_min: str = None,
    fecha_max: str = None,
    leida: Optional[bool] = None
):
    usuario = decode_token(token)
    if not usuario:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol_usuario = usuario["rol"]
    cedula_usuario = str(usuario["sub"])

    # Iniciar la consulta a la tabla de alertas
    query = supabase.table("alertas").select("*")

    # Lógica de permisos y filtros por cédula
    if rol_usuario == "paciente":
        # Se añade un control explícito para evitar que los pacientes filtren por cédula
        if cedula and cedula != cedula_usuario:
            raise HTTPException(status_code=403, detail="No tiene permiso para filtrar por cédula de otro paciente")
        query = query.eq("cedula_paciente", cedula_usuario)
    elif rol_usuario in ["medico", "admin"]:
        if cedula:
            query = query.eq("cedula_paciente", cedula)

    # Filtros universales (aplicables a todos los roles)
    if tipo_alerta:
        query = query.eq("tipo_alerta", tipo_alerta.upper())
    if leida is not None:
        query = query.eq("leida", leida)
    if fecha_min:
        if len(fecha_min) == 10:
            fecha_min += "T00:00:00"
        query = query.gte("fecha_hora", fecha_min)
    if fecha_max:
        if len(fecha_max) == 10:
            fecha_max += "T23:59:59"
        query = query.lte("fecha_hora", fecha_max)

    result = query.execute()
    filas = result.data or []

    # Se aplican los tres criterios de ordenación de manera secuencial (el último es el principal)
    # 1. Por fecha (descendente)
    filas.sort(key=lambda x: x["fecha_hora"], reverse=True)
    # 2. Por tipo de alerta (ascendente)
    filas.sort(key=lambda x: x["tipo_alerta"], reverse=False)
    # 3. Por cédula de paciente (ascendente)
    filas.sort(key=lambda x: x["cedula_paciente"], reverse=False)

    return {"alertas": filas}

# -----------------------
# ACTUALIZAR ALERTA
# -----------------------
class AlertaUpdate(BaseModel):
    leida: bool

@router.put("/alertas/{id}")
async def update_alerta(id: int, datos: AlertaUpdate, token: str = Depends(oauth2_scheme)):
    usuario = decode_token(token)
    if not usuario:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol = usuario["rol"]
    if rol not in ["medico", "admin"]:
        raise HTTPException(status_code=403, detail="No autorizado para actualizar alertas")
    
    result = supabase.table("alertas").select("id").eq("id", id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
        
    supabase.table("alertas").update({"leida": datos.leida}).eq("id", id).execute()
    return {"mensaje": f"Alerta con ID {id} actualizada exitosamente."}


# -----------------------
# ELIMINAR ALERTA
# -----------------------
@router.delete("/alertas/{id}")
async def delete_alerta(id: int, token: str = Depends(oauth2_scheme)):
    usuario = decode_token(token)
    if not usuario:
        raise HTTPException(status_code=401, detail="No autenticado")

    rol_actual = usuario["rol"]
    if rol_actual != "admin":
        raise HTTPException(status_code=403, detail="No autorizado para eliminar alertas")

    result = supabase.table("alertas").select("id").eq("id", id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")

    supabase.table("alertas").delete().eq("id", id).execute()
    return {"mensaje": f"Alerta con ID {id} eliminada exitosamente"}
