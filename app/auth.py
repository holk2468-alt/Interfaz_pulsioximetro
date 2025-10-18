from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

load_dotenv()

# Cargar variables de entorno, usando defaults seguros si faltan
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
# Asegurar que la conversión a int sea robusta
try:
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
except ValueError:
    ACCESS_TOKEN_EXPIRE_MINUTES = 60 # Default si la variable no es un número

# Contexto para hashing de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Definición del límite de bytes para bcrypt
BCRYPT_PASSWORD_LIMIT = 72

# --- Manejo de contraseñas ---
def hash_password(password: str) -> str:
    """Hashea una contraseña, truncándola al límite de 72 bytes de bcrypt."""
    # 🚨 CORRECCIÓN 1: Truncamiento para evitar el ValueError en el hasheo
    if len(password.encode('utf-8')) > BCRYPT_PASSWORD_LIMIT:
        password = password[:BCRYPT_PASSWORD_LIMIT]
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica una contraseña, truncándola para compatibilidad con bcrypt."""
    # 🚨 CORRECCIÓN 2: Truncamiento para evitar el ValueError en la verificación (error del log)
    if len(plain_password.encode('utf-8')) > BCRYPT_PASSWORD_LIMIT:
        plain_password = plain_password[:BCRYPT_PASSWORD_LIMIT]
        
    return pwd_context.verify(plain_password, hashed_password)

# --- Manejo de JWT ---
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Crea un JWT de acceso con tiempo de expiración."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    # Asegúrate de que SECRET_KEY no sea None, aunque load_dotenv debería manejarlo
    if not SECRET_KEY:
         raise ValueError("SECRET_KEY no está configurada. No se puede generar el token.")
         
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    """Decodifica un JWT."""
    try:
        if not SECRET_KEY:
            raise ValueError("SECRET_KEY no está configurada. No se puede decodificar el token.")
            
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
    except ValueError:
        # Manejar el caso donde SECRET_KEY es None
        return None
