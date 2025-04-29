import logging
from datetime import datetime, timedelta
from typing import Optional, Dict
from fastapi import FastAPI, HTTPException, status, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from jose import JWTError, jwt
from passlib.context import CryptContext
import asyncio

# --- Configuration ---
SECRET_KEY = "your-production-secret-key"  # Replace with a secure key in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
RATE_LIMIT = 5  # requests
RATE_LIMIT_WINDOW = 60  # seconds

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
logger = logging.getLogger("auth")

# --- Password Hashing Context ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- In-memory user store (for demonstration) ---
fake_users_db = {
    "alice": {
        "username": "alice",
        "hashed_password": pwd_context.hash("SuperSecret123!"),
        "disabled": False,
    }
}
user_lock = asyncio.Lock()  # For thread-safe user registration

# --- In-memory rate limiter (per IP) ---
rate_limit_store: Dict[str, list] = {}

# --- Pydantic Models ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class AuthRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)

    @validator("password")
    def password_complexity(cls, v):
        # At least 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char
        import re
        if (len(v) < 8 or
            not re.search(r"[A-Z]", v) or
            not re.search(r"[a-z]", v) or
            not re.search(r"\d", v) or
            not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v)):
            raise ValueError("Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.")
        return v

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)

    @validator("username")
    def username_alphanumeric(cls, v):
        if not v.isalnum():
            raise ValueError("Username must be alphanumeric.")
        return v

    @validator("password")
    def password_complexity(cls, v):
        import re
        if (len(v) < 8 or
            not re.search(r"[A-Z]", v) or
            not re.search(r"[a-z]", v) or
            not re.search(r"\d", v) or
            not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v)):
            raise ValueError("Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.")
        return v

class RegisterResponse(BaseModel):
    username: str
    message: str

class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=8, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)

    @validator("new_password")
    def password_complexity(cls, v):
        import re
        if (len(v) < 8 or
            not re.search(r"[A-Z]", v) or
            not re.search(r"[a-z]", v) or
            not re.search(r"\d", v) or
            not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v)):
            raise ValueError("Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.")
        return v

class ChangePasswordResponse(BaseModel):
    message: str

class PasswordResetRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)

class PasswordResetTokenResponse(BaseModel):
    reset_token: str
    message: str

class PasswordResetConfirmRequest(BaseModel):
    reset_token: str
    new_password: str = Field(..., min_length=8, max_length=128)

    @validator("new_password")
    def password_complexity(cls, v):
        import re
        if (len(v) < 8 or
            not re.search(r"[A-Z]", v) or
            not re.search(r"[a-z]", v) or
            not re.search(r"\d", v) or
            not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v)):
            raise ValueError("Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.")
        return v

class PasswordResetConfirmResponse(BaseModel):
    message: str

# --- Utility Functions ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    user = db.get(username)
    return user

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Rate Limiting Dependency ---
async def rate_limiter(request: Request):
    ip = request.client.host
    now = datetime.utcnow().timestamp()
    window_start = now - RATE_LIMIT_WINDOW
    timestamps = rate_limit_store.get(ip, [])
    # Remove timestamps outside the window
    timestamps = [ts for ts in timestamps if ts > window_start]
    if len(timestamps) >= RATE_LIMIT:
        logger.warning(f"Rate limit exceeded for IP: {ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later."
        )
    timestamps.append(now)
    rate_limit_store[ip] = timestamps

# --- FastAPI App ---
app = FastAPI()

@app.post("/auth/login", response_model=AuthResponse, status_code=200)
async def login(auth: AuthRequest, request: Request, _: None = Depends(rate_limiter)):
    logger.info(f"Login attempt for user: {auth.username} from IP: {request.client.host}")
    user = authenticate_user(fake_users_db, auth.username, auth.password)
    if not user:
        logger.warning(f"Invalid credentials for user: {auth.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.get("disabled"):
        logger.warning(f"Disabled user login attempt: {auth.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )
    access_token = create_access_token(data={"sub": user["username"]})
    logger.info(f"User {auth.username} authenticated successfully")
    return AuthResponse(access_token=access_token)

@app.post("/auth/register", response_model=RegisterResponse, status_code=201)
async def register(register: RegisterRequest, request: Request):
    logger.info(f"Registration attempt for user: {register.username} from IP: {request.client.host}")
    async with user_lock:
        if register.username in fake_users_db:
            logger.warning(f"Registration failed: Username {register.username} already exists")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )
        hashed_password = pwd_context.hash(register.password)
        fake_users_db[register.username] = {
            "username": register.username,
            "hashed_password": hashed_password,
            "disabled": False,
        }
    logger.info(f"User {register.username} registered successfully")
    return RegisterResponse(username=register.username, message="Registration successful")

# --- JWT Extraction and Validation Dependency ---
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# --- Protected User Profile Endpoint ---
@app.get("/auth/me", response_model=TokenData)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return TokenData(username=current_user["username"])

@app.post("/auth/change-password", response_model=ChangePasswordResponse, status_code=200)
async def change_password(
    req: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user)
):
    username = current_user["username"]
    user = get_user(fake_users_db, username)
    if not user or not verify_password(req.old_password, user["hashed_password"]):
        logger.warning(f"Password change failed for user: {username} (invalid old password)")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Old password is incorrect"
        )
    if verify_password(req.new_password, user["hashed_password"]):
        logger.warning(f"Password change failed for user: {username} (new password same as old)")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the old password"
        )
    fake_users_db[username]["hashed_password"] = pwd_context.hash(req.new_password)
    logger.info(f"Password changed successfully for user: {username}")
    return ChangePasswordResponse(message="Password changed successfully")

@app.post("/auth/request-password-reset", response_model=PasswordResetTokenResponse, status_code=200)
async def request_password_reset(req: PasswordResetRequest):
    user = get_user(fake_users_db, req.username)
    if not user:
        logger.warning(f"Password reset requested for non-existent user: {req.username}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    # Create a short-lived reset token
    reset_token = create_access_token(
        data={"sub": req.username, "reset": True},
        expires_delta=timedelta(minutes=10)
    )
    logger.info(f"Password reset token generated for user: {req.username}")
    # In a real app, send this token via email. Here, return it in the response.
    return PasswordResetTokenResponse(
        reset_token=reset_token,
        message="Password reset token generated. (In production, this would be emailed to the user.)"
    )

@app.post("/auth/confirm-password-reset", response_model=PasswordResetConfirmResponse, status_code=200)
async def confirm_password_reset(req: PasswordResetConfirmRequest):
    try:
        payload = jwt.decode(req.reset_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        is_reset = payload.get("reset")
        if not username or not is_reset:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid reset token"
            )
    except JWTError:
        logger.warning("Invalid or expired password reset token used")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    user = get_user(fake_users_db, username)
    if not user:
        logger.warning(f"Password reset attempted for non-existent user: {username}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    if verify_password(req.new_password, user["hashed_password"]):
        logger.warning(f"Password reset failed for user: {username} (new password same as old)")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the old password"
        )
    fake_users_db[username]["hashed_password"] = pwd_context.hash(req.new_password)
    logger.info(f"Password reset successful for user: {username}")
    return PasswordResetConfirmResponse(message="Password has been reset successfully.")

# --- Custom Exception Handler for Validation Errors ---
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTPException: {exc.detail} (status: {exc.status_code})")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )