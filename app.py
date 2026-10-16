import os
import time
import uuid
import json
import logging
import asyncio
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
import redis.asyncio as redis
from jose import jwt, JWTError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("AuthGateway")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
JWT_ISSUER = os.getenv("JWT_ISSUER", "auth-gateway-cluster")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "api-services")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

PRIVATE_KEY_PEM = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode("utf-8")

PUBLIC_KEY_PEM = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")

redis_client: Optional[redis.Redis] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    logger.info(f"Initializing Redis connection pool at {REDIS_URL}")
    redis_client = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=5.0)
    try:
        await redis_client.ping()
        logger.info("Redis connection established successfully.")
    except Exception as e:
        logger.critical(f"Failed to connect to Redis: {e}")
        raise e
    
    yield
    
    logger.info("Closing Redis connection pool.")
    await redis_client.close()

app = FastAPI(title="Distributed JWT Auth Gateway", version="1.0.0", lifespan=lifespan)
security = HTTPBearer()

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    roles: List[str] = Field(default_factory=lambda: ["user"])

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class SessionMetadata(BaseModel):
    user_id: str
    session_id: str
    device_info: Optional[str] = None
    ip_address: Optional[str] = None

async def get_redis() -> redis.Redis:
    if not redis_client:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Redis client not initialized")
    return redis_client

def hash_password(password: str) -> str:
    import hashlib
    import hmac
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ":" + pwd_hash.hex()

def verify_password(stored_password: str, provided_password: str) -> bool:
    try:
        salt_hex, pwd_hash_hex = stored_password.split(":")
        salt = bytes.fromhex(salt_hex)
        pwd_hash = bytes.fromhex(pwd_hash_hex)
        new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return hmac.compare_digest(pwd_hash, new_hash)
    except Exception:
        return False

def create_jwt_token(subject: str, session_id: str, roles: List[str], expires_delta: int, is_refresh: bool = False) -> str:
    now = int(time.time())
    expire = now + expires_delta
    payload = {
        "sub": subject,
        "sid": session_id,
        "roles": roles,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": expire,
        "type": "refresh" if is_refresh else "access"
    }
    encoded_jwt = jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256")
    return encoded_jwt

async def is_session_revoked(r: redis.Redis, user_id: str, session_id: str, token_iat: int) -> bool:
    user_revocation_key = f"revocation:user:{user_id}"
    global_revocation_ts = await r.get(user_revocation_key)
    if global_revocation_ts and token_iat < int(global_revocation_ts):
        return True

    session_key = f"session:{user_id}:{session_id}"
    session_data = await r.get(session_key)
    if not session_data:
        return True

    return False

@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister, r: redis.Redis = Depends(get_redis)):
    user_key = f"user:email:{user_data.email}"
    exists = await r.exists(user_key)
    if exists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user_id = str(uuid.uuid4())
    hashed_pwd = hash_password(user_data.password)
    
    user_record = {
        "user_id": user_id,
        "email": user_data.email,
        "password": hashed_pwd,
        "roles": json.dumps(user_data.roles)
    }

    await r.hset(f"user:id:{user_id}", mapping=user_record)
    await r.set(user_key, user_id)

    logger.info(f"User registered: {user_id}")
    return {"message": "User registered successfully", "user_id": user_id}

@app.post("/auth/login", response_model=TokenPair)
async def login(credentials: UserLogin, request: Request, r: redis.Redis = Depends(get_redis)):
    user_id = await r.get(f"user:email:{credentials.email}")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user_record = await r.hgetall(f"user:id:{user_id}")
    if not user_record or not verify_password(user_record["password"], credentials.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    session_id = str(uuid.uuid4())
    roles = json.loads(user_record["roles"])

    access_token_ttl = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_token_ttl = REFRESH_TOKEN_EXPIRE_DAYS * 86400

    access_token = create_jwt_token(user_id, session_id, roles, access_token_ttl, is_refresh=False)
    refresh_token = create_jwt_token(user_id, session_id, roles, refresh_token_ttl, is_refresh=True)

    session_key = f"session:{user_id}:{session_id}"
    session_meta = {
        "user_id": user_id,
        "session_id": session_id,
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
        "created_at": int(time.time())
    }
    
    await r.setex(session_key, refresh_token_ttl, json.dumps(session_meta))
    await r.sadd(f"user_sessions:{user_id}", session_id)

    logger.info(f"Session established: user={user_id} sid={session_id}")
    return TokenPair(access_token=access_token, refresh_token=refresh_token)

@app.post("/auth/refresh", response_model=TokenPair)
async def refresh_tokens(body: TokenRefreshRequest, r: redis.Redis = Depends(get_redis)):
    try:
        payload = jwt.decode(
            body.refresh_token,
            PUBLIC_KEY_PEM,
            algorithms=["RS256"],
            options={"verify_aud": True},
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER
        )
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid refresh token: {str(e)}")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = payload.get("sub")
    session_id = payload.get("sid")
    iat = payload.get("iat")
    roles = payload.get("roles", [])

    if await is_session_revoked(r, user_id, session_id, iat):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session revoked or expired")

    access_token_ttl = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_token_ttl = REFRESH_TOKEN_EXPIRE_DAYS * 86400

    new_access_token = create_jwt_token(user_id, session_id, roles, access_token_ttl, is_refresh=False)
    new_refresh_token = create_jwt_token(user_id, session_id, roles, refresh_token_ttl, is_refresh=True)

    logger.info(f"Tokens refreshed for user={user_id} sid={session_id}")
    return TokenPair(access_token=new_access_token, refresh_token=new_refresh_token)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), r: redis.Redis = Depends(get_redis)) -> Dict[str, Any]:
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY_PEM,
            algorithms=["RS256"],
            options={"verify_aud": True},
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER
        )
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid authentication credentials: {str(e)}")

    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = payload.get("sub")
    session_id = payload.get("sid")
    iat = payload.get("iat")

    if await is_session_revoked(r, user_id, session_id, iat):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been revoked")

    return {
        "user_id": user_id,
        "session_id": session_id,
        "roles": payload.get("roles", [])
    }

@app.post("/auth/logout")
async def logout(current_user: Dict[str, Any] = Depends(get_current_user), r: redis.Redis = Depends(get_redis)):
    user_id = current_user["user_id"]
    session_id = current_user["session_id"]

    session_key = f"session:{user_id}:{session_id}"
    await r.delete(session_key)
    await r.srem(f"user_sessions:{user_id}", session_id)

    logger.info(f"Session terminated (logout): user={user_id} sid={session_id}")
    return {"message": "Successfully logged out"}

@app.post("/auth/revoke-all")
async def revoke_all_sessions(current_user: Dict[str, Any] = Depends(get_current_user), r: redis.Redis = Depends(get_redis)):
    user_id = current_user["user_id"]
    current_time = int(time.time())

    user_revocation_key = f"revocation:user:{user_id}"
    await r.set(user_revocation_key, current_time)
    await r.expire(user_revocation_key, REFRESH_TOKEN_EXPIRE_DAYS * 86400)

    session_ids = await r.smembers(f"user_sessions:{user_id}")
    if session_ids:
        pipe = r.pipeline()
        for sid in session_ids:
            pipe.delete(f"session:{user_id}:{sid}")
        pipe.delete(f"user_sessions:{user_id}")
        await pipe.execute()

    logger.warning(f"All sessions globally revoked for user={user_id} at timestamp {current_time}")
    return {"message": "All sessions revoked successfully"}

@app.get("/auth/sessions")
async def list_sessions(current_user: Dict[str, Any] = Depends(get_current_user), r: redis.Redis = Depends(get_redis)):
    user_id = current_user["user_id"]
    session_ids = await r.smembers(f"user_sessions:{user_id}")
    
    sessions = []
    pipe = r.pipeline()
    for sid in session_ids:
        pipe.get(f"session:{user_id}:{sid}")
    
    results = await pipe.execute()
    for res in results:
        if res:
            sessions.append(json.loads(res))

    return {"active_sessions": sessions}

@app.get("/secure/resource")
async def protected_resource(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "message": "Access granted to secured enterprise infrastructure",
        "user_id": current_user["user_id"],
        "session_id": current_user["session_id"],
        "roles": current_user["roles"]
    }

@app.get("/.well-known/jwks.json")
async def jwks():
    public_numbers = public_key.public_numbers()
    import base64
    def int_to_base64(n: int) -> str:
        byte_length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(byte_length, "big")).rstrip(b"=").decode("utf-8")

    jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
        "kid": "gateway-primary-key"
    }
    return {"keys": [jwk]}