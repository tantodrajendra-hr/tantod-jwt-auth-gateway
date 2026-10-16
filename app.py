import os
import time
import uuid
import json
import logging
import hashlib
import asyncio
from typing import Optional, Dict, Any, Tuple
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator
from jose import jwt, JWTError
import redis.asyncio as redis

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("auth_gateway")

# Environment configurations with strict fail-safes
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY or SECRET_KEY == "super-secret-principal-key-change-in-production":
    raise RuntimeError("CRITICAL SECURITY ERROR: JWT_SECRET_KEY environment variable is not set or using insecure default value.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

app = FastAPI(title="Distributed JWT Auth & Revocation Gateway", version="2.0.0")
security = HTTPBearer()

redis_client: Optional[redis.Redis] = None

@app.on_event("startup")
async def startup_event():
    global redis_client
    try:
        redis_client = redis.from_url(
            REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=5.0,
            socket_connect_timeout=5.0
        )
        await redis_client.ping()
        logger.info("Successfully connected to Redis backend.")
    except Exception as e:
        logger.critical(f"Failed to connect to Redis during startup: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    if redis_client:
        await redis_client.close()
        logger.info("Redis connection closed.")

# In-memory rate limiting tracker (Fallback / Simple Implementation)
# Production deployments should utilize distributed rate-limiting via Redis keys.
LOGIN_ATTEMPT_STORE: Dict[str, list] = {}

class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not v.isalnum():
            raise ValueError("Username must be alphanumeric")
        return v

class TokenRefresh(BaseModel):
    refresh_token: str = Field(..., min_length=10)

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

def check_rate_limit(key: str, max_requests: int = 5, window_seconds: int = 60):
    """Simple in-memory rate limiter to prevent brute-force attacks."""
    now = time.time()
    attempts = LOGIN_ATTEMPT_STORE.get(key, [])
    attempts = [t for t in attempts if now - t < window_seconds]
    if len(attempts) >= max_requests:
        logger.warning(f"Rate limit exceeded for key: {key}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later."
        )
    attempts.append(now)
    LOGIN_ATTEMPT_STORE[key] = attempts

async def is_blacklisted(jti: str) -> bool:
    try:
        res = await redis_client.get(f"blacklist:{jti}")
        return res is not None
    except Exception as e:
        logger.error(f"Redis error checking blacklist for JTI {jti}: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service temporarily unavailable."
        )

async def blacklist_token(jti: str, exp: int):
    try:
        ttl = exp - int(time.time())
        if ttl > 0:
            await redis_client.setex(f"blacklist:{jti}", ttl, "revoked")
    except Exception as e:
        logger.error(f"Redis error blacklisting JTI {jti}: {e}")

async def get_session(user_id: str, session_id: str) -> Optional[Dict[str, Any]]:
    try:
        key = f"session:{user_id}:{session_id}"
        exists = await redis_client.exists(key)
        if not exists:
            return None
        data = await redis_client.hgetall(key)
        return data if data else None
    except Exception as e:
        logger.error(f"Redis error fetching session for user {user_id}: {e}")
        return None

async def save_session_atomic(user_id: str, session_id: str, data: Dict[str, Any], expire_seconds: int):
    """Saves session data safely using a Redis distributed lock pattern to prevent race conditions."""
    lock_key = f"lock:session:{user_id}:{session_id}"
    lock_val = str(uuid.uuid4())
    acquired = False
    try:
        # Try acquiring lock with a 2-second expiration
        acquired = await redis_client.set(lock_key, lock_val, nx=True, px=2000)
        if not acquired:
            logger.warning(f"Failed to acquire lock for session update: {user_id}:{session_id}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Concurrent session modification detected. Please retry."
            )
        
        key = f"session:{user_id}:{session_id}"
        pipeline = redis_client.pipeline()
        pipeline.delete(key)  # Clear stale hash elements if updating
        pipeline.hset(key, mapping=data)
        pipeline.expire(key, expire_seconds)
        await pipeline.execute()
    except redis.RedisError as e:
        logger.error(f"Redis error saving session atomically: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Internal service error during session management."
        )
    finally:
        if acquired:
            try:
                # Release lock safely using Lua evaluation or direct deletion if value matches
                current_val = await redis_client.get(lock_key)
                if current_val == lock_val:
                    await redis_client.delete(lock_key)
            except Exception:
                pass

async def delete_session(user_id: str, session_id: str):
    try:
        await redis_client.delete(f"session:{user_id}:{session_id}")
    except Exception as e:
        logger.error(f"Redis error deleting session for user {user_id}: {e}")

def create_token(data: dict, expires_delta: int, token_type: str, session_id: str) -> Tuple[str, str]:
    to_encode = data.copy()
    jti = str(uuid.uuid4())
    expire = int(time.time()) + expires_delta
    to_encode.update({
        "exp": expire,
        "jti": jti,
        "type": token_type,
        "sid": session_id
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, jti

@app.post("/api/v1/auth/login", response_model=TokenPair)
async def login(body: UserLogin, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"login:{client_ip}", max_requests=5, window_seconds=60)
    
    # Secure user credential verification placeholder 
    # (In production, replace with salted password hashing validation against a persistent database)
    if body.username != "admin" or body.password != "SecurePassword123!":
        logger.warning(f"Failed login attempt for username: {body.username} from IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    user_id = "usr_" + body.username
    session_id = str(uuid.uuid4())
    
    access_token, _ = create_token(
        {"sub": user_id, "role": "admin"},
        ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "access",
        session_id
    )
    
    refresh_token, _ = create_token(
        {"sub": user_id, "role": "admin"},
        REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        "refresh",
        session_id
    )
    
    session_data = {
        "user_id": user_id,
        "session_id": session_id,
        "user_agent": request.headers.get("user-agent", "unknown")[:256],
        "ip": client_ip,
        "created_at": str(int(time.time()))
    }
    
    await save_session_atomic(user_id, session_id, session_data, REFRESH_TOKEN_EXPIRE_DAYS * 86400)
    logger.info(f"User {user_id} successfully logged in. Session ID: {session_id}")
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/v1/auth/refresh", response_model=TokenPair)
async def refresh_tokens(body: TokenRefresh):
    try:
        payload = jwt.decode(body.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    
    jti = payload.get("jti")
    user_id = payload.get("sub")
    session_id = payload.get("sid")
    
    if not jti or not user_id or not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token claims")
    
    if await is_blacklisted(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
    
    session = await get_session(user_id, session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or terminated")
    
    # Blacklist the consumed refresh token immediately to prevent reuse attacks
    await blacklist_token(jti, payload.get("exp"))
    
    new_access_token, _ = create_token(
        {"sub": user_id, "role": payload.get("role", "user")},
        ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "access",
        session_id
    )
    
    new_refresh_token, _ = create_token(
        {"sub": user_id, "role": payload.get("role", "user")},
        REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        "refresh",
        session_id
    )
    
    await save_session_atomic(user_id, session_id, session, REFRESH_TOKEN_EXPIRE_DAYS * 86400)
    logger.info(f"Tokens refreshed successfully for user {user_id}, session {session_id}")
    
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    
    jti = payload.get("jti")
    user_id = payload.get("sub")
    session_id = payload.get("sid")
    
    if not jti or not user_id or not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token claims")
    
    if await is_blacklisted(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
    
    session = await get_session(user_id, session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session terminated")
    
    return {
        "user_id": user_id,
        "role": payload.get("role"),
        "session_id": session_id,
        "jti": jti,
        "exp": payload.get("exp")
    }

@app.post("/api/v1/auth/logout")
async def logout(current_user: Dict[str, Any] = Depends(get_current_user)):
    await blacklist_token(current_user["jti"], current_user["exp"])
    await delete_session(current_user["user_id"], current_user["session_id"])
    logger.info(f"User {current_user['user_id']} logged out. Session {current_user['session_id']} terminated.")
    return {"detail": "Successfully logged out"}

@app.delete("/api/v1/auth/sessions/{session_id}")
async def revoke_session(session_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    user_id = current_user["user_id"]
    await delete_session(user_id, session_id)
    if current_user["session_id"] == session_id:
        await blacklist_token(current_user["jti"], current_user["exp"])
    logger.info(f"Session {session_id} explicitly revoked by user {user_id}")
    return {"detail": f"Session {session_id} revoked"}

@app.get("/api/v1/protected/resource")
async def protected_resource(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "message": "Access granted to secured distributed resource",
        "user": current_user["user_id"],
        "session": current_user["session_id"]
    }