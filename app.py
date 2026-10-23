import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Dict, Optional, Tuple, Any

import redis.asyncio as redis
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# FastAPI & Uvicorn for Gateway Core
from fastapi import FastAPI, Request, Response, HTTPException, status, Depends
from fastapi.responses import JSONResponse
import uvicorn

# -----------------------------------------------------------------------------
# Configuration & Logging
# -----------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("GatewayAuth")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ACCESS_TOKEN_TTL = int(os.getenv("ACCESS_TOKEN_TTL", 900))      # 15 minutes
REFRESH_TOKEN_TTL = int(os.getenv("REFRESH_TOKEN_TTL", 604800)) # 7 days
SLIDING_WINDOW_TTL = int(os.getenv("SLIDING_WINDOW_TTL", 86400))# 1 day

# -----------------------------------------------------------------------------
# Cryptographic Engine (RS256 with Asymmetric Keys)
# -----------------------------------------------------------------------------
class CryptoEngine:
    def __init__(self):
        logger.info("Initializing Cryptographic Engine (RSA 2048)...")
        # Secure Key Storage: In production, load private key securely via KMS or Environment variables.
        private_key_pem = os.getenv("RSA_PRIVATE_KEY_PEM")
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        self.public_key = self.private_key.public_key()
        
    def get_public_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def get_jwk_components(self) -> Dict[str, str]:
        public_numbers = self.public_key.public_numbers()
        n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')
        e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')
        return {
            "n": self._base64url_encode(n_bytes),
            "e": self._base64url_encode(e_bytes)
        }

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _base64url_decode(data: str) -> bytes:
        padding = 4 - (len(data) % 4)
        if padding < 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data.encode("utf-8"))

    def sign(self, payload: Dict[str, Any]) -> str:
        header = {"alg": "RS256", "typ": "JWT"}
        enc_header = self._base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        enc_payload = self._base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        
        signing_input = f"{enc_header}.{enc_payload}".encode("utf-8")
        signature = self.private_key.sign(
            signing_input,
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            cryptography.hazmat.hashes.SHA256()
        )
        enc_sig = self._base64url_encode(signature)
        return f"{enc_header}.{enc_payload}.{enc_sig}"

    def verify(self, token: str) -> Dict[str, Any]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Malformed token format")
            
            enc_header, enc_payload, enc_sig = parts
            
            # Prevent padding oracle / length check attacks
            if len(enc_sig) < 10 or len(enc_header) < 10 or len(enc_payload) < 10:
                raise ValueError("Invalid token structural length")

            signing_input = f"{enc_header}.{enc_payload}".encode("utf-8")
            signature = self._base64url_decode(enc_sig)
            
            self.public_key.verify(
                signature,
                signing_input,
                cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
                cryptography.hazmat.hashes.SHA256()
            )
            
            payload_data = json.loads(self._base64url_decode(enc_payload).decode("utf-8"))
            if payload_data.get("exp", 0) < time.time():
                raise ValueError("Token expired")
            return payload_data
        except Exception as e:
            raise ValueError(f"Token verification failed: {str(e)}")

crypto = CryptoEngine()

# -----------------------------------------------------------------------------
# Redis Persistence & Session Store
# -----------------------------------------------------------------------------
class SessionManager:
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis: Optional[redis.Redis] = None

    async def connect(self, retries: int = 5, delay: float = 2.0):
        for attempt in range(1, retries + 1):
            try:
                self.redis = redis.from_url(self.redis_url, decode_responses=True)
                await self.redis.ping()
                logger.info("Successfully connected to Redis persistence layer.")
                return
            except Exception as e:
                logger.warning(f"Redis connection attempt {attempt} failed: {e}. Retrying in {delay}s...")
                if attempt == retries:
                    raise
                await asyncio.sleep(delay)
                delay *= 2

    async def close(self):
        if self.redis:
            await self.redis.close()

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def blacklist_token(self, token: str, ttl: int):
        if ttl <= 0:
            return
        token_hash = self._hash_token(token)
        await self.redis.set(f"bl:{token_hash}", "revoked", ex=ttl)

    async def is_blacklisted(self, token: str) -> bool:
        token_hash = self._hash_token(token)
        val = await self.redis.get(f"bl:{token_hash}")
        return val is not None

    async def store_session(self, user_id: str, session_id: str, refresh_token: str, ttl: int):
        rt_hash = self._hash_token(refresh_token)
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.set(f"session:{session_id}", user_id, ex=ttl, nx=True)
            pipe.set(f"rt:{rt_hash}", session_id, ex=ttl, nx=True)
            await pipe.execute()

    async def get_session_user(self, session_id: str) -> Optional[str]:
        return await self.redis.get(f"session:{session_id}")

    async def invalidate_session(self, session_id: str):
        user_id = await self.get_session_user(session_id)
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.delete(f"session:{session_id}")
            if user_id:
                pipe.incr(f"user_revocation_epoch:{user_id}")
            await pipe.execute()

    async def invalidate_all_user_sessions(self, user_id: str):
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.incr(f"user_revocation_epoch:{user_id}")
            await pipe.execute()

    async def get_user_epoch(self, user_id: str) -> int:
        epoch = await self.redis.get(f"user_revocation_epoch:{user_id}")
        return int(epoch) if epoch else 0

session_manager = SessionManager(REDIS_URL)

# -----------------------------------------------------------------------------
# Gateway Core & FastAPI Application
# -----------------------------------------------------------------------------
app = FastAPI(title="Distributed JWT Auth & Revocation Gateway", version="1.0.0")

@app.on_event("startup")
async def startup_event():
    await session_manager.connect()

@app.on_event("shutdown")
async def shutdown_event():
    await session_manager.close()

# -----------------------------------------------------------------------------
# Authentication & Gateway Middleware / Dependencies
# -----------------------------------------------------------------------------
async def get_current_user(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header"
        )
    
    token = auth_header.split(" ")[1]
    
    # 1. Check token level revocation blacklist
    if await session_manager.is_blacklisted(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been explicitly revoked"
        )
        
    # 2. Verify cryptographically and extract claims
    try:
        claims = crypto.verify(token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
        
    # 3. Check session structural validity
    session_id = claims.get("sid")
    user_id = claims.get("sub")
    
    if not session_id or not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token structure"
        )
        
    active_user = await session_manager.get_session_user(session_id)
    if not active_user or active_user != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalidated globally"
        )
        
    # 4. Check user revocation epoch (global user logout pattern)
    token_epoch = claims.get("epoch", 0)
    current_epoch = await session_manager.get_user_epoch(user_id)
    if token_epoch < current_epoch:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User sessions invalidated via security reset"
        )
        
    return claims

# -----------------------------------------------------------------------------
# Gateway Route Endpoints
# -----------------------------------------------------------------------------

@app.post("/auth/v1/login", tags=["Authentication"])
async def login(credentials: dict):
    username = credentials.get("username")
    password = credentials.get("password")
    
    # Placeholder User Store Validation Logic
    if not username or password != "securepassword":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credentials provided"
        )
        
    user_id = f"usr_{uuid.uuid4()}"
    session_id = str(uuid.uuid4())
    epoch = await session_manager.get_user_epoch(user_id)
    
    now = int(time.time())
    access_payload = {
        "sub": user_id,
        "sid": session_id,
        "epoch": epoch,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "type": "access"
    }
    
    refresh_payload = {
        "sub": user_id,
        "sid": session_id,
        "epoch": epoch,
        "iat": now,
        "exp": now + REFRESH_TOKEN_TTL,
        "type": "refresh"
    }
    
    access_token = crypto.sign(access_payload)
    refresh_token = crypto.sign(refresh_payload)
    
    # Persist session mapping
    await session_manager.store_session(user_id, session_id, refresh_token, REFRESH_TOKEN_TTL)
    
    logger.info(f"User {user_id} logged in successfully. SessionID: {session_id}")
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_TTL
    }

@app.post("/auth/v1/refresh", tags=["Authentication"])
async def refresh_tokens(payload: dict):
    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token required")
        
    try:
        claims = crypto.verify(refresh_token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
        
    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
        
    user_id = claims.get("sub")
    session_id = claims.get("sid")
    
    active_user = await session_manager.get_session_user(session_id)
    if not active_user or active_user != user_id:
        raise HTTPException(status_code=401, detail="Session expired or revoked")
        
    # Rotate Session & Issue New Tokens
    now = int(time.time())
    epoch = await session_manager.get_user_epoch(user_id)
    
    access_payload = {
        "sub": user_id,
        "sid": session_id,
        "epoch": epoch,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "type": "access"
    }
    
    new_access_token = crypto.sign(access_payload)
    
    # Blacklist old refresh token to handle reuse attacks
    remaining_ttl = max(0, claims.get("exp", 0) - int(time.time()))
    await session_manager.blacklist_token(refresh_token, remaining_ttl)
    
    return {
        "access_token": new_access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_TTL
    }

@app.post("/auth/v1/logout", tags=["Authentication"])
async def logout(request: Request, claims: Dict[str, Any] = Depends(get_current_user)):
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header else ""
    
    session_id = claims.get("sid")
    
    # Blacklist current access token safely handling negative TTLs
    remaining_ttl = max(0, claims.get("exp", int(time.time())) - int(time.time()))
    if remaining_ttl > 0:
        await session_manager.blacklist_token(token, remaining_ttl)
        
    # Invalidate session store structure
    if session_id:
        await session_manager.invalidate_session(session_id)
        
    logger.info(f"User {claims.get('sub')} logged out. Session {session_id} destroyed.")
    return {"status": "success", "message": "Successfully logged out"}

@app.post("/auth/v1/logout-all", tags=["Authentication"])
async def logout_all(claims: Dict[str, Any] = Depends(get_current_user)):
    user_id = claims.get("sub")
    await session_manager.invalidate_all_user_sessions(user_id)
    logger.info(f"Global invalidation triggered for User {user_id}")
    return {"status": "success", "message": "All sessions revoked globally"}

@app.get("/api/v1/protected-resource", tags=["Gateway Proxy"])
async def protected_resource(claims: Dict[str, Any] = Depends(get_current_user)):
    return {
        "message": "Access granted via Distributed Gateway",
        "user_id": claims.get("sub"),
        "session_id": claims.get("sid"),
        "issued_at": claims.get("iat")
    }

@app.get("/.well-known/jwks.json", tags=["Discovery"])
async def jwks():
    jwk_comp = crypto.get_jwk_components()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": jwk_comp["n"],
                "e": jwk_comp["e"],
                "pem": crypto.get_public_pem()
            }
        ]
    }

# -----------------------------------------------------------------------------
# Main Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("__main__:app", host="0.0.0.0", port=8000, reload=False, workers=1)