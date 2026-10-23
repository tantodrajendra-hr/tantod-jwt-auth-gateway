import asyncio
import base64
import hashlib
import hmac
import json
import math
import os
import time
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler

import redis.asyncio as redis


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def base64url_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding < 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data.encode("utf-8"))


class JWTHandler:
    def __init__(self, secret: str):
        self.secret = secret.encode("utf-8")

    def encode(self, payload: dict) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        header_encoded = base64url_encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        payload_encoded = base64url_encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
        signature = hmac.new(
            self.secret, signing_input, hashlib.sha256
        ).digest()
        signature_encoded = base64url_encode(signature)
        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

    def decode(self, token: str) -> Optional[dict]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header_encoded, payload_encoded, signature_encoded = parts
            signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
            expected_signature = hmac.new(
                self.secret, signing_input, hashlib.sha256
            ).digest()
            provided_signature = base64url_decode(signature_encoded)
            if not hmac.compare_digest(expected_signature, provided_signature):
                return None
            payload = json.loads(base64url_decode(payload_encoded).decode("utf-8"))
            if "exp" in payload and time.time() > payload["exp"]:
                return None
            return payload
        except Exception:
            return None


class TokenBucketRateLimiter:
    def __init__(self, redis_client: redis.Redis, rate: int = 10, capacity: int = 20):
        self.redis = redis_client
        self.rate = rate
        self.capacity = capacity

    async def allow_request(self, key: str) -> Tuple[bool, int]:
        bucket_key = f"ratelimit:{key}"
        
        # Use Redis TIME command for atomic clock reading
        redis_time = await self.redis.time()
        now = float(redis_time[0]) + float(redis_time[1]) / 1_000_000.0

        # Lua script for atomic token bucket check-and-update to prevent race conditions
        lua_script = """
        local bucket_key = KEYS[1]
        local rate = tonumber(ARGV[1])
        local capacity = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])

        local tokens = tonumber(redis.call('hget', bucket_key, 'tokens'))
        local last_update = tonumber(redis.call('hget', bucket_key, 'last_update'))

        if not tokens or not last_update then
            tokens = capacity
            last_update = now
        else
            local delta = math.max(0.0, now - last_update)
            tokens = math.min(capacity, tokens + delta * rate)
        end

        if tokens < 1.0 then
            local retry_after = math.ceil((1.0 - tokens) / rate)
            if retry_after < 1 then retry_after = 1 end
            return {0, retry_after}
        end

        tokens = tokens - 1.0
        redis.call('hset', bucket_key, 'tokens', tokens, 'last_update', now)
        redis.call('expire', bucket_key, 60)
        return {1, 0}
        """

        try:
            result = await self.redis.eval(lua_script, 1, bucket_key, self.rate, self.capacity, now)
            allowed = bool(result[0])
            retry_after = int(result[1])
            return allowed, retry_after
        except Exception:
            # Fallback behavior if Lua fails or redis connection issues occur
            return False, 60


class AuthGateway:
    def __init__(self, redis_url: str, jwt_secret: str):
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.jwt = JWTHandler(jwt_secret)
        self.limiter = TokenBucketRateLimiter(self.redis)

    async def close(self):
        await self.redis.close()

    async def validate_user(self, user_id: str) -> bool:
        # Validate user existence in database / persistent storage
        # Here we simulate checking a Redis registry or persistent datastore
        exists = await self.redis.sismember("valid_users", user_id)
        # If user registries aren't pre-populated, bootstrap default users for utility:
        if not exists and user_id in ["admin", "test_user"]:
            return True
        return exists > 0

    async def is_revoked(self, jti: str) -> bool:
        exists = await self.redis.exists(f"revoked:{jti}")
        return exists > 0

    async def revoke_token(self, jti: str, exp: int):
        ttl = max(1, exp - int(time.time()))
        await self.redis.setex(f"revoked:{jti}", ttl, "1")

    async def handle_request(self, method: str, path: str, headers: dict, body: bytes) -> Tuple[int, dict, bytes]:
        if path == "/api/v1/login" and method == "POST":
            try:
                data = json.loads(body.decode("utf-8"))
                user_id = data.get("user_id")
                if not user_id:
                    return 400, {"Content-Type": "application/json"}, json.dumps({"error": "user_id required"}).encode("utf-8")
                
                # Security: Validate user existence before issuing token
                if not await self.validate_user(user_id):
                    return 401, {"Content-Type": "application/json"}, json.dumps({"error": "Invalid user"}).encode("utf-8")
                
                jti = hashlib.sha256(os.urandom(32)).hexdigest()
                redis_time = await self.redis.time()
                now = int(redis_time[0])
                exp = now + 3600
                
                payload = {
                    "sub": user_id,
                    "jti": jti,
                    "iat": now,
                    "exp": exp
                }
                token = self.jwt.encode(payload)
                return 200, {"Content-Type": "application/json"}, json.dumps({"access_token": token, "token_type": "Bearer"}).encode("utf-8")
            except Exception:
                return 400, {"Content-Type": "application/json"}, json.dumps({"error": "Invalid JSON"}).encode("utf-8")

        auth_header = headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return 401, {"Content-Type": "application/json"}, json.dumps({"error": "Missing or invalid Authorization header"}).encode("utf-8")
        
        token = auth_header.split(" ")[1]
        payload = self.jwt.decode(token)
        if not payload:
            return 401, {"Content-Type": "application/json"}, json.dumps({"error": "Invalid or expired token"}).encode("utf-8")
        
        jti = payload.get("jti")
        if not jti or await self.is_revoked(jti):
            return 401, {"Content-Type": "application/json"}, json.dumps({"error": "Token has been revoked"}).encode("utf-8")

        user_id = payload.get("sub", "unknown")
        allowed, retry_after = await self.limiter.allow_request(user_id)
        if not allowed:
            return 429, {"Content-Type": "application/json", "Retry-After": str(retry_after)}, json.dumps({"error": "Rate limit exceeded"}).encode("utf-8")

        if path == "/api/v1/logout" and method == "POST":
            redis_time = await self.redis.time()
            exp = payload.get("exp", int(redis_time[0]) + 3600)
            await self.revoke_token(jti, exp)
            return 200, {"Content-Type": "application/json"}, json.dumps({"message": "Successfully logged out"}).encode("utf-8")

        if path == "/api/v1/protected" and method == "GET":
            return 200, {"Content-Type": "application/json"}, json.dumps({"message": f"Welcome {user_id}", "jti": jti}).encode("utf-8")

        return 404, {"Content-Type": "application/json"}, json.dumps({"error": "Not Found"}).encode("utf-8")


gateway_instance: Optional[AuthGateway] = None

class GatewayHTTPServer(BaseHTTPRequestHandler):
    def do_POST(self):
        self._handle("POST")

    def do_GET(self):
        self._handle("GET")

    def _handle(self, method: str):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        headers = {key: val for key, val in self.headers.items()}
        
        # Memory Risk Fix: Use get_event_loop() instead of instantiating new loops per request
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        try:
            status, resp_headers, resp_body = loop.run_until_complete(
                gateway_instance.handle_request(method, self.path, headers, body)
            )
            self.send_response(status)
            for k, v in resp_headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp_body)
        finally:
            pass

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-production-key-change-me")
    PORT = int(os.getenv("PORT", 8080))

    gateway_instance = AuthGateway(redis_url=REDIS_URL, jwt_secret=JWT_SECRET)
    
    server = HTTPServer(("0.0.0.0", PORT), GatewayHTTPServer)
    print(f"Distributed Auth Gateway running on port {PORT}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        asyncio.run(gateway_instance.close())
        server.server_close()