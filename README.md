# Distributed JWT Auth & Session Revocation Gateway

A high-performance, asynchronous microservice built with FastAPI, Redis, and Asymmetric Cryptography (RSA). Designed for distributed cloud architectures, this gateway provides stateless JWT validation combined with stateful, instant session revocation capabilities.

---

## Architecture Overview & Capabilities

This service implements a hybrid authentication model designed to balance system throughput with strict security requirements:

* **Asymmetric Cryptography (RS256):** Tokens are signed using a 2048-bit RSA private key and can be verified by any downstream microservice possessing the corresponding public key (`/jwks.json`), eliminating centralized auth-service bottlenecks for token validation.
* **Instant Session Revocation:** While JWTs are inherently stateless, this gateway checks token identifiers (`jti`) against a distributed Redis backend upon validation. This allows for immediate logout, token blacklisting, and compromised session termination without waiting for token expiration.
* **Token Rotation & Refresh Flows:** Implements short-lived access tokens (default 15 minutes) coupled with secure, sliding-window refresh tokens stored securely in Redis.
* **Resilient Infrastructure:** Features connection pooling, strict lifespan management (`asynccontextmanager`), and structured JSON logging.

```
                  +-------------------------+
                  |      Client / User      |
                  +------------+------------+
                               |
                       (HTTP Requests)
                               |
                               v
                  +------------+------------+
                  |  Auth & Session Gateway |
                  +---+------------------+--+
                      |                  |
             (Validate JTI)      (Verify Signature)
                      |                  |
                      v                  v
               +------+------+    +------+------+
               |    Redis    |    |  RSA Public |
               |  (Blacklist)|    |     Key     |
               +-------------+    +-------------+
```

---

## Available Endpoints & Examples

### 1. Issue Tokens (Login)
Authenticates user credentials and returns an RSA-signed Access Token and a persistent Refresh Token.

* **URL:** `POST /auth/login`
* **Request Body:**
```json
{
  "email": "engineer@company.com",
  "password": "SecurePassword123!"
}
```
* **cURL Example:**
```bash
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "engineer@company.com", "password": "SecurePassword123!"}'
```

### 2. Protected Resource Access
Validates the bearer token signature, checks expiration, and queries Redis to ensure the session has not been revoked.

* **URL:** `GET /api/v1/protected`
* **Headers:** `Authorization: Bearer <ACCESS_TOKEN>`
* **cURL Example:**
```bash
curl -X GET "http://localhost:8000/api/v1/protected" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5c..."
```

### 3. Revoke Session (Logout)
Blacklists the active token's unique identifier (`jti`) in Redis for the remainder of its lifespan.

* **URL:** `POST /auth/logout`
* **Headers:** `Authorization: Bearer <ACCESS_TOKEN>`
* **cURL Example:**
```bash
curl -X POST "http://localhost:8000/auth/logout" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5c..."
```

### 4. Public Key Distribution (JWKS)
Exposes the public RSA key for downstream services to verify access tokens locally.

* **URL:** `GET /.well-known/jwks.json`
* **cURL Example:**
```bash
curl -X GET "http://localhost:8000/.well-known/jwks.json"
```

---

## Native Execution Instructions

### Prerequisites
* Python 3.10+
* Running Redis instance (locally or accessible via TCP)

### 1. Clone and Setup Virtual Environment
```bash
git clone https://github.com/your-org/distributed-auth-gateway.git
cd distributed-auth-gateway

python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install fastapi uvicorn pydantic redis python-jose cryptography
```

### 3. Configure Environment Variables
Create a `.env` file or export variables directly:
```bash
export REDIS_URL="redis://localhost:6379/0"
export JWT_ISSUER="auth-gateway-cluster"
export JWT_AUDIENCE="api-services"
export ACCESS_TOKEN_EXPIRE_MINUTES=15
export REFRESH_TOKEN_EXPIRE_DAYS=7
export LOG_LEVEL="INFO"
```

### 4. Run the Application
Start the Uvicorn ASGI server with hot-reload enabled for development:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Docker Execution Instructions

### Prerequisites
* Docker & Docker Compose installed

### 1. Build and Run via Docker Compose
Create a `docker-compose.yml` file in your root directory containing both the Gateway service and a Redis container:

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --save 60 1 --loglevel warning

  auth-gateway:
    build: .
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379/0
      - JWT_ISSUER=auth-gateway-cluster
      - JWT_AUDIENCE=api-services
      - LOG_LEVEL=INFO
    depends_on:
      - redis
```

### 2. Build the Docker Image manually (Alternative)
If you prefer running the container standalone, ensure you link it to a reachable Redis network:
```bash
docker build -t auth-gateway .
docker run -d \
  --name auth-gateway-service \
  -p 8000:8000 \
  -e REDIS_URL="redis://host.docker.internal:6379/0" \
  auth-gateway