"""
auth.py — JWT Authentication System for the Vulnerability Scanner.
Rebuilt for FastAPI's request/dependency model (no global request object).
Provides: JWT creation/validation, rate limiting, token blacklisting,
and the require_auth dependency for protecting API routes.
"""

import json
import os
import re
import secrets
import time
import threading
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Request, HTTPException
from werkzeug.security import generate_password_hash, check_password_hash

from config import (
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_HOURS,
    MAX_LOGIN_ATTEMPTS, LOCKOUT_SECONDS, USERS_PATH
)

# ── In-memory state ───────────────────────────────────────
login_attempts = {}
login_attempts_lock = threading.Lock()

token_blacklist = {}  # {jti: expiry_timestamp}
token_blacklist_lock = threading.Lock()


# ── User management ───────────────────────────────────────

def load_users():
    """Load users from JSON file."""
    try:
        with open(USERS_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_users(users):
    """Persist users to JSON file."""
    with open(USERS_PATH, "w") as f:
        json.dump(users, f, indent=4)


def find_user(username):
    """Find user by username (case-insensitive)."""
    users = load_users()
    for u in users:
        if u["username"].lower() == username.lower():
            return u
    return None


# ── JWT helpers ───────────────────────────────────────────

def create_jwt_token(username, role="user"):
    """Create a signed JWT token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token):
    """Decode and validate a JWT token. Returns payload or None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        with token_blacklist_lock:
            if payload.get("jti") in token_blacklist:
                return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def blacklist_token(payload):
    """Add a token's JTI to the blacklist with its expiry time."""
    if payload and payload.get("jti"):
        with token_blacklist_lock:
            token_blacklist[payload["jti"]] = payload.get("exp", time.time() + 86400)
            if len(token_blacklist) > 100:
                now = time.time()
                expired = [k for k, v in token_blacklist.items() if v < now]
                for k in expired:
                    del token_blacklist[k]


# ── Rate limiting ─────────────────────────────────────────

def get_client_ip(request: Request):
    """Get client IP, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_rate_limit(ip):
    """Check if IP is rate-limited. Returns (allowed, message)."""
    with login_attempts_lock:
        if ip not in login_attempts:
            return True, ""

        entry = login_attempts[ip]
        if entry.get("lockout_until", 0) > time.time():
            remaining = int(entry["lockout_until"] - time.time())
            return False, f"Account locked. Try again in {remaining}s."

        if entry.get("lockout_until", 0) <= time.time() and entry.get("lockout_until", 0) > 0:
            login_attempts[ip] = {"attempts": 0, "lockout_until": 0}

        return True, ""


def record_failed_attempt(ip):
    """Record a failed login attempt and possibly trigger lockout."""
    with login_attempts_lock:
        if ip not in login_attempts:
            login_attempts[ip] = {"attempts": 0, "lockout_until": 0}

        login_attempts[ip]["attempts"] += 1
        attempts = login_attempts[ip]["attempts"]

        if attempts >= MAX_LOGIN_ATTEMPTS:
            multiplier = max(1, attempts - MAX_LOGIN_ATTEMPTS + 1)
            lockout_time = min(LOCKOUT_SECONDS * multiplier, 3600)
            login_attempts[ip]["lockout_until"] = time.time() + lockout_time
            return attempts, lockout_time

        return attempts, 0


def clear_failed_attempts(ip):
    """Clear failed login record on successful auth."""
    with login_attempts_lock:
        login_attempts.pop(ip, None)


# ── Auth dependency (used with FastAPI's Depends) ─────────

async def require_auth(request: Request) -> str:
    """
    FastAPI dependency that validates the Bearer token on a request.
    Raises HTTPException(401) if missing/invalid.
    Returns the authenticated username; also stashes role on request.state.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = auth_header[7:]
    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    request.state.auth_user = payload.get("sub", "")
    request.state.auth_role = payload.get("role", "")
    return request.state.auth_user


async def require_admin(request: Request) -> str:
    """Like require_auth, but also enforces admin role."""
    username = await require_auth(request)
    if getattr(request.state, "auth_role", "") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return username


# ── Auth route handlers (called from app.py) ──────────────

async def handle_login(request: Request):
    """Authenticate user and return JWT."""
    client_ip = get_client_ip(request)

    allowed, msg = check_rate_limit(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=msg)

    try:
        data = await request.json()
    except Exception:
        data = None
    if not data:
        raise HTTPException(status_code=400, detail="Invalid request")

    username = (data.get("username") or "").strip()[:64]
    password = data.get("password") or ""

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    if len(password) > 128:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user = find_user(username)

    if not user:
        # Constant-time comparison with a real pbkdf2 hash to prevent timing attacks
        _dummy = generate_password_hash("dummy_constant_time_pad", method="pbkdf2:sha256", salt_length=16)
        check_password_hash(_dummy, password)
        attempts, lockout = record_failed_attempt(client_ip)
        if lockout > 0:
            raise HTTPException(status_code=429, detail=f"Too many attempts. Locked for {lockout}s.")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not check_password_hash(user["password_hash"], password):
        attempts, lockout = record_failed_attempt(client_ip)
        if lockout > 0:
            raise HTTPException(status_code=429, detail=f"Too many attempts. Locked for {lockout}s.")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    clear_failed_attempts(client_ip)
    token = create_jwt_token(username, user.get("role", "user"))

    return {
        "status": "ok",
        "token": token,
        "username": username,
        "role": user.get("role", "user"),
        "expires_in": JWT_EXPIRY_HOURS * 3600
    }


async def handle_verify(request: Request):
    """Verify a JWT token is still valid."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token")

    token = auth_header[7:]
    payload = decode_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return {
        "status": "ok",
        "username": payload.get("sub"),
        "role": payload.get("role"),
        "expires_at": payload.get("exp")
    }


async def handle_logout(request: Request):
    """Blacklist the current token."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = decode_jwt_token(token)
        blacklist_token(payload)

    return {"status": "ok", "message": "Logged out"}


async def handle_change_password(request: Request, auth_user: str):
    """Change password for the authenticated user."""
    try:
        data = await request.json()
    except Exception:
        data = None
    if not data:
        raise HTTPException(status_code=400, detail="Invalid request")

    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not current_password or not new_password:
        raise HTTPException(status_code=400, detail="Both passwords required")

    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    if len(new_password) > 128:
        raise HTTPException(status_code=400, detail="Password too long")

    users = load_users()
    user = None
    for u in users:
        if u["username"].lower() == auth_user.lower():
            user = u
            break

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not check_password_hash(user["password_hash"], current_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    user["password_hash"] = generate_password_hash(
        new_password, method="pbkdf2:sha256", salt_length=16
    )
    save_users(users)

    return {"status": "ok", "message": "Password updated"}


async def handle_register(request: Request):
    """Register a new user account."""
    try:
        data = await request.json()
    except Exception:
        data = None
    if not data:
        raise HTTPException(status_code=400, detail="Invalid request")

    username = (data.get("username") or "").strip()[:64]
    password = data.get("password") or ""

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
        raise HTTPException(
            status_code=400,
            detail="Username can only contain letters, numbers, underscores, hyphens, and dots"
        )

    if find_user(username):
        raise HTTPException(status_code=409, detail="Username already taken")

    users = load_users()
    users.append({
        "username": username,
        "password_hash": generate_password_hash(password, method="pbkdf2:sha256", salt_length=16),
        "role": "user"
    })
    save_users(users)

    token = create_jwt_token(username, "user")
    return {
        "status": "ok",
        "token": token,
        "username": username,
        "role": "user",
        "expires_in": JWT_EXPIRY_HOURS * 3600
    }
