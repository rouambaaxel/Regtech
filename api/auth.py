"""
ComplianceOS — Authentication System
JWT + bcrypt password hashing + refresh tokens + email verification
"""

from fastapi import APIRouter, HTTPException, Depends, Header, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime, timezone, timedelta
import asyncpg
import bcrypt
import jwt
import uuid
import os
import secrets
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()

JWT_SECRET = os.environ.get("JWT_SECRET", "change_me_in_production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30


# ─────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=2)
    company_name: str = Field(..., min_length=2)
    fca_firm_ref: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class InviteUserRequest(BaseModel):
    email: EmailStr
    role: str = Field(default="analyst", pattern="^(admin|mlro|analyst)$")


# ─────────────────────────────────────────────
# DB DEPENDENCY
# ─────────────────────────────────────────────
async def get_db():
    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        yield conn
    finally:
        await conn.close()


# ─────────────────────────────────────────────
# JWT HELPERS
# ─────────────────────────────────────────────
def create_access_token(user_id: str, tenant_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str, tenant_id: str) -> tuple[str, str]:
    """Returns (token_string, jti) — store jti in DB for rotation."""
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "iat": datetime.now(timezone.utc),
        "jti": jti,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM), jti


def decode_token(token: str, expected_type: str = "access") -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != expected_type:
            raise HTTPException(status_code=401, detail="Invalid token type")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ─────────────────────────────────────────────
# AUTH DEPENDENCY (replaces the old Header-based auth)
# ─────────────────────────────────────────────
class CurrentUser:
    def __init__(self, user_id: str, tenant_id: str, email: str, role: str):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.email = email
        self.role = role


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: asyncpg.Connection = Depends(get_db),
) -> CurrentUser:
    payload = decode_token(credentials.credentials, "access")
    user = await db.fetchrow(
        "SELECT id, tenant_id, email, role, is_active FROM users WHERE id = $1",
        payload["sub"]
    )
    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="User not found or deactivated")
    return CurrentUser(
        user_id=str(user["id"]),
        tenant_id=str(user["tenant_id"]),
        email=user["email"],
        role=user["role"],
    )


def require_role(*roles: str):
    """Role-based access control decorator."""
    async def _check(current_user: CurrentUser = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {' or '.join(roles)}")
        return current_user
    return _check


# ─────────────────────────────────────────────
# PASSWORD UTILS
# ─────────────────────────────────────────────
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def generate_api_key() -> tuple[str, str]:
    """Returns (raw_key, hashed_key). Store only the hash."""
    raw = f"cos_{secrets.token_urlsafe(32)}"
    hashed = bcrypt.hashpw(raw.encode(), bcrypt.gensalt(rounds=10)).decode()
    return raw, hashed


# ─────────────────────────────────────────────
# EMAIL (stub — replace with SendGrid/Resend)
# ─────────────────────────────────────────────
async def send_email(to: str, subject: str, body: str):
    """Replace with real email provider in production."""
    logger.info(f"[EMAIL] To: {to} | Subject: {subject}")
    logger.info(f"[EMAIL] Body: {body[:200]}")


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@router.post("/register", status_code=201)
async def register(
    body: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: asyncpg.Connection = Depends(get_db),
):
    """
    Register a new organisation + admin user.
    Creates: tenant → user → API key → verification email.
    """
    # Check email not already taken
    existing = await db.fetchrow("SELECT id FROM users WHERE email = $1", body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    # Create tenant slug
    slug = body.company_name.lower().replace(" ", "-").replace("_", "-")[:50]
    slug_exists = await db.fetchrow("SELECT id FROM tenants WHERE slug = $1", slug)
    if slug_exists:
        slug = f"{slug}-{str(uuid.uuid4())[:6]}"

    # Generate IDs
    tenant_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    raw_api_key, hashed_api_key = generate_api_key()

    # Email verification token
    verify_token = secrets.token_urlsafe(32)

    async with db.transaction():
        # Create tenant
        await db.execute(
            """INSERT INTO tenants (id, name, slug, fca_firm_ref, plan, api_key_hash)
               VALUES ($1,$2,$3,$4,'starter',$5)""",
            tenant_id, body.company_name, slug,
            body.fca_firm_ref, hashed_api_key,
        )

        # Create admin user
        await db.execute(
            """INSERT INTO users
               (id, tenant_id, email, full_name, password_hash, role,
                is_active, email_verified, email_verify_token, created_at)
               VALUES ($1,$2,$3,$4,$5,'admin',TRUE,FALSE,$6,$7)""",
            user_id, tenant_id, body.email, body.full_name,
            hash_password(body.password), verify_token,
            datetime.now(timezone.utc),
        )

        # Audit log
        await db.execute(
            """INSERT INTO audit_log (tenant_id, user_id, action, entity_type, entity_id, after, created_at)
               VALUES ($1,$2,'user_registered','user',$2,$3,$4)""",
            tenant_id, user_id,
            f'{{"email":"{body.email}","company":"{body.company_name}"}}',
            datetime.now(timezone.utc),
        )

    # Send verification email (background)
    verify_url = f"{os.getenv('APP_URL','http://localhost:3000')}/verify-email?token={verify_token}"
    background_tasks.add_task(
        send_email, body.email,
        "Verify your ComplianceOS account",
        f"Welcome {body.full_name}!\n\nVerify your email: {verify_url}\n\nYour API key (save this — shown once): {raw_api_key}"
    )

    # Create tokens
    access_token = create_access_token(user_id, tenant_id, "admin")
    refresh_token, refresh_jti = create_refresh_token(user_id, tenant_id)

    # Store refresh token
    await db.execute(
        """INSERT INTO refresh_tokens (id, user_id, tenant_id, jti, expires_at, created_at)
           VALUES ($1,$2,$3,$4,$5,$6)""",
        str(uuid.uuid4()), user_id, tenant_id, refresh_jti,
        datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        datetime.now(timezone.utc),
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user_id, "email": body.email,
            "full_name": body.full_name, "role": "admin",
        },
        "tenant": {
            "id": tenant_id, "name": body.company_name,
            "slug": slug, "plan": "starter",
        },
        "api_key": raw_api_key,  # Only shown once at registration
        "message": "Check your email to verify your account.",
    }


@router.post("/login")
async def login(
    body: LoginRequest,
    db: asyncpg.Connection = Depends(get_db),
):
    """Login with email + password. Returns JWT access + refresh tokens."""
    user = await db.fetchrow(
        """SELECT u.id, u.tenant_id, u.email, u.full_name, u.password_hash,
              u.role, u.is_active, u.email_verified, t.name AS company_name, t.plan
           FROM users u JOIN tenants t ON u.tenant_id = t.id
           WHERE u.email = $1""",
        body.email,
    )

    if not user or not user["password_hash"] or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Account deactivated — contact support")

    # Create tokens
    access_token = create_access_token(str(user["id"]), str(user["tenant_id"]), user["role"])
    refresh_token, refresh_jti = create_refresh_token(str(user["id"]), str(user["tenant_id"]))

    # Rotate refresh tokens — revoke old ones for this user
    await db.execute(
        "UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE",
        str(user["id"])
    )

    # Store new refresh token
    await db.execute(
        """INSERT INTO refresh_tokens (id, user_id, tenant_id, jti, expires_at, created_at)
           VALUES ($1,$2,$3,$4,$5,$6)""",
        str(uuid.uuid4()), str(user["id"]), str(user["tenant_id"]), refresh_jti,
        datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        datetime.now(timezone.utc),
    )

    # Update last login
    await db.execute(
        "UPDATE users SET last_login_at = $1 WHERE id = $2",
        datetime.now(timezone.utc), str(user["id"])
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": str(user["id"]), "email": user["email"],
            "full_name": user["full_name"], "role": user["role"],
            "email_verified": user["email_verified"],
        },
        "tenant": {
            "id": str(user["tenant_id"]), "name": user["company_name"],
            "plan": user["plan"],
        },
    }


@router.post("/refresh")
async def refresh_token(
    body: RefreshRequest,
    db: asyncpg.Connection = Depends(get_db),
):
    """Exchange refresh token for new access + refresh token pair (rotation)."""
    payload = decode_token(body.refresh_token, "refresh")
    jti = payload.get("jti")

    # Verify token is in DB and not revoked
    stored = await db.fetchrow(
        "SELECT id, revoked FROM refresh_tokens WHERE jti = $1 AND user_id = $2",
        jti, payload["sub"]
    )
    if not stored or stored["revoked"]:
        raise HTTPException(status_code=401, detail="Refresh token revoked or not found")

    user = await db.fetchrow(
        "SELECT id, tenant_id, role, is_active FROM users WHERE id = $1",
        payload["sub"]
    )
    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="User not found")

    # Revoke used refresh token
    await db.execute("UPDATE refresh_tokens SET revoked = TRUE WHERE jti = $1", jti)

    # Issue new pair
    new_access = create_access_token(str(user["id"]), str(user["tenant_id"]), user["role"])
    new_refresh, new_jti = create_refresh_token(str(user["id"]), str(user["tenant_id"]))

    await db.execute(
        """INSERT INTO refresh_tokens (id, user_id, tenant_id, jti, expires_at, created_at)
           VALUES ($1,$2,$3,$4,$5,$6)""",
        str(uuid.uuid4()), str(user["id"]), str(user["tenant_id"]), new_jti,
        datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        datetime.now(timezone.utc),
    )

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/logout")
async def logout(
    body: RefreshRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: asyncpg.Connection = Depends(get_db),
):
    """Revoke refresh token. Access token expires naturally (stateless)."""
    payload = decode_token(body.refresh_token, "refresh")
    await db.execute(
        "UPDATE refresh_tokens SET revoked = TRUE WHERE jti = $1 AND user_id = $2",
        payload.get("jti"), current_user.user_id
    )
    await db.execute(
        """INSERT INTO audit_log (tenant_id, user_id, action, entity_type, entity_id, after, created_at)
           VALUES ($1,$2,'user_logout','user',$2,'{}',$3)""",
        current_user.tenant_id, current_user.user_id, datetime.now(timezone.utc)
    )
    return {"status": "logged_out"}


@router.get("/me")
async def get_me(
    current_user: CurrentUser = Depends(get_current_user),
    db: asyncpg.Connection = Depends(get_db),
):
    """Get current user profile."""
    row = await db.fetchrow(
        """SELECT u.*, t.name AS company_name, t.plan, t.fca_firm_ref, t.slug
           FROM users u JOIN tenants t ON u.tenant_id = t.id WHERE u.id = $1""",
        current_user.user_id
    )
    return {
        "id": str(row["id"]), "email": row["email"],
        "full_name": row["full_name"], "role": row["role"],
        "email_verified": row["email_verified"],
        "last_login_at": row["last_login_at"].isoformat() if row["last_login_at"] else None,
        "tenant": {
            "id": str(row["tenant_id"]), "name": row["company_name"],
            "slug": row["slug"], "plan": row["plan"],
            "fca_firm_ref": row["fca_firm_ref"],
        },
    }


@router.get("/verify-email")
async def verify_email(
    token: str,
    db: asyncpg.Connection = Depends(get_db),
):
    user = await db.fetchrow(
        "SELECT id FROM users WHERE email_verify_token = $1 AND email_verified = FALSE",
        token
    )
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or already used token")

    await db.execute(
        "UPDATE users SET email_verified = TRUE, email_verify_token = NULL WHERE id = $1",
        str(user["id"])
    )
    return {"status": "verified", "message": "Email verified. You can now use all features."}


@router.post("/forgot-password")
async def forgot_password(
    body: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: asyncpg.Connection = Depends(get_db),
):
    user = await db.fetchrow("SELECT id, full_name FROM users WHERE email = $1", body.email)
    # Always return 200 to prevent email enumeration
    if user:
        reset_token = secrets.token_urlsafe(32)
        await db.execute(
            "UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE id = $3",
            reset_token,
            datetime.now(timezone.utc) + timedelta(hours=1),
            str(user["id"])
        )
        reset_url = f"{os.getenv('APP_URL','http://localhost:3000')}/reset-password?token={reset_token}"
        background_tasks.add_task(
            send_email, body.email,
            "Reset your ComplianceOS password",
            f"Hi {user['full_name']},\n\nReset your password (expires in 1 hour): {reset_url}\n\nIf you didn't request this, ignore this email."
        )
    return {"message": "If this email is registered, you will receive a reset link."}


@router.post("/reset-password")
async def reset_password(
    body: ResetPasswordRequest,
    db: asyncpg.Connection = Depends(get_db),
):
    user = await db.fetchrow(
        """SELECT id FROM users
           WHERE password_reset_token = $1 AND password_reset_expires > $2""",
        body.token, datetime.now(timezone.utc)
    )
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    await db.execute(
        """UPDATE users SET
             password_hash = $1,
             password_reset_token = NULL,
             password_reset_expires = NULL
           WHERE id = $2""",
        hash_password(body.new_password), str(user["id"])
    )
    # Revoke all refresh tokens
    await db.execute("UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1", str(user["id"]))

    return {"status": "reset", "message": "Password updated. All sessions have been terminated."}


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: asyncpg.Connection = Depends(get_db),
):
    user = await db.fetchrow("SELECT password_hash FROM users WHERE id = $1", current_user.user_id)
    if not verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    await db.execute(
        "UPDATE users SET password_hash = $1 WHERE id = $2",
        hash_password(body.new_password), current_user.user_id
    )
    await db.execute("UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1", current_user.user_id)

    return {"status": "changed", "message": "Password changed. Please log in again."}


@router.post("/invite", status_code=201)
async def invite_user(
    body: InviteUserRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(require_role("admin")),
    db: asyncpg.Connection = Depends(get_db),
):
    """Admin-only: invite a team member to the organisation."""
    existing = await db.fetchrow("SELECT id FROM users WHERE email = $1", body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    invite_token = secrets.token_urlsafe(32)
    user_id = str(uuid.uuid4())

    await db.execute(
        """INSERT INTO users
           (id, tenant_id, email, full_name, password_hash, role,
            is_active, email_verified, invite_token, created_at)
           VALUES ($1,$2,$3,'Invited User','',  $4,FALSE,FALSE,$5,$6)""",
        user_id, current_user.tenant_id, body.email,
        body.role, invite_token, datetime.now(timezone.utc),
    )

    invite_url = f"{os.getenv('APP_URL','http://localhost:3000')}/accept-invite?token={invite_token}"
    background_tasks.add_task(
        send_email, body.email,
        "You've been invited to ComplianceOS",
        f"You've been invited as {body.role}.\n\nAccept your invitation: {invite_url}"
    )

    return {"status": "invited", "email": body.email, "role": body.role}


@router.get("/users")
async def list_users(
    current_user: CurrentUser = Depends(require_role("admin", "mlro")),
    db: asyncpg.Connection = Depends(get_db),
):
    rows = await db.fetch(
        """SELECT id, email, full_name, role, is_active, email_verified,
              last_login_at, created_at
           FROM users WHERE tenant_id = $1 ORDER BY created_at""",
        current_user.tenant_id
    )
    return {"data": [dict(r) for r in rows]}
