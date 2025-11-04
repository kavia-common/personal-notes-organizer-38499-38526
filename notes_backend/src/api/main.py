from __future__ import annotations

import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from threading import RLock
from typing import Dict, List, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Path, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from starlette.responses import JSONResponse


# -----------------------------
# App initialization and CORS
# -----------------------------
app = FastAPI(
    title="Personal Notes API",
    description="API for user authentication and personal notes CRUD operations.",
    version="1.0.0",
    openapi_tags=[
        {"name": "health", "description": "Health check endpoint"},
        {
            "name": "auth",
            "description": "Signup and login to obtain an access token. Prototype in-memory tokens.",
        },
        {
            "name": "notes",
            "description": "CRUD operations for notes. All endpoints require Authorization: Bearer <token>.",
        },
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permissive for prototype
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Configuration (env with safe defaults)
# -----------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-change-me")
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "86400"))  # 24h

# -----------------------------
# In-memory repositories (thread-safe)
# -----------------------------
class InMemoryUsersRepo:
    """Thread-safe in-memory user repository."""
    def __init__(self) -> None:
        self._lock = RLock()
        self._by_email: Dict[str, Dict] = {}  # email -> user dict
        self._by_id: Dict[str, Dict] = {}

    def create_user(self, email: str, password_hash: str) -> Dict:
        with self._lock:
            if email.lower() in self._by_email:
                raise ValueError("User already exists")
            user_id = str(uuid.uuid4())
            user = {
                "id": user_id,
                "email": email.lower(),
                "password_hash": password_hash,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self._by_email[email.lower()] = user
            self._by_id[user_id] = user
            return user

    def get_by_email(self, email: str) -> Optional[Dict]:
        with self._lock:
            return self._by_email.get(email.lower())

    def get_by_id(self, user_id: str) -> Optional[Dict]:
        with self._lock:
            return self._by_id.get(user_id)


class InMemoryTokensRepo:
    """Thread-safe in-memory token store: token -> (user_id, expiry_epoch)"""
    def __init__(self) -> None:
        self._lock = RLock()
        self._tokens: Dict[str, Tuple[str, float]] = {}

    def create_token(self, user_id: str, ttl_seconds: int) -> str:
        with self._lock:
            token = secrets.token_urlsafe(32)
            expiry = time.time() + ttl_seconds
            self._tokens[token] = (user_id, expiry)
            return token

    def validate_token(self, token: str) -> Optional[str]:
        with self._lock:
            data = self._tokens.get(token)
            if not data:
                return None
            user_id, expiry = data
            if time.time() > expiry:
                # Expired: remove and return None
                self._tokens.pop(token, None)
                return None
            return user_id

    def revoke(self, token: str) -> None:
        with self._lock:
            self._tokens.pop(token, None)


class InMemoryNotesRepo:
    """Thread-safe in-memory notes repository by owner_id."""
    def __init__(self) -> None:
        self._lock = RLock()
        self._notes: Dict[str, Dict] = {}  # note_id -> note dict

    def create(self, owner_id: str, title: str, content: str, tags: List[str]) -> Dict:
        with self._lock:
            now = datetime.now(timezone.utc).isoformat()
            note_id = str(uuid.uuid4())
            note = {
                "id": note_id,
                "title": title,
                "content": content,
                "tags": tags or [],
                "created_at": now,
                "updated_at": now,
                "owner_id": owner_id,
            }
            self._notes[note_id] = note
            return note

    def get(self, note_id: str) -> Optional[Dict]:
        with self._lock:
            return self._notes.get(note_id)

    def update(self, note_id: str, title: str, content: str, tags: List[str]) -> Optional[Dict]:
        with self._lock:
            note = self._notes.get(note_id)
            if not note:
                return None
            note["title"] = title
            note["content"] = content
            note["tags"] = tags or []
            note["updated_at"] = datetime.now(timezone.utc).isoformat()
            return note

    def delete(self, note_id: str) -> bool:
        with self._lock:
            return self._notes.pop(note_id, None) is not None

    def list_for_owner(
        self,
        owner_id: str,
        limit: int,
        offset: int,
        q: Optional[str],
        tag: Optional[str],
    ) -> Tuple[List[Dict], int]:
        with self._lock:
            # Filter by owner
            items = [n for n in self._notes.values() if n["owner_id"] == owner_id]
            # Filter by search query
            if q:
                q_lower = q.lower()
                items = [
                    n
                    for n in items
                    if q_lower in (n["title"] or "").lower()
                    or q_lower in (n["content"] or "").lower()
                ]
            # Filter by tag
            if tag:
                items = [n for n in items if tag in (n.get("tags") or [])]
            total = len(items)
            # Pagination
            items = items[offset : offset + limit]
            return items, total


users_repo = InMemoryUsersRepo()
tokens_repo = InMemoryTokensRepo()
notes_repo = InMemoryNotesRepo()

# -----------------------------
# Security utilities
# -----------------------------
security = HTTPBearer(auto_error=False)


def _hash_password(password: str) -> str:
    """Very simple salted hash using SECRET_KEY for prototype only."""
    # For a prototype; in production use passlib/bcrypt/argon2
    import hashlib, hmac
    return hmac.new(SECRET_KEY.encode("utf-8"), password.encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_password(password: str, password_hash: str) -> bool:
    return secrets.compare_digest(_hash_password(password), password_hash)


# PUBLIC_INTERFACE
def get_current_user_id(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    """Authenticate the request with a Bearer token and return user_id.
    Raises 401 if token is missing/invalid.
    """
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    user_id = tokens_repo.validate_token(token)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return user_id


# -----------------------------
# Pydantic models
# -----------------------------
class HealthResponse(BaseModel):
    message: str = Field(..., description="Health status message")


class SignupRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=6, description="Password (min 6 chars)")


class AuthResponse(BaseModel):
    access_token: str = Field(..., description="Access token to use in Authorization header")
    token_type: str = Field("bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., description="User password")


class NoteCreate(BaseModel):
    title: str = Field(..., description="Note title", min_length=1)
    content: str = Field("", description="Note content")
    tags: List[str] = Field(default_factory=list, description="Tags for the note")


class NoteUpdate(BaseModel):
    title: str = Field(..., description="Note title", min_length=1)
    content: str = Field("", description="Note content")
    tags: List[str] = Field(default_factory=list, description="Tags for the note")


class NoteOut(BaseModel):
    id: str = Field(..., description="Note ID")
    title: str = Field(..., description="Note title")
    content: str = Field(..., description="Note content")
    tags: List[str] = Field(default_factory=list, description="Tags for the note")
    created_at: str = Field(..., description="Creation timestamp (ISO8601)")
    updated_at: str = Field(..., description="Last update timestamp (ISO8601)")
    owner_id: str = Field(..., description="Owner user ID")


class PaginatedNotes(BaseModel):
    total: int = Field(..., description="Total notes matching criteria")
    items: List[NoteOut] = Field(..., description="Notes for current page")


# -----------------------------
# Routes
# -----------------------------
@app.get(
    "/",
    response_model=HealthResponse,
    tags=["health"],
    summary="Health Check",
    description="Simple health check endpoint.",
)
def health_check() -> HealthResponse:
    """Return a simple health status"""
    return HealthResponse(message="Healthy")


@app.post(
    "/auth/signup",
    response_model=AuthResponse,
    tags=["auth"],
    summary="User signup",
    description="Create a new user and return an access token.",
)
def signup(payload: SignupRequest) -> AuthResponse:
    """Signup endpoint that creates a user and returns an access token."""
    # If user exists -> 400
    if users_repo.get_by_email(payload.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    pwd_hash = _hash_password(payload.password)
    user = users_repo.create_user(payload.email, pwd_hash)
    token = tokens_repo.create_token(user["id"], ACCESS_TOKEN_TTL_SECONDS)
    return AuthResponse(access_token=token, token_type="bearer", expires_in=ACCESS_TOKEN_TTL_SECONDS)


@app.post(
    "/auth/login",
    response_model=AuthResponse,
    tags=["auth"],
    summary="User login",
    description="Login with email and password to obtain an access token.",
)
def login(payload: LoginRequest) -> AuthResponse:
    """Login endpoint that validates credentials and returns an access token."""
    user = users_repo.get_by_email(payload.email)
    if not user or not _verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = tokens_repo.create_token(user["id"], ACCESS_TOKEN_TTL_SECONDS)
    return AuthResponse(access_token=token, token_type="bearer", expires_in=ACCESS_TOKEN_TTL_SECONDS)


@app.post(
    "/notes",
    response_model=NoteOut,
    tags=["notes"],
    summary="Create a note",
    description="Create a note owned by the authenticated user.",
)
def create_note(note: NoteCreate, user_id: str = Depends(get_current_user_id)) -> NoteOut:
    """Create a new note for the current user."""
    created = notes_repo.create(owner_id=user_id, title=note.title, content=note.content, tags=note.tags)
    return NoteOut(**created)


@app.get(
    "/notes",
    response_model=PaginatedNotes,
    tags=["notes"],
    summary="List notes",
    description="List notes for the authenticated user with pagination, optional search and tag filter.",
)
def list_notes(
    user_id: str = Depends(get_current_user_id),
    limit: int = Query(20, ge=1, le=100, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    q: Optional[str] = Query(None, description="Search text in title or content"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
) -> PaginatedNotes:
    """List notes for the current user with pagination, search, and tag filtering."""
    items, total = notes_repo.list_for_owner(owner_id=user_id, limit=limit, offset=offset, q=q, tag=tag)
    return PaginatedNotes(total=total, items=[NoteOut(**n) for n in items])


@app.get(
    "/notes/{note_id}",
    response_model=NoteOut,
    tags=["notes"],
    summary="Get a note",
    description="Get a note by ID if it belongs to the authenticated user.",
)
def get_note(
    note_id: str = Path(..., description="Note ID"),
    user_id: str = Depends(get_current_user_id),
) -> NoteOut:
    """Retrieve a single note owned by the current user."""
    note = notes_repo.get(note_id)
    if not note or note["owner_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return NoteOut(**note)


@app.put(
    "/notes/{note_id}",
    response_model=NoteOut,
    tags=["notes"],
    summary="Update a note",
    description="Update title/content/tags for a note owned by the authenticated user.",
)
def update_note(
    note: NoteUpdate,
    note_id: str = Path(..., description="Note ID"),
    user_id: str = Depends(get_current_user_id),
) -> NoteOut:
    """Update a note owned by the current user."""
    existing = notes_repo.get(note_id)
    if not existing or existing["owner_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    updated = notes_repo.update(note_id, title=note.title, content=note.content, tags=note.tags)
    return NoteOut(**updated)  # type: ignore


@app.delete(
    "/notes/{note_id}",
    status_code=204,
    tags=["notes"],
    summary="Delete a note",
    description="Delete a note owned by the authenticated user.",
)
def delete_note(
    note_id: str = Path(..., description="Note ID"),
    user_id: str = Depends(get_current_user_id),
) -> JSONResponse:
    """Delete a note owned by the current user. Returns 204 on success."""
    existing = notes_repo.get(note_id)
    if not existing or existing["owner_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    notes_repo.delete(note_id)
    return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content=None)
