import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Literal
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from hashlib import sha256
from database import db, create_document, get_documents

app = FastAPI(title="Hospital Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------
# Helper functions
# --------------------------

def hash_password(password: str) -> str:
    return sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


def create_token(user_id: str, role: str) -> str:
    import secrets
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    db["token"].insert_one({
        "token": token,
        "user_id": user_id,
        "role": role,
        "expires_at": expires_at,
        "created_at": datetime.now(timezone.utc)
    })
    return token


def get_user_from_token(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    # Expect Bearer <token>
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    token = parts[1]
    tok = db["token"].find_one({"token": token})
    if not tok:
        raise HTTPException(status_code=401, detail="Invalid token")
    if tok.get("expires_at") and tok["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Token expired")
    user = db["user_auth"].find_one({"_id": tok["user_id"]})
    if not user:
        # Handle case where we stored user_id as string
        user = db["user_auth"].find_one({"_id": tok["user_id"]})
    # In case _id stored as ObjectId
    if not user:
        try:
            from bson import ObjectId
            user = db["user_auth"].find_one({"_id": ObjectId(tok["user_id"])})
        except Exception:
            user = None
    if not user:
        raise HTTPException(status_code=401, detail="User not found for token")
    # Normalize response
    user_out = {
        "id": str(user.get("_id")),
        "name": user.get("name"),
        "email": user.get("email"),
        "role": user.get("role"),
        "is_active": user.get("is_active", True)
    }
    return user_out


def require_roles(allowed: List[str]):
    def dep(user=Depends(get_user_from_token)):
        if user["role"] not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden for this role")
        return user
    return dep

# --------------------------
# Models
# --------------------------

class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Literal["admin", "doctor", "receptionist", "patient"] = "patient"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    token: str
    role: str
    name: str
    email: EmailStr


class StaffCreate(BaseModel):
    name: str
    email: EmailStr
    role: Literal["doctor", "nurse", "admin", "receptionist"]
    department: Optional[str] = None
    phone: Optional[str] = None
    is_active: bool = True


class PatientCreate(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    date_of_birth: Optional[str] = None


class AppointmentCreate(BaseModel):
    patient_id: str
    doctor_id: str
    datetime: datetime
    reason: Optional[str] = None

# --------------------------
# Base endpoints
# --------------------------

@app.get("/")
def read_root():
    return {"message": "Hospital Management API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = getattr(db, 'name', None) or "✅ Connected"
            response["connection_status"] = "Connected"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

# --------------------------
# Authentication endpoints
# --------------------------

@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignupRequest):
    # Check existing
    existing = db["user_auth"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": payload.email.lower(),
        "role": payload.role,
        "password_hash": hash_password(payload.password),
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user_auth"].insert_one(user_doc)
    user_id = str(result.inserted_id)
    token = create_token(user_id, payload.role)
    return AuthResponse(token=token, role=payload.role, name=payload.name, email=payload.email)


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    user = db["user_auth"].find_one({"email": payload.email.lower()})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="User is inactive")
    token = create_token(str(user.get("_id")), user.get("role"))
    return AuthResponse(token=token, role=user.get("role"), name=user.get("name"), email=user.get("email"))


@app.get("/auth/me")
def me(user=Depends(get_user_from_token)):
    return user

# --------------------------
# Admin endpoints
# --------------------------

@app.post("/admin/staff")
def create_staff(payload: StaffCreate, user=Depends(require_roles(["admin"]))):
    doc = payload.model_dump()
    doc["created_by"] = user["id"]
    doc["created_at"] = datetime.now(timezone.utc)
    doc["updated_at"] = datetime.now(timezone.utc)
    res_id = db["staff"].insert_one(doc).inserted_id
    return {"id": str(res_id), "message": "Staff created"}


@app.get("/admin/staff")
def list_staff(user=Depends(require_roles(["admin"]))):
    items = list(db["staff"].find({}).limit(100))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.post("/admin/patients")
def create_patient(payload: PatientCreate, user=Depends(require_roles(["admin", "receptionist"]))):
    doc = payload.model_dump()
    doc["created_by"] = user["id"]
    doc["created_at"] = datetime.now(timezone.utc)
    doc["updated_at"] = datetime.now(timezone.utc)
    res_id = db["patient"].insert_one(doc).inserted_id
    return {"id": str(res_id), "message": "Patient created"}


@app.get("/admin/patients")
def list_patients(user=Depends(require_roles(["admin", "receptionist", "doctor"]))):
    items = list(db["patient"].find({}).limit(200))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.post("/admin/appointments")
def create_appointment(payload: AppointmentCreate, user=Depends(require_roles(["admin", "receptionist"]))):
    doc = payload.model_dump()
    doc["status"] = "scheduled"
    doc["created_by"] = user["id"]
    doc["created_at"] = datetime.now(timezone.utc)
    doc["updated_at"] = datetime.now(timezone.utc)
    res_id = db["appointment"].insert_one(doc).inserted_id
    return {"id": str(res_id), "message": "Appointment created"}


@app.get("/admin/appointments")
def list_appointments(user=Depends(require_roles(["admin", "receptionist", "doctor"]))):
    items = list(db["appointment"].find({}).limit(200))
    for it in items:
        it["id"] = str(it.pop("_id"))
        # stringify datetime
        if isinstance(it.get("datetime"), datetime):
            it["datetime"] = it["datetime"].isoformat()
    return items

# Doctor-specific views
@app.get("/doctor/schedule")
def doctor_schedule(user=Depends(require_roles(["doctor"]))):
    items = list(db["appointment"].find({"doctor_id": user["id"]}).limit(200))
    for it in items:
        it["id"] = str(it.pop("_id"))
        if isinstance(it.get("datetime"), datetime):
            it["datetime"] = it["datetime"].isoformat()
    return items


# Reports placeholder (admin only)
@app.get("/admin/reports/summary")
def reports_summary(user=Depends(require_roles(["admin"]))):
    return {
        "patients": db["patient"].count_documents({}),
        "staff": db["staff"].count_documents({}),
        "appointments": db["appointment"].count_documents({}),
        "generated_at": datetime.now(timezone.utc).isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
