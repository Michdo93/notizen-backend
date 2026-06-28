"""
notizen-backend – FastAPI + SQLite + JWT
Deploy auf Render.com als Web Service (Python)
"""
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import os

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY   = os.getenv("SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION_USE_RANDOM_32_CHARS")
ALGORITHM    = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 Tage

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./notizen.db")

# Render.com: /data nur nutzen wenn Disk bereits gemountet ist (existiert + beschreibbar)
# Persistent Disk ist ein bezahltes Add-on – ohne sie läuft die DB im Projektverzeichnis
if DATABASE_URL.startswith("sqlite") and os.path.isdir("/data") and os.access("/data", os.W_OK):
    DATABASE_URL = "sqlite:////data/notizen.db"

ALLOWED_ORIGINS_RAW = os.getenv("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS_RAW.split(",") if o.strip()] or ["*"]

# ── DB Setup ──────────────────────────────────────────────────────────────────
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ── Models ────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id         = Column(Integer, primary_key=True, index=True)
    username   = Column(String(50), unique=True, index=True, nullable=False)
    email      = Column(String(120), unique=True, index=True, nullable=False)
    hashed_pw  = Column(String, nullable=False)
    is_admin   = Column(Boolean, default=False)
    is_active  = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    notizen    = relationship("Notiz", back_populates="owner", cascade="all, delete")

class Notiz(Base):
    __tablename__ = "notizen"
    id         = Column(Integer, primary_key=True, index=True)
    title      = Column(String(200), nullable=False)
    content    = Column(Text, default="")
    color      = Column(String(20), default="#1e2024")
    pinned     = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id   = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner      = relationship("User", back_populates="notizen")

Base.metadata.create_all(bind=engine)

# ── Auth Helpers ──────────────────────────────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(pw: str) -> str:
    return pwd_ctx.hash(pw)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()
    expire  = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    payload.update({"exp": expire})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Ungültiges Token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise cred_exc
    except JWTError:
        raise cred_exc
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise cred_exc
    return user

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin-Rechte erforderlich")
    return current_user

# ── Pydantic Schemas ──────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserOut(BaseModel):
    id: int; username: str; email: str; is_admin: bool; is_active: bool; created_at: datetime
    class Config: from_attributes = True

class TokenOut(BaseModel):
    access_token: str; token_type: str; user: UserOut

class NotizCreate(BaseModel):
    title: str; content: str = ""; color: str = "#1e2024"; pinned: bool = False

class NotizUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    color: Optional[str] = None
    pinned: Optional[bool] = None

class NotizOut(BaseModel):
    id: int; title: str; content: str; color: str; pinned: bool
    created_at: datetime; updated_at: datetime; owner_id: int
    class Config: from_attributes = True

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="Notizen-Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.post("/auth/register", response_model=TokenOut, status_code=201)
def register(data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Benutzername bereits vergeben")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "E-Mail bereits registriert")
    if len(data.password) < 8:
        raise HTTPException(400, "Passwort muss mindestens 8 Zeichen haben")
    # Erster User wird Admin
    is_admin = db.query(User).count() == 0
    user = User(username=data.username, email=data.email,
                hashed_pw=hash_password(data.password), is_admin=is_admin)
    db.add(user); db.commit(); db.refresh(user)
    token = create_token({"sub": user.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer", "user": user}

@app.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_pw):
        raise HTTPException(status_code=401, detail="Benutzername oder Passwort falsch")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Konto gesperrt")
    token = create_token({"sub": user.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer", "user": user}

@app.get("/auth/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user

# ── Notizen Routes ────────────────────────────────────────────────────────────
@app.get("/notizen", response_model=List[NotizOut])
def get_notizen(
    search: Optional[str] = None,
    pinned: Optional[bool] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    q = db.query(Notiz).filter(Notiz.owner_id == current_user.id)
    if search:
        q = q.filter((Notiz.title.contains(search)) | (Notiz.content.contains(search)))
    if pinned is not None:
        q = q.filter(Notiz.pinned == pinned)
    return q.order_by(Notiz.pinned.desc(), Notiz.updated_at.desc()).all()

@app.post("/notizen", response_model=NotizOut, status_code=201)
def create_notiz(data: NotizCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    notiz = Notiz(**data.model_dump(), owner_id=current_user.id)
    db.add(notiz); db.commit(); db.refresh(notiz)
    return notiz

@app.get("/notizen/{notiz_id}", response_model=NotizOut)
def get_notiz(notiz_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    notiz = db.query(Notiz).filter(Notiz.id == notiz_id, Notiz.owner_id == current_user.id).first()
    if not notiz:
        raise HTTPException(404, "Notiz nicht gefunden")
    return notiz

@app.put("/notizen/{notiz_id}", response_model=NotizOut)
def update_notiz(notiz_id: int, data: NotizUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    notiz = db.query(Notiz).filter(Notiz.id == notiz_id, Notiz.owner_id == current_user.id).first()
    if not notiz:
        raise HTTPException(404, "Notiz nicht gefunden")
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(notiz, field, value)
    notiz.updated_at = datetime.utcnow()
    db.commit(); db.refresh(notiz)
    return notiz

@app.delete("/notizen/{notiz_id}", status_code=204)
def delete_notiz(notiz_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    notiz = db.query(Notiz).filter(Notiz.id == notiz_id, Notiz.owner_id == current_user.id).first()
    if not notiz:
        raise HTTPException(404, "Notiz nicht gefunden")
    db.delete(notiz); db.commit()

# ── Admin Routes ──────────────────────────────────────────────────────────────
@app.get("/admin/users", response_model=List[UserOut])
def admin_list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.created_at.desc()).all()

@app.patch("/admin/users/{user_id}/toggle-active", response_model=UserOut)
def admin_toggle_active(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User nicht gefunden")
    if user.id == admin.id:
        raise HTTPException(400, "Eigenes Konto kann nicht gesperrt werden")
    user.is_active = not user.is_active
    db.commit(); db.refresh(user)
    return user

@app.patch("/admin/users/{user_id}/toggle-admin", response_model=UserOut)
def admin_toggle_admin(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User nicht gefunden")
    if user.id == admin.id:
        raise HTTPException(400, "Eigene Admin-Rechte können nicht entzogen werden")
    user.is_admin = not user.is_admin
    db.commit(); db.refresh(user)
    return user

@app.delete("/admin/users/{user_id}", status_code=204)
def admin_delete_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User nicht gefunden")
    if user.id == admin.id:
        raise HTTPException(400, "Eigenes Konto kann nicht gelöscht werden")
    db.delete(user); db.commit()

@app.get("/admin/stats")
def admin_stats(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return {
        "total_users": db.query(User).count(),
        "active_users": db.query(User).filter(User.is_active == True).count(),
        "total_notizen": db.query(Notiz).count(),
        "pinned_notizen": db.query(Notiz).filter(Notiz.pinned == True).count(),
    }

@app.get("/")
def root():
    return {"service": "notizen-backend", "version": "1.0.0", "docs": "/docs"}
