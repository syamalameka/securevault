from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, RoleEnum, AuditLog, ActionEnum, StatusEnum
from app.schemas import UserCreate, UserLogin, UserResponse, Token
from app.auth import hash_password, verify_password, create_access_token, get_current_user
from app.security import record_audit

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")

    role = user_in.role.upper()
    if role not in RoleEnum.ALL:
        role = RoleEnum.EMPLOYEE

    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        full_name=user_in.full_name,
        role=role,
        department=user_in.department or "General"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.post("/login", response_model=Token)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    record_audit(
        db=db,
        user=user,
        action=ActionEnum.LOGIN,
        status_val=StatusEnum.ALLOWED,
        details=f"User logged in successfully with role '{user.role}'"
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@router.get("/demo-login/{role}", response_model=Token)
def demo_login(role: str, db: Session = Depends(get_db)):
    """Fast demo switch for UI testing: Alice (Admin), Bob (Manager), Charlie (Employee)."""
    target_role = role.upper()
    user = db.query(User).filter(User.role == target_role).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"No demo user found for role {role}")
    
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    record_audit(
        db=db,
        user=user,
        action=ActionEnum.LOGIN,
        status_val=StatusEnum.ALLOWED,
        details=f"Demo role switch to {user.role} ({user.full_name})"
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
