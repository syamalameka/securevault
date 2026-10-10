from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import UserResponse
from app.auth import get_current_user, require_roles

router = APIRouter(prefix="/api/users", tags=["Users"])

@router.get("", response_model=List[UserResponse])
def get_users(
    current_user: User = Depends(require_roles("ADMIN", "MANAGER")),
    db: Session = Depends(get_db)
):
    return db.query(User).order_by(User.role, User.username).all()
