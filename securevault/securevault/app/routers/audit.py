from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import AuditLog, User, RoleEnum
from app.schemas import AuditLogResponse
from app.auth import get_current_user

router = APIRouter(prefix="/api/audit", tags=["Audit Logs"])

@router.get("/logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    status: Optional[str] = None,
    action: Optional[str] = None,
    username: Optional[str] = None,
    document_id: Optional[int] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    q = db.query(AuditLog)

    if status and status != "ALL":
        q = q.filter(AuditLog.status == status.upper())
    if action and action != "ALL":
        q = q.filter(AuditLog.action == action.upper())
    if username:
        q = q.filter(AuditLog.username.ilike(f"%{username}%"))
    if document_id:
        q = q.filter(AuditLog.document_id == document_id)

    # Regular employees can only view logs related to them, whereas Managers and Admins can view all organization logs
    if current_user.role == RoleEnum.EMPLOYEE:
        q = q.filter(AuditLog.user_id == current_user.id)

    return q.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()

@router.get("/stats")
def get_audit_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    total = db.query(AuditLog).count()
    allowed = db.query(AuditLog).filter(AuditLog.status == "ALLOWED").count()
    denied = db.query(AuditLog).filter(AuditLog.status == "DENIED").count()
    downloads_blocked = db.query(AuditLog).filter(AuditLog.action == "DOWNLOAD_ATTEMPT").count()
    
    return {
        "total_events": total,
        "allowed_events": allowed,
        "denied_events": denied,
        "downloads_blocked": downloads_blocked
    }
