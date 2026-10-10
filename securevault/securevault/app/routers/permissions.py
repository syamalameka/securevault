from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Document, DocumentPermission, RoleEnum, ActionEnum, StatusEnum
from app.schemas import PermissionRule, PermissionUpdate
from app.auth import get_current_user
from app.security import record_audit

router = APIRouter(prefix="/api/documents/{doc_id}/permissions", tags=["Permissions"])

@router.get("", response_model=List[PermissionRule])
def get_permissions(
    doc_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    
    perms = db.query(DocumentPermission).filter(DocumentPermission.document_id == doc_id).all()
    return perms

@router.put("", response_model=List[PermissionRule])
def update_permissions(
    doc_id: int,
    payload: PermissionUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role not in [RoleEnum.ADMIN, RoleEnum.MANAGER]:
        raise HTTPException(status_code=403, detail="Only Admins and Managers can configure permissions.")

    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    updated_rules = []
    details_summary = []

    for rule in payload.permissions:
        role_name = rule.role.upper()
        perm = db.query(DocumentPermission).filter(
            DocumentPermission.document_id == doc_id,
            DocumentPermission.role == role_name
        ).first()

        if not perm:
            perm = DocumentPermission(
                document_id=doc_id,
                role=role_name
            )
            db.add(perm)

        perm.can_view = rule.can_view
        perm.can_download = rule.can_download
        perm.can_edit = rule.can_edit
        perm.can_delete = rule.can_delete
        updated_rules.append(perm)
        details_summary.append(
            f"{role_name}: view={rule.can_view}, dl={rule.can_download}, edit={rule.can_edit}, del={rule.can_delete}"
        )

    db.commit()

    record_audit(
        db=db,
        user=current_user,
        action=ActionEnum.PERMISSION_UPDATE,
        status_val=StatusEnum.ALLOWED,
        document=doc,
        details=f"Permissions updated: {'; '.join(details_summary)}",
        request=request
    )

    return updated_rules
