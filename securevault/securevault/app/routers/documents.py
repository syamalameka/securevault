from io import BytesIO
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Document, DocumentVersion, DocumentPermission, RoleEnum, ActionEnum, StatusEnum
from app.schemas import DocumentResponse, DocumentListItem, VersionResponse
from app.auth import get_current_user
from app.security import (
    save_encrypted_file,
    read_decrypted_file,
    record_audit,
    get_effective_permissions,
    verify_document_permission
)

router = APIRouter(prefix="/api/documents", tags=["Documents"])

@router.post("/upload", response_model=DocumentResponse)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(...),
    description: str = Form(""),
    category: str = Form("General"),
    admin_view: bool = Form(True),
    admin_download: bool = Form(True),
    admin_edit: bool = Form(True),
    admin_delete: bool = Form(True),
    manager_view: bool = Form(True),
    manager_download: bool = Form(True),
    manager_edit: bool = Form(True),
    manager_delete: bool = Form(False),
    employee_view: bool = Form(True),
    employee_download: bool = Form(False),
    employee_edit: bool = Form(False),
    employee_delete: bool = Form(False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role not in [RoleEnum.ADMIN, RoleEnum.MANAGER]:
        raise HTTPException(status_code=403, detail="Only Admins and Managers can upload new documents.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    encrypted_path, sha_hash, file_size = save_encrypted_file(content, file.filename)

    doc = Document(
        title=title,
        description=description,
        category=category,
        owner_id=current_user.id,
        current_version_num=1
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    v1 = DocumentVersion(
        document_id=doc.id,
        version_number=1,
        file_name=file.filename,
        file_size=file_size,
        mime_type=file.content_type or "application/octet-stream",
        encrypted_file_path=encrypted_path,
        file_hash=sha_hash,
        change_notes="Initial version upload",
        uploaded_by_id=current_user.id
    )
    db.add(v1)

    # Add Permissions Matrix
    permissions = [
        DocumentPermission(
            document_id=doc.id, role=RoleEnum.ADMIN,
            can_view=admin_view, can_download=admin_download, can_edit=admin_edit, can_delete=admin_delete
        ),
        DocumentPermission(
            document_id=doc.id, role=RoleEnum.MANAGER,
            can_view=manager_view, can_download=manager_download, can_edit=manager_edit, can_delete=manager_delete
        ),
        DocumentPermission(
            document_id=doc.id, role=RoleEnum.EMPLOYEE,
            can_view=employee_view, can_download=employee_download, can_edit=employee_edit, can_delete=employee_delete
        )
    ]
    for p in permissions:
        db.add(p)

    db.commit()
    db.refresh(doc)

    record_audit(
        db=db,
        user=current_user,
        action=ActionEnum.UPLOAD,
        status_val=StatusEnum.ALLOWED,
        document=doc,
        version_number=1,
        details=f"Uploaded '{file.filename}' (v1, {file_size} bytes) with encrypted at-rest storage.",
        request=request
    )

    return build_doc_response(doc, current_user, db)

@router.get("", response_model=List[DocumentListItem])
def list_documents(
    query: Optional[str] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    q = db.query(Document).filter(Document.is_deleted == False)
    if query:
        q = q.filter(Document.title.ilike(f"%{query}%") | Document.description.ilike(f"%{query}%"))
    if category and category != "All":
        q = q.filter(Document.category == category)
    
    docs = q.order_by(Document.updated_at.desc()).all()
    results = []
    
    for d in docs:
        perms = get_effective_permissions(db, current_user, d)
        # Only show docs where user has at least view permission
        if not perms.get("can_view", False):
            continue
            
        latest_ver = db.query(DocumentVersion).filter(
            DocumentVersion.document_id == d.id,
            DocumentVersion.version_number == d.current_version_num
        ).first()

        results.append(DocumentListItem(
            id=d.id,
            title=d.title,
            description=d.description or "",
            category=d.category,
            owner_name=d.owner.full_name if d.owner else "Unknown",
            current_version_num=d.current_version_num,
            latest_file_name=latest_ver.file_name if latest_ver else "N/A",
            latest_file_size=latest_ver.file_size if latest_ver else 0,
            latest_mime_type=latest_ver.mime_type if latest_ver else "application/octet-stream",
            created_at=d.created_at,
            updated_at=d.updated_at,
            user_permissions=perms
        ))
    return results

@router.get("/{doc_id}", response_model=DocumentResponse)
def get_document(
    doc_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    verify_document_permission(db, current_user, doc, "VIEW", request=request)
    return build_doc_response(doc, current_user, db)

@router.get("/{doc_id}/view")
def view_document_content(
    doc_id: int,
    request: Request,
    version_num: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    verify_document_permission(db, current_user, doc, "VIEW", request=request)

    target_version_num = version_num if version_num else doc.current_version_num
    ver = db.query(DocumentVersion).filter(
        DocumentVersion.document_id == doc.id,
        DocumentVersion.version_number == target_version_num
    ).first()
    if not ver:
        raise HTTPException(status_code=404, detail="Version not found")

    decrypted_bytes = read_decrypted_file(ver.encrypted_file_path)

    record_audit(
        db=db,
        user=current_user,
        action=ActionEnum.VIEW,
        status_val=StatusEnum.ALLOWED,
        document=doc,
        version_number=target_version_num,
        details=f"Viewed document '{ver.file_name}' (v{target_version_num}) in-app preview.",
        request=request
    )

    return StreamingResponse(
        BytesIO(decrypted_bytes),
        media_type=ver.mime_type,
        headers={
            "Content-Disposition": f'inline; filename="{ver.file_name}"',
            "X-Document-Version": str(target_version_num)
        }
    )

@router.get("/{doc_id}/download")
def download_document_content(
    doc_id: int,
    request: Request,
    version_num: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Downloads file. Checks download permissions.
    If unauthorized (e.g. Employee with View-Only permission), raises 403 Forbidden
    and logs DENIED attempt in Audit Trail!
    """
    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    verify_document_permission(db, current_user, doc, "DOWNLOAD", request=request)

    target_version_num = version_num if version_num else doc.current_version_num
    ver = db.query(DocumentVersion).filter(
        DocumentVersion.document_id == doc.id,
        DocumentVersion.version_number == target_version_num
    ).first()
    if not ver:
        raise HTTPException(status_code=404, detail="Version not found")

    decrypted_bytes = read_decrypted_file(ver.encrypted_file_path)

    record_audit(
        db=db,
        user=current_user,
        action=ActionEnum.DOWNLOAD,
        status_val=StatusEnum.ALLOWED,
        document=doc,
        version_number=target_version_num,
        details=f"Downloaded file '{ver.file_name}' (v{target_version_num}, {ver.file_size} bytes).",
        request=request
    )

    return StreamingResponse(
        BytesIO(decrypted_bytes),
        media_type=ver.mime_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{ver.file_name}"',
            "X-Document-Version": str(target_version_num)
        }
    )

@router.post("/{doc_id}/versions", response_model=DocumentResponse)
async def upload_new_version(
    doc_id: int,
    request: Request,
    file: UploadFile = File(...),
    change_notes: str = Form(""),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    verify_document_permission(db, current_user, doc, "EDIT", request=request)

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    new_version_num = doc.current_version_num + 1
    encrypted_path, sha_hash, file_size = save_encrypted_file(content, file.filename)

    new_version = DocumentVersion(
        document_id=doc.id,
        version_number=new_version_num,
        file_name=file.filename,
        file_size=file_size,
        mime_type=file.content_type or "application/octet-stream",
        encrypted_file_path=encrypted_path,
        file_hash=sha_hash,
        change_notes=change_notes or f"Updated to version {new_version_num}",
        uploaded_by_id=current_user.id
    )
    db.add(new_version)
    doc.current_version_num = new_version_num
    db.commit()
    db.refresh(doc)

    record_audit(
        db=db,
        user=current_user,
        action=ActionEnum.VERSION_ADD,
        status_val=StatusEnum.ALLOWED,
        document=doc,
        version_number=new_version_num,
        details=f"Uploaded new version v{new_version_num} ({file.filename}) notes: '{change_notes}'.",
        request=request
    )

    return build_doc_response(doc, current_user, db)

@router.delete("/{doc_id}")
def delete_document(
    doc_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted == False).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    verify_document_permission(db, current_user, doc, "DELETE", request=request)

    doc.is_deleted = True
    db.commit()

    record_audit(
        db=db,
        user=current_user,
        action=ActionEnum.DELETE,
        status_val=StatusEnum.ALLOWED,
        document=doc,
        details=f"Document '{doc.title}' deleted.",
        request=request
    )

    return {"message": "Document deleted successfully"}

def build_doc_response(doc: Document, user: User, db: Session) -> DocumentResponse:
    perms = get_effective_permissions(db, user, doc)
    
    # Get latest version info
    latest = db.query(DocumentVersion).filter(
        DocumentVersion.document_id == doc.id,
        DocumentVersion.version_number == doc.current_version_num
    ).first()

    versions = db.query(DocumentVersion).filter(
        DocumentVersion.document_id == doc.id
    ).order_by(DocumentVersion.version_number.desc()).all()

    v_responses = [
        VersionResponse(
            id=v.id,
            version_number=v.version_number,
            file_name=v.file_name,
            file_size=v.file_size,
            mime_type=v.mime_type,
            file_hash=v.file_hash,
            change_notes=v.change_notes or "",
            uploaded_by_name=v.uploaded_by.full_name if v.uploaded_by else "Unknown",
            created_at=v.created_at
        )
        for v in versions
    ]

    p_records = db.query(DocumentPermission).filter(DocumentPermission.document_id == doc.id).all()

    return DocumentResponse(
        id=doc.id,
        title=doc.title,
        description=doc.description or "",
        category=doc.category,
        owner_id=doc.owner_id,
        owner_name=doc.owner.full_name if doc.owner else "Unknown",
        current_version_num=doc.current_version_num,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        latest_file_name=latest.file_name if latest else None,
        latest_file_size=latest.file_size if latest else None,
        latest_mime_type=latest.mime_type if latest else None,
        user_permissions=perms,
        permissions=p_records,
        versions=v_responses
    )
