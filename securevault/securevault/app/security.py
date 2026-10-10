import hashlib
import uuid
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import ENCRYPTION_KEY, VAULT_DIR
from app.models import User, Document, DocumentPermission, AuditLog, ActionEnum, StatusEnum, RoleEnum

fernet = Fernet(ENCRYPTION_KEY.encode("utf-8"))

def encrypt_bytes(data: bytes) -> bytes:
    """Encrypts raw document bytes with AES-256 Fernet before storing on disk."""
    return fernet.encrypt(data)

def decrypt_bytes(encrypted_data: bytes) -> bytes:
    """Decrypts ciphertext into raw document bytes in-memory."""
    return fernet.decrypt(encrypted_data)

def save_encrypted_file(content_bytes: bytes, original_filename: str) -> tuple[str, str, int]:
    """
    Encrypts file content and saves to vault directory.
    Returns (relative_file_path, sha256_hash, original_file_size).
    """
    sha256_hash = hashlib.sha256(content_bytes).hexdigest()
    encrypted_bytes = encrypt_bytes(content_bytes)
    
    unique_name = f"{uuid.uuid4().hex}_{Path(original_filename).name}.enc"
    target_path = VAULT_DIR / unique_name
    target_path.write_bytes(encrypted_bytes)
    
    return str(target_path), sha256_hash, len(content_bytes)

def read_decrypted_file(encrypted_path: str) -> bytes:
    """Reads encrypted file from disk and returns decrypted bytes."""
    path = Path(encrypted_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Physical file not found in vault")
    encrypted_bytes = path.read_bytes()
    return decrypt_bytes(encrypted_bytes)

def record_audit(
    db: Session,
    user: Optional[User],
    action: str,
    status_val: str,
    document: Optional[Document] = None,
    version_number: Optional[int] = None,
    details: str = "",
    request: Optional[Request] = None
) -> AuditLog:
    client_ip = "127.0.0.1"
    if request and request.client:
        client_ip = request.client.host

    log = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else "anonymous",
        user_role=user.role if user else "UNKNOWN",
        action=action,
        document_id=document.id if document else None,
        document_title=document.title if document else None,
        version_number=version_number,
        status=status_val,
        ip_address=client_ip,
        details=details
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log

def get_effective_permissions(db: Session, user: User, document: Document) -> dict[str, bool]:
    """Calculates effective permissions (view, download, edit, delete) for a user on a document."""
    if user.role == RoleEnum.ADMIN:
        return {"can_view": True, "can_download": True, "can_edit": True, "can_delete": True}
    
    perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document.id,
        DocumentPermission.role == user.role
    ).first()
    
    if not perm:
        # Default fallback if no permission record exists
        if user.role == RoleEnum.MANAGER:
            return {"can_view": True, "can_download": True, "can_edit": True, "can_delete": False}
        return {"can_view": False, "can_download": False, "can_edit": False, "can_delete": False}
        
    return {
        "can_view": bool(perm.can_view),
        "can_download": bool(perm.can_download),
        "can_edit": bool(perm.can_edit),
        "can_delete": bool(perm.can_delete)
    }

def verify_document_permission(
    db: Session,
    user: User,
    document: Document,
    action: str,
    request: Optional[Request] = None
) -> bool:
    """
    Checks whether user has the required action permission on document.
    If denied: records an audit log with status 'DENIED' and raises HTTP 403 Forbidden.
    """
    perms = get_effective_permissions(db, user, document)
    
    action_map = {
        "VIEW": "can_view",
        "DOWNLOAD": "can_download",
        "EDIT": "can_edit",
        "DELETE": "can_delete"
    }
    
    perm_field = action_map.get(action.upper())
    is_allowed = perms.get(perm_field, False) if perm_field else False
    
    if not is_allowed:
        attempt_action = f"{action.upper()}_ATTEMPT"
        record_audit(
            db=db,
            user=user,
            action=attempt_action,
            status_val=StatusEnum.DENIED,
            document=document,
            version_number=document.current_version_num,
            details=f"Access Denied: User '{user.username}' with role '{user.role}' lacks '{action.upper()}' permission.",
            request=request
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: You do not have permission to {action.lower()} this file."
        )
        
    return True
