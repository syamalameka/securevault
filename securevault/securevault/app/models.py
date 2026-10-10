from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database import Base

class RoleEnum:
    ADMIN = "ADMIN"
    MANAGER = "MANAGER"
    EMPLOYEE = "EMPLOYEE"

    ALL = [ADMIN, MANAGER, EMPLOYEE]

class ActionEnum:
    UPLOAD = "UPLOAD"
    VIEW = "VIEW"
    VIEW_ATTEMPT = "VIEW_ATTEMPT"
    DOWNLOAD = "DOWNLOAD"
    DOWNLOAD_ATTEMPT = "DOWNLOAD_ATTEMPT"
    VERSION_ADD = "VERSION_ADD"
    PERMISSION_UPDATE = "PERMISSION_UPDATE"
    DELETE = "DELETE"
    LOGIN = "LOGIN"

class StatusEnum:
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(20), default=RoleEnum.EMPLOYEE, nullable=False)
    department = Column(String(100), default="General")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    documents = relationship("Document", back_populates="owner")
    versions = relationship("DocumentVersion", back_populates="uploaded_by")

class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), index=True, nullable=False)
    description = Column(Text, default="")
    category = Column(String(50), default="General")
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    current_version_num = Column(Integer, default=1)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    owner = relationship("User", back_populates="documents")
    versions = relationship("DocumentVersion", back_populates="document", cascade="all, delete-orphan", order_by="DocumentVersion.version_number.desc()")
    permissions = relationship("DocumentPermission", back_populates="document", cascade="all, delete-orphan")

class DocumentVersion(Base):
    __tablename__ = "document_versions"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    version_number = Column(Integer, nullable=False)
    file_name = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100), default="application/octet-stream")
    encrypted_file_path = Column(String(500), nullable=False)
    file_hash = Column(String(64), nullable=False)  # SHA-256
    change_notes = Column(Text, default="")
    uploaded_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    document = relationship("Document", back_populates="versions")
    uploaded_by = relationship("User", back_populates="versions")

    __table_args__ = (
        UniqueConstraint("document_id", "version_number", name="uq_doc_version"),
    )

class DocumentPermission(Base):
    __tablename__ = "document_permissions"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    role = Column(String(20), nullable=False)  # ADMIN, MANAGER, EMPLOYEE
    can_view = Column(Boolean, default=True)
    can_download = Column(Boolean, default=False)
    can_edit = Column(Boolean, default=False)
    can_delete = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    document = relationship("Document", back_populates="permissions")

    __table_args__ = (
        UniqueConstraint("document_id", "role", name="uq_doc_role_perm"),
    )

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(50), nullable=False)
    user_role = Column(String(20), nullable=False)
    action = Column(String(50), nullable=False)
    document_id = Column(Integer, nullable=True)
    document_title = Column(String(255), nullable=True)
    version_number = Column(Integer, nullable=True)
    status = Column(String(20), nullable=False)  # ALLOWED, DENIED
    ip_address = Column(String(50), default="127.0.0.1")
    details = Column(Text, default="")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
