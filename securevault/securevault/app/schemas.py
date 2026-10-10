from datetime import datetime
from typing import List, Optional, Dict
from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserResponse"

class UserBase(BaseModel):
    username: str
    email: str
    full_name: str
    role: str
    department: Optional[str] = "General"

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}

class PermissionRule(BaseModel):
    role: str
    can_view: bool = True
    can_download: bool = False
    can_edit: bool = False
    can_delete: bool = False

    model_config = {"from_attributes": True}

class PermissionUpdate(BaseModel):
    permissions: List[PermissionRule]

class VersionResponse(BaseModel):
    id: int
    version_number: int
    file_name: str
    file_size: int
    mime_type: str
    file_hash: str
    change_notes: str
    uploaded_by_name: str
    created_at: datetime

    model_config = {"from_attributes": True}

class DocumentResponse(BaseModel):
    id: int
    title: str
    description: str
    category: str
    owner_id: int
    owner_name: str
    current_version_num: int
    created_at: datetime
    updated_at: datetime
    latest_file_name: Optional[str] = None
    latest_file_size: Optional[int] = None
    latest_mime_type: Optional[str] = None
    user_permissions: Dict[str, bool] = {}
    permissions: List[PermissionRule] = []
    versions: List[VersionResponse] = []

    model_config = {"from_attributes": True}

class DocumentListItem(BaseModel):
    id: int
    title: str
    description: str
    category: str
    owner_name: str
    current_version_num: int
    latest_file_name: str
    latest_file_size: int
    latest_mime_type: str
    created_at: datetime
    updated_at: datetime
    user_permissions: Dict[str, bool]

class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    username: str
    user_role: str
    action: str
    document_id: Optional[int]
    document_title: Optional[str]
    version_number: Optional[int]
    status: str
    ip_address: str
    details: str
    timestamp: datetime

    model_config = {"from_attributes": True}

Token.model_rebuild()
