import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pathlib import Path

from app.database import Base, get_db
from app.main import app
from app.models import User, Document, DocumentPermission, AuditLog, RoleEnum, StatusEnum

# Use dedicated in-memory / temporary test database
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./data/test_securevault.db"
test_engine = create_engine(SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    # Cleanup after test suite
    Base.metadata.drop_all(bind=test_engine)
    test_db_file = Path("./data/test_securevault.db")
    if test_db_file.exists():
        try:
            test_db_file.unlink()
        except Exception:
            pass

client = TestClient(app)

def test_01_user_registration_and_login():
    # Register Admin Alice
    res = client.post("/api/auth/register", json={
        "username": "alice_test",
        "email": "alice_test@securevault.corp",
        "full_name": "Alice Admin",
        "password": "Password123!",
        "role": "ADMIN",
        "department": "Security"
    })
    assert res.status_code == 200
    assert res.json()["username"] == "alice_test"
    assert res.json()["role"] == "ADMIN"

    # Register Manager Bob
    res = client.post("/api/auth/register", json={
        "username": "bob_test",
        "email": "bob_test@securevault.corp",
        "full_name": "Bob Manager",
        "password": "Password123!",
        "role": "MANAGER",
        "department": "Finance"
    })
    assert res.status_code == 200

    # Register Employee Charlie
    res = client.post("/api/auth/register", json={
        "username": "charlie_test",
        "email": "charlie_test@securevault.corp",
        "full_name": "Charlie Employee",
        "password": "Password123!",
        "role": "EMPLOYEE",
        "department": "Operations"
    })
    assert res.status_code == 200

    # Test Login & JWT Issuing
    res = client.post("/api/auth/login", json={
        "username": "alice_test",
        "password": "Password123!"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["username"] == "alice_test"

def test_02_document_upload_and_at_rest_encryption():
    # Login as Manager Bob
    res = client.post("/api/auth/login", json={"username": "bob_test", "password": "Password123!"})
    bob_token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {bob_token}"}

    # Upload Company_Report.pdf with permissions:
    # Admin: all
    # Manager: view, download, edit
    # Employee: view only
    file_bytes = b"%PDF-1.4 Company Report Secret Financial Numbers 2026"
    res = client.post(
        "/api/documents/upload",
        headers=headers,
        data={
            "title": "Company_Report.pdf",
            "description": "Confidential Q3 Executive Financial Overview",
            "category": "Finance",
            "admin_view": "true",
            "admin_download": "true",
            "admin_edit": "true",
            "admin_delete": "true",
            "manager_view": "true",
            "manager_download": "true",
            "manager_edit": "true",
            "manager_delete": "false",
            "employee_view": "true",
            "employee_download": "false",
            "employee_edit": "false",
            "employee_delete": "false"
        },
        files={"file": ("Company_Report.pdf", file_bytes, "application/pdf")}
    )
    assert res.status_code == 200
    doc_data = res.json()
    assert doc_data["title"] == "Company_Report.pdf"
    assert doc_data["current_version_num"] == 1
    assert len(doc_data["versions"]) == 1

    # Verify physical file on disk is encrypted (not plain text)
    db = TestingSessionLocal()
    doc_ver = db.query(Document).filter(Document.id == doc_data["id"]).first().versions[0]
    enc_path = Path(doc_ver.encrypted_file_path)
    assert enc_path.exists()
    raw_disk_bytes = enc_path.read_bytes()
    assert b"Company Report Secret Financial Numbers 2026" not in raw_disk_bytes, "Disk content MUST be encrypted ciphertext!"
    db.close()

def test_03_permission_verification_and_403_access_denied():
    # Charlie (Employee) logs in
    res = client.post("/api/auth/login", json={"username": "charlie_test", "password": "Password123!"})
    charlie_token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {charlie_token}"}

    # Find the document ID
    res = client.get("/api/documents", headers=headers)
    assert res.status_code == 200
    docs = res.json()
    assert len(docs) >= 1
    target_doc = [d for d in docs if d["title"] == "Company_Report.pdf"][0]
    doc_id = target_doc["id"]

    # Charlie CAN view
    res = client.get(f"/api/documents/{doc_id}/view", headers=headers)
    assert res.status_code == 200
    assert b"%PDF-1.4" in res.content

    # Charlie TRIES to download -> MUST BE 403 Forbidden!
    res = client.get(f"/api/documents/{doc_id}/download", headers=headers)
    assert res.status_code == 403
    assert "Access Denied" in res.json()["detail"]

def test_04_audit_log_captures_denied_attempt():
    # Admin Alice inspects audit logs
    res = client.post("/api/auth/login", json={"username": "alice_test", "password": "Password123!"})
    alice_token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {alice_token}"}

    res = client.get("/api/audit/logs?status=DENIED", headers=headers)
    assert res.status_code == 200
    denied_logs = res.json()
    assert len(denied_logs) >= 1

    # Verify denied log entry details match user requirement
    latest_denied = denied_logs[0]
    assert latest_denied["username"] == "charlie_test"
    assert latest_denied["action"] == "DOWNLOAD_ATTEMPT"
    assert latest_denied["document_title"] == "Company_Report.pdf"
    assert latest_denied["status"] == "DENIED"
    assert "Access Denied" in latest_denied["details"]

def test_05_file_versioning():
    # Manager Bob logs in and uploads version 2 of Company_Report.pdf
    res = client.post("/api/auth/login", json={"username": "bob_test", "password": "Password123!"})
    bob_token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {bob_token}"}

    # Get doc id
    res = client.get("/api/documents", headers=headers)
    doc_id = [d for d in res.json() if d["title"] == "Company_Report.pdf"][0]["id"]

    v2_content = b"%PDF-1.4 Company Report v2 Updated Figures with Executive Summary"
    res = client.post(
        f"/api/documents/{doc_id}/versions",
        headers=headers,
        data={"change_notes": "Added executive summary and final tax reconciliation (v2)"},
        files={"file": ("Company_Report_v2.pdf", v2_content, "application/pdf")}
    )
    assert res.status_code == 200
    updated_doc = res.json()
    assert updated_doc["current_version_num"] == 2
    assert len(updated_doc["versions"]) == 2

    # Manager Bob downloads v1 vs v2
    res_v1 = client.get(f"/api/documents/{doc_id}/download?version_num=1", headers=headers)
    assert res_v1.status_code == 200
    assert b"Company Report Secret Financial Numbers 2026" in res_v1.content

    res_v2 = client.get(f"/api/documents/{doc_id}/download?version_num=2", headers=headers)
    assert res_v2.status_code == 200
    assert b"Company Report v2 Updated Figures" in res_v2.content

def test_06_permission_update_grants_download():
    # Admin Alice updates Charlie's permission to allow download
    res = client.post("/api/auth/login", json={"username": "alice_test", "password": "Password123!"})
    alice_token = res.json()["access_token"]
    headers_alice = {"Authorization": f"Bearer {alice_token}"}

    res = client.get("/api/documents", headers=headers_alice)
    doc_id = [d for d in res.json() if d["title"] == "Company_Report.pdf"][0]["id"]

    # Update Employee permissions: set can_download = True
    update_res = client.put(
        f"/api/documents/{doc_id}/permissions",
        headers=headers_alice,
        json={
            "permissions": [
                {"role": "ADMIN", "can_view": True, "can_download": True, "can_edit": True, "can_delete": True},
                {"role": "MANAGER", "can_view": True, "can_download": True, "can_edit": True, "can_delete": False},
                {"role": "EMPLOYEE", "can_view": True, "can_download": True, "can_edit": False, "can_delete": False}
            ]
        }
    )
    assert update_res.status_code == 200

    # Now Charlie tries download again -> Should SUCCEED!
    res = client.post("/api/auth/login", json={"username": "charlie_test", "password": "Password123!"})
    charlie_token = res.json()["access_token"]
    headers_charlie = {"Authorization": f"Bearer {charlie_token}"}

    res_dl = client.get(f"/api/documents/{doc_id}/download", headers=headers_charlie)
    assert res_dl.status_code == 200
    assert len(res_dl.content) > 0
