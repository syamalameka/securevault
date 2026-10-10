from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine, SessionLocal
from app.routers import auth, documents, permissions, audit, users
from app.models import User, RoleEnum, Document, DocumentVersion, DocumentPermission, ActionEnum, StatusEnum
from app.auth import hash_password
from app.security import save_encrypted_file, record_audit

# Initialize Database tables
Base.metadata.create_all(bind=engine)

def seed_db():
    """Seeds default demo users (Admin Alice, Manager Bob, Employee Charlie) and sample report on startup."""
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            print("[SecureVault] Seeding demo users and initial documents...")
            alice = User(
                username="alice_admin",
                email="alice@securevault.corp",
                full_name="Alice (Security Admin)",
                hashed_password=hash_password("admin123"),
                role=RoleEnum.ADMIN,
                department="InfoSec & Governance"
            )
            bob = User(
                username="bob_manager",
                email="bob@securevault.corp",
                full_name="Bob (Finance Manager)",
                hashed_password=hash_password("manager123"),
                role=RoleEnum.MANAGER,
                department="Corporate Finance"
            )
            charlie = User(
                username="charlie_employee",
                email="charlie@securevault.corp",
                full_name="Charlie (Operations Employee)",
                hashed_password=hash_password("employee123"),
                role=RoleEnum.EMPLOYEE,
                department="Operations"
            )
            db.add_all([alice, bob, charlie])
            db.commit()
            db.refresh(bob)

            # Sample PDF / Document: Company_Report.pdf
            sample_content = b"%PDF-1.4\n1 0 obj\n<< /Title (Company_Report_Q3) /Author (Bob Finance) >>\nendobj\nstream\nSecureVault Enterprise Financial & Compliance Report Q3\nConfidential Document.\nendstream\nendobj\nxref\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
            enc_path, sha_hash, fsize = save_encrypted_file(sample_content, "Company_Report.pdf")

            report_doc = Document(
                title="Company_Report.pdf",
                description="Quarterly Enterprise Financial & Compliance audit report. High confidentiality.",
                category="Finance",
                owner_id=bob.id,
                current_version_num=1
            )
            db.add(report_doc)
            db.commit()
            db.refresh(report_doc)

            v1 = DocumentVersion(
                document_id=report_doc.id,
                version_number=1,
                file_name="Company_Report.pdf",
                file_size=fsize,
                mime_type="application/pdf",
                encrypted_file_path=enc_path,
                file_hash=sha_hash,
                change_notes="Initial Q3 Financial & Compliance Draft (v1)",
                uploaded_by_id=bob.id
            )
            db.add(v1)

            perms = [
                DocumentPermission(
                    document_id=report_doc.id, role=RoleEnum.ADMIN,
                    can_view=True, can_download=True, can_edit=True, can_delete=True
                ),
                DocumentPermission(
                    document_id=report_doc.id, role=RoleEnum.MANAGER,
                    can_view=True, can_download=True, can_edit=True, can_delete=False
                ),
                DocumentPermission(
                    document_id=report_doc.id, role=RoleEnum.EMPLOYEE,
                    can_view=True, can_download=False, can_edit=False, can_delete=False
                )
            ]
            for p in perms:
                db.add(p)
            db.commit()

            record_audit(
                db=db,
                user=bob,
                action=ActionEnum.UPLOAD,
                status_val=StatusEnum.ALLOWED,
                document=report_doc,
                version_number=1,
                details="Manager Bob uploaded 'Company_Report.pdf' with RBAC rule: Employee View-Only."
            )
            print("[SecureVault] Seed completed successfully!")
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    seed_db()
    yield

app = FastAPI(
    title="SecureVault – Enterprise Document & Access Management",
    description="Secure Document Storage, Role-Based Access Control, Versioning, and Audit Logging",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(permissions.router)
app.include_router(audit.router)
app.include_router(users.router)

# Mount Static assets
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def serve_index():
    return FileResponse(str(STATIC_DIR / "index.html"))

