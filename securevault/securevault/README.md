# SecureVault – Enterprise Document & Access Management System

SecureVault is an enterprise document governance platform built with FastAPI, modern responsive web UI, zero-trust Role-Based Access Control (RBAC), multi-revision document versioning, AES-256 Fernet at-rest file encryption, and comprehensive audit trail logging.

---

## 🌟 Key Features

1. **Role-Based Access Control (RBAC)**:
   - **Admin (Alice)**: View, Download, Edit Revisions, Delete, Full Permission Governance.
   - **Manager (Bob)**: View, Download, Upload New Revisions, Configure Document Permissions.
   - **Employee (Charlie)**: Default View-Only. Attempting to download triggers a **403 Forbidden** security barrier and instantly writes a `DENIED` record to the audit trail.

2. **Zero-Trust Permission Verification**:
   - Every file request verifies granular permissions (`can_view`, `can_download`, `can_edit`, `can_delete`).
   - Unauthorized attempts immediately log security telemetry with timestamp, client IP, action name, user details, and error reason.

3. **At-Rest AES-256 File Encryption**:
   - Raw documents are never stored in plaintext on disk.
   - Files are encrypted using AES-256 Fernet before disk write; decryption only takes place in-memory upon authorized stream.

4. **Multi-Version Document Tracking (v1, v2, v3)**:
   - Revision history preserves prior uploads with SHA-256 integrity hashes, author details, change notes, and download capabilities for historical revisions.

5. **Real-Time Audit Trail Explorer**:
   - Comprehensive timeline with filtering by status (`ALLOWED` vs `DENIED`), action, document, and user.
   - Live security metric widgets tracking blocked attempts in real-time.

---

## 🚀 Quick Start (Local Run)

### 1. Requirements
- Python 3.10+
- Installed packages: `fastapi`, `uvicorn`, `sqlalchemy`, `cryptography`, `pyjwt`, `bcrypt`, `passlib`

### 2. Run Application
```powershell
cd securevault
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Open **http://127.0.0.1:8000** in your browser.

### 3. Pre-Seeded Demo Accounts
You can switch instantly between accounts using the top role switcher in the UI:
| Role | Username | Password | Default Capabilities |
|---|---|---|---|
| **Admin** | `alice_admin` | `admin123` | Full access (View, Download, Edit, Delete, Permissions) |
| **Manager** | `bob_manager` | `manager123` | View, Download, Edit/Version, Permissions |
| **Employee** | `charlie_employee` | `employee123` | View-only (Download blocked with 403 Forbidden) |

---

## 🐳 Docker Deployment

To run with PostgreSQL 16:
```bash
docker-compose up --build -d
```
The application will be available at `http://localhost:8000` connected to PostgreSQL.

---

## 🧪 Running Automated Tests

Run the full pytest suite:
```powershell
pytest tests/test_securevault.py -v
```
