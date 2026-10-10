import os
from pathlib import Path
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

VAULT_DIR = DATA_DIR / "vault"
VAULT_DIR.mkdir(exist_ok=True)

SECRET_KEY = os.getenv("SECRET_KEY", "securevault-super-secret-enterprise-jwt-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'securevault.db'}")

KEY_FILE = DATA_DIR / "vault.key"
if not KEY_FILE.exists():
    generated_key = Fernet.generate_key().decode("utf-8")
    KEY_FILE.write_text(generated_key, encoding="utf-8")
    ENCRYPTION_KEY = generated_key
else:
    ENCRYPTION_KEY = KEY_FILE.read_text(encoding="utf-8").strip()
