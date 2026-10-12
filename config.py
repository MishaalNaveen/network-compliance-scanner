"""Application settings."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.environ.get("COMPLIANCE_DB", str(BASE_DIR / "instance" / "compliance.sqlite3"))
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "development-only-change-me")




