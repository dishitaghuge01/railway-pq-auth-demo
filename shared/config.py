# shared/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    # Defining fields with types and defaults
    PRS_PORT: int = 8000
    CRIS_SIGNER_PORT: int = 8001
    AUDIT_SERVER_PORT: int = 8002
    HHT_SERVICE_PORT: int = 8003

    DB_PATH: str = "db/railway.db"
    KEYS_DIR: str = "keys/"
    TICKETS_DIR: str = "tickets/"

    CRIS_SIGNER_URL: str = "http://localhost:8001"
    AUDIT_SERVER_URL: str = "http://localhost:8002"
    
    # ADD THESE TWO LINES:
    HHT_SERVICE_URL: str = "http://localhost:8003"
    PRS_URL: str = "http://localhost:8000"

    KEY_ROTATION_GRACE_DAYS: int = 120

    # This tells Pydantic to look for a .env file
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
