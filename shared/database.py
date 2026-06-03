from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from shared.config import settings
from shared.models import Base

# Create engine
engine = create_engine(
    f"sqlite:///{settings.DB_PATH}",
    connect_args={"check_same_thread": False}  # SQLite-specific
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency for FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize DB — creates all tables
def init_db():
    Base.metadata.create_all(bind=engine)
    print(f"✓ Database initialized at {settings.DB_PATH}")