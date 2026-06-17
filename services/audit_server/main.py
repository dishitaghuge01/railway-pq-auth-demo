from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from shared.database import init_db, get_db
from shared.models import AuditLog
from pydantic import BaseModel
import time

app = FastAPI(title="Audit Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:4173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()

class LogEntry(BaseModel):
    uuid: str
    tte_id: str
    train: str
    coach: str | None = None
    result: str
    ip_address: str | None = None

class AuditEvent(BaseModel):
    timestamp: int
    tte_id: str
    result: str
    train: str
    uuid: str

class DuplicateEntry(BaseModel):
    uuid: str
    count: int
    first_seen: int
    last_seen: int

@app.post("/log")
def log_event(entry: LogEntry, db: Session = Depends(get_db)):
    # 1. Check if uuid exists
    existing = db.query(AuditLog).filter(AuditLog.uuid == entry.uuid).first()
    is_duplicate = False
    
    if existing:
        is_duplicate = True
        # Mark all prior entries with this UUID as duplicates
        db.query(AuditLog).filter(AuditLog.uuid == entry.uuid).update({"is_duplicate": 1})
    
    # 2. Insert new log
    new_log = AuditLog(
        **entry.dict(),
        timestamp=int(time.time()),
        is_duplicate=1 if is_duplicate else 0
    )
    db.add(new_log)
    db.commit()
    return {"is_duplicate": is_duplicate}

@app.get("/duplicates")
def get_duplicates(db: Session = Depends(get_db)):
    """
    Returns list of duplicate UUIDs with their scan counts and timestamps.
    Response format: list of { uuid, count, first_seen, last_seen }
    """
    # Get all UUIDs that have is_duplicate flag set
    dupes = (
        db.query(
            AuditLog.uuid,
            func.count(AuditLog.id).label("count"),
            func.min(AuditLog.timestamp).label("first_seen"),
            func.max(AuditLog.timestamp).label("last_seen"),
        )
        .filter(AuditLog.is_duplicate == 1)
        .group_by(AuditLog.uuid)
        .all()
    )
    
    return [
        {
            "uuid": dup[0],
            "count": dup[1],
            "first_seen": dup[2],
            "last_seen": dup[3],
        }
        for dup in dupes
    ]

@app.get("/log/{uuid}")
def get_log_by_uuid(uuid: str, db: Session = Depends(get_db)):
    """
    Returns all audit log entries for a given UUID.
    Response format: list of { timestamp, tte_id, result, train, uuid }
    """
    logs = db.query(AuditLog).filter(AuditLog.uuid == uuid).all()
    return [
        {
            "timestamp": log.timestamp,
            "tte_id": log.tte_id,
            "result": log.result,
            "train": log.train,
            "uuid": log.uuid,
        }
        for log in logs
    ]

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """
    Returns aggregate verification statistics.
    Response format: { "VALID": n, "FORGED": n, ... }
    """
    stats = db.query(AuditLog.result, func.count(AuditLog.id)).group_by(AuditLog.result).all()
    return {result: count for result, count in stats}

@app.get("/health")
def health():
    return {"status": "ok", "service": "audit_server"}