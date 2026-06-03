from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from shared.database import init_db, get_db
from shared.models import AuditLog
from pydantic import BaseModel
import time

app = FastAPI(title="Audit Server")

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
    # Query all marked as duplicate
    dupes = db.query(AuditLog).filter(AuditLog.is_duplicate == 1).all()
    return {"duplicates": [log.__dict__ for log in dupes]}

@app.get("/log/{uuid}")
def get_log_by_uuid(uuid: str, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).filter(AuditLog.uuid == uuid).all()
    return {"events": [log.__dict__ for log in logs]}

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    from sqlalchemy import func
    stats = db.query(AuditLog.result, func.count(AuditLog.id)).group_by(AuditLog.result).all()
    return {result: count for result, count in stats}

@app.get("/health")
def health():
    return {"status": "ok"}