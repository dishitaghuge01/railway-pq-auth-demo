from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class IssuedTicket(Base):
    __tablename__ = 'issued_tickets'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(String, unique=True, nullable=False)
    pnr = Column(String, unique=True, nullable=False)
    jwt_string = Column(String, nullable=False)
    train = Column(String, nullable=False)
    from_stn = Column(String, nullable=False)
    to_stn = Column(String, nullable=False)
    ticket_class = Column(String, nullable=False)
    travel_date = Column(String, nullable=False)
    ticket_type = Column(String, nullable=False)
    issued_at = Column(Integer, nullable=False)
    passenger_names = Column(String, nullable=False)

class PassengerChart(Base):
    __tablename__ = 'passenger_chart'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    pnr = Column(String, nullable=False)
    uuid = Column(String, nullable=False)
    train = Column(String, nullable=False)
    travel_date = Column(String, nullable=False)
    berth = Column(String, nullable=True)
    passenger_name = Column(String, nullable=False)
    ticket_class = Column(String, nullable=False)
    aadhaar_hash = Column(String, nullable=True)

class AuditLog(Base):
    __tablename__ = 'audit_log'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(String, nullable=False)
    tte_id = Column(String, nullable=False)
    train = Column(String, nullable=False)
    coach = Column(String, nullable=True)
    timestamp = Column(Integer, nullable=False)
    result = Column(String, nullable=False)
    is_duplicate = Column(Integer, default=0)
    ip_address = Column(String, nullable=True)