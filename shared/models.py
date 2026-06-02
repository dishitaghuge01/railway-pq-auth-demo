from dataclasses import dataclass

@dataclass
class Ticket:
    id: int
    holder: str
    issued_at: str
