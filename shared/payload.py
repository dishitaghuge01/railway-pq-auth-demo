import json

def encode(payload: dict) -> bytes:
    return json.dumps(payload).encode('utf-8')


def decode(b: bytes) -> dict:
    return json.loads(b.decode('utf-8'))
