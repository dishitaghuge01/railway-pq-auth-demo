def sign(message: bytes) -> bytes:
    # Placeholder: integrate Dilithium2 signing here
    return b"signed:" + message


def verify(message: bytes, signature: bytes) -> bool:
    # Placeholder verification
    return signature == b"signed:" + message
