import base64


def enc(data: bytes) -> str:
    """base64url sem preenchimento (o formato do WebAuthn)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def dec(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("base64url esperado")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
