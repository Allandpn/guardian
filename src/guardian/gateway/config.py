import os
from dataclasses import dataclass


@dataclass
class Config:
    origin: str = "https://localhost"          # origem pública exata (WebAuthn): esquema + host
    rp_id: str = "localhost"                   # hostname do Funnel; precisa ser estável
    db_path: str = "/data/gateway.db"
    bind: str = "127.0.0.1"
    port: int = 8080
    secure_cookies: bool = True                # só desligue em teste local sem HTTPS
    max_connections: int = 64                  # conexões simultâneas (cada uma uma thread)
    max_pending_per_dev: int = 200
    max_poll_s: int = 25
    session_ttl_s: int = 12 * 3600
    invite_ttl_s: int = 24 * 3600
    challenge_ttl_s: int = 120
    limit_scale: float = 1.0                   # multiplica os limites de taxa (só os testes mexem)

    @staticmethod
    def from_env() -> "Config":
        e = os.environ
        origin = e.get("GATEWAY_ORIGIN", "https://localhost").rstrip("/")
        host = origin.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        return Config(
            origin=origin,
            rp_id=e.get("GATEWAY_RP_ID", host),
            db_path=e.get("GATEWAY_DB", "/data/gateway.db"),
            bind=e.get("GATEWAY_BIND", "127.0.0.1"),
            port=int(e.get("GATEWAY_PORT", "8080")),
            secure_cookies=e.get("GATEWAY_INSECURE_COOKIES", "") != "1",
            max_connections=int(e.get("GATEWAY_MAX_CONNECTIONS", "64")),
        )
