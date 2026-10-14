"""Limites simples em memória: balde de fichas por chave, com limpeza para não crescer sem fim."""
import threading
import time


class Limiter:
    def __init__(self, per_minute: float, burst: int, max_keys: int = 5000):
        self.rate = per_minute / 60.0
        self.burst = burst
        self.max_keys = max_keys
        self._b: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, last = self._b.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            if len(self._b) >= self.max_keys and key not in self._b:
                self._b = {k: v for k, v in self._b.items() if v[0] < self.burst}  # descarta os cheios
                if len(self._b) >= self.max_keys:
                    return False
            self._b[key] = (tokens - 1 if ok else tokens, now)
            return ok


class NonceCache:
    """Nonces já vistos dentro da janela de validade (anti-replay das requisições do aparelho)."""

    def __init__(self, ttl_s: int, max_items: int = 20000):
        self.ttl, self.max = ttl_s, max_items
        self._n: dict[str, float] = {}
        self._lock = threading.Lock()

    def seen(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._n) >= self.max:
                self._n = {k: t for k, t in self._n.items() if t > now}
                if len(self._n) >= self.max:
                    return True  # cheio: recusa por segurança
            if self._n.get(key, 0) > now:
                return True
            self._n[key] = now + self.ttl
            return False
