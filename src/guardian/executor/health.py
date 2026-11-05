"""Saúde do Pi (CPU, carga, temperatura, memória, disco, rede): lida de /proc e /sys, sem rodar nenhum comando.

O executor chama `sample()` a cada relatório (1 min) e guarda os últimos pontos na memória; o site desenha o histórico.
Só leitura de arquivos do sistema: nada aqui altera o Pi, e um arquivo que não existe (outro hardware) só deixa o campo de fora.
"""
import os
import shutil
import time
from collections import deque

HIST_MAX = 60          # 1 hora, um ponto por minuto
NET_IFACES = ("tailscale0", "eth0", "wlan0")  # tailscale0: o tráfego dos aparelhos que usam o Pi como saída
# Bits de /sys/.../get_throttled (firmware do Raspberry Pi): o que aconteceu desde o boot (16..19) ou está acontecendo (0..3).
THROTTLE_NOW = {0: "subtensão", 1: "frequência limitada", 2: "CPU limitada", 3: "superaquecimento"}
THROTTLE_PAST = {16: "subtensão", 17: "frequência limitada", 18: "CPU limitada", 19: "superaquecimento"}
THROTTLE_PATHS = ("/sys/devices/platform/soc/soc:firmware/get_throttled", "/sys/class/hwmon/hwmon0/device/get_throttled")


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _cpu_times(root: str) -> tuple[int, int] | None:
    s = _read(root + "/proc/stat")
    if not s or not s.startswith("cpu "):
        return None
    try:
        v = [int(x) for x in s.split("\n", 1)[0].split()[1:]]
    except ValueError:
        return None
    return sum(v), v[3] + (v[4] if len(v) > 4 else 0)  # total e ocioso (idle + iowait)


def _net_bytes(root: str) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    for line in (_read(root + "/proc/net/dev") or "").splitlines()[2:]:
        name, _, rest = line.partition(":")
        name, f = name.strip(), rest.split()
        if name in NET_IFACES and len(f) >= 9 and f[0].isdigit() and f[8].isdigit():
            out[name] = (int(f[0]), int(f[8]))
    return out


def _meminfo(root: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in (_read(root + "/proc/meminfo") or "").splitlines():
        k, _, v = line.partition(":")
        p = v.split()
        if p and p[0].isdigit():
            out[k] = int(p[0]) * 1024
    return out


def throttled(root: str = "") -> dict | None:
    for p in THROTTLE_PATHS:
        raw = _read(root + p)
        if raw is None:
            continue
        try:
            n = int(raw.strip(), 16)
        except ValueError:
            continue
        return {"raw": n, "now": [t for b, t in THROTTLE_NOW.items() if n >> b & 1], "past": [t for b, t in THROTTLE_PAST.items() if n >> b & 1]}
    return None


class Health:
    def __init__(self, root: str = "", disk_path: str = "/", clock=time.monotonic):
        self.root, self.disk_path, self.clock = root, disk_path, clock
        self.hist: deque = deque(maxlen=HIST_MAX)
        self._cpu = _cpu_times(root)
        self._net = _net_bytes(root)
        self._t = clock()

    def sample(self, ts: int) -> dict:
        """Um retrato agora, mais o histórico. CPU e rede são médias desde a amostra anterior."""
        root, now = self.root, self.clock()
        h: dict = {"ts": ts}
        cpu, net, dt = _cpu_times(root), _net_bytes(root), max(now - self._t, 0.001)
        if cpu and self._cpu and cpu[0] > self._cpu[0]:
            h["cpu"] = round(100 * (1 - (cpu[1] - self._cpu[1]) / (cpu[0] - self._cpu[0])), 1)
        if net and self._net:
            h["net"] = {i: [max(0, round((b[0] - self._net[i][0]) / dt)), max(0, round((b[1] - self._net[i][1]) / dt))]  # bytes/s: recebido, enviado
                        for i, b in net.items() if i in self._net}
        self._cpu, self._net, self._t = cpu, net, now
        la = (_read(root + "/proc/loadavg") or "").split()
        if len(la) >= 3:
            try:
                h["load"] = [float(x) for x in la[:3]]
            except ValueError:
                pass
        h["cores"] = os.cpu_count() or 1
        t = _read(root + "/sys/class/thermal/thermal_zone0/temp")
        if t and t.strip().lstrip("-").isdigit():
            h["temp"] = round(int(t) / 1000, 1)
        mi = _meminfo(root)
        if mi.get("MemTotal"):
            h["mem"] = [mi["MemTotal"] - mi.get("MemAvailable", mi.get("MemFree", 0)), mi["MemTotal"]]
        if mi.get("SwapTotal"):
            h["swap"] = [mi["SwapTotal"] - mi.get("SwapFree", 0), mi["SwapTotal"]]
        try:
            u = shutil.disk_usage(self.disk_path)
            h["disk"] = [u.used, u.total]
        except OSError:
            pass
        up = (_read(root + "/proc/uptime") or "").split()
        if up:
            try:
                h["uptime"] = int(float(up[0]))
            except ValueError:
                pass
        th = throttled(root)
        if th is not None:
            h["throttle"] = th
        pt = {k: h[k] for k in ("ts", "cpu", "temp") if k in h}
        if "load" in h:
            pt["load"] = h["load"][0]
        if "mem" in h:
            pt["mem"] = round(100 * h["mem"][0] / h["mem"][1], 1)
        if "net" in h:
            pt["net"] = h["net"]
        self.hist.append(pt)
        return {**h, "hist": list(self.hist)}
