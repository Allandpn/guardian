"""Saúde do Pi: leitura de /proc e /sys, sem rodar comandos."""
import os

from guardian.executor.health import HIST_MAX, Health, throttled


def _w(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)


def _fake(root, busy, idle, rx=0, tx=0, temp=51234, thr="0x50005"):
    _w(root, "proc/stat", f"cpu  {busy} 0 0 {idle} 0 0 0 0 0 0\ncpu0 1 1 1 1\n")
    _w(root, "proc/loadavg", "0.52 0.40 0.30 1/200 999\n")
    _w(root, "proc/uptime", "3600.5 100.0\n")
    _w(root, "proc/meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n")
    _w(root, "proc/net/dev", "Inter-|   Receive\n face |bytes\n"
       f"  lo: 5 0 0 0 0 0 0 0 5 0\ntailscale0: {rx} 0 0 0 0 0 0 0 {tx} 0\n")
    _w(root, "sys/class/thermal/thermal_zone0/temp", str(temp))
    _w(root, "sys/devices/platform/soc/soc:firmware/get_throttled", thr)


def test_sample_reads_everything(tmp_path):
    root = str(tmp_path)
    _fake(root, 100, 900)
    t = [0.0]
    hl = Health(root, str(tmp_path), clock=lambda: t[0])
    _fake(root, 300, 1700, rx=2000, tx=500)  # +200 ocupado, +800 ocioso = 20%
    t[0] = 10.0
    s = hl.sample(1000)
    assert s["cpu"] == 20.0 and s["temp"] == 51.2 and s["load"] == [0.52, 0.4, 0.3]
    assert s["mem"] == [600 * 1024, 1000 * 1024] and s["swap"] == [50 * 1024, 200 * 1024]
    assert s["net"] == {"tailscale0": [200, 50]} and s["uptime"] == 3600 and s["disk"][1] > 0
    assert s["throttle"]["now"] == ["subtensão", "CPU limitada"] and s["throttle"]["past"] == ["subtensão", "CPU limitada"]
    assert s["hist"][-1]["cpu"] == 20.0 and s["hist"][-1]["mem"] == 60.0


def test_missing_files_just_leave_fields_out(tmp_path):
    hl = Health(str(tmp_path), str(tmp_path))
    s = hl.sample(1)
    assert "cpu" not in s and "temp" not in s and "throttle" not in s and s["ts"] == 1


def test_history_is_capped_and_garbage_is_ignored(tmp_path):
    root = str(tmp_path)
    _fake(root, 1, 1, temp="lixo", thr="zz")
    hl = Health(root, root)
    for i in range(HIST_MAX + 5):
        s = hl.sample(i)
    assert len(s["hist"]) == HIST_MAX and "temp" not in s and "throttle" not in s
    assert throttled(root) is None
