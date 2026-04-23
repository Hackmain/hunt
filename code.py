#!/usr/bin/env python3
"""Creates the hunt/ project. Run once from /workspaces/hunt."""
import base64
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path("/workspaces/hunt")

FILES_PLAIN = {
    "requirements.txt": "requests>=2.31\n",
    ".gitignore": "venv/\n__pycache__/\n*.pyc\nsessions/\nrecordings/\ndrafts/\n.env\n",
    "hunt_cli/__init__.py": "",
}

FILES_B64 = {
    "hunt_cli/h1.py": "IiIiSGFja2VyT25lIEFQSSBjbGllbnQuIiIiCmltcG9ydCBvcwppbXBvcnQgcmVxdWVzdHMKCkJBU0UgPSAiaHR0cHM6Ly9hcGkuaGFja2Vyb25lLmNvbS92MSIKCgpjbGFzcyBIMUVycm9yKEV4Y2VwdGlvbik6CiAgICBwYXNzCgoKZGVmIF9hdXRoKCk6CiAgICB1c2Vy
ID0gb3MuZW52aXJvbi5nZXQoIkhBQ0tFUk9ORV9VU0VSTkFNRSIpCiAgICB0b2tlbiA9IG9zLmVudmlyb24uZ2V0KCJIQUNLRVJPTkVfVE9LRU4iKQogICAgaWYgbm90IHVzZXIgb3Igbm90IHRva2VuOgogICAgICAgIHJhaXNlIEgxRXJyb3IoIkhBQ0tFUk9ORV9VU0VSTkFNRSBvciBIQUNLRVJPTkV
fVE9LRU4gbm90IHNldCIpCiAgICByZXR1cm4gKHVzZXIsIHRva2VuKQoKCmRlZiBfZ2V0X2FsbChwYXRoLCBwYXJhbXM9Tm9uZSk6CiAgICB1cmwgPSBmIntCQVNFfXtwYXRofSIKICAgIHBhcmFtcyA9IHBhcmFtcyBvciB7fQogICAgb3V0ID0gW10KICAgIHdoaWxlIHVybDoKICAgICAgICByID0gcm
VxdWVzdHMuZ2V0KHVybCwgYXV0aD1fYXV0aCgpLCBwYXJhbXM9cGFyYW1zLCB0aW1lb3V0PTMwKQogICAgICAgIHBhcmFtcyA9IE5vbmUKICAgICAgICBpZiByLnN0YXR1c19jb2RlID09IDQwMToKICAgICAgICAgICAgcmFpc2UgSDFFcnJvcigiNDAxIHVuYXV0aG9yaXplZCAtIGNoZWNrIEhBQ0tFU
k9ORV9VU0VSTkFNRSAvIEhBQ0tFUk9ORV9UT0tFTiIpCiAgICAgICAgaWYgci5zdGF0dXNfY29kZSAhPSAyMDA6CiAgICAgICAgICAgIHJhaXNlIEgxRXJyb3IoZiJ7ci5zdGF0dXNfY29kZX0gZnJvbSB7dXJsfToge3IudGV4dFs6MjAwXX0iKQogICAgICAgIGRhdGEgPSByLmpzb24oKQogICAgICAg
IG91dC5leHRlbmQoZGF0YS5nZXQoImRhdGEiLCBbXSkpCiAgICAgICAgdXJsID0gKGRhdGEuZ2V0KCJsaW5rcyIpIG9yIHt9KS5nZXQoIm5leHQiKQogICAgcmV0dXJuIG91dAoKCmRlZiBsaXN0X3Byb2dyYW1zKCk6CiAgICByZXR1cm4gX2dldF9hbGwoIi9oYWNrZXJzL3Byb2dyYW1zIiwgeyJwYWd
lW3NpemVdIjogMTAwfSkKCgpkZWYgcHJvZ3JhbV9zY29wZXMoaGFuZGxlKToKICAgIHJldHVybiBfZ2V0X2FsbChmIi9oYWNrZXJzL3Byb2dyYW1zL3toYW5kbGV9L3N0cnVjdHVyZWRfc2NvcGVzIiwgeyJwYWdlW3NpemVdIjogMTAwfSkKCgpkZWYgcHJvZ3JhbV93ZWFrbmVzc2VzKGhhbmRsZSk6Ci
AgICByZXR1cm4gX2dldF9hbGwoZiIvaGFja2Vycy9wcm9ncmFtcy97aGFuZGxlfS93ZWFrbmVzc2VzIiwgeyJwYWdlW3NpemVdIjogMTAwfSkK",
    "hunt_cli/__main__.py": "aW1wb3J0IGFyZ3BhcnNlCmltcG9ydCBvcwppbXBvcnQgc3lzCmZyb20gLiBpbXBvcnQgaDEKClJFUVVJUkVEX1NFQ1JFVFMgPSBbCiAgICAiQU5USFJPUElDX0FQSV9LRVkiLAogICAgIkhBQ0tFUk9ORV9VU0VSTkFNRSIsCiAgICAiSEFDS0VST05FX1RPS0VOIi
wKICAgICJURUxFR1JBTV9CT1RfVE9LRU4iLAogICAgIlRFTEVHUkFNX0NIQVRfSUQiLApdCgoKZGVmIGNtZF92ZXJzaW9uKGFyZ3MpOgogICAgcHJpbnQoImh1bnQgMC4xLjAiKQogICAgcmV0dXJuIDAKCgpkZWYgY21kX2RvY3RvcihhcmdzKToKICAgIG9rID0gVHJ1ZQogICAgZm9yIG5hbWUgaW4gU
kVRVUlSRURfU0VDUkVUUzoKICAgICAgICBwcmVzZW50ID0gYm9vbChvcy5lbnZpcm9uLmdldChuYW1lKSkKICAgICAgICBtYXJrID0gIk9LICIgaWYgcHJlc2VudCBlbHNlICJNSVNTIgogICAgICAgIHByaW50KGYiICBbe21hcmt9XSB7bmFtZX0iKQogICAgICAgIGlmIG5vdCBwcmVzZW50OgogICAg
ICAgICAgICBvayA9IEZhbHNlCiAgICBpZiBub3Qgb2s6CiAgICAgICAgcHJpbnQoIiIpCiAgICAgICAgcHJpbnQoIlNlY3JldHMgbWlzc2luZy4gQWRkIGluIENvZGVzcGFjZXMgU2VjcmV0cywgcmVzdGFydCBDb2Rlc3BhY2UuIikKICAgICAgICByZXR1cm4gMQogICAgcHJpbnQoIiIpCiAgICBwcml
udCgiYWxsIHNlY3JldHMgcHJlc2VudCIpCiAgICByZXR1cm4gMAoKCmRlZiBjbWRfcHJvZ3JhbXMoYXJncyk6CiAgICB0cnk6CiAgICAgICAgcHJvZ3JhbXMgPSBoMS5saXN0X3Byb2dyYW1zKCkKICAgIGV4Y2VwdCBoMS5IMUVycm9yIGFzIGU6CiAgICAgICAgcHJpbnQoZiJlcnJvcjoge2V9IiwgZm
lsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCiAgICBpZiBub3QgcHJvZ3JhbXM6CiAgICAgICAgcHJpbnQoIm5vIHByb2dyYW1zIGZvdW5kIikKICAgICAgICByZXR1cm4gMAogICAgcHJpbnQoZiJ7J2hhbmRsZSc6PDMwfSB7J25hbWUnfSIpCiAgICBwcmludChmInsnLScqMzB9IHsnLScqN
DB9IikKICAgIGZvciBwIGluIHByb2dyYW1zOgogICAgICAgIGEgPSBwLmdldCgiYXR0cmlidXRlcyIsIHt9KQogICAgICAgIHByaW50KGYie2EuZ2V0KCdoYW5kbGUnLCc/Jyk6PDMwfSB7YS5nZXQoJ25hbWUnLCc/Jyl9IikKICAgIHByaW50KGYiIikKICAgIHByaW50KGYie2xlbihwcm9ncmFtcyl9
IHByb2dyYW0ocykiKQogICAgcmV0dXJuIDAKCgpkZWYgbWFpbigpOgogICAgcCA9IGFyZ3BhcnNlLkFyZ3VtZW50UGFyc2VyKHByb2c9Imh1bnQiKQogICAgc3ViID0gcC5hZGRfc3VicGFyc2VycyhkZXN0PSJjbWQiLCByZXF1aXJlZD1UcnVlKQogICAgc3ViLmFkZF9wYXJzZXIoInZlcnNpb24iKQo
gICAgc3ViLmFkZF9wYXJzZXIoImRvY3RvciIpCiAgICBzdWIuYWRkX3BhcnNlcigicHJvZ3JhbXMiKQogICAgYXJncyA9IHAucGFyc2VfYXJncygpCiAgICByZXR1cm4geyJ2ZXJzaW9uIjogY21kX3ZlcnNpb24sICJkb2N0b3IiOiBjbWRfZG9jdG9yLCAicHJvZ3JhbXMiOiBjbWRfcHJvZ3JhbXN9W2
FyZ3MuY21kXShhcmdzKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBzeXMuZXhpdChtYWluKCkpCg==",
    "hunt": "IyEvdXNyL2Jpbi9lbnYgYmFzaApzZXQgLWUKY2QgIiQoZGlybmFtZSAiJChyZWFscGF0aCAiJDAiKSIpIgpleGVjIC4vdmVudi9iaW4vcHl0aG9uIC1tIGh1bnRfY2xpICIkQCIK",
}


def main():
    os.chdir(ROOT)
    for d in ["hunt_cli", "sessions", "recordings", "drafts"]:
        (ROOT / d).mkdir(exist_ok=True)
    for name, content in FILES_PLAIN.items():
        (ROOT / name).write_text(content)
    for name, b64 in FILES_B64.items():
        (ROOT / name).write_bytes(base64.b64decode(b64))
    (ROOT / "hunt").chmod(0o755)

    if not (ROOT / "venv").exists():
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
    subprocess.run(["./venv/bin/pip", "install", "--quiet", "--upgrade", "pip"], check=True)
    subprocess.run(["./venv/bin/pip", "install", "--quiet", "requests"], check=True)

    print("")
    print("=== tree ===")
    subprocess.run(["ls", "-la"])
    print("")
    print("=== version ===")
    subprocess.run(["./hunt", "version"])
    print("")
    print("=== doctor ===")
    subprocess.run(["./hunt", "doctor"])


if __name__ == "__main__":
    main()