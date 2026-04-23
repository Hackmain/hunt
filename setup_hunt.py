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
      "hunt_cli/h1.py": "IiIiSGFja2VyT25lIEFQSSBjbGllbnQuIiIiCmltcG9ydCBvcwppbXBvcnQgcmVxdWVzdHMKCkJBU0UgPSAiaHR0cHM6Ly9hcGk
  uaGFja2Vyb25lLmNvbS92MSIKCgpjbGFzcyBIMUVycm9yKEV4Y2VwdGlvbik6CiAgICBwYXNzCgoKZGVmIF9hdXRoKCk6CiAgICB1c2VyID0gb3MuZW52aXJvb
  i5nZXQoIkhBQ0tFUk9ORV9VU0VSTkFNRSIpCiAgICB0b2tlbiA9IG9zLmVudmlyb24uZ2V0KCJIQUNLRVJPTkVfVE9LRU4iKQogICAgaWYgbm90IHVzZXIgb3I
  gbm90IHRva2VuOgogICAgICAgIHJhaXNlIEgxRXJyb3IoIkhBQ0tFUk9ORV9VU0VSTkFNRSBvciBIQUNLRVJPTkVfVE9LRU4gbm90IHNldCIpCiAgICByZXR1c
  m4gKHVzZXIsIHRva2VuKQoKCmRlZiBfZ2V0X2FsbChwYXRoLCBwYXJhbXM9Tm9uZSk6CiAgICB1cmwgPSBmIntCQVNFfXtwYXRofSIKICAgIHBhcmFtcyA9IHB
  hcmFtcyBvciB7fQogICAgb3V0ID0gW10KICAgIHdoaWxlIHVybDoKICAgICAgICByID0gcmVxdWVzdHMuZ2V0KHVybCwgYXV0aD1fYXV0aCgpLCBwYXJhbXM9c
  GFyYW1zLCB0aW1lb3V0PTMwKQogICAgICAgIHBhcmFtcyA9IE5vbmUKICAgICAgICBpZiByLnN0YXR1c19jb2RlID09IDQwMToKICAgICAgICAgICAgcmFpc2U
  gSDFFcnJvcigiNDAxIHVuYXV0aG9yaXplZCAtIGNoZWNrIEhBQ0tFUk9ORV9VU0VSTkFNRSAvIEhBQ0tFUk9ORV9UT0tFTiIpCiAgICAgICAgaWYgci5zdGF0d
  XNfY29kZSAhPSAyMDA6CiAgICAgICAgICAgIHJhaXNlIEgxRXJyb3IoZiJ7ci5zdGF0dXNfY29kZX0gZnJvbSB7dXJsfToge3IudGV4dFs6MjAwXX0iKQogICA
  gICAgIGRhdGEgPSByLmpzb24oKQogICAgICAgIG91dC5leHRlbmQoZGF0YS5nZXQoImRhdGEiLCBbXSkpCiAgICAgICAgdXJsID0gKGRhdGEuZ2V0KCJsaW5rc
  yIpIG9yIHt9KS5nZXQoIm5leHQiKQogICAgcmV0dXJuIG91dAoKCmRlZiBsaXN0X3Byb2dyYW1zKCk6CiAgICByZXR1cm4gX2dldF9hbGwoIi9oYWNrZXJzL3B
  yb2dyYW1zIiwgeyJwYWdlW3NpemVdIjogMTAwfSkKCgpkZWYgcHJvZ3JhbV9zY29wZXMoaGFuZGxlKToKICAgIHJldHVybiBfZ2V0X2FsbChmIi9oYWNrZXJzL
  3Byb2dyYW1zL3toYW5kbGV9L3N0cnVjdHVyZWRfc2NvcGVzIiwgeyJwYWdlW3NpemVdIjogMTAwfSkKCgpkZWYgcHJvZ3JhbV93ZWFrbmVzc2VzKGhhbmRsZSk
  6CiAgICByZXR1cm4gX2dldF9hbGwoZiIvaGFja2Vycy9wcm9ncmFtcy97aGFuZGxlfS93ZWFrbmVzc2VzIiwgeyJwYWdlW3NpemVdIjogMTAwfSkK",
      "hunt_cli/__main__.py": "aW1wb3J0IGFyZ3BhcnNlCmltcG9ydCBvcwppbXBvcnQgc3lzCmZyb20gLiBpbXBvcnQgaDEKClJFUVVJUkVEX1NFQ1JFV
  FMgPSBbCiAgICAiQU5USFJPUElDX0FQSV9LRVkiLAogICAgIkhBQ0tFUk9ORV9VU0VSTkFNRSIsCiAgICAiSEFDS0VST05FX1RPS0VOIiwKICAgICJURUxFR1J
  BTV9CT1RfVE9LRU4iLAogICAgIlRFTEVHUkFNX0NIQVRfSUQiLApdCgoKZGVmIGNtZF92ZXJzaW9uKGFyZ3MpOgogICAgcHJpbnQoImh1bnQgMC4xLjAiKQogI
  CAgcmV0dXJuIDAKCgpkZWYgY21kX2RvY3RvcihhcmdzKToKICAgIG9rID0gVHJ1ZQogICAgZm9yIG5hbWUgaW4gUkVRVUlSRURfU0VDUkVUUzoKICAgICAgICB
  wcmVzZW50ID0gYm9vbChvcy5lbnZpcm9uLmdldChuYW1lKSkKICAgICAgICBtYXJrID0gIk9LICIgaWYgcHJlc2VudCBlbHNlICJNSVNTIgogICAgICAgIHBya
  W50KGYiICBbe21hcmt9XSB7bmFtZX0iKQogICAgICAgIGlmIG5vdCBwcmVzZW50OgogICAgICAgICAgICBvayA9IEZhbHNlCiAgICBpZiBub3Qgb2s6CiAgICA
  gICAgcHJpbnQoIiIpCiAgICAgICAgcHJpbnQoIlNlY3JldHMgbWlzc2luZy4gQWRkIGluIENvZGVzcGFjZXMgU2VjcmV0cywgcmVzdGFydCBDb2Rlc3BhY2UuI
  ikKICAgICAgICByZXR1cm4gMQogICAgcHJpbnQoIiIpCiAgICBwcmludCgiYWxsIHNlY3JldHMgcHJlc2VudCIpCiAgICByZXR1cm4gMAoKCmRlZiBjbWRfcHJ
  vZ3JhbXMoYXJncyk6CiAgICB0cnk6CiAgICAgICAgcHJvZ3JhbXMgPSBoMS5saXN0X3Byb2dyYW1zKCkKICAgIGV4Y2VwdCBoMS5IMUVycm9yIGFzIGU6CiAgI
  CAgICAgcHJpbnQoZiJlcnJvcjoge2V9IiwgZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCiAgICBpZiBub3QgcHJvZ3JhbXM6CiAgICAgICAgcHJ
  pbnQoIm5vIHByb2dyYW1zIGZvdW5kIikKICAgICAgICByZXR1cm4gMAogICAgcHJpbnQoZiJ7J2hhbmRsZSc6PDMwfSB7J25hbWUnfSIpCiAgICBwcmludChmI
  nsnLScqMzB9IHsnLScqNDB9IikKICAgIGZvciBwIGluIHByb2dyYW1zOgogICAgICAgIGEgPSBwLmdldCgiYXR0cmlidXRlcyIsIHt9KQogICAgICAgIHByaW5
  0KGYie2EuZ2V0KCdoYW5kbGUnLCc/Jyk6PDMwfSB7YS5nZXQoJ25hbWUnLCc/Jyl9IikKICAgIHByaW50KGYiIikKICAgIHByaW50KGYie2xlbihwcm9ncmFtc
  yl9IHByb2dyYW0ocykiKQogICAgcmV0dXJuIDAKCgpkZWYgbWFpbigpOgogICAgcCA9IGFyZ3BhcnNlLkFyZ3VtZW50UGFyc2VyKHByb2c9Imh1bnQiKQogICA
  gc3ViID0gcC5hZGRfc3VicGFyc2VycyhkZXN0PSJjbWQiLCByZXF1aXJlZD1UcnVlKQogICAgc3ViLmFkZF9wYXJzZXIoInZlcnNpb24iKQogICAgc3ViLmFkZ
  F9wYXJzZXIoImRvY3RvciIpCiAgICBzdWIuYWRkX3BhcnNlcigicHJvZ3JhbXMiKQogICAgYXJncyA9IHAucGFyc2VfYXJncygpCiAgICByZXR1cm4geyJ2ZXJ
  zaW9uIjogY21kX3ZlcnNpb24sICJkb2N0b3IiOiBjbWRfZG9jdG9yLCAicHJvZ3JhbXMiOiBjbWRfcHJvZ3JhbXN9W2FyZ3MuY21kXShhcmdzKQoKCmlmIF9fb
  mFtZV9fID09ICJfX21haW5fXyI6CiAgICBzeXMuZXhpdChtYWluKCkpCg==",
      "hunt": "IyEvdXNyL2Jpbi9lbnYgYmFzaApzZXQgLWUKY2QgIiQoZGlybmFtZSAiJChyZWFscGF0aCAiJDAiKSIpIgpleGVjIC4vdmVudi9iaW4vcHl0a
  G9uIC1tIGh1bnRfY2xpICIkQCIK",
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