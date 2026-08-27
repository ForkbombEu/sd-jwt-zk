#!/usr/bin/env python3
"""Independent OpenSSL verification of fixed raw JOSE ES256 fixture signatures."""
import base64, json, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuNJkR8N/mIF4OiHzsbGdAoPFN9cy
GZHN2rTeZS1L/p/qnrhmL4XYUqz1EUHxX4QVYLuOsOTyMM/7XvMgbLglcA==
-----END PUBLIC KEY-----
"""
OTHER_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5q2hXqnw/b2jpfi3/U2vCLpAXXWm
6CSe2LkA+xSGDstW71rkbw/Az/wuL3a9vyWVJ9e9ppQU9eqfntGusDTy5w==
-----END PUBLIC KEY-----
"""
EXPECTED_JWK = {"crv":"P-256", "kty":"EC", "x":"uNJkR8N_mIF4OiHzsbGdAoPFN9cyGZHN2rTeZS1L_p8", "y":"6p64Zi-F2FKs9RFB8V-EFWC7jrDk8jDP-17zIGy4JXA"}
def raw_to_der(raw):
    def integer(part):
        part = part.lstrip(b"\0") or b"\0"
        if part[0] & 128: part = b"\0" + part
        return b"\2" + bytes([len(part)]) + part
    body = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(body)]) + body
def verify(jws, pem):
    signing, sig = jws.rsplit(".", 1)
    raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    if len(raw) != 64: return False
    with tempfile.TemporaryDirectory() as d:
        d = Path(d); (d / "pub.pem").write_bytes(pem); (d / "input").write_bytes(signing.encode("ascii")); (d / "sig.der").write_bytes(raw_to_der(raw))
        return subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(d / "pub.pem"), "-signature", str(d / "sig.der"), str(d / "input")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
if __name__ == "__main__":
    vectors = json.loads((ROOT / "fixtures/compact-vectors.json").read_text())
    for v in vectors["positive"]:
        if v["issuer_jwk"] != EXPECTED_JWK or v["holder_jwk"] != EXPECTED_JWK: raise SystemExit("JWK mismatch")
        if not verify(v["issuer_jws"], PEM) or not verify(v["kb_jwt"], PEM): raise SystemExit("ES256 fixture verification failed: " + v["name"])
    print("ES256 OpenSSL OK: 2 issuer and 2 KB-JWT signatures")
