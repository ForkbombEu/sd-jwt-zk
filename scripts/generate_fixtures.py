#!/usr/bin/env python3
"""Independent host oracle for RFC 9901 disclosure and KB sd_hash bytes.

This tool is intentionally stdlib-only and is not shared with future circuit
code. It validates byte commitments, not ES256 signatures (those are zero-byte
placeholders in protocol fixtures).
"""
import argparse, base64, hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures/compact-vectors.json"
PUBLIC_JWK = {"crv":"P-256", "kty":"EC", "x":"uNJkR8N_mIF4OiHzsbGdAoPFN9cyGZHN2rTeZS1L_p8", "y":"6p64Zi-F2FKs9RFB8V-EFWC7jrDk8jDP-17zIGy4JXA"}
ISSUER_SIG = {"explicit-sha-256": "RS6qxwyHcY1UIV7JU60XommQaDyhl1NTMyE-EESB6-ViM6WjVNJC56lUFwZLW82dtNMbySOKZBphd8jfRAICBQ", "omitted-default-sha-256": "_wMfQWZndu20SLA-4JUMEIEpNtEaLEvF-ErYT9sjWLLlwAgUeMYAD7fjfwNCSvuJU6eqBXnA_zJF3u5ao9ps9A"}
KB_SIG = {"explicit-sha-256": "wZm5Q5D-b9stytMg-PFLi62qN4XzYBazkc3fwa5JJcY7k9Ta_YvTWGoQ8KrFKLbyviGJRJsCnN2SNqwiazTlbg", "omitted-default-sha-256": "0m68RxTDfxewlhvz6qo3GQiJHRozjgnvDvTRodASGFdRD4g92_j42EPlthIRTLRpHUrjCn31sLb2vkAUtJ2tSw"}

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
def canonical(value): return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
def digest(disclosure_ascii): return b64(hashlib.sha256(disclosure_ascii.encode("ascii")).digest())
def compact(header, payload, signature=None): return b64(canonical(header)) + "." + b64(canonical(payload)) + "." + (signature or b64(bytes(64)))
def unb64(text): return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
def parse_jws(value):
    h, p, s = value.split(".")
    if len(unb64(s)) != 64: raise ValueError("signature width")
    return json.loads(unb64(h)), json.loads(unb64(p))

def vector(name, explicit):
    disclosure = b64(canonical(["salt-0001", "age_over", True]))
    payload = {"_sd": [digest(disclosure)], "iss": "https://issuer.example", "vct": "example"}
    if explicit: payload["_sd_alg"] = "sha-256"
    issuer = compact({"alg": "ES256", "typ": "dc+sd-jwt", "profile_version": "swiss-profile-vc:1.0.0"}, payload, ISSUER_SIG[name])
    presentation = issuer + "~" + disclosure + "~"
    sd_hash = b64(hashlib.sha256(presentation.encode("ascii")).digest())
    kb = compact({"alg": "ES256", "typ": "kb+jwt"}, {"aud": "https://verifier.example", "nonce": "challenge-0001", "iat": 1777334400, "sd_hash": sd_hash}, KB_SIG[name])
    return {"name": name, "sd_alg": "sha-256" if explicit else "omitted-default-sha-256", "issuer_jwk": PUBLIC_JWK, "issuer_jws": issuer, "disclosures": [disclosure], "presentation_ascii": presentation, "expected_disclosure_digests": [digest(disclosure)], "holder_jwk": PUBLIC_JWK, "kb_jwt": kb, "expected_sd_hash": sd_hash, "signature_note": "Fixed raw JOSE ES256 signatures are independently checked with OpenSSL; this stdlib oracle deterministically checks disclosure and sd_hash bytes."}

def build():
    positive = [vector("explicit-sha-256", True), vector("omitted-default-sha-256", False)]
    base = positive[0]
    negatives = []
    for field, mutate in [
        ("issuer-header-alg", lambda x: x.replace('"ES256"', '"ES384"', 1)),
        ("issuer-header-typ", lambda x: x.replace('"dc+sd-jwt"', '"JWT"', 1)),
        ("profile-version", lambda x: x.replace('"swiss-profile-vc:1.0.0"', '"swiss-profile-vc:9.0.0"', 1)),
        ("sd-alg", lambda x: x.replace('"sha-256"', '"sha-512"', 1)),
        ("payload-digest", lambda x: "A" + x[1:]),
        ("disclosure", lambda x: x[:-1] + ("A" if x[-1] != "A" else "B")),
        ("issuer-jws", lambda x: "X" + x[1:]),
        ("tilde", lambda x: x[:-1]),
        ("disclosure-order", lambda x: x.replace("~", "~", 1) + "x"),
        ("sd-hash", lambda x: "A" + x[1:]),
    ]:
        item = {"name": "mutate-" + field, "field": field, "expected": "reject"}
        if field == "sd-hash": item["presentation_ascii"] = base["presentation_ascii"]; item["provided_sd_hash"] = mutate(base["expected_sd_hash"])
        elif field == "tilde": item["presentation_ascii"] = mutate(base["presentation_ascii"])
        elif field in ("issuer-jws", "issuer-header-alg", "issuer-header-typ", "profile-version", "sd-alg"):
            raw_header, raw_payload = parse_jws(base["issuer_jws"])
            if field == "issuer-header-alg": raw_header["alg"] = "ES384"
            elif field == "issuer-header-typ": raw_header["typ"] = "JWT"
            elif field == "profile-version": raw_header["profile_version"] = "swiss-profile-vc:9.0.0"
            elif field == "sd-alg": raw_payload["_sd_alg"] = "sha-512"
            else: item["presentation_ascii"] = mutate(base["issuer_jws"]) + "~" + base["disclosures"][0] + "~"; negatives.append(item); continue
            item["presentation_ascii"] = compact(raw_header, raw_payload) + "~" + base["disclosures"][0] + "~"
        elif field == "payload-digest":
            raw_header, raw_payload = parse_jws(base["issuer_jws"]); raw_payload["_sd"][0] = mutate(raw_payload["_sd"][0])
            item["presentation_ascii"] = compact(raw_header, raw_payload) + "~" + base["disclosures"][0] + "~"
        elif field == "disclosure": item["presentation_ascii"] = base["issuer_jws"] + "~" + mutate(base["disclosures"][0]) + "~"
        else: item["presentation_ascii"] = mutate(base["presentation_ascii"])
        negatives.append(item)
    signed = base["issuer_jws"].rsplit(".", 1)
    negatives.append({"name":"mutate-issuer-signature", "field":"issuer-signature", "expected":"reject by ES256 verification", "presentation_ascii":signed[0] + ".A" + signed[1][1:] + "~" + base["disclosures"][0] + "~"})
    negatives.append({"name":"mutate-issuer-key", "field":"issuer-key", "expected":"reject by ES256 verification", "presentation_ascii":base["presentation_ascii"], "provided_issuer_jwk":{"crv":"P-256", "kty":"EC", "x":"5q2hXqnw_b2jpfi3_U2vCLpAXXWm6CSe2LkA-xSGDss", "y":"Vu9a5G8PwM_8Li92vb8llSfXvaaUFPXqn57RrrA08uc"}})
    return {"format": "sd-jwt-zk-fixture-v1", "positive": positive, "negative": negatives}

def valid_presentation(presentation, provided_sd_hash=None):
    try:
        issuer, disclosure, end = presentation.split("~")
        if end != "": return False
        header, payload = parse_jws(issuer)
        if header != {"alg":"ES256", "typ":"dc+sd-jwt", "profile_version":"swiss-profile-vc:1.0.0"}: return False
        if payload.get("_sd_alg", "sha-256") != "sha-256" or payload.get("_sd") != [digest(disclosure)]: return False
        actual = b64(hashlib.sha256(presentation.encode("ascii")).digest())
        return provided_sd_hash is None or actual == provided_sd_hash
    except (ValueError, KeyError, UnicodeError, json.JSONDecodeError): return False

def validate(doc):
    for item in doc["positive"]:
        assert valid_presentation(item["presentation_ascii"], item["expected_sd_hash"])
    for item in doc["negative"]:
        if item["field"] == "issuer-key": assert item["provided_issuer_jwk"] != PUBLIC_JWK
        elif item["field"] == "issuer-signature": assert item["presentation_ascii"].split("~")[0].rsplit(".", 1)[1] not in ISSUER_SIG.values()
        else: assert not valid_presentation(item["presentation_ascii"], item.get("provided_sd_hash"))
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--check", action="store_true"); args = parser.parse_args()
    generated = build(); validate(generated)
    rendered = json.dumps(generated, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUT.exists() or OUT.read_text() != rendered: raise SystemExit("fixture drift; run generate_fixtures.py")
        print("fixture oracle OK: 2 positive, 12 negative")
    else: OUT.write_text(rendered); print("wrote fixtures/compact-vectors.json")
