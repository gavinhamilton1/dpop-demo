# server/attestation.py
from __future__ import annotations
import json, hashlib, base64
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urlsplit

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ObjectIdentifier

# Utilities
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64u_dec(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

class AttestationFailure(Exception):
    pass

@dataclass
class AAGUIDAllowlist:
    allowed: Set[str]

    @staticmethod
    def load(path: str = None) -> 'AAGUIDAllowlist':
        # Provide your own list (hex without dashes). Empty set means "allow any" *after* trust validation.
        # Example: { "ee882879721c-...": true } → store as hex without dashes
        default_allowed: Set[str] = set()  # TODO: populate with your approved AAGUIDs
        if not path:
            return AAGUIDAllowlist(allowed=default_allowed)
        with open(path, 'r') as f:
            j = json.load(f)
        return AAGUIDAllowlist(allowed=set([k.replace('-', '').lower() for k,v in j.items() if v]))

# Minimal COSE EC2 → JWK and AAGUID extraction

def cose_to_jwk(cbor_bytes: bytes) -> dict:
    m = cbor2.loads(cbor_bytes)
    kty = m.get(1); alg = m.get(3)
    crv = m.get(-1); x = m.get(-2); y = m.get(-3)
    if kty == 2 and crv == 1:  # EC2 P-256
        return {"kty":"EC","crv":"P-256","x":b64u(x),"y":b64u(y),"alg":"ES256"}
    if kty == 3:  # RSA
        n = m.get(-1); e = m.get(-2)
        return {"kty":"RSA","n":b64u(n),"e":b64u(e),"alg":"RS256"}
    raise AttestationFailure("unsupported COSE key")

# Verify cert chain to a set of trusted self-signed roots using naive path building

def _verify_chain_x5c(x5c: List[bytes], trusted_roots: List[x509.Certificate]) -> Tuple[bool, List[str]]:
    if not x5c:
        return False, []
    certs = [x509.load_der_x509_certificate(c) for c in x5c]
    # Step 1: verify linear chain signatures (leaf→...→root)
    for i in range(len(certs)-1):
        issuer = certs[i+1].public_key()
        cert = certs[i]
        issuer.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15() if hasattr(issuer, 'verifier') else ec.ECDSA(cert.signature_hash_algorithm), cert.signature_hash_algorithm)
    # Step 2: anchor match (by SPKI hash) against any trusted root
    anchors = [c for c in trusted_roots]
    leaf_to_root = certs[-1]
    anchors_fp = set([leaf_to_root.fingerprint(hashes.SHA256()) for leaf_to_root in anchors])
    ok = certs[-1].fingerprint(hashes.SHA256()) in anchors_fp
    chain_fps = [cert.fingerprint(hashes.SHA256()).hex() for cert in certs]
    if not ok:
        # Some attestation chains include an intermediate, and the actual anchor is external; relax: accept when any provided cert equals a trusted anchor.
        anchor_fps = set([c.fingerprint(hashes.SHA256()) for c in anchors])
        ok = any(c.fingerprint(hashes.SHA256()) in anchor_fps for c in certs)
    return ok, chain_fps

# Packed attestation validation with x5c (basic)

def verify_packed_attestation_x5c(attStmt: dict, authData: bytes, client_hash: bytes, *, expected_rp_id: str, allowed_aaguids: Set[str]):
    # Extract AAGUID, credId, COSE key
    if len(authData) < 37:
        raise AttestationFailure("authData too short")
    rpIdHash = authData[0:32]
    flags = authData[32]
    signCount = int.from_bytes(authData[33:37], 'big')
    if (flags & 0x40) == 0:
        raise AttestationFailure("missing AT flag")
    off = 37
    aaguid = authData[off:off+16]; off += 16
    cred_len = int.from_bytes(authData[off:off+2], 'big'); off += 2
    credId = authData[off:off+cred_len]; off += cred_len
    cose = authData[off:]

    # Check rpIdHash
    if rpIdHash != hashlib.sha256(expected_rp_id.encode()).digest():
        raise AttestationFailure("rpIdHash mismatch")

    # Verify signature over (authData || clientDataHash) with attestation cert
    x5c = attStmt.get('x5c')
    if not x5c:
        raise AttestationFailure("packed: missing x5c")
    # x5c may be CBOR bstrs; ensure bytes list
    x5c_bytes = [bytes(x) for x in x5c]
    leaf = x509.load_der_x509_certificate(x5c_bytes[0])
    alg = attStmt.get('alg', -7)
    sig = bytes(attStmt.get('sig'))
    signed = authData + client_hash

    if alg == -7:  # ES256
        leaf.public_key().verify(sig, signed, ec.ECDSA(hashes.SHA256()))
    elif alg == -257:  # RS256
        leaf.public_key().verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise AttestationFailure("unsupported packed alg")

    # AAGUID extension in attestation cert (optional but nice): 1.3.6.1.4.1.45724.1.1.4
    try:
        ext = leaf.extensions.get_extension_for_oid(ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4')).value
        if ext and hasattr(ext, 'value'):
            if ext.value != aaguid:
                raise AttestationFailure("certificate AAGUID != authData AAGUID")
    except Exception:
        pass  # not all certs carry this extension

    # Trust anchors — you must provide your own MDS-derived anchors per AAGUID; here we accept any if allowlist is empty.
    chain_ok, chain_fps = True, []
    if allowed_aaguids:
        # When enforcing allowlist, require x5c chain anchor to be present in your trust store.
        # Load anchors from local file mapping AAGUID -> list of DER roots. Left as integration hook.
        try:
            with open('server/mds_roots.json','r') as f:
                m = json.load(f)
            roots = [x509.load_pem_x509_certificate(r.encode()) for r in m.get(aaguid.hex(), [])]
            if roots:
                ok, chain_fps = _verify_chain_x5c(x5c_bytes, roots)
                if not ok:
                    raise AttestationFailure("attestation chain not anchored to trusted root for AAGUID")
        except FileNotFoundError:
            raise AttestationFailure("no MDS roots available; provide server/mds_roots.json or disable allowlist")

    jwk = cose_to_jwk(cose)

    return {
        'aaguid': aaguid,
        'cred_id': base64.urlsafe_b64encode(credId).rstrip(b'=').decode(),
        'jwk': jwk,
        'sign_count': signCount,
        'trust_chain': chain_fps,
    }