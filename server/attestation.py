# server/attestation.py
from __future__ import annotations
import json, hashlib, base64
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import ObjectIdentifier

from server.config import load_settings

# -------- Config-backed settings --------
SETTINGS = load_settings()

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
    def load(path: Optional[str] = None) -> 'AAGUIDAllowlist':
        """
        Loads an AAGUID allowlist JSON mapping of { aaguid_hex[with/without-dashes]: true/false }.
        If `path` is not provided, falls back to Settings.aaguid_allow_path. Empty set => allow any
        AAGUID *after* cryptographic verification and (optionally) trust-chain validation.
        """
        # Default: empty means "allow any AAGUID" (policy decided elsewhere)
        if path is None:
            path = SETTINGS.aaguid_allow_path
        if not path:
            return AAGUIDAllowlist(allowed=set())
        with open(path, 'r') as f:
            j = json.load(f)
        return AAGUIDAllowlist(allowed=set([k.replace('-', '').lower() for k, v in j.items() if v]))

# -------- Minimal COSE → JWK --------

def cose_to_jwk(cbor_bytes: bytes) -> dict:
    m = cbor2.loads(cbor_bytes)
    kty = m.get(1)   # 1=OKP, 2=EC2, 3=RSA
    if kty == 2:  # EC2
        crv = m.get(-1); x = m.get(-2); y = m.get(-3)
        if crv != 1:  # P-256 only
            raise AttestationFailure("unsupported EC curve")
        return {"kty":"EC","crv":"P-256","x":b64u(x),"y":b64u(y),"alg":"ES256"}
    if kty == 3:  # RSA
        n = m.get(-1); e = m.get(-2)
        return {"kty":"RSA","n":b64u(n),"e":b64u(e),"alg":"RS256"}
    raise AttestationFailure("unsupported COSE key")

# -------- Verify cert chain to trusted roots (naive path building) --------

def _verify_chain_x5c(x5c: List[bytes], trusted_roots: List[x509.Certificate]) -> Tuple[bool, List[str]]:
    if not x5c:
        return False, []
    certs = [x509.load_der_x509_certificate(c) for c in x5c]
    # Step 1: verify linear chain signatures (leaf→...→root)
    for i in range(len(certs) - 1):
        issuer_pk = certs[i + 1].public_key()
        cert = certs[i]
        try:
            if isinstance(issuer_pk, rsa.RSAPublicKey):
                issuer_pk.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
            else:
                issuer_pk.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        except Exception:
            return False, []
    # Step 2: anchor match (accept if any provided cert matches a trusted root)
    chain_fps = [cert.fingerprint(hashes.SHA256()).hex() for cert in certs]
    if not trusted_roots:
        return True, chain_fps
    anchor_fps = set(c.fingerprint(hashes.SHA256()) for c in trusted_roots)
    ok = any(c.fingerprint(hashes.SHA256()) in anchor_fps for c in certs)
    return ok, chain_fps

# -------- Packed attestation validation with x5c --------

def verify_packed_attestation_x5c(
    attStmt: dict,
    authData: bytes,
    client_hash: bytes,
    *,
    expected_rp_id: str,
    allowed_aaguids: Set[str],
    mds_roots_path: Optional[str] = None,  # if None, uses Settings.mds_roots_path
):
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

    # Optional AAGUID cert extension check: 1.3.6.1.4.1.45724.1.1.4
    try:
        ext = leaf.extensions.get_extension_for_oid(ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4')).value
        if ext and hasattr(ext, 'value') and ext.value != aaguid:
            raise AttestationFailure("certificate AAGUID != authData AAGUID")
    except Exception:
        pass  # not all certs carry the extension

    # Trust anchors (per-AAGUID) — optional unless allowlist is enforced.
    chain_fps: List[str] = []
    if allowed_aaguids:
        # Only enforce chain anchoring when you explicitly allowlist devices.
        if mds_roots_path is None:
            mds_roots_path = SETTINGS.mds_roots_path
        if not mds_roots_path:
            raise AttestationFailure("no MDS roots path configured; set passkeys.mds_roots_path or disable allowlist")
        try:
            with open(mds_roots_path, 'r') as f:
                m = json.load(f)  # { aaguid_hex: [PEM, PEM, ...] }
            pem_list = m.get(aaguid.hex(), [])
            roots: List[x509.Certificate] = []
            for pem in pem_list:
                try:
                    roots.append(x509.load_pem_x509_certificate(pem.encode()))
                except Exception:
                    pass
            ok, chain_fps = _verify_chain_x5c(x5c_bytes, roots)
            if not ok:
                raise AttestationFailure("attestation chain not anchored to trusted root for AAGUID")
        except FileNotFoundError:
            raise AttestationFailure("MDS roots file not found")
        except json.JSONDecodeError:
            raise AttestationFailure("invalid MDS roots file format")

    jwk = cose_to_jwk(cose)

    return {
        'aaguid': aaguid,
        'cred_id': b64u(credId),
        'jwk': jwk,
        'sign_count': signCount,
        'trust_chain': chain_fps,
    }
