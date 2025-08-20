# server/config.py
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Literal

try:
    import yaml  # add PyYAML to server/requirements.txt
except Exception:  # pragma: no cover
    yaml = None

# Fallbacks
_DEF_DB_PATH = str((Path(__file__).resolve().parent / "stronghold.db"))
_DEF_SECRET_FILE = "/etc/secrets/STRONGHOLD_SERVER_EC_PRIVATE_KEY_PEM"

def _load_yaml() -> dict:
    """
    Load YAML config from STRONGHOLD_CONFIG if set,
    otherwise server/stronghold.yml or server/stronghold.yaml if present.
    """
    path = os.getenv("STRONGHOLD_CONFIG")
    if not path:
        base = Path(__file__).resolve().parent
        for name in ("stronghold.yml", "stronghold.yaml"):
            p = base / name
            if p.exists():
                path = str(p)
                break
    if not path or yaml is None:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}

def _g(cfg: dict, dotted: str, default=None):
    node = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node

def _bool_env(key: str, default: bool) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")

def _samesite(v: Optional[str], default: str="lax") -> Literal["lax","strict","none"]:
    v = (v or default).strip().lower()
    return v if v in ("lax","strict","none") else "lax"

@dataclass
class Settings:
    # Server
    external_origin: Optional[str]
    # Cookies
    session_cookie_name: str
    session_samesite: Literal["lax","strict","none"]
    dev_allow_insecure_cookie: bool
    # DB
    db_path: str
    # Passkeys
    passkeys_policy: Literal["compat","strict"]
    aaguid_allow_path: Optional[str]
    mds_roots_path: Optional[str]
    # Security windows
    skew_sec: int
    nonce_window: int
    nonce_ttl: int
    jti_ttl: int
    bind_ttl: int
    # Keys
    server_ec_private_key_pem: Optional[str]
    server_ec_private_key_pem_file: Optional[str]
    # For visibility
    cfg_file_used: Optional[str]

    @property
    def https_only(self) -> bool:
        return not self.dev_allow_insecure_cookie

def load_settings() -> Settings:
    cfg = _load_yaml()

    external_origin = (
        os.getenv("EXTERNAL_ORIGIN")
        or os.getenv("STRONGHOLD_EXTERNAL_ORIGIN")
        or _g(cfg, "server.external_origin")
    )

    db_path = os.getenv("STRONGHOLD_DB_PATH") or _g(cfg, "db.path", _DEF_DB_PATH)

    session_cookie_name = (
        os.getenv("SESSION_COOKIE_NAME")
        or _g(cfg, "session.cookie_name", "stronghold_session")
    )
    session_samesite = _samesite(os.getenv("SESSION_SAMESITE") or _g(cfg, "session.same_site"), "lax")
    dev_allow_insecure_cookie = _bool_env("DEV_ALLOW_INSECURE_COOKIE", _g(cfg, "session.dev_allow_insecure_cookie", False))

    passkeys_policy = (os.getenv("PASSKEYS_POLICY") or _g(cfg, "passkeys.policy", "compat")).lower()
    if passkeys_policy not in ("compat","strict"):
        passkeys_policy = "compat"
    aaguid_allow_path = os.getenv("AAGUID_ALLOW_PATH") or _g(cfg, "passkeys.aaguid_allow_path")
    mds_roots_path = os.getenv("MDS_ROOTS_PATH") or _g(cfg, "passkeys.mds_roots_path")

    skew_sec     = int(os.getenv("STRONGHOLD_SKEW_SEC"    , _g(cfg, "security.skew_sec"   , 120)))
    nonce_window = int(os.getenv("STRONGHOLD_NONCE_WINDOW", _g(cfg, "security.nonce_window", 5)))
    nonce_ttl    = int(os.getenv("STRONGHOLD_NONCE_TTL"   , _g(cfg, "security.nonce_ttl"  , 60)))
    jti_ttl      = int(os.getenv("STRONGHOLD_JTI_TTL"     , _g(cfg, "security.jti_ttl"    , 60)))
    bind_ttl     = int(os.getenv("STRONGHOLD_BIND_TTL"    , _g(cfg, "security.bind_ttl"   , 3600)))

    pem_inline = os.getenv("STRONGHOLD_SERVER_EC_PRIVATE_KEY_PEM") or _g(cfg, "server.ec_private_key_pem")
    pem_file   = (
        os.getenv("STRONGHOLD_SERVER_EC_PRIVATE_KEY_PEM_FILE")
        or _g(cfg, "server.ec_private_key_pem_file")
        or (_DEF_SECRET_FILE if Path(_DEF_SECRET_FILE).exists() else None)
    )
    pem = pem_inline or (Path(pem_file).read_text(encoding="utf-8") if pem_file and Path(pem_file).exists() else None)

    cfg_file_used = os.getenv("STRONGHOLD_CONFIG")
    if not cfg_file_used:
        base = Path(__file__).resolve().parent
        for name in ("stronghold.yml", "stronghold.yaml"):
            if (base / name).exists():
                cfg_file_used = str(base / name)
                break

    return Settings(
        external_origin=external_origin,
        session_cookie_name=session_cookie_name,
        session_samesite=session_samesite,
        dev_allow_insecure_cookie=dev_allow_insecure_cookie,
        db_path=str(db_path),
        passkeys_policy=passkeys_policy,
        aaguid_allow_path=aaguid_allow_path,
        mds_roots_path=mds_roots_path,
        skew_sec=skew_sec,
        nonce_window=nonce_window,
        nonce_ttl=nonce_ttl,
        jti_ttl=jti_ttl,
        bind_ttl=bind_ttl,
        server_ec_private_key_pem=pem,
        server_ec_private_key_pem_file=pem_file,
        cfg_file_used=cfg_file_used,
    )

def apply_env_overrides(s: Settings) -> None:
    """
    Ensure modules that read env at import time (db.py, passkeys.py) see the right values.
    Call this BEFORE importing those modules.
    """
    os.environ.setdefault("STRONGHOLD_DB_PATH", s.db_path)
    os.environ["PASSKEYS_POLICY"] = s.passkeys_policy
