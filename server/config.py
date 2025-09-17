# server/config.py
from __future__ import annotations
import os
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Literal, Dict, Any, List
import yaml

log = logging.getLogger("stronghold")

@dataclass
class Settings:
    # Server / external
    external_origin: Optional[str]
    allowed_origins: List[str]  # List of allowed origins for multi-domain support
    # Cookie/session
    session_cookie_name: str
    session_samesite: Literal["lax","strict","none"]
    session_secret_key: Optional[str]
    dev_allow_insecure_cookie: bool
    # DB
    db_path: str
    # Passkeys / attestation
    passkeys_policy: Literal["compat","strict"]
    aaguid_allow_path: Optional[str]
    mds_roots_path: Optional[str]
    # Security windows
    skew_sec: int
    nonce_ttl: int
    jti_ttl: int
    bind_ttl: int
    # Linking
    link_ttl_seconds: int
    # Keys
    server_ec_private_key_pem: Optional[str]
    server_ec_private_key_pem_file: Optional[str]
    # Logging
    log_level: str
    # Informational
    cfg_file_used: Optional[str] = None

    @property
    def https_only(self) -> bool:
        return not self.dev_allow_insecure_cookie

_DEFAULTS: Dict[str, Any] = {
    "server": {
        "external_origin": None,
        "allowed_origins": [],  # List of allowed origins for multi-domain support
        "ec_private_key_pem": None,
        "ec_private_key_pem_file": None,
    },
    "db": {"path": "/tmp/stronghold.db"},
    "session": {
        "cookie_name": "stronghold_session",
        "same_site": "lax",
        "secret_key": None,  # if None, app will generate an ephemeral key on startup (dev only)
        "dev_allow_insecure_cookie": True,
    },
    "passkeys": {
        "policy": "compat",
        "aaguid_allow_path": None,
        "mds_roots_path": None,
    },
    "security": {"skew_sec": 120, "nonce_ttl": 60, "jti_ttl": 60, "bind_ttl": 3600},
    "linking": {"ttl_seconds": 180},
    "logging": {"level": "INFO"},
}

_SEARCH_ORDER = (
    "stronghold.yaml",
    "stronghold.yml",
    "stronghold.dev.yaml",
)

def _merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out

def _resolve_path(s: str, base_dir: Path) -> Optional[Path]:
    """
    Try multiple resolution strategies for a relative path:
    - as given relative to CWD
    - relative to server/ (this module)
    - relative to repo root (parent of server/)
    Return first existing path; else None.
    """
    p = Path(s)
    if p.is_absolute():
        return p if p.exists() else None
    candidates = [
        Path.cwd() / p,
        base_dir / p,
        base_dir.parent / p,
        p,  # raw relative
    ]
    for c in candidates:
        if c.exists():
            return c
    return None

def load_settings(path: Optional[str] = None) -> Settings:
    """
    Load YAML settings with sensible overrides:

    Priority:
      1) explicit `path` arg (absolute or relative)
      2) env STRONGHOLD_CONFIG (absolute or relative; robustly resolved)
      3) search order inside server/: stronghold.yaml|yml|stronghold.dev.yaml
    """
    base_dir = Path(__file__).resolve().parent
    cfg_file_used: Optional[Path] = None

    if path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = _resolve_path(path, base_dir) or candidate
        if not candidate or not candidate.exists():
            raise FileNotFoundError(f"Config file not found: {candidate}")
        cfg_file_used = candidate
    else:
        env_cfg = os.getenv("STRONGHOLD_CONFIG")
        if env_cfg:
            candidate = _resolve_path(env_cfg, base_dir)
            if not candidate:
                tried = [
                    str(Path(env_cfg)),
                    str(base_dir / env_cfg),
                    str(base_dir.parent / env_cfg),
                    str(Path.cwd() / env_cfg),
                ]
                raise FileNotFoundError(
                    "STRONGHOLD_CONFIG not found. Tried: " + ", ".join(tried)
                )
            cfg_file_used = candidate
        else:
            for name in _SEARCH_ORDER:
                p = base_dir / name
                if p.exists():
                    cfg_file_used = p
                    break

    data: Dict[str, Any] = {}
    if cfg_file_used:
        with open(cfg_file_used, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        log.info("Loaded config from: %s", str(cfg_file_used))

    cfg = _merge(_DEFAULTS, data)

    # Resolve private key material: prefer inline, else file
    pem_inline = (cfg.get("server") or {}).get("ec_private_key_pem")
    pem_file   = (cfg.get("server") or {}).get("ec_private_key_pem_file")
    pem: Optional[str] = None
    if pem_inline:
        pem = pem_inline
    elif pem_file:
        p = Path(pem_file)
        if not p.is_absolute():
            p = _resolve_path(pem_file, base_dir) or (base_dir / p)
        if p and p.exists():
            pem = p.read_text(encoding="utf-8")

    # Normalize db path
    db_path = (cfg.get("db") or {}).get("path") or "/data/stronghold.db"
    dbp = Path(db_path)
    if not dbp.is_absolute():
        # relative to server/ to ease local dev (e.g., data/stronghold.db)
        dbp = base_dir / dbp
    db_path = str(dbp)

    s = Settings(
        external_origin=(cfg.get("server") or {}).get("external_origin"),
        allowed_origins=(cfg.get("server") or {}).get("allowed_origins", []),
        session_cookie_name=(cfg.get("session") or {}).get("cookie_name") or "stronghold_session",
        session_samesite=((cfg.get("session") or {}).get("same_site") or "lax").lower(),  # type: ignore
        session_secret_key=(cfg.get("session") or {}).get("secret_key"),
        dev_allow_insecure_cookie=bool((cfg.get("session") or {}).get("dev_allow_insecure_cookie", False)),
        db_path=db_path,
        passkeys_policy=((cfg.get("passkeys") or {}).get("policy") or "compat"),
        aaguid_allow_path=(cfg.get("passkeys") or {}).get("aaguid_allow_path"),
        mds_roots_path=(cfg.get("passkeys") or {}).get("mds_roots_path"),
        skew_sec=int((cfg.get("security") or {}).get("skew_sec", 120)),
        nonce_ttl=int((cfg.get("security") or {}).get("nonce_ttl", 60)),
        jti_ttl=int((cfg.get("security") or {}).get("jti_ttl", 60)),
        bind_ttl=int((cfg.get("security") or {}).get("bind_ttl", 3600)),
        link_ttl_seconds=int((cfg.get("linking") or {}).get("ttl_seconds", 180)),
        server_ec_private_key_pem=pem,
        server_ec_private_key_pem_file=pem_file,
        log_level=str((cfg.get("logging") or {}).get("level") or "INFO").upper(),
        cfg_file_used=str(cfg_file_used) if cfg_file_used else None,
    )
    return s
