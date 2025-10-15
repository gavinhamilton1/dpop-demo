# server/config.py
from __future__ import annotations
import os
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Literal, Dict, Any, List
import yaml

log = logging.getLogger(__name__)


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
        "allowed_origins": ["http://localhost:8000", "https://dpop.fun", "https://dpop-fun.onrender.com"],  # List of allowed origins for multi-domain support
        "ec_private_key_pem": None,
        "ec_private_key_pem_file": None,
    },
    "db": {"path": "../data/dpop-fun.db"},
    "session": {
        "cookie_name": "dpop-fun_session",
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
    "dpop-fun.yaml",
    "dpop-fun.yml",
    "dpop-fun.dev.yaml",
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
      2) env DPOP_FUN_CONFIG (absolute or relative; robustly resolved)
      3) search order in project root: dpop-fun.yaml|yml|dpop-fun.dev.yaml
    """
    base_dir = Path(__file__).resolve().parent.parent.parent  # Go up to project root
    cfg_file_used: Optional[Path] = None

    if path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = _resolve_path(path, base_dir) or candidate
        if not candidate or not candidate.exists():
            raise FileNotFoundError(f"Config file not found: {candidate}")
        cfg_file_used = candidate
    else:
        env_cfg = os.getenv("DPOP_FUN_CONFIG")
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
                    "DPOP_FUN_CONFIG not found. Tried: " + ", ".join(tried)
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
        print(f"DEBUG: Loaded config from: {str(cfg_file_used)}")
        print(f"DEBUG: Config data (before env substitution): {data}")
        
        # Substitute environment variables in the format ${VAR_NAME}
        def substitute_env_vars(obj):
            if isinstance(obj, dict):
                return {k: substitute_env_vars(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [substitute_env_vars(item) for item in obj]
            elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
                var_name = obj[2:-1]
                env_value = os.getenv(var_name)
                if env_value:
                    print(f"DEBUG: Substituted ${{{var_name}}} with env value (length: {len(env_value)})")
                    return env_value
                else:
                    print(f"DEBUG: Environment variable {var_name} not found, keeping placeholder")
                    return obj
            else:
                return obj
        
        data = substitute_env_vars(data)
        print(f"DEBUG: Config data (after env substitution): {data}")
        log.info("Loaded config from: %s", str(cfg_file_used))

    cfg = _merge(_DEFAULTS, data)

    # Resolve private key material: prefer environment variable, then file (Render secrets), then inline, then config file
    pem_env = os.getenv("DPOP_FUN_SERVER_EC_PRIVATE_KEY_PEM")
    pem_inline = (cfg.get("server") or {}).get("ec_private_key_pem")
    pem_file   = (cfg.get("server") or {}).get("ec_private_key_pem_file")
    pem: Optional[str] = None
    
    # Check if key is in Render secrets file location
    render_secret_path = Path("/etc/secrets/DPOP_FUN_SERVER_EC_PRIVATE_KEY_PEM")
    
    print(f"DEBUG: Checking Render secrets path: {render_secret_path}")
    print(f"DEBUG: Render secrets file exists: {render_secret_path.exists()}")
    print(f"DEBUG: pem_env exists: {pem_env is not None}")
    print(f"DEBUG: pem_env length: {len(pem_env) if pem_env else 0}")
    if pem_env:
        print(f"DEBUG: pem_env preview: {pem_env[:50]}..." if len(pem_env) > 50 else f"DEBUG: pem_env: {pem_env}")
    print(f"DEBUG: pem_inline exists: {pem_inline is not None}")
    if pem_inline:
        print(f"DEBUG: pem_inline length: {len(pem_inline)}")
        print(f"DEBUG: pem_inline preview: {pem_inline[:50]}..." if len(pem_inline) > 50 else f"DEBUG: pem_inline: {pem_inline}")
    print(f"DEBUG: pem_file: {pem_file}")
    
    if pem_env:
        # Handle escaped newlines in environment variables (e.g., \n as literal text)
        if '\\n' in pem_env:
            pem = pem_env.replace('\\n', '\n')
            print(f"DEBUG: Converted escaped newlines in pem_env")
        else:
            pem = pem_env
        print(f"DEBUG: Using pem_env (length: {len(pem)})")
        log.info("Loaded ES256 private key from environment variable DPOP_FUN_SERVER_EC_PRIVATE_KEY_PEM")
    elif render_secret_path.exists():
        # Check Render secrets file location
        pem = render_secret_path.read_text(encoding="utf-8").strip()
        print(f"DEBUG: Using Render secrets file (length: {len(pem)})")
        log.info("Loaded ES256 private key from Render secrets file: %s", render_secret_path)
    elif pem_inline and not (pem_inline.startswith("${") and pem_inline.endswith("}")):
        # Only use pem_inline if it's not an unsubstituted placeholder
        pem = pem_inline
        # Handle escaped newlines
        if '\\n' in pem:
            pem = pem.replace('\\n', '\n')
            print(f"DEBUG: Converted escaped newlines in pem_inline")
        print(f"DEBUG: Using pem_inline (length: {len(pem)})")
        log.info("Loaded ES256 private key from config inline")
    elif pem_file:
        p = Path(pem_file)
        if not p.is_absolute():
            p = _resolve_path(pem_file, base_dir) or (base_dir / p)
        if p and p.exists():
            pem = p.read_text(encoding="utf-8")
            print(f"DEBUG: Using pem_file (length: {len(pem)})")
            log.info("Loaded ES256 private key from file: %s", pem_file)
    
    print(f"DEBUG: Final pem value exists: {pem is not None}")
    if pem:
        print(f"DEBUG: Final pem length: {len(pem)}")
    else:
        print(f"WARNING: No server EC private key configured - will generate ephemeral key")
        log.warning("No server EC private key found in environment, config, or file")

    # Normalize db path
    db_path = (cfg.get("db") or {}).get("path") or "/tmp/dpop-fun.db"
    print(f"DEBUG: Original db_path: {db_path}")
    dbp = Path(db_path)
    print(f"DEBUG: Path object: {dbp}")
    print(f"DEBUG: Is absolute: {dbp.is_absolute()}")
    print(f"DEBUG: base_dir: {base_dir}")
    if not dbp.is_absolute():
        # relative to server/ to ease local dev (e.g., data/dpop-fun.db)
        dbp = base_dir / dbp
        print(f"DEBUG: Resolved relative path: {dbp}")
    db_path = str(dbp)
    print(f"DEBUG: Final db_path: {db_path}")

    s = Settings(
        external_origin=(cfg.get("server") or {}).get("external_origin"),
        allowed_origins=(cfg.get("server") or {}).get("allowed_origins", []),
        session_cookie_name=(cfg.get("session") or {}).get("cookie_name") or "dpop-fun_session",
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
