# server/db.py
from __future__ import annotations
import json, time, asyncio
from typing import Any, Dict, List, Optional, Tuple
import aiosqlite

_NOW = lambda: int(time.time())

def _json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

def _json_load(s: Optional[str]) -> Any:
    return json.loads(s) if s else None

class SqliteDB:
    """Low-level DB holder + schema init."""
    def __init__(self, path: str):
        self.path = path
        self._init_lock = asyncio.Lock()
        self._initialized = False

    async def connect(self) -> aiosqlite.Connection:
        """
        Return a configured, STARTED aiosqlite connection.
        Do NOT wrap this in 'async with'; close it yourself.
        """
        # Awaiting aiosqlite.connect() starts the worker thread.
        conn = await aiosqlite.connect(self.path)
        conn.row_factory = aiosqlite.Row
        # 'foreign_keys' is per-connection; enable every time.
        await conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    async def init(self):
        if self._initialized:
            return
        async with self._init_lock:
            if self._initialized:
                return
            conn = await aiosqlite.connect(self.path)  # start thread
            try:
                # Set WAL once (persists at DB level)
                await conn.execute("PRAGMA journal_mode=WAL;")
                await conn.execute("PRAGMA foreign_keys=ON;")
                await conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions(
                  sid TEXT PRIMARY KEY,
                  data TEXT NOT NULL,
                  updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS nonces(
                  sid TEXT NOT NULL,
                  nonce TEXT NOT NULL,
                  exp INTEGER NOT NULL,
                  PRIMARY KEY (sid, nonce)
                );

                CREATE TABLE IF NOT EXISTS jtis(
                  sid TEXT NOT NULL,
                  jti TEXT NOT NULL,
                  exp INTEGER NOT NULL,
                  PRIMARY KEY (sid, jti)
                );

                CREATE TABLE IF NOT EXISTS passkeys(
                  cred_id TEXT PRIMARY KEY,
                  principal TEXT NOT NULL,
                  public_key_jwk TEXT NOT NULL,
                  sign_count INTEGER NOT NULL DEFAULT 0,
                  aaguid TEXT,
                  transports TEXT,
                  bik_jkt TEXT,
                  dpop_jkt TEXT,
                  created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_passkeys_principal
                  ON passkeys(principal);

                CREATE TABLE IF NOT EXISTS links(
                  link_id TEXT PRIMARY KEY,
                  desktop_sid TEXT NOT NULL,
                  status TEXT NOT NULL,         -- pending | scanned | linked | expired
                  token TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  exp INTEGER NOT NULL,
                  applied INTEGER NOT NULL DEFAULT 0,
                  principal TEXT,
                  mobile_sid TEXT
                );
                """)
                await conn.commit()
            finally:
                await conn.close()
            self._initialized = True


# ---------------- Session/nonce/jti store ----------------

class SqlStore:
    """
    Drop-in replacement for your in-memory Store with SQLite persistence.
    Methods mirror your existing Store API.
    """
    def __init__(self, db: SqliteDB):
        self.db = db

    # ---- sessions ----
    async def set_session(self, sid: str, data: Dict[str, Any]):
        await self.db.init()
        conn = await self.db.connect()
        try:
            await conn.execute(
                "INSERT INTO sessions(sid, data, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(sid) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                (sid, _json(data), _NOW())
            )
            await conn.commit()
        finally:
            await conn.close()

    async def get_session(self, sid: str) -> Optional[Dict[str, Any]]:
        await self.db.init()
        conn = await self.db.connect()
        try:
            cur = await conn.execute("SELECT data FROM sessions WHERE sid=?", (sid,))
            row = await cur.fetchone()
            return _json_load(row["data"]) if row else None
        finally:
            await conn.close()

    async def update_session(self, sid: str, patch: Dict[str, Any]):
        s = await self.get_session(sid) or {}
        s.update(patch)
        await self.set_session(sid, s)

    # ---- nonces ----
    async def add_nonce(self, sid: str, nonce: str, ttl: int):
        await self.db.init()
        exp = _NOW() + int(ttl)
        conn = await self.db.connect()
        try:
            await conn.execute("DELETE FROM nonces WHERE sid=? AND exp < ?", (sid, _NOW()))
            await conn.execute(
                "INSERT OR REPLACE INTO nonces(sid, nonce, exp) VALUES(?,?,?)",
                (sid, nonce, exp)
            )
            await conn.commit()
        finally:
            await conn.close()

    async def nonce_valid(self, sid: str, nonce: str) -> bool:
        await self.db.init()
        conn = await self.db.connect()
        try:
            await conn.execute("DELETE FROM nonces WHERE exp < ?", (_NOW(),))
            cur = await conn.execute(
                "SELECT 1 FROM nonces WHERE sid=? AND nonce=? LIMIT 1",
                (sid, nonce)
            )
            return (await cur.fetchone()) is not None
        finally:
            await conn.close()

    # ---- jtis ----
    async def add_jti(self, sid: str, jti: str, ttl: int) -> bool:
        await self.db.init()
        exp = _NOW() + int(ttl)
        conn = await self.db.connect()
        try:
            await conn.execute("DELETE FROM jtis WHERE exp < ?", (_NOW(),))
            try:
                await conn.execute("INSERT INTO jtis(sid, jti, exp) VALUES(?,?,?)", (sid, jti, exp))
                await conn.commit()
                return True
            except Exception:
                return False
        finally:
            await conn.close()

    # ---- links ----
    async def link_create(self, rec: Dict[str, Any]):
        await self.db.init()
        conn = await self.db.connect()
        try:
            await conn.execute(
                "INSERT INTO links(link_id, desktop_sid, status, token, created_at, exp, applied, principal, mobile_sid) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    rec["link_id"], rec["desktop_sid"], rec["status"], rec["token"],
                    rec["created_at"], rec["exp"], 1 if rec.get("applied") else 0,
                    rec.get("principal"), rec.get("mobile_sid")
                )
            )
            await conn.commit()
        finally:
            await conn.close()

    async def link_get(self, link_id: str) -> Optional[Dict[str, Any]]:
        await self.db.init()
        conn = await self.db.connect()
        try:
            cur = await conn.execute("SELECT * FROM links WHERE link_id=?", (link_id,))
            row = await cur.fetchone()
            if not row:
                return None
            return {
                "link_id": row["link_id"],
                "desktop_sid": row["desktop_sid"],
                "status": row["status"],
                "token": row["token"],
                "created_at": row["created_at"],
                "exp": row["exp"],
                "applied": bool(row["applied"]),
                "principal": row["principal"],
                "mobile_sid": row["mobile_sid"],
            }
        finally:
            await conn.close()

    async def link_patch(self, link_id: str, patch: Dict[str, Any]):
        if not patch:
            return
        await self.db.init()
        cols = []
        vals = []
        for k, v in patch.items():
            if k == "applied":
                v = 1 if v else 0
            cols.append(f"{k}=?")
            vals.append(v)
        vals.append(link_id)
        conn = await self.db.connect()
        try:
            await conn.execute(f"UPDATE links SET {', '.join(cols)} WHERE link_id=?", vals)
            await conn.commit()
        finally:
            await conn.close()

    async def flush(self):
        await self.db.init()
        conn = await self.db.connect()
        try:
            for t in ("sessions", "nonces", "jtis", "passkeys", "links"):
                await conn.execute(f"DELETE FROM {t}")
            await conn.commit()
        finally:
            await conn.close()


# ---------------- Passkey repo (DB-backed) ----------------

class SqlitePasskeyRepo:
    """DB-backed implementation of your PasskeyRepo API."""
    def __init__(self, db: SqliteDB):
        self.db = db

    async def get_for_principal(self, principal: str) -> List[Dict[str, Any]]:
        await self.db.init()
        conn = await self.db.connect()
        try:
            cur = await conn.execute("SELECT * FROM passkeys WHERE principal=?", (principal,))
            rows = await cur.fetchall()
            out = []
            for r in rows:
                out.append({
                    "principal": r["principal"],
                    "cred_id": r["cred_id"],
                    "public_key_jwk": _json_load(r["public_key_jwk"]),
                    "sign_count": r["sign_count"],
                    "aaguid": r["aaguid"],
                    "attestation": {},
                    "transports": _json_load(r["transports"]) or [],
                    "bik_jkt": r["bik_jkt"],
                    "dpop_jkt": r["dpop_jkt"],
                    "created_at": r["created_at"],
                })
            return out
        finally:
            await conn.close()

    async def upsert(self, principal: str, rec: Dict[str, Any]) -> None:
        await self.db.init()
        conn = await self.db.connect()
        try:
            await conn.execute(
                "INSERT INTO passkeys(cred_id, principal, public_key_jwk, sign_count, aaguid, transports, bik_jkt, dpop_jkt, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(cred_id) DO UPDATE SET "
                "principal=excluded.principal, public_key_jwk=excluded.public_key_jwk, "
                "sign_count=excluded.sign_count, aaguid=excluded.aaguid, transports=excluded.transports, "
                "bik_jkt=excluded.bik_jkt, dpop_jkt=excluded.dpop_jkt",
                (
                    rec["cred_id"], principal, _json(rec["public_key_jwk"]),
                    int(rec.get("sign_count", 0)), rec.get("aaguid"),
                    _json(rec.get("transports") or []),
                    rec.get("bik_jkt"), rec.get("dpop_jkt"),
                    int(rec.get("created_at") or _NOW())
                )
            )
            await conn.commit()
        finally:
            await conn.close()

    async def find_by_cred_id(self, principal: str, cred_id: str) -> Optional[Dict[str, Any]]:
        await self.db.init()
        conn = await self.db.connect()
        try:
            cur = await conn.execute(
                "SELECT * FROM passkeys WHERE cred_id=? AND principal=?",
                (cred_id, principal)
            )
            r = await cur.fetchone()
            if not r:
                return None
            return {
                "principal": r["principal"],
                "cred_id": r["cred_id"],
                "public_key_jwk": _json_load(r["public_key_jwk"]),
                "sign_count": r["sign_count"],
                "aaguid": r["aaguid"],
                "transports": _json_load(r["transports"]) or [],
                "bik_jkt": r["bik_jkt"],
                "dpop_jkt": r["dpop_jkt"],
                "created_at": r["created_at"],
            }
        finally:
            await conn.close()

    async def get_by_cred_id(self, cred_id: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        await self.db.init()
        conn = await self.db.connect()
        try:
            cur = await conn.execute("SELECT * FROM passkeys WHERE cred_id=?", (cred_id,))
            r = await cur.fetchone()
            if not r:
                return None
            rec = {
                "principal": r["principal"],
                "cred_id": r["cred_id"],
                "public_key_jwk": _json_load(r["public_key_jwk"]),
                "sign_count": r["sign_count"],
                "aaguid": r["aaguid"],
                "transports": _json_load(r["transports"]) or [],
                "bik_jkt": r["bik_jkt"],
                "dpop_jkt": r["dpop_jkt"],
                "created_at": r["created_at"],
            }
            return (r["principal"], rec)
        finally:
            await conn.close()

    async def update_sign_count(self, cred_id: str, new_count: int):
        await self.db.init()
        conn = await self.db.connect()
        try:
            await conn.execute("UPDATE passkeys SET sign_count=? WHERE cred_id=?", (int(new_count), cred_id))
            await conn.commit()
        finally:
            await conn.close()

    async def remove(self, principal: str, cred_id: str) -> bool:
        await self.db.init()
        conn = await self.db.connect()
        try:
            cur = await conn.execute("DELETE FROM passkeys WHERE cred_id=? AND principal=?", (cred_id, principal))
            await conn.commit()
            return cur.rowcount > 0
        finally:
            await conn.close()
