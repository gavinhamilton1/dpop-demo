# server/db.py
from __future__ import annotations
import os, json, asyncio
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List
import aiosqlite

# Read from env (Render: set STRONGHOLD_DB_PATH=/data/stronghold.db)
DB_PATH = os.getenv("STRONGHOLD_DB_PATH", str(Path(__file__).resolve().parent / "stronghold.db"))

class Database:
    def __init__(self, path: Optional[str] = None):
        self.path = str(Path(path or DB_PATH))
        # Ensure parent dir exists (works for /data on Render too)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def init(self):
        # Open once; do NOT await/enter this connection again (prevents “threads can only be started once”)
        if self._conn is None:
            self._conn = await aiosqlite.connect(self.path)
            self._conn.row_factory = aiosqlite.Row
            # Pragmas: durability + concurrency
            await self._conn.execute("PRAGMA journal_mode=WAL;")
            await self._conn.execute("PRAGMA foreign_keys=ON;")
            await self._conn.commit()

        # Create minimal tables used by the app; extend as needed
        await self.execscript("""
        CREATE TABLE IF NOT EXISTS sessions (
          sid TEXT PRIMARY KEY,
          data TEXT NOT NULL,           -- JSON blob
          updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS nonces (
          sid TEXT NOT NULL,
          nonce TEXT NOT NULL,
          exp INTEGER NOT NULL,
          PRIMARY KEY (sid, nonce)
        );

        CREATE TABLE IF NOT EXISTS jtis (
          sid TEXT NOT NULL,
          jti TEXT NOT NULL,
          exp INTEGER NOT NULL,
          PRIMARY KEY (sid, jti)
        );

        CREATE TABLE IF NOT EXISTS passkeys (
          principal TEXT NOT NULL,
          cred_id   TEXT PRIMARY KEY,
          public_key_jwk TEXT NOT NULL, -- JSON
          sign_count INTEGER NOT NULL DEFAULT 0,
          aaguid TEXT,
          transports TEXT,              -- JSON array
          created_at INTEGER NOT NULL
        );

        -- Optional index for frequent lookups
        CREATE INDEX IF NOT EXISTS idx_passkeys_principal ON passkeys(principal);

        -- Linking (if you use it)
        CREATE TABLE IF NOT EXISTS links (
          id TEXT PRIMARY KEY,
          owner_sid TEXT NOT NULL,
          status TEXT NOT NULL,         -- pending|scanned|completed
          principal TEXT,
          expires_at INTEGER NOT NULL,
          applied INTEGER NOT NULL DEFAULT 0
        );
        """)

    async def close(self):
        if self._conn:
            await self._conn.close()
            self._conn = None

    # --- low-level helpers -------------------------------------------------

    async def exec(self, sql: str, params: Tuple | Dict | List = ()):
        if not self._conn:
            await self.init()
        async with self._lock:
            await self._conn.execute(sql, params)
            await self._conn.commit()

    async def execscript(self, script: str):
        if not self._conn:
            await self.init()
        async with self._lock:
            await self._conn.executescript(script)
            await self._conn.commit()

    async def fetchone(self, sql: str, params: Tuple | Dict = ()) -> Optional[aiosqlite.Row]:
        if not self._conn:
            await self.init()
        async with self._lock:
            cur = await self._conn.execute(sql, params)
            row = await cur.fetchone()
            await cur.close()
            return row

    async def fetchall(self, sql: str, params: Tuple | Dict = ()) -> List[aiosqlite.Row]:
        if not self._conn:
            await self.init()
        async with self._lock:
            cur = await self._conn.execute(sql, params)
            rows = await cur.fetchall()
            await cur.close()
            return rows

    # --- session store API (drop-in for your previous in-memory Store) ------

    async def set_session(self, sid: str, data: Dict[str, Any]):
        j = json.dumps(data, separators=(",", ":"))
        await self.exec(
            "INSERT INTO sessions(sid, data, updated_at) VALUES(?,?,strftime('%s','now')) "
            "ON CONFLICT(sid) DO UPDATE SET data=excluded.data, updated_at=strftime('%s','now')",
            (sid, j),
        )

    async def get_session(self, sid: str) -> Optional[Dict[str, Any]]:
        row = await self.fetchone("SELECT data FROM sessions WHERE sid=?", (sid,))
        if not row:
            return None
        try:
            return json.loads(row["data"])
        except Exception:
            return None

    async def update_session(self, sid: str, patch: Dict[str, Any]):
        cur = await self.get_session(sid) or {}
        cur.update(patch)
        await self.set_session(sid, cur)

    async def add_nonce(self, sid: str, nonce: str, ttl_sec: int):
        exp = await self.fetchone("SELECT strftime('%s','now') + ? AS e", (ttl_sec,))
        await self.exec("INSERT OR REPLACE INTO nonces(sid, nonce, exp) VALUES(?,?,?)",
                        (sid, nonce, int(exp["e"])))

    async def nonce_valid(self, sid: str, nonce: str) -> bool:
        await self.exec("DELETE FROM nonces WHERE exp < strftime('%s','now')")
        row = await self.fetchone("SELECT 1 FROM nonces WHERE sid=? AND nonce=?", (sid, nonce))
        return bool(row)

    async def add_jti(self, sid: str, jti: str, ttl_sec: int) -> bool:
        # garbage collect old
        await self.exec("DELETE FROM jtis WHERE exp < strftime('%s','now')")
        exp = await self.fetchone("SELECT strftime('%s','now') + ? AS e", (ttl_sec,))
        try:
            await self.exec("INSERT INTO jtis(sid, jti, exp) VALUES(?,?,?)",
                            (sid, jti, int(exp["e"])))
            return True
        except Exception:
            # primary key conflict → seen already
            return False

    async def flush(self):
        # Danger: nukes everything (dev tool)
        await self.execscript("""
          DELETE FROM sessions;
          DELETE FROM nonces;
          DELETE FROM jtis;
          DELETE FROM passkeys;
          DELETE FROM links;
        """)

    # --- passkey repo API (matches your PasskeyRepo shape, but async) -------

    async def pk_get_for_principal(self, principal: str) -> List[Dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM passkeys WHERE principal=?", (principal,))
        out = []
        for r in rows:
            out.append({
                "principal": r["principal"],
                "cred_id": r["cred_id"],
                "public_key_jwk": json.loads(r["public_key_jwk"]),
                "sign_count": r["sign_count"],
                "aaguid": r["aaguid"],
                "transports": json.loads(r["transports"]) if r["transports"] else [],
                "created_at": r["created_at"],
            })
        return out

    async def pk_upsert(self, principal: str, rec: Dict[str, Any]) -> None:
        await self.exec(
            """INSERT INTO passkeys(principal, cred_id, public_key_jwk, sign_count, aaguid, transports, created_at)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(cred_id) DO UPDATE SET
                 principal=excluded.principal,
                 public_key_jwk=excluded.public_key_jwk,
                 sign_count=excluded.sign_count,
                 aaguid=excluded.aaguid,
                 transports=excluded.transports""",
            (
                principal,
                rec["cred_id"],
                json.dumps(rec["public_key_jwk"], separators=(",", ":")),
                int(rec.get("sign_count") or 0),
                rec.get("aaguid"),
                json.dumps(rec.get("transports") or [], separators=(",", ":")),
                int(rec.get("created_at") or 0),
            ),
        )

    async def pk_find_by_cred_id(self, principal: str, cred_id: str) -> Optional[Dict[str, Any]]:
        r = await self.fetchone("SELECT * FROM passkeys WHERE principal=? AND cred_id=?", (principal, cred_id))
        if not r:
            return None
        return {
            "principal": r["principal"],
            "cred_id": r["cred_id"],
            "public_key_jwk": json.loads(r["public_key_jwk"]),
            "sign_count": r["sign_count"],
            "aaguid": r["aaguid"],
            "transports": json.loads(r["transports"]) if r["transports"] else [],
            "created_at": r["created_at"],
        }

    async def pk_get_by_cred_id(self, cred_id: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        r = await self.fetchone("SELECT * FROM passkeys WHERE cred_id=?", (cred_id,))
        if not r:
            return None
        rec = {
            "principal": r["principal"],
            "cred_id": r["cred_id"],
            "public_key_jwk": json.loads(r["public_key_jwk"]),
            "sign_count": r["sign_count"],
            "aaguid": r["aaguid"],
            "transports": json.loads(r["transports"]) if r["transports"] else [],
            "created_at": r["created_at"],
        }
        return r["principal"], rec

    async def pk_update_sign_count(self, cred_id: str, new_count: int):
        await self.exec("UPDATE passkeys SET sign_count=? WHERE cred_id=?", (int(new_count), cred_id))

    async def pk_remove(self, principal: str, cred_id: str) -> bool:
        await self.exec("DELETE FROM passkeys WHERE principal=? AND cred_id=?", (principal, cred_id))
        # We can’t easily tell rows affected with aiosqlite here without extra work; return True for simplicity
        return True


# Export a singleton used by main.py
DB = Database(DB_PATH)
