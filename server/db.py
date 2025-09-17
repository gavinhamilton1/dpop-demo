# server/db.py
from __future__ import annotations
import json, asyncio
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

import aiosqlite
from server.config import load_settings

# Load config once at import
_SETTINGS = load_settings()
# Use config-provided path (fallback to /tmp for Render compatibility)
_DEFAULT_DB_PATH = Path(_SETTINGS.db_path if _SETTINGS.db_path else "/tmp/stronghold.db")
print(f"DEBUG: Using database path: {_DEFAULT_DB_PATH}")

class Database:
    def __init__(self, path: Optional[str] = None):
        # Prefer explicit path, else config file path
        self.path = str(Path(path) if path else _DEFAULT_DB_PATH)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def init(self, path: Optional[str] = None):
        """
        Initialize (or re-initialize) the DB connection.
        If `path` is provided and differs from the current path, the connection is reopened.
        """
        if path:
            new_path = str(Path(path))
            if new_path != self.path:
                # Re-point and reopen if needed
                await self.close()
                self.path = new_path
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)

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

        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          session_id TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          FOREIGN KEY (session_id) REFERENCES sessions(sid)
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

        CREATE TABLE IF NOT EXISTS face_embeddings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT NOT NULL,        -- User identifier (could be session_id or username)
          embedding BLOB NOT NULL,     -- Face embedding as binary data
          video_path TEXT,              -- Path to original video file
          frame_count INTEGER,          -- Number of frames processed
          created_at INTEGER NOT NULL,
          metadata TEXT                 -- JSON metadata (bbox, confidence, etc.)
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

    async def delete_session(self, sid: str):
        """Delete a session from the database"""
        await self.exec("DELETE FROM sessions WHERE sid=?", (sid,))

    async def get_session_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get session by username - used for duplicate username validation"""
        rows = await self.fetchall("SELECT sid, data FROM sessions")
        for row in rows:
            try:
                data = json.loads(row["data"])
                if data.get("username") == username:
                    return data
            except Exception:
                continue
        return None

    # --- User management methods ---
    
    async def create_user(self, username: str, session_id: str) -> bool:
        """Create a new user record"""
        try:
            await self.exec(
                "INSERT INTO users(username, session_id, created_at) VALUES(?, ?, strftime('%s','now'))",
                (username, session_id)
            )
            return True
        except Exception:
            return False

    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        row = await self.fetchone(
            "SELECT id, username, session_id, created_at FROM users WHERE username = ?",
            (username,)
        )
        if not row:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "session_id": row["session_id"],
            "created_at": row["created_at"]
        }

    async def get_user_by_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get user by session ID"""
        row = await self.fetchone(
            "SELECT id, username, session_id, created_at FROM users WHERE session_id = ?",
            (session_id,)
        )
        if not row:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "session_id": row["session_id"],
            "created_at": row["created_at"]
        }

    async def delete_user(self, username: str) -> bool:
        """Delete a user record"""
        try:
            await self.exec("DELETE FROM users WHERE username = ?", (username,))
            return True
        except Exception:
            return False

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
        # We can't easily tell rows affected with aiosqlite here without extra work; return True for simplicity
        return True

    # Face embeddings methods
    async def store_face_embedding(self, user_id: str, embedding: bytes, video_path: str = None, 
                                   frame_count: int = 0, metadata: Dict[str, Any] = None) -> int:
        """Store a face embedding in the database"""
        import time
        await self.exec(
            """INSERT INTO face_embeddings(user_id, embedding, video_path, frame_count, created_at, metadata)
               VALUES(?,?,?,?,?,?)""",
            (
                user_id,
                embedding,
                video_path,
                frame_count,
                int(time.time()),
                json.dumps(metadata or {}, separators=(",", ":"))
            )
        )
        # Get the inserted ID
        row = await self.fetchone("SELECT last_insert_rowid() as id")
        return row["id"]

    async def get_face_embeddings_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all face embeddings for a user"""
        rows = await self.fetchall("SELECT * FROM face_embeddings WHERE user_id=?", (user_id,))
        embeddings = []
        for r in rows:
            embeddings.append({
                "id": r["id"],
                "user_id": r["user_id"],
                "embedding": r["embedding"],  # Keep as bytes for numpy conversion
                "video_path": r["video_path"],
                "frame_count": r["frame_count"],
                "created_at": r["created_at"],
                "metadata": json.loads(r["metadata"]) if r["metadata"] else {}
            })
        return embeddings

    async def get_all_face_embeddings(self) -> List[Dict[str, Any]]:
        """Get all face embeddings (for verification against all users)"""
        rows = await self.fetchall("SELECT * FROM face_embeddings ORDER BY created_at DESC")
        embeddings = []
        for r in rows:
            embeddings.append({
                "id": r["id"],
                "user_id": r["user_id"],
                "embedding": r["embedding"],  # Keep as bytes for numpy conversion
                "video_path": r["video_path"],
                "frame_count": r["frame_count"],
                "created_at": r["created_at"],
                "metadata": json.loads(r["metadata"]) if r["metadata"] else {}
            })
        return embeddings

    async def delete_face_embeddings_for_user(self, user_id: str) -> bool:
        """Delete all face embeddings for a user"""
        await self.exec("DELETE FROM face_embeddings WHERE user_id=?", (user_id,))
        return True


# Export a singleton used by main.py
DB = Database()  # will use config-provided path by default
