# server/db.py
from __future__ import annotations
import json, asyncio, time, logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

import aiosqlite
from server.core.config import load_settings

# Load config once at import
_SETTINGS = load_settings()
# Use config-provided path (fallback to /tmp for Render compatibility)
_DEFAULT_DB_PATH = Path(_SETTINGS.db_path if _SETTINGS.db_path else "/tmp/dpop-fun.db")

# Logger instance
log = logging.getLogger(__name__)
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

        # Create device-centric tables
        await self.execscript("""
        CREATE TABLE IF NOT EXISTS devices (
          device_id TEXT PRIMARY KEY,           -- Browser UUID (unique device identifier)
          device_type TEXT NOT NULL,            -- 'browser' or 'mobile'
          bik_jkt TEXT,                         -- Browser Identity Key Thumbprint
          bik_public_jwk TEXT,                  -- BIK public key (JSON)
          signal_data TEXT,                     -- Device fingerprint/signal data (JSON)
          first_seen INTEGER NOT NULL,          -- Unix timestamp of first device registration
          last_seen INTEGER NOT NULL,           -- Unix timestamp of last activity
          created_at INTEGER NOT NULL,          -- Unix timestamp of record creation
          updated_at INTEGER NOT NULL           -- Unix timestamp of last update
        );

        CREATE TABLE IF NOT EXISTS sessions (
          session_id TEXT PRIMARY KEY,          -- Unique session identifier
          device_id TEXT NOT NULL,              -- Foreign key to devices.device_id
          user_id TEXT,                         -- User identifier (NULL if not authenticated)
          state TEXT NOT NULL,                  -- 'pending-bind', 'bound-bik', 'bound', 'authenticated'
          dpop_jkt TEXT,                        -- DPoP key thumbprint
          dpop_public_jwk TEXT,                 -- DPoP public key (JSON)
          bind_token TEXT,                      -- Current binding token (JWT)
          bind_expires_at INTEGER,              -- Binding token expiration timestamp
          csrf_token TEXT NOT NULL,             -- CSRF protection token
          created_at INTEGER NOT NULL,              -- Unix timestamp of session creation
          updated_at INTEGER NOT NULL,          -- Unix timestamp of last session update
          expires_at INTEGER,                   -- Session expiration timestamp
          FOREIGN KEY (device_id) REFERENCES devices(device_id)
        );

        CREATE TABLE IF NOT EXISTS nonces (
          session_id TEXT NOT NULL,             -- Foreign key to sessions.session_id
          nonce TEXT NOT NULL,                  -- Nonce value
          expires_at INTEGER NOT NULL,          -- Nonce expiration timestamp
          created_at INTEGER NOT NULL,          -- Unix timestamp of nonce creation
          PRIMARY KEY (session_id, nonce),
          FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );

        CREATE TABLE IF NOT EXISTS jtis (
          session_id TEXT NOT NULL,             -- Foreign key to sessions.session_id
          jti TEXT NOT NULL,                    -- JWT ID for replay protection
          expires_at INTEGER NOT NULL,          -- JTI expiration timestamp
          created_at INTEGER NOT NULL,          -- Unix timestamp of JTI creation
          PRIMARY KEY (session_id, jti),
          FOREIGN KEY (session_id) REFERENCES sessions(session_id)
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

        -- Signal/Fingerprint data linked to BIK for cross-session comparison
        CREATE TABLE IF NOT EXISTS signal_data (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          bik_jkt TEXT NOT NULL,
          session_id TEXT NOT NULL,
          device_type TEXT NOT NULL,
          fingerprint_data TEXT NOT NULL,  -- JSON
          ip_address TEXT,
          geolocation_data TEXT,          -- JSON
          bik_authenticated INTEGER DEFAULT 0,  -- 0 = not authenticated, 1 = authenticated
          authenticated_user TEXT,        -- username when authenticated
          authentication_method TEXT,     -- 'desktop passkey', 'face verify', 'mobile passkey'
          authentication_timestamp INTEGER, -- when authentication occurred
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );

        -- Index for efficient BIK-based lookups
        CREATE INDEX IF NOT EXISTS idx_signal_data_bik ON signal_data(bik_jkt);
        CREATE INDEX IF NOT EXISTS idx_signal_data_session ON signal_data(session_id);
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

    # Device management methods
    async def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device by device_id"""
        row = await self.fetchone("SELECT * FROM devices WHERE device_id=?", (device_id,))
        if not row:
            return None
        return dict(row)

    async def create_device(self, device_id: str, device_type: str, signal_data: str = None) -> None:
        """Create a new device record"""
        now = int(time.time())
        await self.exec("""
            INSERT INTO devices (device_id, device_type, signal_data, first_seen, last_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (device_id, device_type, signal_data, now, now, now, now))

    async def update_device(self, device_id: str, **updates) -> None:
        """Update device record"""
        updates['updated_at'] = int(time.time())
        set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values()) + [device_id]
        await self.exec(f"UPDATE devices SET {set_clause} WHERE device_id = ?", values)

    # Session management methods
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by session_id"""
        row = await self.fetchone("SELECT * FROM sessions WHERE session_id=?", (session_id,))
        if not row:
            return None
        return dict(row)

    async def create_session(self, session_id: str, device_id: str, csrf_token: str, state: str = "pending-bind") -> None:
        """Create a new session"""
        now = int(time.time())
        await self.exec("""
            INSERT INTO sessions (session_id, device_id, state, csrf_token, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session_id, device_id, state, csrf_token, now, now))

    async def update_session(self, session_id: str, **updates) -> None:
        """Update session record"""
        updates['updated_at'] = int(time.time())
        set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values()) + [session_id]
        await self.exec(f"UPDATE sessions SET {set_clause} WHERE session_id = ?", values)

    async def delete_session(self, session_id: str):
        """Delete a session from the database"""
        await self.exec("DELETE FROM sessions WHERE session_id=?", (session_id,))

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

    async def add_nonce(self, session_id: str, nonce: str, ttl_sec: int):
        """Add a nonce for a session"""
        now = int(time.time())
        expires_at = now + ttl_sec
        await self.exec("INSERT OR REPLACE INTO nonces(session_id, nonce, expires_at, created_at) VALUES(?,?,?,?)",
                        (session_id, nonce, expires_at, now))

    async def nonce_valid(self, session_id: str, nonce: str) -> bool:
        """Check if a nonce is valid for a session"""
        await self.exec("DELETE FROM nonces WHERE expires_at < ?", (int(time.time()),))
        row = await self.fetchone("SELECT 1 FROM nonces WHERE session_id=? AND nonce=?", (session_id, nonce))
        return bool(row)

    async def add_jti(self, session_id: str, jti: str, ttl_sec: int) -> bool:
        """Add a JTI for replay protection"""
        now = int(time.time())
        expires_at = now + ttl_sec
        try:
            await self.exec("INSERT INTO jtis(session_id, jti, expires_at, created_at) VALUES(?,?,?,?)",
                            (session_id, jti, expires_at, now))
            return True
        except Exception:
            # primary key conflict → seen already
            return False

    async def flush(self):
        # Danger: nukes everything (dev tool)
        # Must delete in order to respect foreign key constraints
        await self.execscript("""
          -- Disable foreign key checks temporarily
          PRAGMA foreign_keys=OFF;
          
          -- Delete in reverse dependency order
          DELETE FROM face_embeddings; -- References users
          DELETE FROM links;           -- References sessions
          DELETE FROM nonces;          -- References sessions
          DELETE FROM jtis;          -- References sessions
          DELETE FROM passkeys;        -- No foreign keys
          DELETE FROM sessions;        -- References devices
          DELETE FROM devices;         -- Base table
          
          -- Re-enable foreign key checks
          PRAGMA foreign_keys=ON;
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

    async def get_face_embeddings_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        """Get face embeddings for a specific user"""
        rows = await self.fetchall("SELECT * FROM face_embeddings WHERE user_id=? ORDER BY created_at DESC", (user_id,))
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

    # --- Link management methods ---
    
    async def create_link(self, link_id: str, owner_sid: str, principal: str = None, expires_at: int = None) -> bool:
        """Create a new link record"""
        try:
            await self.exec(
                "INSERT INTO links(id, owner_sid, status, principal, expires_at) VALUES(?, ?, 'pending', ?, ?)",
                (link_id, owner_sid, principal, expires_at)
            )
            return True
        except Exception:
            return False

    async def get_link(self, link_id: str) -> Optional[Dict[str, Any]]:
        """Get a link by ID"""
        row = await self.fetchone(
            "SELECT id, owner_sid, status, principal, expires_at, applied FROM links WHERE id = ?",
            (link_id,)
        )
        if not row:
            return None
        return {
            "id": row["id"],
            "owner_sid": row["owner_sid"],
            "status": row["status"],
            "principal": row["principal"],
            "expires_at": row["expires_at"],
            "applied": bool(row["applied"])
        }

    async def update_link_status(self, link_id: str, status: str) -> bool:
        """Update link status"""
        try:
            await self.exec(
                "UPDATE links SET status = ? WHERE id = ?",
                (status, link_id)
            )
            return True
        except Exception:
            return False

    async def update_link_principal(self, link_id: str, principal: str) -> bool:
        """Update link principal"""
        try:
            await self.exec(
                "UPDATE links SET principal = ? WHERE id = ?",
                (principal, link_id)
            )
            return True
        except Exception:
            return False

    async def mark_link_applied(self, link_id: str) -> bool:
        """Mark link as applied"""
        try:
            await self.exec(
                "UPDATE links SET applied = 1 WHERE id = ?",
                (link_id,)
            )
            return True
        except Exception:
            return False

    async def delete_link(self, link_id: str) -> bool:
        """Delete a link"""
        try:
            await self.exec("DELETE FROM links WHERE id = ?", (link_id,))
            return True
        except Exception:
            return False

    async def delete_links_by_owner(self, owner_sid: str) -> bool:
        """Delete all links for an owner"""
        try:
            await self.exec("DELETE FROM links WHERE owner_sid = ?", (owner_sid,))
            return True
        except Exception:
            return False

    async def cleanup_expired_links(self) -> int:
        """Clean up expired links and return count of deleted links"""
        try:
            result = await self.exec(
                "DELETE FROM links WHERE expires_at < strftime('%s','now')"
            )
            # Get count of deleted rows
            row = await self.fetchone("SELECT changes() as count")
            return row["count"] if row else 0
        except Exception:
            return 0

    # --- Signal Data management methods ---
    
    async def store_signal_data(self, bik_jkt: str, session_id: str, device_type: str, 
                               fingerprint_data: dict, ip_address: str = None, 
                               geolocation_data: dict = None) -> bool:
        """Store signal/fingerprint data linked to BIK"""
        try:
            await self.exec(
                """INSERT INTO signal_data(bik_jkt, session_id, device_type, fingerprint_data, 
                   ip_address, geolocation_data, created_at, updated_at) 
                   VALUES(?, ?, ?, ?, ?, ?, strftime('%s','now'), strftime('%s','now'))""",
                (bik_jkt, session_id, device_type, json.dumps(fingerprint_data, separators=(",", ":")),
                 ip_address, json.dumps(geolocation_data or {}, separators=(",", ":")),)
            )
            return True
        except Exception:
            return False

    async def get_signal_data_by_bik(self, bik_jkt: str) -> List[Dict[str, Any]]:
        """Get all signal data for a BIK"""
        rows = await self.fetchall(
            "SELECT * FROM signal_data WHERE bik_jkt = ? ORDER BY created_at DESC",
            (bik_jkt,)
        )
        signal_data = []
        for r in rows:
            signal_data.append({
                "id": r["id"],
                "bik_jkt": r["bik_jkt"],
                "session_id": r["session_id"],
                "device_type": r["device_type"],
                "fingerprint_data": json.loads(r["fingerprint_data"]),
                "ip_address": r["ip_address"],
                "geolocation_data": json.loads(r["geolocation_data"]) if r["geolocation_data"] else {},
                "created_at": r["created_at"],
                "updated_at": r["updated_at"]
            })
        return signal_data

    async def get_latest_signal_data_by_bik(self, bik_jkt: str) -> Optional[Dict[str, Any]]:
        """Get the most recent signal data for a BIK"""
        row = await self.fetchone(
            "SELECT * FROM signal_data WHERE bik_jkt = ? ORDER BY created_at DESC LIMIT 1",
            (bik_jkt,)
        )
        if not row:
            return None
        return {
            "id": row["id"],
            "bik_jkt": row["bik_jkt"],
            "session_id": row["session_id"],
            "device_type": row["device_type"],
            "fingerprint_data": json.loads(row["fingerprint_data"]),
            "ip_address": row["ip_address"],
            "geolocation_data": json.loads(row["geolocation_data"]) if row["geolocation_data"] else {},
            "created_at": row["created_at"],
            "updated_at": row["updated_at"]
        }

    async def update_signal_data(self, signal_id: int, fingerprint_data: dict, 
                                ip_address: str = None, geolocation_data: dict = None) -> bool:
        """Update existing signal data"""
        try:
            await self.exec(
                """UPDATE signal_data SET fingerprint_data = ?, ip_address = ?, 
                   geolocation_data = ?, updated_at = strftime('%s','now') WHERE id = ?""",
                (json.dumps(fingerprint_data, separators=(",", ":")), ip_address,
                 json.dumps(geolocation_data or {}, separators=(",", ":")), signal_id)
            )
            return True
        except Exception:
            return False

    async def delete_signal_data_by_session(self, session_id: str) -> bool:
        """Delete signal data for a specific session"""
        try:
            await self.exec("DELETE FROM signal_data WHERE session_id = ?", (session_id,))
            return True
        except Exception:
            return False

    async def cleanup_old_signal_data(self, days_old: int = 30) -> int:
        """Clean up signal data older than specified days"""
        try:
            result = await self.exec(
                "DELETE FROM signal_data WHERE created_at < strftime('%s','now') - ?",
                (days_old * 24 * 60 * 60,)
            )
            row = await self.fetchone("SELECT changes() as count")
            return row["count"] if row else 0
        except Exception:
            return 0

    async def mark_bik_authenticated(self, bik_jkt: str, session_id: str, username: str, method: str):
        """Mark a BIK as authenticated in the latest signal_data record, or create one if none exists"""
        timestamp = int(time.time())
        
        # First, try to update the most recent record for this BIK
        result = await self.exec("""
            UPDATE signal_data 
            SET bik_authenticated = 1,
                authenticated_user = ?,
                authentication_method = ?,
                authentication_timestamp = ?,
                updated_at = ?
            WHERE bik_jkt = ? 
            AND id = (
                SELECT id FROM signal_data 
                WHERE bik_jkt = ? 
                ORDER BY created_at DESC 
                LIMIT 1
            )
        """, (username, method, timestamp, timestamp, bik_jkt, bik_jkt))
        
        # Check if any rows were updated
        rows_updated = result.rowcount if hasattr(result, 'rowcount') else 0
        log.info(f"UPDATE query affected {rows_updated} rows for BIK {bik_jkt[:8]}")
        
        if rows_updated == 0:
            # No existing record found, create a new one
            log.info("No existing signal_data record found for BIK %s, creating new authentication record", bik_jkt[:8])
            try:
                await self.exec("""
                    INSERT INTO signal_data (
                        bik_jkt, session_id, device_type, fingerprint_data,
                        ip_address, geolocation_data, created_at, updated_at,
                        bik_authenticated, authenticated_user, authentication_method, authentication_timestamp
                    ) VALUES (?, ?, 'authentication', '{}', NULL, NULL, ?, ?, 1, ?, ?, ?)
                """, (bik_jkt, session_id, timestamp, timestamp, username, method, timestamp))
                log.info("Successfully created new signal_data record for BIK %s authentication", bik_jkt[:8])
            except Exception as e:
                log.error(f"Failed to create signal_data record for BIK {bik_jkt[:8]}: {e}", exc_info=True)
        else:
            log.info("Updated existing signal_data record for BIK %s authentication", bik_jkt[:8])
        
        log.info("Marked BIK %s as authenticated for user %s via %s", bik_jkt[:8], username, method)

    async def is_bik_authenticated(self, bik_jkt: str) -> bool:
        """Check if a BIK has ever been authenticated"""
        log.info(f"Checking if BIK {bik_jkt[:8] if bik_jkt else 'None'} is authenticated")
        result = await self.fetchone("""
            SELECT 1 FROM signal_data 
            WHERE bik_jkt = ? AND bik_authenticated = 1
            LIMIT 1
        """, (bik_jkt,))
        log.info(f"BIK authentication query result: {result}")
        return result is not None

    async def get_bik_authentication_history(self, bik_jkt: str):
        """Get authentication history for a BIK"""
        rows = await self.fetchall("""
            SELECT bik_authenticated, authenticated_user, authentication_method, 
                   authentication_timestamp, created_at, session_id
            FROM signal_data 
            WHERE bik_jkt = ?
            ORDER BY created_at DESC
        """, (bik_jkt,))
        
        # Convert rows to dictionaries
        return [dict(row) for row in rows]

    async def get_authenticated_biks(self):
        """Get all BIKs that have been authenticated"""
        rows = await self.fetchall("""
            SELECT DISTINCT bik_jkt, authenticated_user, authentication_method, 
                   MAX(authentication_timestamp) as last_authenticated
            FROM signal_data 
            WHERE bik_authenticated = 1
            GROUP BY bik_jkt
            ORDER BY last_authenticated DESC
        """)
        
        # Convert rows to dictionaries
        return [dict(row) for row in rows]


# Export a singleton used by main.py
DB = Database()  # will use config-provided path by default
