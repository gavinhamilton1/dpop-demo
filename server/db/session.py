# server/db.py
from __future__ import annotations
import json, asyncio, time, logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List
from server.utils.helpers import now
import aiosqlite
from server.core.config import load_settings
_SETTINGS = load_settings()


log = logging.getLogger("dpop-fun")

class Database:
    _instance = None
    _initialized = False
    
    def __new__(cls, path: str = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, path: str = None):
        if self._initialized:
            return
            
        # Prefer explicit path, else config file path
        self.path = str(Path(path)) if path else None
        if self.path:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()
        self._initialized = True

    async def init(self, path: str = None):
        """
        Initialize (or re-initialize) the DB connection.
        If `path` is provided and differs from the current path, the connection is reopened.
        """
        if path:
            if path != self.path:
                # Re-point and reopen if needed
                await self.close()
                self.path = str(Path(path))
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
          device_type TEXT,            -- 'browser' or 'mobile'
          bik_jkt TEXT,                         -- Browser Identity Key Thumbprint
          bik_jwk TEXT,                  -- BIK public key (JSON)
          signal_data TEXT,                     -- Device fingerprint/signal data (JSON)
          first_seen INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),          -- Unix timestamp of first device registration
          last_seen INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),           -- Unix timestamp of last activity
          created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),          -- Unix timestamp of record creation
          updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))           -- Unix timestamp of last update
        );

        CREATE TABLE IF NOT EXISTS sessions (
          _session_id TEXT PRIMARY KEY,          -- Unique session identifier
          _session_status TEXT NOT NULL DEFAULT 'ACTIVE'
                CHECK (_session_status IN ('ACTIVE', 'EXPIRED', 'TERMINATED')),
          auth_method TEXT,             -- Authentication method
          auth_status TEXT,             -- Authentication status
          auth_username TEXT,           -- Authentication username
          _access_token TEXT,           -- Access token
          _refresh_token TEXT,          -- Refresh token
          _id_token TEXT,               -- ID token
          device_id TEXT,              -- Foreign key to devices.device_id
          user_id TEXT,                         -- User identifier (NULL if not authenticated)
          state TEXT,                  -- 'pending-bind', 'bound-bik', 'bound', 'authenticated'
          dpop_jkt TEXT,                        -- DPoP key thumbprint
          dpop_jwk TEXT,                 -- DPoP public key (JSON)
          dpop_bind_expires_at INTEGER,              -- Binding token expiration timestamp
          _x_x_csrf_token TEXT,             -- CSRF protection token
          _x_dpop_nonce TEXT,             -- DPoP nonce
          _x_dpop_bind TEXT,             -- DPoP bind token
          client_ip TEXT,                   -- Client IP address
          signal_data TEXT,                 -- Signal data
          created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),              -- Unix timestamp of session creation
          updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),          -- Unix timestamp of last session update
          expires_at INTEGER,                   -- Session expiration timestamp
          geolocation TEXT,                   -- Geolocation data
          FOREIGN KEY (device_id) REFERENCES devices(device_id)
        );

        CREATE TABLE IF NOT EXISTS nonces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        nonce TEXT NOT NULL UNIQUE,                                -- Nonce value must be globally unique
        nonce_status TEXT NOT NULL DEFAULT 'PENDING' 
            CHECK (nonce_status IN ('PENDING', 'REDEEMED', 'EXPIRED')),
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS nonces_nonce_idx ON nonces (nonce);
        CREATE INDEX IF NOT EXISTS nonces_expires_at_idx ON nonces (expires_at);

        CREATE TABLE IF NOT EXISTS jtis (
          session_id TEXT NOT NULL,             -- Foreign key to sessions.session_id
          jti TEXT NOT NULL,                    -- JWT ID for replay protection
          expires_at INTEGER NOT NULL,          -- JTI expiration timestamp
          created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),          -- Unix timestamp of JTI creation
          PRIMARY KEY (session_id, jti),
          FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );
        """)

    async def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device by device_id"""
        row = await self.fetchone("SELECT * FROM devices WHERE device_id=?", (device_id,))
        if not row:
            return None
        return dict(row)
    
    async def set_device(self, device_id: str, data: Dict[str, Any]):        
        device = await self.get_device(device_id)
        if device:
            raise ValueError("Device already exists")
        else:            
            await self.exec(
                """INSERT INTO devices(device_id, device_type, bik_jkt, bik_jwk, signal_data, first_seen, 
                                    last_seen, created_at, updated_at) 
                    VALUES(?,?,?,?,?,?,?,?,?) """,
                    (device_id, data.get("device_type"), data.get("bik_jkt"), data.get("bik_jwk"), 
                     data.get("signal_data"), now(), now(), now(), now())
            )


    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session by session_id"""
        row = await self.fetchone("SELECT * FROM sessions WHERE _session_id=?", (session_id,))
        if not row:
            return None
        return dict(row)

    async def set_session(self, session_id: str, data: Dict[str, Any]):
        session = await self.get_session(session_id)
        if session:
            raise ValueError("Session already exists")
        else:
            await self.exec(
                """INSERT INTO sessions(_session_id, _session_status, auth_method, auth_status, auth_username, 
                                        _access_token, _refresh_token, _id_token, device_id, user_id, state, 
                                        dpop_jkt, dpop_jwk, dpop_bind_expires_at, _x_x_csrf_token, 
                                        _x_dpop_nonce, _x_dpop_bind, client_ip, signal_data, created_at, 
                                        updated_at, expires_at, geolocation) 
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) """,
                    (session_id, data.get("_session_status"), data.get("auth_method"), data.get("auth_status"), data.get("auth_username"), 
                     data.get("_access_token"), data.get("_refresh_token"), data.get("_id_token"), 
                     data.get("device_id"), data.get("user_id"), data.get("state"), data.get("dpop_jkt"), 
                     data.get("dpop_jwk"), data.get("dpop_bind_expires_at"), data.get("_x_x-csrf-token"), 
                     data.get("_x_dpop-nonce"), data.get("_x_dpop-bind"), data.get("client_ip"), 
                     data.get("signal_data"), now(), now(), data.get("expires_at"), data.get("geolocation"))
            )

    async def terminate_session(self, session_id: str) -> bool:
        """Terminate session by session_id"""
        log.info("Terminating session: %s", session_id)
        row = await self.fetchone("UPDATE sessions SET _session_status='TERMINATED' WHERE _session_id=?", (session_id,))
        if not row:
            return False
        return True



    async def revoke_session(self, session_id: str):
        """Delete a session from the database"""
        await self.exec("UPDATE sessions SET state='revoked' WHERE _session_id=?", (session_id,))
        
        

    async def get_nonce(self, session_id: str, nonce: str) -> Optional[Dict[str, Any]]:
        """Get nonce by session_id and nonce"""
        row = await self.fetchone("SELECT * FROM nonces WHERE session_id=? AND nonce=?", (session_id, nonce))
        if not row:
            return None
        if row.get("expires_at") < int(time.time()):
            await self.exec("UPDATE nonces SET nonce_status='EXPIRED' WHERE session_id=? AND nonce=?", (session_id, nonce))
            row["nonce_status"] = "EXPIRED"
        return dict(row) 

    
    async def set_nonce(self, session_id: str, nonce: str, nonce_status: str, ttl_sec: int):
        """Set a nonce for a session"""
        if nonce_status not in ["PENDING", "REDEEMED", "EXPIRED", None]:
            raise ValueError("Invalid nonce status")
        
        now = int(time.time())
        expires_at = now + ttl_sec
        await self.exec("""INSERT INTO nonces(session_id, nonce, nonce_status, expires_at, created_at) 
                        VALUES(?,?,?,?,?)""", 
                        (session_id, nonce, nonce_status, expires_at, now))  
        
        


# --- low-level helpers -------------------------------------------------

    async def close(self):
        if self._conn:
            await self._conn.close()
            self._conn = None
            
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

# Create singleton instance
SessionDB = Database(_SETTINGS.db_path)
