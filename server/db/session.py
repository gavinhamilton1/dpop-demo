# server/db.py
from __future__ import annotations
import json, asyncio, time, logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List
from server.utils.helpers import now
import aiosqlite
from server.core.config import load_settings
_SETTINGS = load_settings()


log = logging.getLogger(__name__)

class SessionDB:
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
          bound_username TEXT,                  -- Username bound to this device (set after first auth)
          bik_jkt TEXT,                         -- Browser Identity Key Thumbprint
          bik_jwk TEXT,                  -- BIK public key (JSON)
          signal_data TEXT,                     -- Device fingerprint/signal data (JSON)
          first_seen INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),          -- Unix timestamp of first device registration
          last_seen INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),           -- Unix timestamp of last activity
          created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),          -- Unix timestamp of record creation
          updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))           -- Unix timestamp of last update
        );
        
        -- Add bound_username column to existing devices table if it doesn't exist
        -- This is a migration for existing databases
        """)
        
        # Check if bound_username column exists, if not add it
        try:
            await self.exec("SELECT bound_username FROM devices LIMIT 1", ())
        except:
            log.info("Adding bound_username column to devices table...")
            await self.exec("ALTER TABLE devices ADD COLUMN bound_username TEXT", ())
            log.info("bound_username column added successfully")
        
        await self.execscript("""

        CREATE TABLE IF NOT EXISTS sessions (
          _session_id TEXT PRIMARY KEY,          -- Unique session identifier
          session_status TEXT NOT NULL DEFAULT 'ACTIVE'
                CHECK (session_status IN ('NEW', 'ACTIVE', 'EXPIRED', 'TERMINATED')),
          _x_x_csrf_token TEXT,             -- CSRF protection token
          _x_dpop_nonce TEXT,             -- DPoP nonce
          _x_dpop_bind TEXT,             -- DPoP bind token
          _access_token TEXT,           -- Access token
          _refresh_token TEXT,          -- Refresh token
          _id_token TEXT,               -- ID token
          signal_data TEXT,                 -- Signal data
          signal_hash TEXT,                 -- Signal hash
          dpop_jkt TEXT,                        -- DPoP key thumbprint
          dpop_jwk TEXT,                 -- DPoP public key (JSON)
          session_flag TEXT NOT NULL DEFAULT 'GREEN'
                CHECK (session_flag IN ('RED', 'AMBER', 'GREEN')),
          session_flag_comment TEXT,       -- Session flag comment
          auth_method TEXT,             -- Authentication method
          auth_status TEXT,             -- Authentication status
          auth_username TEXT,           -- Authentication username
          device_id TEXT,              -- Foreign key to devices.device_id
          device_type TEXT,            -- Device type (mobile, desktop, tablet)
          state TEXT,                  -- 'pending-bind', 'bound-bik', 'bound', 'authenticated'
          dpop_bind_expires_at INTEGER,              -- Binding token expiration timestamp
          client_ip TEXT,                   -- Client IP address
          created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),              -- Unix timestamp of session creation
          updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),          -- Unix timestamp of last session update
          expires_at INTEGER,                   -- Session expiration timestamp
          geolocation TEXT,                   -- Geolocation data
          linked_session_id TEXT,           -- ID of linked session (mobile<->desktop)
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
        
        CREATE TABLE IF NOT EXISTS passkeys (
          principal TEXT NOT NULL,
          cred_id   TEXT PRIMARY KEY,
          public_key_jwk TEXT NOT NULL, -- JSON
          sign_count INTEGER NOT NULL DEFAULT 0,
          aaguid TEXT,
          transports TEXT,              -- JSON array
          device_type TEXT,             -- Device type (desktop, mobile, tablet) - tracks where passkey was created
          usage_count INTEGER NOT NULL DEFAULT 0, -- Server-side counter for actual usage
          created_at INTEGER NOT NULL
        );
        -- Optional index for frequent lookups
        CREATE INDEX IF NOT EXISTS idx_passkeys_principal ON passkeys(principal);

        CREATE TABLE IF NOT EXISTS links (
          id TEXT PRIMARY KEY,
          owner_sid TEXT NOT NULL,
          status TEXT NOT NULL,         -- pending|scanned|completed
          principal TEXT,
          expires_at INTEGER NOT NULL,
          applied INTEGER NOT NULL DEFAULT 0
        );
        
        """)
        
        # Check if usage_count column exists in passkeys table, if not add it
        try:
            await self.exec("SELECT usage_count FROM passkeys LIMIT 1", ())
        except:
            log.info("Adding usage_count column to passkeys table...")
            await self.exec("ALTER TABLE passkeys ADD COLUMN usage_count INTEGER NOT NULL DEFAULT 0", ())
            log.info("usage_count column added successfully")

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
                """INSERT INTO devices(device_id, device_type, bound_username, bik_jkt, bik_jwk, signal_data, first_seen, 
                                    last_seen, created_at, updated_at) 
                    VALUES(?,?,?,?,?,?,?,?,?,?) """,
                    (device_id, data.get("device_type"), data.get("bound_username"), data.get("bik_jkt"), data.get("bik_jwk"), 
                     data.get("signal_data"), now(), now(), now(), now())
            )
    
    async def bind_device_to_user(self, device_id: str, username: str) -> bool:
        """Bind a device to a username after first successful authentication"""
        log.info(f"Binding device {device_id} to username: {username}")
        
        # Check if device exists
        device = await self.get_device(device_id)
        if not device:
            log.warning(f"Cannot bind device {device_id} - device not found")
            return False
        
        # Check if device is already bound to a different user
        existing_username = device.get("bound_username")
        if existing_username and existing_username != username:
            log.warning(f"Device {device_id} already bound to '{existing_username}', cannot rebind to '{username}'")
            return False
        
        # Bind the device to the user
        await self.exec(
            "UPDATE devices SET bound_username=?, updated_at=? WHERE device_id=?",
            (username, now(), device_id)
        )
        
        log.info(f"Device {device_id} successfully bound to username: {username}")
        return True


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
                """INSERT INTO sessions(_session_id, session_status, session_flag, session_flag_comment, auth_method, auth_status, auth_username, 
                                        _access_token, _refresh_token, _id_token, device_id, device_type, state, 
                                        dpop_jkt, dpop_jwk, dpop_bind_expires_at, _x_x_csrf_token, 
                                        _x_dpop_nonce, _x_dpop_bind, client_ip, signal_data, signal_hash, created_at, 
                                        updated_at, expires_at, geolocation) 
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) """,
                    (session_id, data.get("session_status"), data.get("session_flag"), data.get("session_flag_comment"), data.get("auth_method"), data.get("auth_status"), data.get("auth_username"), 
                     data.get("_access_token"), data.get("_refresh_token"), data.get("_id_token"), 
                     data.get("device_id"), data.get("device_type"), data.get("state"), data.get("dpop_jkt"), 
                     data.get("dpop_jwk"), data.get("dpop_bind_expires_at"), data.get("_x_x-csrf-token"), 
                     data.get("_x_dpop-nonce"), data.get("_x_dpop-bind"), data.get("client_ip"), 
                     data.get("signal_data"), data.get("signal_hash"), now(), now(), data.get("expires_at"), data.get("geolocation"))
            )

    async def terminate_session(self, session_id: str) -> bool:
        """Terminate session by session_id"""
        log.info("Terminating session: %s", session_id)
        row = await self.fetchone("UPDATE sessions SET session_status='TERMINATED' WHERE _session_id=?", (session_id,))
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
        
        # Convert to dict first
        row_dict = dict(row)
        
        # Check if expired and update both database and dict
        if row_dict["expires_at"] < int(now()):
            await self.exec("UPDATE nonces SET nonce_status='EXPIRED' WHERE session_id=? AND nonce=?", (session_id, nonce))
            row_dict["nonce_status"] = "EXPIRED"
        
        return row_dict 

        
    async def set_nonce(self, session_id: str, nonce: str, nonce_status: str, ttl_sec: int):
        """Set a nonce for a session"""
        if nonce_status not in ["PENDING", "REDEEMED", "EXPIRED", None]:
            raise ValueError("Invalid nonce status")
        
        #if nonce already exists, update it, if not creat a new one
        if await self.get_nonce(session_id, nonce):
            await self.exec("UPDATE nonces SET nonce_status=?, expires_at=? WHERE session_id=? AND nonce=?", (nonce_status, now() + ttl_sec, session_id, nonce))
            return
        else:
            expires_at = now() + ttl_sec
            await self.exec("""INSERT INTO nonces(session_id, nonce, nonce_status, expires_at, created_at) 
                            VALUES(?,?,?,?,?)""", 
                            (session_id, nonce, nonce_status, expires_at, now()))  
        
    async def get_active_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get active user sessions by user_id that are not expired"""
        current_time = now()
        rows = await self.fetchall(
            "SELECT * FROM sessions WHERE auth_username=? AND session_status='ACTIVE' AND expires_at > ?", 
            [user_id, current_time]
        )
        return [dict(row) for row in rows]

    async def expire_old_sessions(self) -> int:
        """Mark expired sessions as TERMINATED and update auth_status to logged_out"""
        current_time = now()
        # Update sessions that have passed their expiration time
        await self.exec(
            """UPDATE sessions 
               SET session_status='TERMINATED', 
                   auth_status='logged_out',
                   state='expired'
               WHERE session_status='ACTIVE' 
               AND expires_at <= ?""",
            [current_time]
        )
        # Return count of affected rows (if available)
        return 0  # SQLite doesn't easily return affected row count in this setup

    async def get_session_history(self, authenticated_username: str, created_at: int) -> List[Dict[str, Any]]:
        """Get session history for an authenticated user with linked session info"""
        rows = await self.fetchall(
            """SELECT 
                s.*,
                linked_devices.device_type as linked_device_type,
                linked_devices.bound_username as linked_bound_username,
                linked.created_at as linked_created_at,
                linked.auth_username as linked_auth_username
               FROM sessions s
               LEFT JOIN sessions linked ON s.linked_session_id = linked._session_id
               LEFT JOIN devices linked_devices ON linked.device_id = linked_devices.device_id
               WHERE s.auth_username=? AND s.created_at > ? 
               ORDER BY s.created_at DESC""", 
            [authenticated_username, created_at]
        )
        # Filter out sessions where linked device belongs to a different user
        filtered_rows = []
        for row in rows:
            row_dict = dict(row)
            # If there's a linked device, verify it belongs to the same user or is unbound
            if row_dict.get('linked_bound_username') and row_dict.get('linked_bound_username') != authenticated_username:
                log.warning(f"Filtering out session with mismatched linked device - Session user: {authenticated_username}, Linked device user: {row_dict.get('linked_bound_username')}")
                # Remove the linked session info to avoid showing cross-user data
                row_dict['linked_session_id'] = None
                row_dict['linked_device_type'] = None
                row_dict['linked_created_at'] = None
            filtered_rows.append(row_dict)
        return filtered_rows


# --- Passkeys

    async def pk_get_for_principal(self, principal: str) -> List[Dict[str, Any]]:
        rows = await self.fetchall("SELECT * FROM passkeys WHERE principal=?", (principal,))
        out = []
        for r in rows:
            # Handle usage_count with fallback for backwards compatibility
            try:
                usage_count = r["usage_count"]
            except (KeyError, IndexError):
                usage_count = 0
            
            out.append({
                "principal": r["principal"],
                "cred_id": r["cred_id"],
                "public_key_jwk": json.loads(r["public_key_jwk"]),
                "sign_count": r["sign_count"],
                "aaguid": r["aaguid"],
                "transports": json.loads(r["transports"]) if r["transports"] else [],
                "device_type": r["device_type"],
                "usage_count": usage_count,
                "created_at": r["created_at"],
            })
        return out

    async def pk_upsert(self, principal: str, rec: Dict[str, Any]) -> None:
        await self.exec(
            """INSERT INTO passkeys(principal, cred_id, public_key_jwk, sign_count, aaguid, transports, device_type, usage_count, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(cred_id) DO UPDATE SET
                 principal=excluded.principal,
                 public_key_jwk=excluded.public_key_jwk,
                 sign_count=excluded.sign_count,
                 aaguid=excluded.aaguid,
                 transports=excluded.transports,
                 device_type=excluded.device_type
                 -- Note: usage_count is NOT updated here; use pk_increment_usage() instead""",
            (
                principal,
                rec["cred_id"],
                json.dumps(rec["public_key_jwk"], separators=(",", ":")),
                int(rec.get("sign_count") or 0),
                rec.get("aaguid"),
                json.dumps(rec.get("transports") or [], separators=(",", ":")),
                rec.get("device_type"),
                int(rec.get("usage_count") or 0),
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
            "device_type": r["device_type"],
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
            "device_type": r["device_type"],
            "created_at": r["created_at"],
        }
        return r["principal"], rec

    async def pk_update_sign_count(self, cred_id: str, new_count: int):
        await self.exec("UPDATE passkeys SET sign_count=? WHERE cred_id=?", (int(new_count), cred_id))

    async def pk_remove(self, principal: str, cred_id: str) -> bool:
        await self.exec("DELETE FROM passkeys WHERE principal=? AND cred_id=?", (principal, cred_id))
        # We can't easily tell rows affected with aiosqlite here without extra work; return True for simplicity
        return True
    
    async def pk_increment_usage(self, cred_id: str) -> None:
        """Increment the usage counter for a passkey"""
        log.info(f"Incrementing usage count for credential: {cred_id[:20]}...")
        await self.exec(
            "UPDATE passkeys SET usage_count = usage_count + 1 WHERE cred_id=?",
            (cred_id,)
        )
        # Verify the update
        row = await self.fetchone("SELECT usage_count FROM passkeys WHERE cred_id=?", (cred_id,))
        if row:
            log.info(f"Updated usage count for credential {cred_id[:20]}..., new count: {row['usage_count']}")
        else:
            log.warning(f"Failed to find credential {cred_id[:20]}... after increment")

    # --- Passkey Challenge Management ---
    
    async def store_webauthn_challenge(self, session_id: str, challenge_type: str, challenge: str, expires_at: int) -> None:
        """Store WebAuthn challenge for validation"""
        # Store in nonces table for simplicity (challenges are like nonces)
        await self.exec(
            "INSERT INTO nonces(session_id, nonce, nonce_status, expires_at, created_at) VALUES(?,?,?,?,?)",
            (session_id, f"{challenge_type}:{challenge}", "PENDING", expires_at, now())
        )
    
    async def validate_webauthn_challenge(self, session_id: str, challenge_type: str, challenge: str) -> bool:
        """Validate WebAuthn challenge"""
        nonce = f"{challenge_type}:{challenge}"
        row = await self.fetchone(
            "SELECT * FROM nonces WHERE session_id=? AND nonce=? AND nonce_status='PENDING'",
            (session_id, nonce)
        )
        if not row:
            return False
        
        # Check if expired
        if row["expires_at"] < now():
            await self.exec("UPDATE nonces SET nonce_status='EXPIRED' WHERE session_id=? AND nonce=?", (session_id, nonce))
            return False
        
        # Mark as redeemed
        await self.exec("UPDATE nonces SET nonce_status='REDEEMED' WHERE session_id=? AND nonce=?", (session_id, nonce))
        return True
    
    async def update_session_auth_status(self, session_id: str, auth_method: str, auth_status: str, username: str = None) -> None:
        """Update session authentication method, status, and username"""
        if username:
            await self.exec(
                "UPDATE sessions SET auth_method=?, auth_status=?, auth_username=? WHERE _session_id=?",
                (auth_method, auth_status, username, session_id)
            )
        else:
            await self.exec(
                "UPDATE sessions SET auth_method=?, auth_status=? WHERE _session_id=?",
                (auth_method, auth_status, session_id)
            )

    async def logout_session(self, session_id: str) -> None:
        """Logout session by setting auth_status to logged_out and session_status to TERMINATED"""
        log.info("Logging out session in database: %s", session_id)
        await self.exec(
            "UPDATE sessions SET auth_status=?, session_status=? WHERE _session_id=?",
            ("logged_out", "TERMINATED", session_id)
        )
    
    async def link_sessions(self, session_id_1: str, session_id_2: str) -> None:
        """Create bidirectional link between two sessions (e.g., desktop and mobile)"""
        log.info(f"Linking sessions: {session_id_1} <-> {session_id_2}")
        # Update both sessions to reference each other
        await self.exec(
            "UPDATE sessions SET linked_session_id=? WHERE _session_id=?",
            (session_id_2, session_id_1)
        )
        await self.exec(
            "UPDATE sessions SET linked_session_id=? WHERE _session_id=?",
            (session_id_1, session_id_2)
        )
    
    async def get_user_devices(self, username: str) -> List[Dict[str, Any]]:
        """Get all devices registered by a user (only devices bound to this user)"""
        rows = await self.fetchall(
            """SELECT 
                d.*,
                MAX(s.updated_at) as last_used,
                COUNT(DISTINCT s._session_id) as session_count
               FROM devices d
               LEFT JOIN sessions s ON d.device_id = s.device_id AND s.auth_username = ?
               WHERE (d.bound_username = ? OR d.bound_username IS NULL) 
                 AND d.bik_jkt IS NOT NULL
               GROUP BY d.device_id
               ORDER BY last_used DESC""",
            [username, username]
        )
        return [dict(row) for row in rows]
    
    async def remove_device(self, device_id: str, username: str) -> bool:
        """Remove a device for a specific user (unregister BIK)"""
        # Verify the device belongs to the user
        rows = await self.fetchall(
            "SELECT COUNT(*) as count FROM sessions WHERE device_id=? AND auth_username=?",
            [device_id, username]
        )
        
        if rows and rows[0]['count'] > 0:
            # Instead of deleting, clear the BIK data to "unregister" the device
            # This preserves session history while removing the device's authentication capability
            await self.exec(
                "UPDATE devices SET bik_jkt=NULL, bik_jwk=NULL, updated_at=? WHERE device_id=?", 
                [now(), device_id]
            )
            log.info(f"Unregistered device {device_id} for user {username} (cleared BIK)")
            return True
        else:
            log.warning(f"Device {device_id} not found or doesn't belong to user {username}")
            return False


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
SessionDB = SessionDB(_SETTINGS.db_path)
