"""
Database storage layer for SplitSmart server.
Manages SQLite database for users and ledger entries.
"""

import sqlite3
import os
from typing import Optional, List, Dict, Any
from datetime import datetime

from shared.constants import DB_FILE, DATA_DIR


class Storage:
    """SQLite database manager for SplitSmart."""
    
    def __init__(self, db_path: str = DB_FILE):
        """
        Initialize storage.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._ensure_data_dir()
        self._init_database()
    
    def _ensure_data_dir(self):
        """Ensure data directory exists."""
        os.makedirs(DATA_DIR, exist_ok=True)
    
    def _init_database(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                password_hash TEXT,
                counter INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Add password_hash column if it doesn't exist (for existing databases)
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Ledger table (Blockchain structure)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_height INTEGER NOT NULL,
                user_id TEXT NOT NULL,
                payer TEXT NOT NULL,
                amount REAL NOT NULL,
                description TEXT,
                timestamp TEXT NOT NULL,
                counter INTEGER NOT NULL,
                signature TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                merkle_root TEXT,
                block_hash TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        # Add blockchain columns if they don't exist (for existing databases)
        try:
            cursor.execute("ALTER TABLE ledger ADD COLUMN block_height INTEGER DEFAULT 0")
            cursor.execute("ALTER TABLE ledger ADD COLUMN merkle_root TEXT")
            cursor.execute("ALTER TABLE ledger ADD COLUMN block_hash TEXT")
        except sqlite3.OperationalError:
            pass  # Columns already exist
        
        # Server metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS server_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
    
    def register_user(self, user_id: str, public_key: str, password_hash: Optional[str] = None) -> bool:
        """
        Register a new user.
        
        Args:
            user_id: User identifier
            public_key: User's public key (PEM format)
            password_hash: Hashed password (optional, for password-based auth)
            
        Returns:
            True if successful, False if user already exists
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (user_id, public_key, password_hash, counter) VALUES (?, ?, ?, ?)",
                (user_id, public_key, password_hash, 0)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            if conn:
                conn.close()
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user information.
        
        Args:
            user_id: User identifier
            
        Returns:
            User dictionary or None if not found
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT user_id, public_key, password_hash, counter, created_at FROM users WHERE user_id = ?",
                (user_id,)
            )
            row = cursor.fetchone()
        finally:
            conn.close()
        
        if row:
            return {
                "user_id": row[0],
                "public_key": row[1],
                "password_hash": row[2] if len(row) > 2 else None,
                "counter": row[3] if len(row) > 3 else row[2],
                "created_at": row[4] if len(row) > 4 else row[3]
            }
        return None
    
    def get_user_password_hash(self, user_id: str) -> Optional[str]:
        """
        Get user's password hash.
        
        Args:
            user_id: User identifier
            
        Returns:
            Password hash or None if not found
        """
        user = self.get_user(user_id)
        return user.get("password_hash") if user else None
    
    def verify_user_password(self, user_id: str, password: str) -> bool:
        """
        Verify user password.
        
        Args:
            user_id: User identifier
            password: Plain text password
            
        Returns:
            True if password is correct, False otherwise
        """
        import bcrypt
        password_hash = self.get_user_password_hash(user_id)
        if not password_hash:
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False
    
    def get_user_public_key(self, user_id: str) -> Optional[str]:
        """
        Get user's public key.
        
        Args:
            user_id: User identifier
            
        Returns:
            Public key (PEM format) or None
        """
        user = self.get_user(user_id)
        return user["public_key"] if user else None
    
    def get_user_counter(self, user_id: str) -> Optional[int]:
        """
        Get user's current counter value.
        
        Args:
            user_id: User identifier
            
        Returns:
            Counter value or None if user not found
        """
        user = self.get_user(user_id)
        return user["counter"] if user else None
    
    def update_user_counter(self, user_id: str, new_counter: int) -> bool:
        """
        Update user's counter value.
        
        Args:
            user_id: User identifier
            new_counter: New counter value
            
        Returns:
            True if successful
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET counter = ? WHERE user_id = ?",
                (new_counter, user_id)
            )
            conn.commit()
            success = cursor.rowcount > 0
            return success
        finally:
            conn.close()
    
    def add_ledger_entry(self, user_id: str, payer: str, amount: float,
                        description: str, timestamp: str, counter: int,
                        signature: str, prev_hash: str, entry_hash: str,
                        block_height: int = 0, merkle_root: Optional[str] = None,
                        block_hash: Optional[str] = None) -> Optional[int]:
        """
        Add entry to blockchain ledger.
        
        Args:
            user_id: User who created the entry
            payer: User who paid
            amount: Amount paid
            description: Expense description
            timestamp: ISO timestamp
            counter: Counter value
            signature: User's signature
            prev_hash: Previous entry hash
            entry_hash: This entry's hash
            block_height: Block height/number
            merkle_root: Merkle root hash
            block_hash: Block hash
            
        Returns:
            Entry ID if successful, None otherwise
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ledger 
                (user_id, payer, amount, description, timestamp, counter, signature, 
                 prev_hash, entry_hash, block_height, merkle_root, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, payer, amount, description, timestamp, counter, signature, 
                  prev_hash, entry_hash, block_height, merkle_root, block_hash))
            entry_id = cursor.lastrowid
            conn.commit()
            return entry_id
        except Exception as e:
            print(f"Error adding ledger entry: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    def get_ledger_entries(self) -> List[Dict[str, Any]]:
        """
        Get all ledger entries.
        
        Returns:
            List of ledger entry dictionaries
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, block_height, user_id, payer, amount, description, timestamp, 
                       counter, signature, prev_hash, entry_hash, merkle_root, block_hash
                FROM ledger
                ORDER BY id ASC
            """)
            rows = cursor.fetchall()
        finally:
            conn.close()
        
        entries = []
        for row in rows:
            entry = {
                "id": row[0],
                "block_height": row[1] if len(row) > 1 else 0,
                "user_id": row[2] if len(row) > 2 else row[1],
                "payer": row[3] if len(row) > 3 else row[2],
                "amount": row[4] if len(row) > 4 else row[3],
                "description": row[5] if len(row) > 5 else row[4],
                "timestamp": row[6] if len(row) > 6 else row[5],
                "counter": row[7] if len(row) > 7 else row[6],
                "signature": row[8] if len(row) > 8 else row[7],
                "prev_hash": row[9] if len(row) > 9 else row[8],
                "entry_hash": row[10] if len(row) > 10 else row[9]
            }
            # Add blockchain fields if available
            if len(row) > 11:
                entry["merkle_root"] = row[11]
            if len(row) > 12:
                entry["block_hash"] = row[12]
            entries.append(entry)
        return entries
    
    def get_last_ledger_entry(self) -> Optional[Dict[str, Any]]:
        """
        Get the most recent ledger entry.
        
        Returns:
            Last entry dictionary or None if ledger is empty
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, block_height, user_id, payer, amount, description, timestamp,
                       counter, signature, prev_hash, entry_hash, merkle_root, block_hash
                FROM ledger
                ORDER BY id DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
        finally:
            conn.close()
        
        if row:
            entry = {
                "id": row[0],
                "block_height": row[1] if len(row) > 1 else 0,
                "user_id": row[2] if len(row) > 2 else row[1],
                "payer": row[3] if len(row) > 3 else row[2],
                "amount": row[4] if len(row) > 4 else row[3],
                "description": row[5] if len(row) > 5 else row[4],
                "timestamp": row[6] if len(row) > 6 else row[5],
                "counter": row[7] if len(row) > 7 else row[6],
                "signature": row[8] if len(row) > 8 else row[7],
                "prev_hash": row[9] if len(row) > 9 else row[8],
                "entry_hash": row[10] if len(row) > 10 else row[9]
            }
            if len(row) > 11:
                entry["merkle_root"] = row[11]
            if len(row) > 12:
                entry["block_hash"] = row[12]
            return entry
        return None
    
    def get_metadata(self, key: str) -> Optional[str]:
        """
        Get server metadata value.
        
        Args:
            key: Metadata key
            
        Returns:
            Value or None
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM server_metadata WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            conn.close()
    
    def set_metadata(self, key: str, value: str):
        """
        Set server metadata value.
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO server_metadata (key, value)
                VALUES (?, ?)
            """, (key, value))
            conn.commit()
        finally:
            conn.close()
    
    def list_users(self) -> List[str]:
        """
        Get list of all registered users.
        
        Returns:
            List of user IDs
        """
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM users ORDER BY user_id")
            rows = cursor.fetchall()
            return [row[0] for row in rows]
        finally:
            conn.close()
