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
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                counter INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Ledger table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                payer TEXT NOT NULL,
                amount REAL NOT NULL,
                description TEXT,
                timestamp TEXT NOT NULL,
                counter INTEGER NOT NULL,
                signature TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        # Server metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS server_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
    
    def register_user(self, user_id: str, public_key: str) -> bool:
        """
        Register a new user.
        
        Args:
            user_id: User identifier
            public_key: User's public key (PEM format)
            
        Returns:
            True if successful, False if user already exists
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (user_id, public_key, counter) VALUES (?, ?, ?)",
                (user_id, public_key, 0)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user information.
        
        Args:
            user_id: User identifier
            
        Returns:
            User dictionary or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id, public_key, counter, created_at FROM users WHERE user_id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                "user_id": row[0],
                "public_key": row[1],
                "counter": row[2],
                "created_at": row[3]
            }
        return None
    
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
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET counter = ? WHERE user_id = ?",
            (new_counter, user_id)
        )
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        return success
    
    def add_ledger_entry(self, user_id: str, payer: str, amount: float,
                        description: str, timestamp: str, counter: int,
                        signature: str, prev_hash: str, entry_hash: str) -> Optional[int]:
        """
        Add entry to ledger.
        
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
            
        Returns:
            Entry ID if successful, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ledger 
                (user_id, payer, amount, description, timestamp, counter, signature, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, payer, amount, description, timestamp, counter, signature, prev_hash, entry_hash))
            entry_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return entry_id
        except Exception as e:
            print(f"Error adding ledger entry: {e}")
            return None
    
    def get_ledger_entries(self) -> List[Dict[str, Any]]:
        """
        Get all ledger entries.
        
        Returns:
            List of ledger entry dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, payer, amount, description, timestamp, 
                   counter, signature, prev_hash, entry_hash
            FROM ledger
            ORDER BY id ASC
        """)
        rows = cursor.fetchall()
        conn.close()
        
        entries = []
        for row in rows:
            entries.append({
                "id": row[0],
                "user_id": row[1],
                "payer": row[2],
                "amount": row[3],
                "description": row[4],
                "timestamp": row[5],
                "counter": row[6],
                "signature": row[7],
                "prev_hash": row[8],
                "entry_hash": row[9]
            })
        return entries
    
    def get_last_ledger_entry(self) -> Optional[Dict[str, Any]]:
        """
        Get the most recent ledger entry.
        
        Returns:
            Last entry dictionary or None if ledger is empty
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, payer, amount, description, timestamp,
                   counter, signature, prev_hash, entry_hash
            FROM ledger
            ORDER BY id DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                "id": row[0],
                "user_id": row[1],
                "payer": row[2],
                "amount": row[3],
                "description": row[4],
                "timestamp": row[5],
                "counter": row[6],
                "signature": row[7],
                "prev_hash": row[8],
                "entry_hash": row[9]
            }
        return None
    
    def get_metadata(self, key: str) -> Optional[str]:
        """
        Get server metadata value.
        
        Args:
            key: Metadata key
            
        Returns:
            Value or None
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM server_metadata WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    
    def set_metadata(self, key: str, value: str):
        """
        Set server metadata value.
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO server_metadata (key, value)
            VALUES (?, ?)
        """, (key, value))
        conn.commit()
        conn.close()
    
    def list_users(self) -> List[str]:
        """
        Get list of all registered users.
        
        Returns:
            List of user IDs
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users ORDER BY user_id")
        rows = cursor.fetchall()
        conn.close()
        return [row[0] for row in rows]
