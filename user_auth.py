"""
User Authentication System
- Bcrypt password hashing
- Login/logout with session management
- SQLite with WAL mode for concurrent access
"""
import sqlite3
import bcrypt

DB_FILE = "users.db"


class UserAuth:
    """Handle user authentication and sessions"""
    
    def __init__(self):
        self.current_user = None
        self._init_database()
    
    def _get_connection(self):
        """Get database connection with WAL mode to prevent locking"""
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    
    def _init_database(self):
        """Initialize users table"""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        print(f"✅ Database initialized: {DB_FILE}")
    
    def _ensure_bytes(self, password_hash):
        """Convert password_hash to bytes if it's a string"""
        return password_hash.encode('utf-8') if isinstance(password_hash, str) else password_hash
    
    def create_account(self, username: str, email: str, password: str) -> tuple[bool, str]:
        """
        Create new user account
        Returns: (success: bool, message: str)
        """
        # Validate
        if len(username) < 3 or len(username) > 20:
            return False, "Username must be 3-20 characters"
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insert to database
        try:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, password_hash)
                )
                conn.commit()
            
            print(f"✅ Account created: {username}")
            return True, "Account created successfully!"
        
        except sqlite3.IntegrityError:
            return False, "Username or email already exists"
        except sqlite3.OperationalError as e:
            return False, "Database is busy. Try again." if "locked" in str(e) else f"Database error: {e}"
        except Exception as e:
            return False, f"Error: {e}"
    
    def login(self, username: str, password: str) -> tuple[bool, str]:
        """
        Verify credentials and login
        Returns: (success: bool, message: str)
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                
                if not result:
                    return False, "Username not found"
                
                password_hash = self._ensure_bytes(result[0])
                
                if bcrypt.checkpw(password.encode('utf-8'), password_hash):
                    self.current_user = username
                    print(f"✅ Login successful: {username}")
                    return True, "Login successful!"
                else:
                    return False, "Wrong password"
        
        except sqlite3.OperationalError as e:
            return False, "Database is busy. Try again." if "locked" in str(e) else f"Database error: {e}"
        except Exception as e:
            return False, f"Error: {e}"
    
    def verify_password(self, username: str, password: str) -> bool:
        """
        Verify password for re-authentication
        Returns: True if password matches
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                
                if not result:
                    return False
                
                password_hash = self._ensure_bytes(result[0])
                return bcrypt.checkpw(password.encode('utf-8'), password_hash)
        
        except Exception as e:
            print(f"❌ Verify password error: {e}")
            return False
    
    def _delete_account(self, username: str):
        """
        Delete account (internal use only)
        Used for rollback when keypair generation fails
        """
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM users WHERE username = ?", (username,))
                conn.commit()
            print(f"⚠️ Account deleted (rollback): {username}")
        except Exception as e:
            print(f"❌ Delete account error: {e}")
    
    def logout(self):
        """Logout current user"""
        self.current_user = None
        print("✅ Logged out")
    
    def is_logged_in(self) -> bool:
        """Check if user is logged in"""
        return self.current_user is not None
    
    def get_current_user(self) -> str:
        """Get current username or empty string"""
        return self.current_user or ""