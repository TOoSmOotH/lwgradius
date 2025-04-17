import sqlite3
import os
import time
import logging
from functools import wraps
from contextlib import contextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('db_utils')

# Database path from environment variable
DB_PATH = os.environ.get('SQLITE_DB', '/data/sqlite/radius.db')

# Maximum number of retries for database operations
MAX_RETRIES = 3
# Delay between retries (in seconds)
RETRY_DELAY = 0.5

class DatabaseError(Exception):
    """Custom exception for database errors"""
    pass

@contextmanager
def get_db_connection(isolation_level=None):
    """
    Context manager for database connections with improved error handling.
    
    Args:
        isolation_level: SQLite isolation level (None for default)
    
    Yields:
        sqlite3.Connection: Database connection
    
    Raises:
        DatabaseError: If connection fails
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, isolation_level=isolation_level)
        conn.row_factory = sqlite3.Row
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        raise DatabaseError(f"Failed to connect to database: {e}")
    finally:
        if conn:
            conn.close()

@contextmanager
def transaction():
    """
    Context manager for database transactions with automatic commit/rollback.
    
    Yields:
        sqlite3.Connection: Database connection with transaction
    
    Raises:
        DatabaseError: If transaction fails
    """
    with get_db_connection(isolation_level="IMMEDIATE") as conn:
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Transaction error: {e}")
            raise DatabaseError(f"Transaction failed: {e}")

def retry_on_error(func):
    """
    Decorator to retry database operations on failure.
    
    Args:
        func: Function to decorate
    
    Returns:
        Function with retry logic
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except (sqlite3.Error, DatabaseError) as e:
                last_error = e
                logger.warning(f"Database operation failed (attempt {attempt+1}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
        
        # If we get here, all retries failed
        logger.error(f"Database operation failed after {MAX_RETRIES} attempts: {last_error}")
        raise DatabaseError(f"Operation failed after {MAX_RETRIES} attempts: {last_error}")
    
    return wrapper

def execute_query(query, params=(), fetchone=False, fetchall=False):
    """
    Execute a query with retry logic and proper error handling.
    
    Args:
        query: SQL query string
        params: Query parameters
        fetchone: Whether to fetch one result
        fetchall: Whether to fetch all results
    
    Returns:
        Query results or None
    
    Raises:
        DatabaseError: If query execution fails
    """
    @retry_on_error
    def _execute():
        with get_db_connection() as conn:
            cursor = conn.execute(query, params)
            
            if fetchone:
                return cursor.fetchone()
            elif fetchall:
                return cursor.fetchall()
            else:
                return None
    
    return _execute()

def execute_transaction(queries):
    """
    Execute multiple queries in a single transaction.
    
    Args:
        queries: List of (query, params) tuples
    
    Returns:
        True if successful
    
    Raises:
        DatabaseError: If transaction fails
    """
    @retry_on_error
    def _execute_transaction():
        with transaction() as conn:
            for query, params in queries:
                conn.execute(query, params)
            return True
    
    return _execute_transaction()

def check_database_integrity():
    """
    Check database integrity and attempt to fix issues.
    
    Returns:
        dict: Integrity check results
    """
    try:
        with get_db_connection() as conn:
            # Run integrity check
            integrity_check = conn.execute("PRAGMA integrity_check").fetchall()
            
            # Check if vacuum is needed
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            free_pages = conn.execute("PRAGMA freelist_count").fetchone()[0]
            
            # Calculate fragmentation percentage
            fragmentation = (free_pages / page_count * 100) if page_count > 0 else 0
            
            # Run vacuum if fragmentation is high
            vacuum_needed = fragmentation > 10
            if vacuum_needed:
                logger.info(f"Database fragmentation is {fragmentation:.2f}%, running VACUUM")
                conn.execute("VACUUM")
            
            return {
                "integrity_check": "ok" if integrity_check[0][0] == "ok" else integrity_check,
                "fragmentation_percent": fragmentation,
                "vacuum_performed": vacuum_needed
            }
    except Exception as e:
        logger.error(f"Database integrity check failed: {e}")
        return {
            "integrity_check": f"error: {str(e)}",
            "fragmentation_percent": None,
            "vacuum_performed": False
        }

def optimize_database():
    """
    Optimize database performance.
    
    Returns:
        dict: Optimization results
    """
    try:
        with get_db_connection() as conn:
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode = WAL")
            
            # Set synchronous mode to NORMAL for better performance
            conn.execute("PRAGMA synchronous = NORMAL")
            
            # Enable foreign key constraints
            conn.execute("PRAGMA foreign_keys = ON")
            
            # Analyze database for query optimization
            conn.execute("ANALYZE")
            
            # Get current settings
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            synchronous = conn.execute("PRAGMA synchronous").fetchone()[0]
            foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
            
            return {
                "journal_mode": journal_mode,
                "synchronous": synchronous,
                "foreign_keys": foreign_keys == 1,
                "analyzed": True
            }
    except Exception as e:
        logger.error(f"Database optimization failed: {e}")
        return {
            "error": str(e)
        }

def get_database_stats():
    """
    Get database statistics.
    
    Returns:
        dict: Database statistics
    """
    try:
        with get_db_connection() as conn:
            # Get table counts
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            
            table_stats = {}
            for table in tables:
                table_name = table[0]
                count = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
                table_stats[table_name] = count
            
            # Get database size
            db_size = os.path.getsize(DB_PATH)
            
            # Get database page stats
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            
            return {
                "size_bytes": db_size,
                "size_mb": round(db_size / (1024 * 1024), 2),
                "page_size": page_size,
                "page_count": page_count,
                "tables": table_stats
            }
    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        return {
            "error": str(e)
        }

def create_backup(backup_path=None):
    """
    Create a backup of the database.
    
    Args:
        backup_path: Path to save the backup (default: DB_PATH + timestamp)
    
    Returns:
        str: Path to the backup file or None if failed
    """
    if not backup_path:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_path = f"{os.path.splitext(DB_PATH)[0]}_{timestamp}.backup.db"
    
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        
        with get_db_connection() as source_conn:
            # Create a new database connection for the backup
            backup_conn = sqlite3.connect(backup_path)
            
            # Copy database
            source_conn.backup(backup_conn)
            backup_conn.close()
            
            logger.info(f"Database backup created at {backup_path}")
            return backup_path
    except Exception as e:
        logger.error(f"Database backup failed: {e}")
        return None