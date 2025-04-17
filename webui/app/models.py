import os
import sqlite3
import bcrypt
from flask_login import UserMixin
from datetime import datetime

# Database path from environment variable
DB_PATH = os.environ.get('SQLITE_DB', '/data/sqlite/radius.db')

def get_db_connection():
    """Create a connection to the SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

class User:
    """Model for RADIUS users"""
    
    @staticmethod
    def get_all(search=None, limit=100, offset=0):
        """Get all users with optional search filter"""
        conn = get_db_connection()
        query = """
            SELECT DISTINCT username FROM radcheck
            WHERE username LIKE ? 
            ORDER BY username
            LIMIT ? OFFSET ?
        """
        users = conn.execute(query, (f"%{search}%" if search else "%", limit, offset)).fetchall()
        conn.close()
        return [dict(user) for user in users]
    
    @staticmethod
    def get_count(search=None):
        """Get count of users with optional search filter"""
        conn = get_db_connection()
        query = "SELECT COUNT(DISTINCT username) as count FROM radcheck WHERE username LIKE ?"
        count = conn.execute(query, (f"%{search}%" if search else "%",)).fetchone()['count']
        conn.close()
        return count
    
    @staticmethod
    def get_by_username(username):
        """Get user by username"""
        conn = get_db_connection()
        query = """
            SELECT r.username, r.attribute, r.value, r.op
            FROM radcheck r
            WHERE r.username = ?
        """
        user_attrs = conn.execute(query, (username,)).fetchall()
        
        if not user_attrs:
            conn.close()
            return None
        
        # Get TOTP status
        totp_query = "SELECT * FROM totp_users WHERE username = ?"
        totp_info = conn.execute(totp_query, (username,)).fetchone()
        
        # Get user groups
        groups_query = "SELECT groupname FROM radusergroup WHERE username = ? ORDER BY priority"
        groups = conn.execute(groups_query, (username,)).fetchall()
        
        conn.close()
        
        # Build user object
        user = {
            'username': username,
            'attributes': {},
            'has_totp': totp_info is not None,
            'totp_enabled': totp_info['enabled'] if totp_info else False,
            'groups': [g['groupname'] for g in groups]
        }
        
        for attr in user_attrs:
            user['attributes'][attr['attribute']] = {
                'value': attr['value'],
                'op': attr['op']
            }
        
        return user
    
    @staticmethod
    def create(username, password=None, totp_enabled=False, groups=None):
        """Create a new user"""
        conn = get_db_connection()
        
        try:
            conn.execute("BEGIN TRANSACTION")
            
            # Add user with password if provided
            if password:
                conn.execute(
                    "INSERT INTO radcheck (username, attribute, op, value) VALUES (?, ?, ?, ?)",
                    (username, "Cleartext-Password", ":=", password)
                )
            
            # Add user to groups
            if groups:
                for i, group in enumerate(groups):
                    conn.execute(
                        "INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, ?)",
                        (username, group, i)
                    )
            
            # Generate TOTP if enabled
            if totp_enabled:
                import pyotp
                totp_secret = pyotp.random_base32()
                
                # Add TOTP secret to radcheck
                conn.execute(
                    "INSERT INTO radcheck (username, attribute, op, value) VALUES (?, ?, ?, ?)",
                    (username, "TOTP-Secret", ":=", totp_secret)
                )
                
                # Add to totp_users table
                conn.execute(
                    "INSERT INTO totp_users (username, secret, enabled) VALUES (?, ?, ?)",
                    (username, totp_secret, 1)
                )
            
            conn.execute("COMMIT")
            return True
        except Exception as e:
            conn.execute("ROLLBACK")
            print(f"Error creating user: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def update(username, password=None, totp_enabled=None, groups=None):
        """Update an existing user"""
        conn = get_db_connection()
        
        try:
            conn.execute("BEGIN TRANSACTION")
            
            # Update password if provided
            if password:
                # Check if password attribute exists
                exists = conn.execute(
                    "SELECT id FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'",
                    (username,)
                ).fetchone()
                
                if exists:
                    conn.execute(
                        "UPDATE radcheck SET value = ? WHERE username = ? AND attribute = 'Cleartext-Password'",
                        (password, username)
                    )
                else:
                    conn.execute(
                        "INSERT INTO radcheck (username, attribute, op, value) VALUES (?, ?, ?, ?)",
                        (username, "Cleartext-Password", ":=", password)
                    )
            
            # Update TOTP if status changed
            if totp_enabled is not None:
                totp_exists = conn.execute(
                    "SELECT id FROM totp_users WHERE username = ?",
                    (username,)
                ).fetchone()
                
                if totp_enabled and not totp_exists:
                    # Enable TOTP
                    import pyotp
                    totp_secret = pyotp.random_base32()
                    
                    # Add TOTP secret to radcheck
                    conn.execute(
                        "INSERT INTO radcheck (username, attribute, op, value) VALUES (?, ?, ?, ?)",
                        (username, "TOTP-Secret", ":=", totp_secret)
                    )
                    
                    # Add to totp_users table
                    conn.execute(
                        "INSERT INTO totp_users (username, secret, enabled) VALUES (?, ?, ?)",
                        (username, totp_secret, 1)
                    )
                elif not totp_enabled and totp_exists:
                    # Disable TOTP
                    conn.execute(
                        "DELETE FROM totp_users WHERE username = ?",
                        (username,)
                    )
                    conn.execute(
                        "DELETE FROM radcheck WHERE username = ? AND attribute = 'TOTP-Secret'",
                        (username,)
                    )
                elif totp_exists:
                    # Update enabled status
                    conn.execute(
                        "UPDATE totp_users SET enabled = ? WHERE username = ?",
                        (1 if totp_enabled else 0, username)
                    )
            
            # Update groups if provided
            if groups is not None:
                # Remove existing groups
                conn.execute(
                    "DELETE FROM radusergroup WHERE username = ?",
                    (username,)
                )
                
                # Add new groups
                for i, group in enumerate(groups):
                    conn.execute(
                        "INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, ?)",
                        (username, group, i)
                    )
            
            conn.execute("COMMIT")
            return True
        except Exception as e:
            conn.execute("ROLLBACK")
            print(f"Error updating user: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def delete(username):
        """Delete a user"""
        conn = get_db_connection()
        
        try:
            conn.execute("BEGIN TRANSACTION")
            
            # Delete from radcheck
            conn.execute("DELETE FROM radcheck WHERE username = ?", (username,))
            
            # Delete from radreply
            conn.execute("DELETE FROM radreply WHERE username = ?", (username,))
            
            # Delete from radusergroup
            conn.execute("DELETE FROM radusergroup WHERE username = ?", (username,))
            
            # Delete from totp_users
            conn.execute("DELETE FROM totp_users WHERE username = ?", (username,))
            
            conn.execute("COMMIT")
            return True
        except Exception as e:
            conn.execute("ROLLBACK")
            print(f"Error deleting user: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def reset_totp(username):
        """Reset TOTP for a user"""
        conn = get_db_connection()
        
        try:
            conn.execute("BEGIN TRANSACTION")
            
            import pyotp
            totp_secret = pyotp.random_base32()
            
            # Update TOTP secret in radcheck
            exists = conn.execute(
                "SELECT id FROM radcheck WHERE username = ? AND attribute = 'TOTP-Secret'",
                (username,)
            ).fetchone()
            
            if exists:
                conn.execute(
                    "UPDATE radcheck SET value = ? WHERE username = ? AND attribute = 'TOTP-Secret'",
                    (totp_secret, username)
                )
            else:
                conn.execute(
                    "INSERT INTO radcheck (username, attribute, op, value) VALUES (?, ?, ?, ?)",
                    (username, "TOTP-Secret", ":=", totp_secret)
                )
            
            # Update totp_users table
            totp_exists = conn.execute(
                "SELECT id FROM totp_users WHERE username = ?",
                (username,)
            ).fetchone()
            
            if totp_exists:
                conn.execute(
                    "UPDATE totp_users SET secret = ?, enabled = 1 WHERE username = ?",
                    (totp_secret, username)
                )
            else:
                conn.execute(
                    "INSERT INTO totp_users (username, secret, enabled) VALUES (?, ?, ?)",
                    (username, totp_secret, 1)
                )
            
            conn.execute("COMMIT")
            return totp_secret
        except Exception as e:
            conn.execute("ROLLBACK")
            print(f"Error resetting TOTP: {e}")
            return None
        finally:
            conn.close()
    
    @staticmethod
    def get_totp_secret(username):
        """Get TOTP secret for a user"""
        conn = get_db_connection()
        query = """
            SELECT value FROM radcheck 
            WHERE username = ? AND attribute = 'TOTP-Secret'
        """
        result = conn.execute(query, (username,)).fetchone()
        conn.close()
        
        if result:
            return result['value']
        return None
    
    @staticmethod
    def verify_totp(username, token):
        """Verify TOTP token for a user"""
        import pyotp
        
        secret = User.get_totp_secret(username)
        if not secret:
            return False
        
        totp = pyotp.TOTP(secret)
        return totp.verify(token)


class RadiusClient:
    """Model for RADIUS clients (NAS)"""
    
    @staticmethod
    def get_all():
        """Get all RADIUS clients"""
        conn = get_db_connection()
        query = "SELECT * FROM nas ORDER BY nasname"
        clients = conn.execute(query).fetchall()
        conn.close()
        return [dict(client) for client in clients]
    
    @staticmethod
    def get_by_id(client_id):
        """Get client by ID"""
        conn = get_db_connection()
        query = "SELECT * FROM nas WHERE id = ?"
        client = conn.execute(query, (client_id,)).fetchone()
        conn.close()
        return dict(client) if client else None
    
    @staticmethod
    def create(nasname, shortname, type, secret, ports=None, server=None, community=None, description=None):
        """Create a new RADIUS client"""
        conn = get_db_connection()
        
        try:
            query = """
                INSERT INTO nas (nasname, shortname, type, ports, secret, server, community, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            conn.execute(query, (nasname, shortname, type, ports, secret, server, community, description))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error creating client: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def update(client_id, nasname, shortname, type, secret, ports=None, server=None, community=None, description=None):
        """Update an existing RADIUS client"""
        conn = get_db_connection()
        
        try:
            query = """
                UPDATE nas SET 
                nasname = ?, shortname = ?, type = ?, ports = ?, 
                secret = ?, server = ?, community = ?, description = ?
                WHERE id = ?
            """
            conn.execute(query, (nasname, shortname, type, ports, secret, server, community, description, client_id))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating client: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def delete(client_id):
        """Delete a RADIUS client"""
        conn = get_db_connection()
        
        try:
            conn.execute("DELETE FROM nas WHERE id = ?", (client_id,))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting client: {e}")
            return False
        finally:
            conn.close()


class AuthLog:
    """Model for authentication logs"""
    
    @staticmethod
    def get_all(limit=100, offset=0, username=None, status=None, start_date=None, end_date=None):
        """Get authentication logs with filters"""
        conn = get_db_connection()
        
        query_parts = ["SELECT * FROM radacct WHERE 1=1"]
        params = []
        
        if username:
            query_parts.append("AND username LIKE ?")
            params.append(f"%{username}%")
        
        if status:
            if status == 'success':
                query_parts.append("AND acctstoptime IS NOT NULL")
            elif status == 'failure':
                query_parts.append("AND acctstoptime IS NULL")
        
        if start_date:
            query_parts.append("AND acctstarttime >= ?")
            params.append(start_date)
        
        if end_date:
            query_parts.append("AND acctstarttime <= ?")
            params.append(end_date)
        
        query_parts.append("ORDER BY acctstarttime DESC LIMIT ? OFFSET ?")
        params.extend([limit, offset])
        
        query = " ".join(query_parts)
        logs = conn.execute(query, params).fetchall()
        conn.close()
        
        return [dict(log) for log in logs]
    
    @staticmethod
    def get_count(username=None, status=None, start_date=None, end_date=None):
        """Get count of authentication logs with filters"""
        conn = get_db_connection()
        
        query_parts = ["SELECT COUNT(*) as count FROM radacct WHERE 1=1"]
        params = []
        
        if username:
            query_parts.append("AND username LIKE ?")
            params.append(f"%{username}%")
        
        if status:
            if status == 'success':
                query_parts.append("AND acctstoptime IS NOT NULL")
            elif status == 'failure':
                query_parts.append("AND acctstoptime IS NULL")
        
        if start_date:
            query_parts.append("AND acctstarttime >= ?")
            params.append(start_date)
        
        if end_date:
            query_parts.append("AND acctstarttime <= ?")
            params.append(end_date)
        
        query = " ".join(query_parts)
        count = conn.execute(query, params).fetchone()['count']
        conn.close()
        
        return count


class AdminUser(UserMixin):
    """Model for admin users of the web UI"""
    
    def __init__(self, id, username, password_hash, email=None, role='admin'):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.role = role
    
    def check_password(self, password):
        """Check if password matches hash"""
        if self.password_hash.startswith('$2'):
            # bcrypt hash
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        else:
            # Plain text (for initial setup only)
            return password == self.password_hash
    
    @staticmethod
    def get_by_id(user_id):
        """Get admin user by ID"""
        conn = get_db_connection()
        query = "SELECT * FROM admin_users WHERE id = ?"
        user = conn.execute(query, (user_id,)).fetchone()
        conn.close()
        
        if not user:
            return None
        
        return AdminUser(
            id=user['id'],
            username=user['username'],
            password_hash=user['password_hash'],
            email=user['email'],
            role=user['role']
        )
    
    @staticmethod
    def get_by_username(username):
        """Get admin user by username"""
        conn = get_db_connection()
        query = "SELECT * FROM admin_users WHERE username = ?"
        user = conn.execute(query, (username,)).fetchone()
        conn.close()
        
        if not user:
            return None
        
        return AdminUser(
            id=user['id'],
            username=user['username'],
            password_hash=user['password_hash'],
            email=user['email'],
            role=user['role']
        )
    
    @staticmethod
    def create(username, password, email=None, role='admin'):
        """Create a new admin user"""
        conn = get_db_connection()
        
        try:
            # Hash the password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            query = """
                INSERT INTO admin_users (username, password_hash, email, role)
                VALUES (?, ?, ?, ?)
            """
            conn.execute(query, (username, password_hash, email, role))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error creating admin user: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def update(user_id, password=None, email=None, role=None):
        """Update an admin user"""
        conn = get_db_connection()
        
        try:
            updates = []
            params = []
            
            if password:
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                updates.append("password_hash = ?")
                params.append(password_hash)
            
            if email is not None:
                updates.append("email = ?")
                params.append(email)
            
            if role:
                updates.append("role = ?")
                params.append(role)
            
            if not updates:
                return True
            
            query = f"UPDATE admin_users SET {', '.join(updates)} WHERE id = ?"
            params.append(user_id)
            
            conn.execute(query, params)
            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating admin user: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def delete(user_id):
        """Delete an admin user"""
        conn = get_db_connection()
        
        try:
            conn.execute("DELETE FROM admin_users WHERE id = ?", (user_id,))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting admin user: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def get_all():
        """Get all admin users"""
        conn = get_db_connection()
        query = "SELECT * FROM admin_users ORDER BY username"
        users = conn.execute(query).fetchall()
        conn.close()
        
        return [
            AdminUser(
                id=user['id'],
                username=user['username'],
                password_hash=user['password_hash'],
                email=user['email'],
                role=user['role']
            )
            for user in users
        ]


class AuditLog:
    """Model for audit logs"""
    
    @staticmethod
    def log_action(admin_username, action, details=None):
        """Log an administrative action"""
        conn = get_db_connection()
        
        try:
            # Create audit_logs table if it doesn't exist
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            query = """
                INSERT INTO audit_logs (admin_username, action, details)
                VALUES (?, ?, ?)
            """
            conn.execute(query, (admin_username, action, details))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error logging action: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def get_logs(limit=100, offset=0, admin=None, action=None, start_date=None, end_date=None):
        """Get audit logs with filters"""
        conn = get_db_connection()
        
        # Create audit_logs table if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        query_parts = ["SELECT * FROM audit_logs WHERE 1=1"]
        params = []
        
        if admin:
            query_parts.append("AND admin_username LIKE ?")
            params.append(f"%{admin}%")
        
        if action:
            query_parts.append("AND action LIKE ?")
            params.append(f"%{action}%")
        
        if start_date:
            query_parts.append("AND timestamp >= ?")
            params.append(start_date)
        
        if end_date:
            query_parts.append("AND timestamp <= ?")
            params.append(end_date)
        
        query_parts.append("ORDER BY timestamp DESC LIMIT ? OFFSET ?")
        params.extend([limit, offset])
        
        query = " ".join(query_parts)
        logs = conn.execute(query, params).fetchall()
        conn.close()
        
        return [dict(log) for log in logs]
    
    @staticmethod
    def get_count(admin=None, action=None, start_date=None, end_date=None):
        """Get count of audit logs with filters"""
        conn = get_db_connection()
        
        # Create audit_logs table if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        query_parts = ["SELECT COUNT(*) as count FROM audit_logs WHERE 1=1"]
        params = []
        
        if admin:
            query_parts.append("AND admin_username LIKE ?")
            params.append(f"%{admin}%")
        
        if action:
            query_parts.append("AND action LIKE ?")
            params.append(f"%{action}%")
        
        if start_date:
            query_parts.append("AND timestamp >= ?")
            params.append(start_date)
        
        if end_date:
            query_parts.append("AND timestamp <= ?")
            params.append(end_date)
        
        query = " ".join(query_parts)
        count = conn.execute(query, params).fetchone()['count']
        conn.close()
        
        return count