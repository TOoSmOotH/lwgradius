import os
import pyotp
import qrcode
from io import BytesIO
import base64
import csv
import sqlite3
from datetime import datetime
import bcrypt
from .models import get_db_connection, User, AuditLog

def generate_totp_qrcode(username, secret, issuer="FreeRADIUS-TOTP"):
    """Generate a QR code for TOTP setup"""
    # Create the TOTP provisioning URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(username, issuer_name=issuer)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for embedding in HTML
    buffered = BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def import_users_from_csv(csv_data, has_header=True):
    """Import users from CSV data"""
    results = {
        'success': 0,
        'failed': 0,
        'errors': []
    }
    
    try:
        # Parse CSV data
        reader = csv.reader(csv_data.splitlines())
        
        # Skip header if present
        if has_header:
            next(reader, None)
        
        for row in reader:
            if len(row) < 2:
                results['failed'] += 1
                results['errors'].append(f"Row has insufficient columns: {','.join(row)}")
                continue
            
            username = row[0].strip()
            password = row[1].strip()
            
            # Optional TOTP flag (True/False)
            totp_enabled = False
            if len(row) > 2 and row[2].strip().lower() in ('true', 'yes', '1'):
                totp_enabled = True
            
            # Optional groups
            groups = []
            if len(row) > 3 and row[3].strip():
                groups = [g.strip() for g in row[3].split(',')]
            
            # Create user
            if User.create(username, password, totp_enabled, groups):
                results['success'] += 1
            else:
                results['failed'] += 1
                results['errors'].append(f"Failed to create user: {username}")
        
        return results
    except Exception as e:
        results['failed'] += 1
        results['errors'].append(f"Error processing CSV: {str(e)}")
        return results

def export_users_to_csv():
    """Export users to CSV format"""
    conn = get_db_connection()
    
    # Get all usernames
    usernames = conn.execute(
        "SELECT DISTINCT username FROM radcheck ORDER BY username"
    ).fetchall()
    
    csv_data = []
    csv_data.append(['Username', 'Has Password', 'TOTP Enabled', 'Groups'])
    
    for user in usernames:
        username = user['username']
        
        # Check if user has password
        has_password = conn.execute(
            "SELECT COUNT(*) as count FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'",
            (username,)
        ).fetchone()['count'] > 0
        
        # Check if user has TOTP
        has_totp = conn.execute(
            "SELECT COUNT(*) as count FROM totp_users WHERE username = ? AND enabled = 1",
            (username,)
        ).fetchone()['count'] > 0
        
        # Get user groups
        groups_query = "SELECT groupname FROM radusergroup WHERE username = ? ORDER BY priority"
        groups = conn.execute(groups_query, (username,)).fetchall()
        groups_str = ','.join([g['groupname'] for g in groups])
        
        csv_data.append([username, 'Yes' if has_password else 'No', 'Yes' if has_totp else 'No', groups_str])
    
    conn.close()
    
    # Convert to CSV string
    output = BytesIO()
    writer = csv.writer(output)
    for row in csv_data:
        writer.writerow(row)
    
    return output.getvalue().decode('utf-8')

def get_system_status():
    """Get system status information"""
    conn = get_db_connection()
    
    # Get user counts
    total_users = conn.execute("SELECT COUNT(DISTINCT username) as count FROM radcheck").fetchone()['count']
    totp_users = conn.execute("SELECT COUNT(*) as count FROM totp_users WHERE enabled = 1").fetchone()['count']
    
    # Get client counts
    total_clients = conn.execute("SELECT COUNT(*) as count FROM nas").fetchone()['count']
    
    # Get authentication statistics
    total_auth = conn.execute("SELECT COUNT(*) as count FROM radacct").fetchone()['count']
    successful_auth = conn.execute("SELECT COUNT(*) as count FROM radacct WHERE acctstoptime IS NOT NULL").fetchone()['count']
    failed_auth = total_auth - successful_auth
    
    # Get recent authentication attempts
    recent_auth = conn.execute(
        "SELECT username, nasipaddress, acctstarttime, acctstoptime FROM radacct ORDER BY acctstarttime DESC LIMIT 5"
    ).fetchall()
    
    # Get database size
    db_path = os.environ.get('SQLITE_DB', '/data/sqlite/radius.db')
    db_size = os.path.getsize(db_path) if os.path.exists(db_path) else 0
    db_size_mb = round(db_size / (1024 * 1024), 2)
    
    conn.close()
    
    return {
        'users': {
            'total': total_users,
            'with_totp': totp_users
        },
        'clients': {
            'total': total_clients
        },
        'authentication': {
            'total': total_auth,
            'successful': successful_auth,
            'failed': failed_auth
        },
        'recent_auth': [dict(auth) for auth in recent_auth],
        'database': {
            'size_mb': db_size_mb,
            'path': db_path
        },
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

def rotate_client_secret(client_id):
    """Generate and set a new random secret for a RADIUS client"""
    import secrets
    import string
    
    # Generate a random secret (16 characters)
    alphabet = string.ascii_letters + string.digits
    new_secret = ''.join(secrets.choice(alphabet) for _ in range(16))
    
    conn = get_db_connection()
    
    try:
        conn.execute("UPDATE nas SET secret = ? WHERE id = ?", (new_secret, client_id))
        conn.commit()
        return new_secret
    except Exception as e:
        print(f"Error rotating client secret: {e}")
        return None
    finally:
        conn.close()

def create_admin_user_if_not_exists(username, password, role='admin'):
    """Create an admin user if it doesn't exist"""
    conn = get_db_connection()
    
    try:
        # Check if user exists
        user = conn.execute("SELECT * FROM admin_users WHERE username = ?", (username,)).fetchone()
        
        if not user:
            # Hash the password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Create user
            conn.execute(
                "INSERT INTO admin_users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )
            conn.commit()
            return True
        
        return False
    except Exception as e:
        print(f"Error creating admin user: {e}")
        return False
    finally:
        conn.close()

def update_admin_password(username, new_password):
    """Update an admin user's password"""
    conn = get_db_connection()
    
    try:
        # Hash the password
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        conn.execute(
            "UPDATE admin_users SET password_hash = ? WHERE username = ?",
            (password_hash, username)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating admin password: {e}")
        return False
    finally:
        conn.close()

def log_admin_action(admin_username, action, details=None):
    """Log an administrative action"""
    return AuditLog.log_action(admin_username, action, details)

def verify_totp_code(username, token):
    """Verify a TOTP code for a user"""
    return User.verify_totp(username, token)