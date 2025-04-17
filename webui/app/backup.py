import os
import sqlite3
import datetime
import shutil
import tempfile
import zipfile
import json
from flask import current_app, send_file

class BackupManager:
    """
    Manages database backups and restoration
    """
    
    @staticmethod
    def create_backup():
        """
        Create a backup of the SQLite database and configuration files
        Returns the path to the backup file
        """
        db_path = current_app.config['SQLITE_DB']
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"radius_backup_{timestamp}.zip"
        
        # Create a temporary directory for the backup
        temp_dir = tempfile.mkdtemp()
        backup_db_path = os.path.join(temp_dir, "radius.db")
        
        try:
            # Create a copy of the database
            conn = sqlite3.connect(db_path)
            backup_conn = sqlite3.connect(backup_db_path)
            conn.backup(backup_conn)
            conn.close()
            backup_conn.close()
            
            # Create metadata file with backup information
            metadata = {
                "backup_date": datetime.datetime.now().isoformat(),
                "database_path": db_path,
                "version": "1.0.0",  # Add version information
                "description": "FreeRADIUS TOTP Management System Backup"
            }
            
            metadata_path = os.path.join(temp_dir, "backup_metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Create a zip file containing the database and metadata
            backup_path = os.path.join(current_app.config.get('BACKUP_DIR', '/tmp'), backup_filename)
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(backup_db_path, "radius.db")
                zipf.write(metadata_path, "backup_metadata.json")
                
                # Add configuration files if available
                radius_config_dir = "/etc/raddb"
                if os.path.exists(radius_config_dir):
                    for root, _, files in os.walk(radius_config_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            rel_path = os.path.relpath(file_path, os.path.dirname(radius_config_dir))
                            zipf.write(file_path, os.path.join("config", rel_path))
            
            return backup_path
        
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir)
    
    @staticmethod
    def restore_backup(backup_file):
        """
        Restore a backup from a zip file
        Returns True if successful, False otherwise
        """
        db_path = current_app.config['SQLITE_DB']
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Extract the backup zip file
            with zipfile.ZipFile(backup_file, 'r') as zipf:
                zipf.extractall(temp_dir)
            
            # Verify backup metadata
            metadata_path = os.path.join(temp_dir, "backup_metadata.json")
            if not os.path.exists(metadata_path):
                return False, "Invalid backup file: missing metadata"
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Check backup version compatibility
            if "version" not in metadata:
                return False, "Invalid backup file: missing version information"
            
            # Restore the database
            backup_db_path = os.path.join(temp_dir, "radius.db")
            if not os.path.exists(backup_db_path):
                return False, "Invalid backup file: missing database"
            
            # Create a backup of the current database before restoring
            current_backup = f"{db_path}.bak.{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(db_path, current_backup)
            
            # Restore the database
            conn = sqlite3.connect(backup_db_path)
            backup_conn = sqlite3.connect(db_path)
            conn.backup(backup_conn)
            conn.close()
            backup_conn.close()
            
            # Optionally restore configuration files
            config_dir = os.path.join(temp_dir, "config")
            if os.path.exists(config_dir):
                # This would require additional logic to safely restore config files
                # For now, we'll just restore the database
                pass
            
            return True, f"Backup restored successfully. Original database backed up to {current_backup}"
        
        except Exception as e:
            return False, f"Error restoring backup: {str(e)}"
        
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir)
    
    @staticmethod
    def get_backup_file(backup_path):
        """
        Return a Flask send_file response for the backup file
        """
        return send_file(
            backup_path,
            as_attachment=True,
            download_name=os.path.basename(backup_path),
            mimetype='application/zip'
        )
    
    @staticmethod
    def list_backups():
        """
        List all available backups
        """
        backup_dir = current_app.config.get('BACKUP_DIR', '/tmp')
        backups = []
        
        if os.path.exists(backup_dir):
            for file in os.listdir(backup_dir):
                if file.startswith("radius_backup_") and file.endswith(".zip"):
                    file_path = os.path.join(backup_dir, file)
                    file_stat = os.stat(file_path)
                    
                    backups.append({
                        "filename": file,
                        "path": file_path,
                        "size": file_stat.st_size,
                        "created": datetime.datetime.fromtimestamp(file_stat.st_ctime).isoformat()
                    })
        
        return sorted(backups, key=lambda x: x["created"], reverse=True)
    
    @staticmethod
    def delete_backup(backup_path):
        """
        Delete a backup file
        """
        if os.path.exists(backup_path):
            os.remove(backup_path)
            return True
        return False