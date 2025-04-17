from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
import datetime
from .backup import BackupManager
from .utils import log_admin_action

backup_bp = Blueprint('backup', __name__)

@backup_bp.route('/')
@login_required
def index():
    """Display backup management page"""
    backups = BackupManager.list_backups()
    return render_template('backup/index.html', backups=backups)

@backup_bp.route('/create', methods=['POST'])
@login_required
def create_backup():
    """Create a new backup"""
    try:
        backup_path = BackupManager.create_backup()
        log_admin_action(current_user.username, 'create_backup', f"Created backup: {os.path.basename(backup_path)}")
        flash('Backup created successfully', 'success')
    except Exception as e:
        flash(f'Error creating backup: {str(e)}', 'danger')
    
    return redirect(url_for('backup.index'))

@backup_bp.route('/download/<path:filename>')
@login_required
def download_backup(filename):
    """Download a backup file"""
    backup_dir = current_app.config.get('BACKUP_DIR', '/tmp')
    backup_path = os.path.join(backup_dir, secure_filename(filename))
    
    if not os.path.exists(backup_path):
        flash('Backup file not found', 'danger')
        return redirect(url_for('backup.index'))
    
    log_admin_action(current_user.username, 'download_backup', f"Downloaded backup: {filename}")
    return BackupManager.get_backup_file(backup_path)

@backup_bp.route('/delete/<path:filename>', methods=['POST'])
@login_required
def delete_backup(filename):
    """Delete a backup file"""
    backup_dir = current_app.config.get('BACKUP_DIR', '/tmp')
    backup_path = os.path.join(backup_dir, secure_filename(filename))
    
    if not os.path.exists(backup_path):
        flash('Backup file not found', 'danger')
    else:
        if BackupManager.delete_backup(backup_path):
            log_admin_action(current_user.username, 'delete_backup', f"Deleted backup: {filename}")
            flash('Backup deleted successfully', 'success')
        else:
            flash('Error deleting backup', 'danger')
    
    return redirect(url_for('backup.index'))

@backup_bp.route('/restore', methods=['POST'])
@login_required
def restore_backup():
    """Restore a backup from an uploaded file"""
    if 'backup_file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('backup.index'))
    
    backup_file = request.files['backup_file']
    
    if backup_file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('backup.index'))
    
    try:
        # Save the uploaded file to a temporary location
        temp_dir = current_app.config.get('TEMP_DIR', '/tmp')
        os.makedirs(temp_dir, exist_ok=True)
        
        temp_path = os.path.join(temp_dir, f"restore_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
        backup_file.save(temp_path)
        
        # Restore the backup
        success, message = BackupManager.restore_backup(temp_path)
        
        if success:
            log_admin_action(current_user.username, 'restore_backup', f"Restored backup: {backup_file.filename}")
            flash(message, 'success')
        else:
            flash(message, 'danger')
        
        # Clean up the temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)
    
    except Exception as e:
        flash(f'Error restoring backup: {str(e)}', 'danger')
    
    return redirect(url_for('backup.index'))