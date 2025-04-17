from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, send_file
from flask_login import login_user, logout_user, login_required, current_user
from io import BytesIO
import csv
from datetime import datetime

from .models import User, RadiusClient, AuthLog, AdminUser, AuditLog
from .forms import (
    LoginForm, UserForm, TOTPVerifyForm, ClientForm, 
    AdminUserForm, SearchForm, LogFilterForm, ImportUsersForm
)
from .utils import (
    generate_totp_qrcode, import_users_from_csv, export_users_to_csv,
    get_system_status, rotate_client_secret, log_admin_action, verify_totp_code
)

# Create blueprints for different sections
auth_bp = Blueprint('auth', __name__)
user_bp = Blueprint('user', __name__)
totp_bp = Blueprint('totp', __name__)
client_bp = Blueprint('client', __name__)
admin_bp = Blueprint('admin', __name__)
log_bp = Blueprint('log', __name__)

# Authentication routes
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = AdminUser.get_by_username(form.username.data)
        
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            log_admin_action(user.username, 'login', 'Admin user logged in')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('auth/login.html', form=form, title='Login')

@auth_bp.route('/logout')
@login_required
def logout():
    log_admin_action(current_user.username, 'logout', 'Admin user logged out')
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))

# User management routes
@user_bp.route('/')
@login_required
def list_users():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    users = User.get_all(search=search, limit=per_page, offset=(page-1)*per_page)
    total = User.get_count(search=search)
    
    search_form = SearchForm()
    search_form.query.data = search
    
    return render_template(
        'user/list.html',
        users=users,
        search_form=search_form,
        search=search,
        page=page,
        per_page=per_page,
        total=total,
        title='User Management'
    )

@user_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_user():
    form = UserForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data if form.password.data else None
        totp_enabled = form.enable_totp.data
        
        groups = []
        if form.groups.data:
            groups = [g.strip() for g in form.groups.data.split(',')]
        
        if User.create(username, password, totp_enabled, groups):
            log_admin_action(
                current_user.username, 
                'create_user', 
                f'Created user {username} with TOTP: {totp_enabled}'
            )
            flash(f'User {username} created successfully', 'success')
            
            if totp_enabled:
                return redirect(url_for('totp.setup', username=username))
            else:
                return redirect(url_for('user.list_users'))
        else:
            flash('Failed to create user', 'danger')
    
    return render_template('user/form.html', form=form, title='Create User')

@user_bp.route('/edit/<username>', methods=['GET', 'POST'])
@login_required
def edit_user(username):
    user = User.get_by_username(username)
    if not user:
        flash(f'User {username} not found', 'danger')
        return redirect(url_for('user.list_users'))
    
    form = UserForm(obj=user)
    
    # Pre-populate form
    form.username.data = user['username']
    form.enable_totp.data = user['has_totp']
    form.groups.data = ','.join(user['groups']) if user['groups'] else ''
    
    if form.validate_on_submit():
        password = form.password.data if form.password.data else None
        totp_enabled = form.enable_totp.data
        
        groups = []
        if form.groups.data:
            groups = [g.strip() for g in form.groups.data.split(',')]
        
        if User.update(username, password, totp_enabled, groups):
            log_admin_action(
                current_user.username, 
                'update_user', 
                f'Updated user {username}'
            )
            flash(f'User {username} updated successfully', 'success')
            
            if totp_enabled and not user['has_totp']:
                return redirect(url_for('totp.setup', username=username))
            else:
                return redirect(url_for('user.list_users'))
        else:
            flash('Failed to update user', 'danger')
    
    return render_template('user/form.html', form=form, user=user, title='Edit User')

@user_bp.route('/delete/<username>', methods=['POST'])
@login_required
def delete_user(username):
    if User.delete(username):
        log_admin_action(
            current_user.username, 
            'delete_user', 
            f'Deleted user {username}'
        )
        flash(f'User {username} deleted successfully', 'success')
    else:
        flash(f'Failed to delete user {username}', 'danger')
    
    return redirect(url_for('user.list_users'))

@user_bp.route('/import', methods=['GET', 'POST'])
@login_required
def import_users():
    form = ImportUsersForm()
    
    if form.validate_on_submit():
        results = import_users_from_csv(form.csv_data.data, form.has_header.data)
        
        log_admin_action(
            current_user.username, 
            'import_users', 
            f'Imported users: {results["success"]} successful, {results["failed"]} failed'
        )
        
        if results['failed'] > 0:
            flash(f'Imported {results["success"]} users with {results["failed"]} failures', 'warning')
            return render_template(
                'user/import.html', 
                form=form, 
                results=results,
                title='Import Users'
            )
        else:
            flash(f'Successfully imported {results["success"]} users', 'success')
            return redirect(url_for('user.list_users'))
    
    return render_template('user/import.html', form=form, title='Import Users')

@user_bp.route('/export')
@login_required
def export_users():
    csv_data = export_users_to_csv()
    
    log_admin_action(
        current_user.username, 
        'export_users', 
        'Exported user data to CSV'
    )
    
    buffer = BytesIO(csv_data.encode('utf-8'))
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'radius_users_{timestamp}.csv',
        mimetype='text/csv'
    )

# TOTP management routes
@totp_bp.route('/setup/<username>')
@login_required
def setup(username):
    user = User.get_by_username(username)
    if not user:
        flash(f'User {username} not found', 'danger')
        return redirect(url_for('user.list_users'))
    
    # Get or generate TOTP secret
    secret = User.get_totp_secret(username)
    if not secret:
        secret = User.reset_totp(username)
        if not secret:
            flash('Failed to generate TOTP secret', 'danger')
            return redirect(url_for('user.edit_user', username=username))
    
    # Generate QR code
    qrcode = generate_totp_qrcode(username, secret)
    
    form = TOTPVerifyForm()
    
    return render_template(
        'totp/setup.html',
        username=username,
        secret=secret,
        qrcode=qrcode,
        form=form,
        title='TOTP Setup'
    )

@totp_bp.route('/verify/<username>', methods=['POST'])
@login_required
def verify(username):
    form = TOTPVerifyForm()
    
    if form.validate_on_submit():
        token = form.token.data
        
        if verify_totp_code(username, token):
            log_admin_action(
                current_user.username, 
                'verify_totp', 
                f'Verified TOTP setup for user {username}'
            )
            flash('TOTP verification successful', 'success')
            return redirect(url_for('user.list_users'))
        else:
            flash('Invalid TOTP token', 'danger')
    
    return redirect(url_for('totp.setup', username=username))

@totp_bp.route('/reset/<username>', methods=['POST'])
@login_required
def reset(username):
    secret = User.reset_totp(username)
    
    if secret:
        log_admin_action(
            current_user.username, 
            'reset_totp', 
            f'Reset TOTP for user {username}'
        )
        flash('TOTP reset successfully', 'success')
        return redirect(url_for('totp.setup', username=username))
    else:
        flash('Failed to reset TOTP', 'danger')
        return redirect(url_for('user.edit_user', username=username))

# Client management routes
@client_bp.route('/')
@login_required
def list_clients():
    clients = RadiusClient.get_all()
    return render_template('client/list.html', clients=clients, title='Client Management')

@client_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_client():
    form = ClientForm()
    
    if form.validate_on_submit():
        if RadiusClient.create(
            form.nasname.data,
            form.shortname.data,
            form.type.data,
            form.secret.data,
            form.ports.data,
            form.server.data,
            form.community.data,
            form.description.data
        ):
            log_admin_action(
                current_user.username, 
                'create_client', 
                f'Created RADIUS client {form.shortname.data} ({form.nasname.data})'
            )
            flash(f'Client {form.shortname.data} created successfully', 'success')
            return redirect(url_for('client.list_clients'))
        else:
            flash('Failed to create client', 'danger')
    
    return render_template('client/form.html', form=form, title='Create Client')

@client_bp.route('/edit/<int:client_id>', methods=['GET', 'POST'])
@login_required
def edit_client(client_id):
    client = RadiusClient.get_by_id(client_id)
    if not client:
        flash('Client not found', 'danger')
        return redirect(url_for('client.list_clients'))
    
    form = ClientForm(obj=client)
    
    if form.validate_on_submit():
        if RadiusClient.update(
            client_id,
            form.nasname.data,
            form.shortname.data,
            form.type.data,
            form.secret.data,
            form.ports.data,
            form.server.data,
            form.community.data,
            form.description.data
        ):
            log_admin_action(
                current_user.username, 
                'update_client', 
                f'Updated RADIUS client {form.shortname.data} ({form.nasname.data})'
            )
            flash(f'Client {form.shortname.data} updated successfully', 'success')
            return redirect(url_for('client.list_clients'))
        else:
            flash('Failed to update client', 'danger')
    
    return render_template('client/form.html', form=form, client=client, title='Edit Client')

@client_bp.route('/delete/<int:client_id>', methods=['POST'])
@login_required
def delete_client(client_id):
    client = RadiusClient.get_by_id(client_id)
    if not client:
        flash('Client not found', 'danger')
        return redirect(url_for('client.list_clients'))
    
    if RadiusClient.delete(client_id):
        log_admin_action(
            current_user.username, 
            'delete_client', 
            f'Deleted RADIUS client {client["shortname"]} ({client["nasname"]})'
        )
        flash(f'Client {client["shortname"]} deleted successfully', 'success')
    else:
        flash('Failed to delete client', 'danger')
    
    return redirect(url_for('client.list_clients'))

@client_bp.route('/rotate-secret/<int:client_id>', methods=['POST'])
@login_required
def rotate_secret(client_id):
    client = RadiusClient.get_by_id(client_id)
    if not client:
        flash('Client not found', 'danger')
        return redirect(url_for('client.list_clients'))
    
    new_secret = rotate_client_secret(client_id)
    
    if new_secret:
        log_admin_action(
            current_user.username, 
            'rotate_client_secret', 
            f'Rotated shared secret for RADIUS client {client["shortname"]}'
        )
        flash(f'Secret for client {client["shortname"]} rotated successfully. New secret: {new_secret}', 'success')
    else:
        flash('Failed to rotate client secret', 'danger')
    
    return redirect(url_for('client.edit_client', client_id=client_id))

# Log management routes
@log_bp.route('/auth')
@login_required
def auth_logs():
    form = LogFilterForm(request.args)
    
    username = request.args.get('username', '')
    status = request.args.get('status', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    logs = AuthLog.get_all(
        limit=per_page,
        offset=(page-1)*per_page,
        username=username,
        status=status,
        start_date=start_date,
        end_date=end_date
    )
    
    total = AuthLog.get_count(
        username=username,
        status=status,
        start_date=start_date,
        end_date=end_date
    )
    
    return render_template(
        'log/auth.html',
        logs=logs,
        form=form,
        page=page,
        per_page=per_page,
        total=total,
        title='Authentication Logs'
    )

@log_bp.route('/audit')
@login_required
def audit_logs():
    admin = request.args.get('admin', '')
    action = request.args.get('action', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    logs = AuditLog.get_logs(
        limit=per_page,
        offset=(page-1)*per_page,
        admin=admin,
        action=action,
        start_date=start_date,
        end_date=end_date
    )
    
    total = AuditLog.get_count(
        admin=admin,
        action=action,
        start_date=start_date,
        end_date=end_date
    )
    
    return render_template(
        'log/audit.html',
        logs=logs,
        admin=admin,
        action=action,
        start_date=start_date,
        end_date=end_date,
        page=page,
        per_page=per_page,
        total=total,
        title='Audit Logs'
    )

# Admin management routes
@admin_bp.route('/')
@login_required
def list_admins():
    if current_user.role != 'admin':
        flash('You do not have permission to manage administrators', 'danger')
        return redirect(url_for('main.dashboard'))
    
    admins = AdminUser.get_all()
    return render_template('admin/list.html', admins=admins, title='Admin Management')

@admin_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_admin():
    if current_user.role != 'admin':
        flash('You do not have permission to create administrators', 'danger')
        return redirect(url_for('main.dashboard'))
    
    form = AdminUserForm()
    
    if form.validate_on_submit():
        if AdminUser.create(
            form.username.data,
            form.password.data,
            form.email.data,
            form.role.data
        ):
            log_admin_action(
                current_user.username, 
                'create_admin', 
                f'Created admin user {form.username.data} with role {form.role.data}'
            )
            flash(f'Admin user {form.username.data} created successfully', 'success')
            return redirect(url_for('admin.list_admins'))
        else:
            flash('Failed to create admin user', 'danger')
    
    return render_template('admin/form.html', form=form, title='Create Admin User')

@admin_bp.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_admin(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to edit administrators', 'danger')
        return redirect(url_for('main.dashboard'))
    
    admin = AdminUser.get_by_id(user_id)
    if not admin:
        flash('Admin user not found', 'danger')
        return redirect(url_for('admin.list_admins'))
    
    form = AdminUserForm(obj=admin)
    
    if form.validate_on_submit():
        if AdminUser.update(
            user_id,
            form.password.data if form.password.data else None,
            form.email.data,
            form.role.data
        ):
            log_admin_action(
                current_user.username, 
                'update_admin', 
                f'Updated admin user {admin.username}'
            )
            flash(f'Admin user {admin.username} updated successfully', 'success')
            return redirect(url_for('admin.list_admins'))
        else:
            flash('Failed to update admin user', 'danger')
    
    # Pre-populate form
    form.username.data = admin.username
    form.email.data = admin.email
    form.role.data = admin.role
    
    return render_template('admin/form.html', form=form, admin=admin, title='Edit Admin User')

@admin_bp.route('/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_admin(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to delete administrators', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Prevent self-deletion
    if user_id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin.list_admins'))
    
    admin = AdminUser.get_by_id(user_id)
    if not admin:
        flash('Admin user not found', 'danger')
        return redirect(url_for('admin.list_admins'))
    
    if AdminUser.delete(user_id):
        log_admin_action(
            current_user.username, 
            'delete_admin', 
            f'Deleted admin user {admin.username}'
        )
        flash(f'Admin user {admin.username} deleted successfully', 'success')
    else:
        flash('Failed to delete admin user', 'danger')
    
    return redirect(url_for('admin.list_admins'))

# Main routes
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def dashboard():
    status = get_system_status()
    return render_template('dashboard.html', status=status, title='Dashboard')

@main_bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='My Profile')

@main_bp.route('/api-keys')
@login_required
def api_keys():
    if current_user.role != 'admin':
        flash('You do not have permission to manage API keys', 'danger')
        return redirect(url_for('main.dashboard'))
    
    return render_template('api/keys.html', title='API Key Management')

@main_bp.route('/api-docs')
@login_required
def api_docs():
    return render_template('api/documentation.html', title='API Documentation')

@main_bp.route('/performance')
@login_required
def performance_dashboard():
    if current_user.role != 'admin':
        flash('You do not have permission to access the performance dashboard', 'danger')
        return redirect(url_for('main.dashboard'))
    
    return render_template('admin/performance.html', title='Performance Dashboard')

@main_bp.route('/monitoring')
@login_required
def monitoring_dashboard():
    if current_user.role != 'admin':
        flash('You do not have permission to access the monitoring dashboard', 'danger')
        return redirect(url_for('main.dashboard'))
    
    return render_template('admin/monitoring.html', title='System Monitoring')

@main_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = PasswordForm()
    
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            if AdminUser.update(current_user.id, form.new_password.data):
                log_admin_action(
                    current_user.username, 
                    'change_password', 
                    'Changed own password'
                )
                flash('Password updated successfully', 'success')
                return redirect(url_for('main.profile'))
            else:
                flash('Failed to update password', 'danger')
        else:
            flash('Current password is incorrect', 'danger')
    
    return render_template('change_password.html', form=form, title='Change Password')

# Error handlers
@main_bp.app_errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@main_bp.app_errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

# Password form for changing password
from wtforms import PasswordField
from wtforms.validators import DataRequired, Length, EqualTo

class PasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])