import os
import ssl
from flask import Flask, render_template, jsonify, redirect, url_for
from flask_login import LoginManager, current_user
from werkzeug.middleware.proxy_fix import ProxyFix

from .models import AdminUser
from .routes import (
    auth_bp, user_bp, totp_bp, client_bp, admin_bp, log_bp, main_bp
)
from .api_routes import api_bp
from .backup_routes import backup_bp
from .utils import create_admin_user_if_not_exists, log_admin_action
from .performance import init_app as init_performance_monitoring
from .db_utils import optimize_database

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    app.config['SQLITE_DB'] = os.environ.get('SQLITE_DB', '/data/sqlite/radius.db')
    app.config['USE_SSL'] = os.environ.get('USE_SSL', 'false').lower() == 'true'
    app.config['BACKUP_DIR'] = os.environ.get('BACKUP_DIR', '/data/backups')
    app.config['TEMP_DIR'] = os.environ.get('TEMP_DIR', '/tmp')
    
    # Create backup directory if it doesn't exist
    os.makedirs(app.config['BACKUP_DIR'], exist_ok=True)
    
    # Handle reverse proxies
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return AdminUser.get_by_id(int(user_id))
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/users')
    app.register_blueprint(totp_bp, url_prefix='/totp')
    app.register_blueprint(client_bp, url_prefix='/clients')
    app.register_blueprint(admin_bp, url_prefix='/admins')
    app.register_blueprint(log_bp, url_prefix='/logs')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(backup_bp, url_prefix='/backups')
    app.register_blueprint(main_bp)
    
    # Redirect root to dashboard if logged in, otherwise to login
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('main.dashboard'))
        return redirect(url_for('auth.login'))
    
    # Create default admin user if not exists
    admin_user = os.environ.get('ADMIN_USER', 'admin')
    admin_password = os.environ.get('ADMIN_PASSWORD_HASH', 'changeme')
    create_admin_user_if_not_exists(admin_user, admin_password)
    
    # Create template and static directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Initialize performance monitoring
    init_performance_monitoring(app)
    
    # Optimize database on startup
    try:
        optimize_database()
    except Exception as e:
        print(f"Database optimization failed: {e}")
    
    return app

app = create_app()

if __name__ == '__main__':
    if app.config['USE_SSL']:
        # SSL configuration
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert_path = os.environ.get('SSL_CERT', '/app/ssl/cert.pem')
        key_path = os.environ.get('SSL_KEY', '/app/ssl/key.pem')
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            context.load_cert_chain(cert_path, key_path)
            app.run(host='0.0.0.0', port=8080, ssl_context=context, debug=True)
        else:
            print("SSL certificates not found. Running without SSL.")
            app.run(host='0.0.0.0', port=8080, debug=True)
    else:
        app.run(host='0.0.0.0', port=8080, debug=True)