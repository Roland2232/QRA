#!/usr/bin/env python3
"""
Render-specific configuration for QR Attendance System
PostgreSQL-optimized with comprehensive error handling
"""

import os
from urllib.parse import quote_plus

class RenderConfig:
    """Render deployment configuration - PostgreSQL optimized"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'render-production-secret-key-change-this')
    DEBUG = False
    
    # Database Configuration - PostgreSQL focused
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    # Handle different PostgreSQL URL formats and convert to psycopg3
    if DATABASE_URL:
        # Render sometimes provides postgres:// instead of postgresql://
        if DATABASE_URL.startswith('postgres://'):
            DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql+psycopg://', 1)
        elif DATABASE_URL.startswith('postgresql://'):
            DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)
    else:
        # Fallback construction if DATABASE_URL not provided
        DB_HOST = os.environ.get('DB_HOST', 'localhost')
        DB_USER = os.environ.get('DB_USER', 'postgres')
        DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
        DB_NAME = os.environ.get('DB_NAME', 'qra_attendance')
        DB_PORT = int(os.environ.get('DB_PORT', '5432'))
        
        if DB_PASSWORD:
            password = quote_plus(DB_PASSWORD)
            DATABASE_URL = f'postgresql+psycopg://{DB_USER}:{password}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
        else:
            DATABASE_URL = f'postgresql+psycopg://{DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
    
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'connect_args': {
            'sslmode': 'require'  # Required for Render PostgreSQL
        }
    }
    
    # Email Configuration - Gmail SMTP
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', os.environ.get('MAIL_USERNAME'))
    
    # Server Configuration
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 10000))
    
    # File Upload Configuration - Render uses ephemeral storage
    UPLOAD_FOLDER = '/tmp/uploads'
    QR_CODES_FOLDER = '/tmp/qr_codes'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Security Configuration
    ADMIN_SECRET_CODE = os.environ.get('ADMIN_SECRET_CODE', '23456')
    SESSION_TIMEOUT_MINUTES = 15
    LOCATION_RADIUS_METERS = 300
    
    # Render-specific settings
    RENDER_EXTERNAL_URL = os.environ.get('RENDER_EXTERNAL_URL')
    
    def __init__(self):
        """Ensure required directories exist"""
        os.makedirs(self.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(self.QR_CODES_FOLDER, exist_ok=True)

# Environment variable validation
def validate_render_env():
    """Validate required environment variables for Render"""
    required_vars = {
        'SECRET_KEY': 'Flask secret key for session security',
        'DATABASE_URL': 'PostgreSQL connection string',
        'MAIL_USERNAME': 'Gmail username for sending emails',
        'MAIL_PASSWORD': 'Gmail app password (not regular password)'
    }
    
    missing_vars = []
    for var, description in required_vars.items():
        if not os.environ.get(var):
            missing_vars.append(f"{var} - {description}")
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        return False
    
    print("✅ All required environment variables are set")
    return True

def test_database_connection():
    """Test PostgreSQL database connection"""
    try:
        import psycopg
        from urllib.parse import urlparse
        
        config = RenderConfig()
        url = urlparse(config.DATABASE_URL)
        
        with psycopg.connect(
            host=url.hostname,
            port=url.port,
            user=url.username,
            password=url.password,
            dbname=url.path[1:],  # Remove leading slash
            sslmode='require'
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT version();')
                version = cursor.fetchone()
        
        print(f"✅ PostgreSQL connection successful: {version[0]}")
        return True
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

def test_email_config():
    """Test email configuration"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        
        config = RenderConfig()
        
        if not config.MAIL_USERNAME or not config.MAIL_PASSWORD:
            print("❌ Email credentials not configured")
            return False
        
        # Test SMTP connection
        server = smtplib.SMTP(config.MAIL_SERVER, config.MAIL_PORT)
        server.starttls()
        server.login(config.MAIL_USERNAME, config.MAIL_PASSWORD)
        server.quit()
        
        print("✅ Email configuration successful")
        return True
        
    except Exception as e:
        print(f"❌ Email configuration failed: {e}")
        return False

if __name__ == "__main__":
    print("🔧 RENDER DEPLOYMENT CONFIGURATION CHECK")
    print("="*60)
    
    config = RenderConfig()
    print(f"Database URL: {config.SQLALCHEMY_DATABASE_URI[:50]}...")
    print(f"Mail Username: {config.MAIL_USERNAME}")
    print(f"Port: {config.PORT}")
    print(f"Upload Folder: {config.UPLOAD_FOLDER}")
    print(f"Admin Secret Code: {'*' * len(config.ADMIN_SECRET_CODE) if config.ADMIN_SECRET_CODE else 'Not set'}")
    
    print("\n🔍 VALIDATION CHECKS")
    print("-" * 30)
    
    env_valid = validate_render_env()
    
    if env_valid:
        print("\n📊 CONNECTION TESTS")
        print("-" * 20)
        test_database_connection()
        test_email_config()
    
    print("="*60) 