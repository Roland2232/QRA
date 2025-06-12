#!/usr/bin/env python3
"""
Render-specific configuration for QR Attendance System
"""

import os
from urllib.parse import quote_plus

class RenderConfig:
    """Render deployment configuration"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'render-production-secret-key')
    DEBUG = False
    
    # Database Configuration - Render supports PostgreSQL by default
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    # If DATABASE_URL is not set, construct from individual components
    if not DATABASE_URL:
        DB_HOST = os.environ.get('DB_HOST', 'localhost')
        DB_USER = os.environ.get('DB_USER', 'postgres')
        DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
        DB_NAME = os.environ.get('DB_NAME', 'qra_attendance')
        DB_PORT = int(os.environ.get('DB_PORT', '5432'))
        
        if DB_PASSWORD:
            password = quote_plus(DB_PASSWORD)
            DATABASE_URL = f'postgresql://{DB_USER}:{password}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
        else:
            DATABASE_URL = f'postgresql://{DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
    
    # Handle Render's PostgreSQL URL format
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', os.environ.get('MAIL_USERNAME'))
    
    # Server Configuration
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 10000))
    
    # File Upload Configuration
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
    required_vars = [
        'SECRET_KEY',
        'DATABASE_URL',
        'MAIL_USERNAME',
        'MAIL_PASSWORD'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        return False
    
    print("✅ All required environment variables are set")
    return True

if __name__ == "__main__":
    print("🔧 RENDER DEPLOYMENT CONFIGURATION")
    print("="*50)
    config = RenderConfig()
    print(f"Database URL: {config.SQLALCHEMY_DATABASE_URI[:50]}...")
    print(f"Mail Username: {config.MAIL_USERNAME}")
    print(f"Port: {config.PORT}")
    print(f"Upload Folder: {config.UPLOAD_FOLDER}")
    print("="*50)
    validate_render_env() 