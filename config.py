#!/usr/bin/env python3
"""
Configuration file for QR Attendance System
Easily configurable settings for different deployment environments
"""

import os
from urllib.parse import quote_plus

class Config:
    """Base configuration class"""
    
    # Database Configuration
    # Update these settings when transferring to another computer
    DB_HOST = os.environ.get('DB_HOST', 'localhost')  # Change to MySQL server IP when needed
    DB_USER = os.environ.get('DB_USER', 'remi')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '1234')
    DB_NAME = os.environ.get('DB_NAME', 'Qra')
    DB_PORT = int(os.environ.get('DB_PORT', '3307'))
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    # Email Configuration (Gmail SMTP)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'notorios2003@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'ckqy wnqy ufqy wnqy')  # App password
    
    # Network Configuration
    HOST = os.environ.get('FLASK_HOST', '0.0.0.0')  # Listen on all interfaces
    PORT = int(os.environ.get('FLASK_PORT', '5000'))
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
    QR_CODES_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'qr_codes')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Security Configuration
    ADMIN_SECRET_CODE = os.environ.get('ADMIN_SECRET_CODE', '23456')
    SESSION_TIMEOUT_MINUTES = 15  # Attendance session timeout
    LOCATION_RADIUS_METERS = 300  # Attendance location radius
    
    @property
    def SQLALCHEMY_DATABASE_URI(self):
        """Generate SQLAlchemy database URI"""
        password = quote_plus(self.DB_PASSWORD)
        return f'mysql+pymysql://{self.DB_USER}:{password}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}'
    
    @property
    def PYMYSQL_CONFIG(self):
        """Generate PyMySQL connection config"""
        return {
            'host': self.DB_HOST,
            'user': self.DB_USER,
            'password': self.DB_PASSWORD,
            'database': self.DB_NAME,
            'port': self.DB_PORT,
            'charset': 'utf8mb4'
        }
    
    def __init__(self):
        """Ensure required directories exist"""
        os.makedirs(self.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(self.QR_CODES_FOLDER, exist_ok=True)

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    
class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'production-secret-key-change-me'

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DB_NAME = 'Qra_test'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])()

# Create default config instance
app_config = get_config()

# Helper function to update database host for different computers
def update_database_host(new_host):
    """
    Update database host for deployment on different computers
    
    Args:
        new_host (str): New database host IP or hostname
    
    Example:
        update_database_host('192.168.1.100')  # For different computer on network
        update_database_host('myserver.com')   # For remote server
    """
    global app_config
    app_config.DB_HOST = new_host
    print(f"✅ Database host updated to: {new_host}")
    print(f"🔗 New connection string: {app_config.SQLALCHEMY_DATABASE_URI}")

if __name__ == "__main__":
    # Display current configuration
    config = get_config()
    print("🔧 QR ATTENDANCE SYSTEM - CONFIGURATION")
    print("="*50)
    print(f"Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"Database Host: {config.DB_HOST}")
    print(f"Database Port: {config.DB_PORT}")
    print(f"Database Name: {config.DB_NAME}")
    print(f"Database User: {config.DB_USER}")
    print(f"Flask Host: {config.HOST}")
    print(f"Flask Port: {config.PORT}")
    print(f"Debug Mode: {config.DEBUG}")
    print("="*50)
    print(f"📋 Connection URI: {config.SQLALCHEMY_DATABASE_URI}")
    print("\n💡 To change database host for different computer:")
    print("   python config.py")
    print("   >>> from config import update_database_host")
    print("   >>> update_database_host('NEW_IP_ADDRESS')") 