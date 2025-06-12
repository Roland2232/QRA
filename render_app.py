#!/usr/bin/env python3
"""
Render-compatible version of QR Attendance System
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import qrcode
import numpy as np
import json
import os
import secrets
import string
from datetime import datetime, timedelta
from PIL import Image
from geopy.distance import geodesic
import pymysql
from models import db, Admin, Teacher, Course, Student, AttendanceSession, Attendance
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from functools import wraps
from render_config import RenderConfig

def create_app():
    """Application factory for Render deployment"""
    app = Flask(__name__)
    
    # Load Render configuration
    config = RenderConfig()
    
    # Configure Flask app
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.SQLALCHEMY_TRACK_MODIFICATIONS
    
    # Email Configuration
    app.config['MAIL_SERVER'] = config.MAIL_SERVER
    app.config['MAIL_PORT'] = config.MAIL_PORT
    app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
    app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
    app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
    app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_DEFAULT_SENDER
    
    # File Upload Configuration
    app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
    
    # Server Configuration
    app.config['SERVER_NAME'] = None  # Allow flexible host names
    app.config['RENDER_EXTERNAL_URL'] = config.RENDER_EXTERNAL_URL
    app.config['ADMIN_SECRET_CODE'] = config.ADMIN_SECRET_CODE
    
    # Initialize extensions
    db.init_app(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    mail = Mail(app)
    
    # Ensure directories exist
    os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(config.QR_CODES_FOLDER, exist_ok=True)
    
    def teacher_password_required(f):
        """Decorator to ensure teacher has changed their initial password"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if isinstance(current_user, Teacher) and current_user.must_change_password:
                flash('You must change your password before accessing this feature', 'warning')
                return redirect(url_for('change_password'))
            return f(*args, **kwargs)
        return decorated_function

    @login_manager.user_loader
    def load_user(user_id):
        user = Admin.query.get(user_id)
        if user:
            return user
        return Teacher.query.get(user_id)

    # Utility Functions
    def generate_password(length=12):
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(characters) for _ in range(length))

    def send_email(to, subject, template, **kwargs):
        msg = Message(
            subject=subject,
            recipients=[to],
            html=template,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        try:
            mail.send(msg)
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False

    def generate_qr_code(data, filename):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        filepath = os.path.join(config.QR_CODES_FOLDER, filename)
        img.save(filepath)
        return filepath

    def calculate_distance(lat1, lon1, lat2, lon2):
        return geodesic((lat1, lon1), (lat2, lon2)).meters

    def get_external_url(endpoint, **values):
        """Generate external URL using Render's external URL"""
        with app.test_request_context():
            path = url_for(endpoint, **values)
        
        # Use Render's external URL if available
        base_url = config.RENDER_EXTERNAL_URL or request.host_url.rstrip('/')
        return f"{base_url}{path}"

    # Make external URL function available in templates
    @app.template_global()
    def external_url(endpoint, **values):
        """Template global function for generating external URLs"""
        return get_external_url(endpoint, **values)

    # Routes
    @app.route('/')
    def index():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            login_type = request.form.get('login_type')
            
            if login_type == 'admin':
                secret_code = request.form.get('secret_code')
                if secret_code == app.config['ADMIN_SECRET_CODE']:
                    # Create or get admin user
                    admin = Admin.query.filter_by(username='admin').first()
                    if not admin:
                        admin = Admin(
                            id='admin001',
                            username='admin',
                            email='admin@system.local',
                            password_hash=generate_password_hash('admin123')
                        )
                        db.session.add(admin)
                        db.session.commit()
                    
                    login_user(admin)
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Invalid admin secret code', 'error')
            
            elif login_type == 'teacher':
                username = request.form.get('username')
                password = request.form.get('password')
                
                teacher = Teacher.query.filter_by(username=username).first()
                if teacher and check_password_hash(teacher.password_hash, password):
                    login_user(teacher)
                    return redirect(url_for('teacher_dashboard'))
                else:
                    flash('Invalid username or password', 'error')
        
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/admin/dashboard')
    @login_required
    def admin_dashboard():
        if not isinstance(current_user, Admin):
            flash('Access denied', 'error')
            return redirect(url_for('login'))
        
        teachers = Teacher.query.all()
        return render_template('admin_dashboard.html', teachers=teachers)

    @app.route('/teacher/dashboard')
    @login_required
    @teacher_password_required
    def teacher_dashboard():
        if not isinstance(current_user, Teacher):
            flash('Access denied', 'error')
            return redirect(url_for('login'))
        
        courses = Course.query.filter_by(teacher_id=current_user.id).all()
        return render_template('teacher_dashboard.html', courses=courses)

    @app.route('/health')
    def health_check():
        """Health check endpoint for Render"""
        return {'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}

    # Create database tables
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database tables created successfully")
        except Exception as e:
            print(f"❌ Error creating database tables: {e}")

    return app

# Create the Flask application
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False) 