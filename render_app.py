#!/usr/bin/env python3
"""
Render-compatible version of QR Attendance System
PostgreSQL-optimized with comprehensive validation and security
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
import re
from datetime import datetime, timedelta
from PIL import Image
from geopy.distance import geodesic
from models import db, Admin, Teacher, Course, Student, AttendanceSession, Attendance
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from functools import wraps
from render_config import RenderConfig, validate_render_env
from render_validation import FormValidator, validate_form_data, sanitize_all_inputs

def create_app():
    """Application factory for Render deployment with enhanced security"""
    app = Flask(__name__)
    
    # Load Render configuration
    config = RenderConfig()
    
    # Configure Flask app
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config.SQLALCHEMY_TRACK_MODIFICATIONS
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = config.SQLALCHEMY_ENGINE_OPTIONS
    
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
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            print("❌ Email not configured - skipping email send")
            return False
            
        msg = Message(
            subject=subject,
            recipients=[to],
            html=template,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        try:
            mail.send(msg)
            print(f"✅ Email sent successfully to {to}")
            return True
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
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
        
        # Use Render's external URL if available, otherwise use request host
        if config.RENDER_EXTERNAL_URL:
            base_url = config.RENDER_EXTERNAL_URL.rstrip('/')
        else:
            base_url = request.host_url.rstrip('/')
        return f"{base_url}{path}"

    # Make external URL function available in templates
    @app.template_global()
    def external_url(endpoint, **values):
        """Template global function for generating external URLs"""
        return get_external_url(endpoint, **values)

    # Routes with Enhanced Validation
    @app.route('/')
    def index():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            # Sanitize all inputs
            form_data = sanitize_all_inputs(request.form.to_dict())
            login_type = form_data.get('login_type')
            
            if login_type == 'admin':
                # Validate admin login
                is_valid, errors = validate_form_data(form_data, 'admin_login')
                if not is_valid:
                    for field, error in errors.items():
                        flash(f'{error}', 'error')
                    return render_template('login.html')
                
                secret_code = form_data.get('secret_code')
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
                        try:
                            db.session.commit()
                            print("✅ Admin user created successfully")
                        except Exception as e:
                            print(f"❌ Error creating admin user: {e}")
                            db.session.rollback()
                            flash('Database error - please try again', 'error')
                            return render_template('login.html')
                    
                    login_user(admin)
                    flash('Admin access granted', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Invalid admin secret code', 'error')
            
            elif login_type == 'teacher':
                # Validate teacher login
                is_valid, errors = validate_form_data(form_data, 'teacher_login')
                if not is_valid:
                    for field, error in errors.items():
                        flash(f'{error}', 'error')
                    return render_template('login.html')
                
                username = form_data.get('username')
                password = form_data.get('password')
                
                teacher = Teacher.query.filter_by(username=username).first()
                if teacher and check_password_hash(teacher.password_hash, password):
                    login_user(teacher)
                    
                    if teacher.must_change_password:
                        flash('You must change your password before continuing', 'warning')
                        return redirect(url_for('change_password'))
                    
                    flash('Welcome back!', 'success')
                    return redirect(url_for('teacher_dashboard'))
                else:
                    flash('Invalid username or password', 'error')
        
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out successfully', 'info')
        return redirect(url_for('login'))

    @app.route('/change_password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        if not isinstance(current_user, Teacher):
            flash('Access denied', 'error')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            # Sanitize and validate inputs
            form_data = sanitize_all_inputs(request.form.to_dict())
            is_valid, errors = validate_form_data(form_data, 'change_password')
            
            if not is_valid:
                for field, error in errors.items():
                    flash(f'{error}', 'error')
                return render_template('change_password.html')
            
            current_password = form_data.get('current_password')
            new_password = form_data.get('new_password')
            
            if not check_password_hash(current_user.password_hash, current_password):
                flash('Current password is incorrect', 'error')
                return render_template('change_password.html')
            
            # Update password
            current_user.password_hash = generate_password_hash(new_password)
            current_user.must_change_password = False
            
            try:
                db.session.commit()
                flash('Password changed successfully!', 'success')
                return redirect(url_for('teacher_dashboard'))
            except Exception as e:
                db.session.rollback()
                flash('Error changing password - please try again', 'error')
        
        return render_template('change_password.html')

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

    @app.route('/teacher/create_course', methods=['GET', 'POST'])
    @login_required
    @teacher_password_required
    def create_course():
        if not isinstance(current_user, Teacher):
            flash('Access denied', 'error')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            # Sanitize and validate inputs
            form_data = sanitize_all_inputs(request.form.to_dict())
            
            # Enhanced validation for course creation
            validator = FormValidator()
            errors = []
            
            course_name = form_data.get('course_name', '').strip()
            is_valid, message = validator.validate_name(course_name)
            if not is_valid:
                errors.append(f'Course name: {message}')
            
            course_code = form_data.get('course_code', '').strip().upper()
            if not course_code:
                errors.append('Course code is required')
            elif len(course_code) < 3 or len(course_code) > 20:
                errors.append('Course code must be between 3 and 20 characters')
            elif not re.match(r'^[A-Z0-9\-]+$', course_code):
                errors.append('Course code can only contain letters, numbers, and hyphens')
            
            if errors:
                for error in errors:
                    flash(error, 'error')
                return render_template('create_course.html')
            
            # Check if course code already exists for this teacher
            existing_course = Course.query.filter_by(
                course_code=course_code, 
                teacher_id=current_user.id
            ).first()
            
            if existing_course:
                flash('Course code already exists for your courses', 'error')
                return render_template('create_course.html')
            
            description = form_data.get('description', '')
            
            course = Course(
                course_name=course_name,
                course_code=course_code,
                description=description,
                teacher_id=current_user.id
            )
            
            try:
                db.session.add(course)
                db.session.commit()
                
                # Generate QR code for student registration
                registration_url = get_external_url('student_registration', course_id=course.id)
                qr_filename = f'registration_{course.id}.png'
                generate_qr_code(registration_url, qr_filename)
                
                course.registration_qr_code = qr_filename
                db.session.commit()
                
                flash('Course created successfully!', 'success')
                return redirect(url_for('teacher_dashboard'))
            except Exception as e:
                db.session.rollback()
                flash('Error creating course - please try again', 'error')
        
        return render_template('create_course.html')

    @app.route('/teacher/course/<course_id>')
    @login_required
    @teacher_password_required
    def course_details(course_id):
        course = Course.query.get_or_404(course_id)
        
        if course.teacher_id != current_user.id:
            flash('Access denied', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        students = Student.query.filter_by(course_id=course_id).all()
        sessions = AttendanceSession.query.filter_by(course_id=course_id).order_by(AttendanceSession.created_at.desc()).all()
        
        return render_template('course_details.html', course=course, students=students, sessions=sessions)

    @app.route('/health')
    def health_check():
        """Health check endpoint for Render"""
        try:
            # Test database connection
            db.session.execute('SELECT 1')
            db_status = "healthy"
        except Exception as e:
            db_status = f"error: {str(e)}"
        
        return {
            'status': 'healthy' if db_status == "healthy" else 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': db_status,
            'email_configured': bool(app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']),
            'validation_enabled': True
        }

    @app.route('/admin/create_teacher', methods=['GET', 'POST'])
    @login_required
    def create_teacher():
        if not isinstance(current_user, Admin):
            flash('Access denied', 'error')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            # Sanitize and validate inputs
            form_data = sanitize_all_inputs(request.form.to_dict())
            is_valid, errors = validate_form_data(form_data, 'create_teacher')
            
            if not is_valid:
                for field, error in errors.items():
                    flash(f'{error}', 'error')
                return render_template('create_teacher.html')
            
            username = form_data.get('username')
            email = form_data.get('email')
            full_name = form_data.get('full_name')
            
            # Check for existing username and email
            if Teacher.query.filter_by(username=username).first():
                flash('Username already exists', 'error')
                return render_template('create_teacher.html')
                
            if Teacher.query.filter_by(email=email).first():
                flash('Email already exists', 'error')
                return render_template('create_teacher.html')
            
            # Generate random password
            temp_password = generate_password()
            
            # Create teacher
            teacher = Teacher(
                username=username,
                email=email,
                full_name=full_name,
                password_hash=generate_password_hash(temp_password),
                created_by=current_user.id
            )
            
            try:
                db.session.add(teacher)
                db.session.commit()
                
                # Send email with credentials
                email_template = f"""
                <h2>Welcome to QR Attendance System</h2>
                <p>Hello {full_name},</p>
                <p>Your teacher account has been created. Here are your login credentials:</p>
                
                <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>Username:</strong> {username}</p>
                    <p><strong>Temporary Password:</strong> {temp_password}</p>
                </div>
                
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 5px;">
                    <h4 style="color: #856404; margin-top: 0;">⚠️ Important Security Notice</h4>
                    <p style="color: #856404; margin-bottom: 0;">
                        <strong>You must change your password when you first login.</strong> 
                        The system will automatically redirect you to change your password for security purposes.
                    </p>
                </div>
                
                <p>Login URL: {get_external_url('login')}</p>
                <p>For mobile access, scan QR codes from your phone!</p>
                """
                
                if send_email(email, "QR Attendance System - Account Created", email_template):
                    flash(f'Teacher {full_name} created successfully! Credentials sent to {email}', 'success')
                else:
                    flash(f'Teacher {full_name} created successfully! Please manually share credentials: Username: {username}, Password: {temp_password}', 'warning')
                
                return redirect(url_for('admin_dashboard'))
                
            except Exception as e:
                db.session.rollback()
                print(f"❌ Error creating teacher: {e}")
                flash('Error creating teacher - please try again', 'error')
        
        return render_template('create_teacher.html')

    @app.route('/student/register/<course_id>', methods=['GET', 'POST'])
    def student_registration(course_id):
        course = Course.query.get_or_404(course_id)
        
        if request.method == 'POST':
            # Sanitize and validate inputs
            form_data = sanitize_all_inputs(request.form.to_dict())
            is_valid, errors = validate_form_data(form_data, 'student_registration')
            
            if not is_valid:
                error_messages = []
                for field, error in errors.items():
                    error_messages.append(error)
                return jsonify({'error': '; '.join(error_messages)}), 400
            
            name = form_data['name']
            matricule = form_data['matricule'].lower()  # Ensure lowercase for consistency
            sex = form_data['sex']
            
            # Check if student is already registered for THIS specific course
            existing_registration = Student.query.filter_by(matricule=matricule, course_id=course_id).first()
            if existing_registration:
                return jsonify({'error': 'You are already registered for this course'}), 400
            
            # Check if student exists in other courses to get consistent name/sex
            existing_student = Student.query.filter_by(matricule=matricule).first()
            if existing_student:
                # Use existing student's name and sex for consistency
                if existing_student.name != name or existing_student.sex != sex:
                    return jsonify({
                        'error': f'Student with matricule {matricule} already exists with different details. Please use: Name: {existing_student.name}, Sex: {existing_student.sex}'
                    }), 400
            
            # Create new registration for this course
            student = Student(
                name=name,
                matricule=matricule,
                sex=sex,
                course_id=course_id
            )
            
            try:
                db.session.add(student)
                db.session.commit()
                
                # Get student's total course count for response
                total_courses = Student.query.filter_by(matricule=matricule).count()
                
                return jsonify({
                    'success': f'Registration successful! You are now registered for {total_courses} course(s).',
                    'student_name': name,
                    'matricule': matricule,
                    'course_name': course.course_name
                })
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Registration failed: {str(e)}'}), 500
        
        return render_template('student_registration.html', course=course)

    @app.route('/attendance/<session_id>', methods=['GET', 'POST'])
    def take_attendance(session_id):
        session = AttendanceSession.query.get_or_404(session_id)
        
        # Check if session is expired
        if session.is_expired():
            return render_template('error.html', 
                                 message=f'This attendance session has expired. Sessions are only valid for 15 minutes.')
        
        if not session.is_active:
            return render_template('error.html', message='This attendance session is no longer active')
        
        course = Course.query.get(session.course_id)
        students = Student.query.filter_by(course_id=course.id).all()
        
        if request.method == 'POST':
            # Sanitize and validate inputs
            form_data = sanitize_all_inputs(request.form.to_dict())
            
            # Enhanced validation for attendance
            validator = FormValidator()
            errors = []
            
            selected_matricule = form_data.get('selected_matricule', '').strip()
            if not selected_matricule:
                errors.append('Please select your matricule')
            
            # Validate location coordinates
            try:
                student_latitude = float(form_data.get('latitude', 0))
                student_longitude = float(form_data.get('longitude', 0))
                
                if not (-90 <= student_latitude <= 90):
                    errors.append('Invalid latitude coordinate')
                if not (-180 <= student_longitude <= 180):
                    errors.append('Invalid longitude coordinate')
            except (ValueError, TypeError):
                errors.append('Invalid location coordinates')
                return jsonify({'error': 'Invalid location data provided'}), 400
            
            if errors:
                return jsonify({'error': '; '.join(errors)}), 400
            
            # Find student by matricule in this course
            student = Student.query.filter_by(matricule=selected_matricule, course_id=course.id).first()
            if not student:
                return jsonify({'error': 'Invalid matricule selection'}), 400
            
            # Check if student already marked attendance
            existing_attendance = Attendance.query.filter_by(
                student_id=student.id,
                session_id=session_id
            ).first()
            
            if existing_attendance:
                return jsonify({'error': 'Attendance already marked for this session'}), 400
            
            # Verify location (within specified radius)
            if session.latitude and session.longitude:
                distance = calculate_distance(
                    float(session.latitude), float(session.longitude),
                    student_latitude, student_longitude
                )
                
                if distance > session.radius_meters:
                    return jsonify({
                        'error': f'You are {distance:.0f}m away from the class location. Please move closer (within {session.radius_meters}m)'
                    }), 400
            
            # Mark attendance
            attendance = Attendance(
                student_id=student.id,
                session_id=session_id,
                latitude=student_latitude,
                longitude=student_longitude
            )
            
            try:
                db.session.add(attendance)
                db.session.commit()
                
                return jsonify({
                    'success': f'Attendance marked successfully!',
                    'student_name': student.name,
                    'student_matricule': student.matricule,
                    'student_sex': student.sex,
                    'time_remaining': session.minutes_remaining()
                })
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to mark attendance: {str(e)}'}), 500
        
        return render_template('take_attendance.html', session=session, course=course, students=students)

    @app.route('/teacher/create_attendance_session/<course_id>', methods=['GET', 'POST'])
    @login_required
    @teacher_password_required
    def create_attendance_session(course_id):
        course = Course.query.get_or_404(course_id)
        
        if course.teacher_id != current_user.id:
            flash('Access denied', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        if request.method == 'POST':
            # Sanitize and validate inputs
            form_data = sanitize_all_inputs(request.form.to_dict())
            
            # Enhanced validation for session creation
            validator = FormValidator()
            errors = []
            
            session_name = form_data.get('session_name', '').strip()
            if not session_name:
                errors.append('Session name is required')
            elif len(session_name) < 3:
                errors.append('Session name must be at least 3 characters long')
            elif len(session_name) > 100:
                errors.append('Session name must not exceed 100 characters')
            elif not re.match(r'^[a-zA-Z0-9\s\-_.,()]+$', session_name):
                errors.append('Session name contains invalid characters')
            
            # Validate location coordinates
            try:
                latitude = float(form_data.get('latitude', 0))
                longitude = float(form_data.get('longitude', 0))
                
                if not (-90 <= latitude <= 90):
                    errors.append('Invalid latitude. Must be between -90 and 90')
                if not (-180 <= longitude <= 180):
                    errors.append('Invalid longitude. Must be between -180 and 180')
            except (ValueError, TypeError):
                errors.append('Invalid location coordinates provided')
                return render_template('create_attendance_session.html', course=course)
            
            # Validate radius
            try:
                radius = int(form_data.get('radius', 300))
                if radius < 50 or radius > 1000:
                    errors.append('Radius must be between 50 and 1000 meters')
            except (ValueError, TypeError):
                radius = 300
            
            if errors:
                for error in errors:
                    flash(error, 'error')
                return render_template('create_attendance_session.html', course=course)
            
            # Create attendance session with 15-minute expiry
            expires_at = datetime.utcnow() + timedelta(minutes=15)
            
            session = AttendanceSession(
                session_name=session_name,
                course_id=course_id,
                latitude=latitude,
                longitude=longitude,
                radius_meters=radius,
                expires_at=expires_at,
                is_active=True
            )
            
            try:
                db.session.add(session)
                db.session.commit()
                
                # Generate QR code for the session
                qr_data = get_external_url('take_attendance', session_id=session.id)
                qr_filename = f'session_{session.id}.png'
                generate_qr_code(qr_data, qr_filename)
                
                session.qr_code_path = qr_filename
                db.session.commit()
                
                flash(f'Attendance session created successfully! Valid for 15 minutes until {expires_at.strftime("%H:%M")}', 'success')
                return redirect(url_for('course_details', course_id=course_id))
            except Exception as e:
                db.session.rollback()
                flash('Error creating session - please try again', 'error')
        
        current_date = datetime.now().strftime('%Y-%m-%d')
        return render_template('create_attendance_session.html', course=course, current_date=current_date)

    @app.route('/teacher/end_session/<session_id>')
    @login_required
    @teacher_password_required
    def end_attendance_session(session_id):
        session = AttendanceSession.query.get_or_404(session_id)
        course = Course.query.get(session.course_id)
        
        if course.teacher_id != current_user.id:
            flash('Access denied', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        session.is_active = False
        
        try:
            db.session.commit()
            flash(f'Attendance session "{session.session_name}" has been ended', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error ending session - please try again', 'error')
        
        return redirect(url_for('course_details', course_id=session.course_id))

    @app.route('/student/profile/<matricule>')
    def student_profile(matricule):
        """View all courses a student is registered for"""
        # Validate matricule format
        validator = FormValidator()
        matricule = matricule.strip().lower()
        is_valid, message = validator.validate_matricule(matricule)
        
        if not is_valid:
            return render_template('error.html', message=f'Invalid matricule format: {message}')
        
        student_registrations = Student.query.filter_by(matricule=matricule).all()
        
        if not student_registrations:
            return render_template('error.html', message='No student found with this matricule')
        
        # Get the student's basic info from first registration
        student_info = student_registrations[0]
        
        # Get all courses the student is registered for
        courses = []
        for registration in student_registrations:
            course = Course.query.get(registration.course_id)
            if course:
                teacher = Teacher.query.get(course.teacher_id)
                
                # Get attendance records for this student in this course
                attendance_records = Attendance.query.join(AttendanceSession).filter(
                    Attendance.student_id == registration.id,
                    AttendanceSession.course_id == course.id
                ).all()
                
                courses.append({
                    'course': course,
                    'teacher': teacher,
                    'registration_date': registration.registered_at,
                    'attendance_count': len(attendance_records)
                })
        
        return render_template('student_profile.html', 
                             student_info=student_info, 
                             courses=courses,
                             total_courses=len(courses))

    @app.route('/teacher/course_analytics/<course_id>')
    @login_required
    @teacher_password_required
    def course_analytics(course_id):
        course = Course.query.get_or_404(course_id)
        
        if course.teacher_id != current_user.id:
            flash('Access denied', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        # Get all students and sessions for this course
        students = Student.query.filter_by(course_id=course_id).all()
        sessions = AttendanceSession.query.filter_by(course_id=course_id).order_by(AttendanceSession.created_at.desc()).all()
        
        # Calculate analytics
        total_students = len(students)
        total_sessions = len(sessions)
        
        # Gender distribution
        male_students = len([s for s in students if s.sex == 'Male'])
        female_students = len([s for s in students if s.sex == 'Female'])
        
        # Attendance statistics
        attendance_data = []
        student_attendance = {}
        
        for session in sessions:
            attendances = Attendance.query.filter_by(session_id=session.id).all()
            attendance_count = len(attendances)
            attendance_rate = (attendance_count / total_students * 100) if total_students > 0 else 0
            
            attendance_data.append({
                'session': session,
                'attendance_count': attendance_count,
                'attendance_rate': round(attendance_rate, 1)
            })
            
            # Track individual student attendance
            for attendance in attendances:
                student = Student.query.get(attendance.student_id)
                if student and student.matricule not in student_attendance:
                    student_attendance[student.matricule] = {
                        'student': student,
                        'sessions_attended': 0,
                        'attendance_rate': 0
                    }
                if student:
                    student_attendance[student.matricule]['sessions_attended'] += 1
        
        # Calculate individual attendance rates
        for matricule, data in student_attendance.items():
            data['attendance_rate'] = round((data['sessions_attended'] / total_sessions * 100) if total_sessions > 0 else 0, 1)
        
        return render_template('course_analytics.html',
                             course=course,
                             students=students,
                             sessions=sessions,
                             attendance_data=attendance_data,
                             student_attendance=student_attendance,
                             total_students=total_students,
                             total_sessions=total_sessions,
                             male_students=male_students,
                             female_students=female_students)

    @app.route('/teacher/export_attendance/<session_id>/<format>')
    @login_required
    @teacher_password_required
    def export_attendance(session_id, format):
        session = AttendanceSession.query.get_or_404(session_id)
        course = Course.query.get(session.course_id)
        
        if course.teacher_id != current_user.id:
            flash('Access denied', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        # Validate format
        if format.lower() not in ['excel', 'pdf']:
            flash('Invalid export format', 'error')
            return redirect(url_for('course_details', course_id=course.id))
        
        # Get attendance data
        attendances = Attendance.query.filter_by(session_id=session_id).all()
        students = Student.query.filter_by(course_id=course.id).all()
        
        # Prepare data
        attendance_data = []
        for student in students:
            attendance = next((a for a in attendances if a.student_id == student.id), None)
            attendance_data.append({
                'Name': student.name,
                'Matricule': student.matricule,
                'Sex': student.sex,
                'Status': 'Present' if attendance else 'Absent',
                'Time': attendance.marked_at.strftime('%Y-%m-%d %H:%M:%S') if attendance else 'N/A'
            })
        
        if format.lower() == 'excel':
            return export_to_excel(attendance_data, session, course)
        elif format.lower() == 'pdf':
            return export_to_pdf(attendance_data, session, course)

    @app.route('/mobile-test')
    def mobile_test():
        """Simple test page to verify mobile access"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Mobile Test - QR Attendance</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    padding: 20px; 
                    text-align: center; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    min-height: 100vh;
                    margin: 0;
                }}
                .container {{
                    max-width: 400px;
                    margin: 0 auto;
                    background: white;
                    color: #333;
                    padding: 30px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                }}
                .success {{ 
                    color: #28a745; 
                    font-size: 24px; 
                    margin: 20px 0; 
                    font-weight: bold;
                }}
                .info {{ 
                    background: #f8f9fa; 
                    padding: 20px; 
                    border-radius: 10px; 
                    margin: 20px 0; 
                    border-left: 4px solid #007bff;
                }}
                .btn {{
                    background: #007bff;
                    color: white;
                    padding: 12px 24px;
                    border: none;
                    border-radius: 25px;
                    text-decoration: none;
                    display: inline-block;
                    margin: 10px;
                    font-size: 16px;
                    transition: all 0.3s;
                }}
                .btn:hover {{
                    background: #0056b3;
                    transform: translateY(-2px);
                }}
                h1 {{ margin-top: 0; }}
                @media (max-width: 480px) {{
                    body {{ padding: 10px; }}
                    .container {{ padding: 20px; }}
                    .success {{ font-size: 20px; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📱 Mobile Access Test</h1>
                <div class="success">✅ SUCCESS!</div>
                <p>Your mobile device can access this server!</p>
                
                <div class="info">
                    <h3>🌐 Connection Details</h3>
                    <p><strong>Server:</strong> Render Cloud Platform</p>
                    <p><strong>Status:</strong> ✅ Connected</p>
                    <p><strong>Validation:</strong> ✅ Enhanced Security Enabled</p>
                </div>
                
                <div class="info">
                    <h3>📋 Next Steps</h3>
                    <p>1. Login with admin secret code</p>
                    <p>2. Create teacher accounts with email verification</p>
                    <p>3. Generate QR codes for courses</p>
                    <p>4. Students can scan & register from their phones!</p>
                </div>
                
                <a href="/" class="btn">🚀 Go to Login</a>
            </div>
        </body>
        </html>
        """

    def export_to_excel(attendance_data, session, course):
        """Export attendance data to Excel format"""
        import io
        df = pd.DataFrame(attendance_data)
        
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name=f'{course.course_code}_Attendance', index=False)
            
            # Add summary sheet
            summary_data = {
                'Course': [course.course_name],
                'Course Code': [course.course_code],
                'Session': [session.session_name],
                'Date': [session.created_at.strftime('%Y-%m-%d %H:%M:%S')],
                'Total Students': [len(attendance_data)],
                'Present': [len([d for d in attendance_data if d['Status'] == 'Present'])],
                'Absent': [len([d for d in attendance_data if d['Status'] == 'Absent'])]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        output.seek(0)
        filename = f"{course.course_code}_{session.session_name.replace(' ', '_')}_attendance.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )

    def export_to_pdf(attendance_data, session, course):
        """Export attendance data to PDF format"""
        import io
        from reportlab.lib.units import inch
        
        output = io.BytesIO()
        doc = SimpleDocTemplate(output, pagesize=letter, topMargin=0.5*inch)
        
        # Container for the 'Flowable' objects
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title = Paragraph(f"<b>{course.course_name} - Attendance Report</b>", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        # Session info
        session_info = f"""
        <b>Course Code:</b> {course.course_code}<br/>
        <b>Session:</b> {session.session_name}<br/>
        <b>Date:</b> {session.created_at.strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Total Students:</b> {len(attendance_data)}<br/>
        <b>Present:</b> {len([d for d in attendance_data if d['Status'] == 'Present'])}<br/>
        <b>Absent:</b> {len([d for d in attendance_data if d['Status'] == 'Absent'])}
        """
        elements.append(Paragraph(session_info, styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Attendance table
        table_data = [['Name', 'Matricule', 'Sex', 'Status', 'Time']]
        for record in attendance_data:
            table_data.append([
                record['Name'],
                record['Matricule'],
                record['Sex'],
                record['Status'],
                record['Time']
            ])
        
        table = Table(table_data, colWidths=[2*inch, 1.5*inch, 0.8*inch, 1*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]))
        
        elements.append(table)
        doc.build(elements)
        
        output.seek(0)
        filename = f"{course.course_code}_{session.session_name.replace(' ', '_')}_attendance.pdf"
        
        return send_file(
            output,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )

    # Create database tables with error handling
    with app.app_context():
        try:
            print("🔧 Creating database tables...")
            db.create_all()
            print("✅ Database tables created successfully")
        except Exception as e:
            print(f"❌ Error creating database tables: {e}")
            print("This might be normal on first deployment - tables will be created on first request")

    return app

# Create the Flask application
app = create_app()

# Validate environment on startup
print("🔍 Validating Render environment...")
if not validate_render_env():
    print("⚠️  Some environment variables are missing - app may not function correctly")
else:
    print("✅ Environment validation passed")

print("🔒 Enhanced security features enabled:")
print("   • Comprehensive form validation")
print("   • Anti-SQL injection protection")
print("   • Email domain verification")
print("   • Phone-friendly interfaces")
print("   • Real-time input validation")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    print(f"🚀 Starting QR Attendance System on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False) 