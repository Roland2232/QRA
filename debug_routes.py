#!/usr/bin/env python3
"""
Debug routes for QR Attendance System - Render deployment
Add these routes to help identify and fix remaining issues
"""

from flask import jsonify, render_template_string
import os

def add_debug_routes(app, db):
    """Add temporary debug routes to help identify issues"""
    
    @app.route('/debug/qr-status')
    def debug_qr_status():
        """Check QR code file status"""
        from models import Course, AttendanceSession
        
        qr_status = {
            'static_qr_folder_exists': os.path.exists('static/qr_codes'),
            'courses': [],
            'sessions': []
        }
        
        # Check QR codes folder
        if os.path.exists('static/qr_codes'):
            qr_files = os.listdir('static/qr_codes')
            qr_status['qr_files_in_folder'] = qr_files
        else:
            qr_status['qr_files_in_folder'] = []
        
        # Check course QR codes
        courses = Course.query.all()
        for course in courses:
            qr_exists = False
            if course.registration_qr_code:
                qr_path = os.path.join('static/qr_codes', course.registration_qr_code)
                qr_exists = os.path.exists(qr_path)
            
            qr_status['courses'].append({
                'id': course.id,
                'name': course.name,
                'code': course.code,
                'qr_filename': course.registration_qr_code,
                'qr_exists': qr_exists
            })
        
        # Check session QR codes
        sessions = AttendanceSession.query.filter_by(is_active=True).all()
        for session in sessions:
            qr_exists = False
            if session.qr_code_path:
                qr_path = os.path.join('static/qr_codes', session.qr_code_path)
                qr_exists = os.path.exists(qr_path)
            
            qr_status['sessions'].append({
                'id': session.id,
                'name': session.session_name,
                'qr_filename': session.qr_code_path,
                'qr_exists': qr_exists,
                'is_active': session.is_active
            })
        
        return jsonify(qr_status)
    
    @app.route('/debug/regenerate-missing-qr')
    def debug_regenerate_missing_qr():
        """Regenerate missing QR codes"""
        from models import Course, AttendanceSession
        from render_app import generate_qr_code, get_external_url
        
        results = {
            'courses_fixed': 0,
            'sessions_fixed': 0,
            'errors': []
        }
        
        try:
            # Ensure QR codes directory exists
            os.makedirs('static/qr_codes', exist_ok=True)
            
            # Check and fix course QR codes
            courses = Course.query.all()
            for course in courses:
                if course.registration_qr_code:
                    qr_path = os.path.join('static/qr_codes', course.registration_qr_code)
                    if not os.path.exists(qr_path):
                        try:
                            registration_url = get_external_url('student_registration', course_id=course.id)
                            generate_qr_code(registration_url, course.registration_qr_code)
                            results['courses_fixed'] += 1
                        except Exception as e:
                            results['errors'].append(f"Course {course.name}: {str(e)}")
            
            # Check and fix active session QR codes
            sessions = AttendanceSession.query.filter_by(is_active=True).all()
            for session in sessions:
                if session.qr_code_path:
                    qr_path = os.path.join('static/qr_codes', session.qr_code_path)
                    if not os.path.exists(qr_path):
                        try:
                            attendance_url = get_external_url('take_attendance', session_id=session.id)
                            generate_qr_code(attendance_url, session.qr_code_path)
                            results['sessions_fixed'] += 1
                        except Exception as e:
                            results['errors'].append(f"Session {session.session_name}: {str(e)}")
            
            results['success'] = True
            
        except Exception as e:
            results['success'] = False
            results['errors'].append(f"General error: {str(e)}")
        
        return jsonify(results)
    
    @app.route('/debug/database-info')
    def debug_database_info():
        """Get database connection and table info"""
        from models import Course, AttendanceSession, Student, Teacher, Admin
        
        info = {
            'database_url': app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set')[:50] + '...',
            'tables': {},
            'sample_data': {}
        }
        
        try:
            # Count records in each table
            info['tables']['courses'] = Course.query.count()
            info['tables']['sessions'] = AttendanceSession.query.count()
            info['tables']['students'] = Student.query.count()
            info['tables']['teachers'] = Teacher.query.count()
            info['tables']['admins'] = Admin.query.count()
            
            # Get sample data
            sample_course = Course.query.first()
            if sample_course:
                info['sample_data']['course'] = {
                    'id': sample_course.id,
                    'name': sample_course.name,
                    'code': sample_course.code,
                    'qr_code': sample_course.registration_qr_code
                }
            
            sample_session = AttendanceSession.query.first()
            if sample_session:
                info['sample_data']['session'] = {
                    'id': sample_session.id,
                    'name': sample_session.session_name,
                    'qr_path': sample_session.qr_code_path,
                    'is_active': sample_session.is_active
                }
            
            info['success'] = True
            
        except Exception as e:
            info['success'] = False
            info['error'] = str(e)
        
        return jsonify(info)
    
    @app.route('/debug/file-system')
    def debug_file_system():
        """Check file system structure"""
        info = {
            'current_directory': os.getcwd(),
            'static_exists': os.path.exists('static'),
            'static_qr_exists': os.path.exists('static/qr_codes'),
            'tmp_exists': os.path.exists('/tmp'),
            'tmp_qr_exists': os.path.exists('/tmp/qr_codes')
        }
        
        # List static directory
        if os.path.exists('static'):
            info['static_contents'] = os.listdir('static')
        
        # List QR codes if folder exists
        if os.path.exists('static/qr_codes'):
            info['qr_files'] = os.listdir('static/qr_codes')
        
        return jsonify(info)
    
    @app.route('/debug/test-export')
    def debug_test_export():
        """Test export functionality with sample data"""
        from models import Course, AttendanceSession, Student
        
        # Get first available course and session
        course = Course.query.first()
        session = AttendanceSession.query.first()
        
        if not course or not session:
            return jsonify({
                'error': 'No course or session available for testing',
                'courses_count': Course.query.count(),
                'sessions_count': AttendanceSession.query.count()
            })
        
        # Create sample attendance data
        sample_data = [
            {
                'Name': 'Test Student',
                'Matricule': 'ICTU12345678',
                'Sex': 'Male',
                'Status': 'Present',
                'Time': '2025-06-27 10:00:00'
            }
        ]
        
        try:
            # Test PDF creation (don't actually send file)
            import io
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate
            
            output = io.BytesIO()
            doc = SimpleDocTemplate(output, pagesize=letter)
            
            pdf_info = {
                'course_name': course.name,
                'course_code': course.code,
                'session_name': session.session_name,
                'test_success': True
            }
            
            # Test Excel creation
            import pandas as pd
            df = pd.DataFrame(sample_data)
            excel_output = io.BytesIO()
            
            with pd.ExcelWriter(excel_output, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Test_Attendance', index=False)
            
            excel_info = {
                'dataframe_shape': df.shape,
                'test_success': True
            }
            
            return jsonify({
                'success': True,
                'pdf_test': pdf_info,
                'excel_test': excel_info,
                'sample_data': sample_data
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e),
                'course': {
                    'name': course.name,
                    'code': course.code
                },
                'session': {
                    'name': session.session_name
                }
            })
    
    return app 