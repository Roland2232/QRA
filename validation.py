"""
Comprehensive form validation and security utility for QR Attendance System
Protects against SQL injection, XSS, and validates input formats
"""

import re
import smtplib
import dns.resolver
from email.utils import parseaddr
from werkzeug.utils import secure_filename
import bleach
import html
from flask import flash

class FormValidator:
    """Comprehensive form validation utility class"""
    
    @staticmethod
    def validate_teacher_name(name):
        """Validate teacher name: letters, spaces, hyphens, and apostrophes only (no numbers)"""
        if not name:
            return False, "Teacher name is required"
        
        name = name.strip()
        
        if len(name) < 2:
            return False, "Teacher name must be at least 2 characters long"
        
        if len(name) > 100:
            return False, "Teacher name must not exceed 100 characters"
        
        # Only allow letters, spaces, hyphens, apostrophes, and dots (no numbers)
        if not re.match(r"^[a-zA-Z\s\-'.]+$", name):
            return False, "Teacher name can only contain letters, spaces, hyphens, apostrophes, and dots (no numbers allowed)"
        
        # Check for consecutive spaces or special characters
        if re.search(r'\s{2,}', name) or re.search(r'[-\'.]{2,}', name):
            return False, "Teacher name cannot contain consecutive spaces or special characters"
        
        # Must start and end with a letter
        if len(name) > 1 and not re.match(r'^[a-zA-Z].*[a-zA-Z]$', name):
            return False, "Teacher name must start and end with a letter"
        
        return True, "Valid teacher name"
    
    @staticmethod
    def validate_username(username):
        """Validate username: minimum 4 letters, alphanumeric and underscore only"""
        if not username:
            return False, "Username is required"
        
        username = username.strip()
        
        if len(username) < 4:
            return False, "Username must be at least 4 characters long"
        
        if len(username) > 20:
            return False, "Username must not exceed 20 characters"
        
        # Must contain at least 4 letters
        letter_count = len(re.findall(r'[a-zA-Z]', username))
        if letter_count < 4:
            return False, "Username must contain at least 4 letters"
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        if username.startswith('_') or username.endswith('_'):
            return False, "Username cannot start or end with underscore"
        
        # Check for suspicious patterns
        if re.search(r'(-0|-1|admin|root|test)', username, re.IGNORECASE):
            return False, "Username contains invalid pattern"
        
        return True, "Valid username"
    
    @staticmethod
    def validate_student_name(name):
        """Validate student name: letters, spaces, hyphens, and apostrophes only"""
        if not name:
            return False, "Student name is required"
        
        name = name.strip()
        
        if len(name) < 2:
            return False, "Student name must be at least 2 characters long"
        
        if len(name) > 100:
            return False, "Student name must not exceed 100 characters"
        
        # Allow letters, spaces, hyphens, apostrophes, and dots (for initials)
        if not re.match(r"^[a-zA-Z\s\-'.]+$", name):
            return False, "Student name can only contain letters, spaces, hyphens, apostrophes, and dots"
        
        # Check for consecutive spaces or special characters
        if re.search(r'\s{2,}', name) or re.search(r'[-\'.]{2,}', name):
            return False, "Student name cannot contain consecutive spaces or special characters"
        
        # Must start and end with a letter
        if len(name) > 1 and not re.match(r'^[a-zA-Z].*[a-zA-Z]$', name):
            return False, "Student name must start and end with a letter"
        
        return True, "Valid student name"
    
    @staticmethod
    def validate_matricule(matricule):
        """Validate matricule: must be 'ICTU' followed by exactly 8 digits"""
        if not matricule:
            return False, "Matricule is required"
        
        matricule = matricule.strip().upper()  # Convert to uppercase for consistency
        
        if not re.match(r'^ICTU\d{8}$', matricule):
            return False, "Matricule must be 'ICTU' followed by exactly 8 digits (e.g., ICTU12345678)"
        
        return True, "Valid matricule"
    
    @staticmethod
    def validate_email(email):
        """Validate email format with comprehensive security checks"""
        if not email:
            return False, "Email is required"
        
        email = email.strip().lower()
        
        # Check for basic security patterns
        if re.search(r'[<>"\';\\]', email):
            return False, "Email contains invalid characters"
        
        # Basic format validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return False, "Invalid email format"
        
        # Parse email to get local and domain parts
        name, addr = parseaddr(email)
        if not addr or '@' not in addr:
            return False, "Invalid email format"
        
        local, domain = addr.rsplit('@', 1)
        
        # Validate local part
        if len(local) > 64:
            return False, "Email local part too long"
        
        # Validate domain part
        if len(domain) > 255:
            return False, "Email domain too long"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'(script|javascript|vbscript)',
            r'[<>]',
            r'(drop|delete|insert|update|select|union)',
            r'(-0|-1|admin@|test@|temp@)'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                return False, "Email contains invalid pattern"
        
        return True, "Valid email format"
    
    @staticmethod
    def validate_password(password):
        """Validate password strength"""
        if not password:
            return False, "Password is required"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) > 128:
            return False, "Password must not exceed 128 characters"
        
        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        # Check for at least one digit
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)"
        
        return True, "Strong password"
    
    @staticmethod
    def validate_admin_code(code):
        """Validate admin code"""
        if not code:
            return False, "Admin code is required"
        
        code = code.strip()
        
        if not re.match(r'^\d{5}$', code):
            return False, "Admin code must be exactly 5 digits"
        
        return True, "Valid admin code format"
    
    @staticmethod
    def sanitize_input(text):
        """Comprehensive input sanitization to prevent XSS and injection attacks"""
        if not text:
            return ""
        
        # Remove any HTML tags and suspicious characters
        sanitized = bleach.clean(str(text).strip(), tags=[], strip=True)
        
        # HTML escape
        sanitized = html.escape(sanitized)
        
        # Remove SQL injection patterns
        sql_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)',
            r'([\'";])',
            r'(--|\#|\/\*|\*\/)',
            r'(\bOR\b|\bAND\b)(\s+\d+\s*=\s*\d+)',
            r'(\bor\b|\band\b)(\s+\d+\s*=\s*\d+)',
            r'(<script|</script>|javascript:|vbscript:)',
            r'(onload|onerror|onclick|onmouseover)=',
        ]
        
        for pattern in sql_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Remove dangerous characters and patterns
        dangerous_chars = ['<', '>', '"', "'", ';', '--', '/*', '*/', '=', '|']
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Remove numbers that could be used for injection (-0, -1, etc.)
        sanitized = re.sub(r'-[0-9]+', '', sanitized)
        
        return sanitized.strip()
    
    @staticmethod
    def validate_file_upload(file):
        """Validate file uploads"""
        if not file or file.filename == '':
            return False, "No file selected"
        
        # Check file size (16MB max)
        if len(file.read()) > 16 * 1024 * 1024:
            return False, "File size exceeds 16MB limit"
        
        file.seek(0)  # Reset file pointer
        
        # Check file extension
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
        filename = secure_filename(file.filename)
        
        if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
        
        return True, "Valid file"
    
    @staticmethod
    def validate_location(latitude, longitude):
        """Validate GPS coordinates"""
        try:
            lat = float(latitude)
            lng = float(longitude)
            
            if not (-90 <= lat <= 90):
                return False, "Invalid latitude. Must be between -90 and 90"
            
            if not (-180 <= lng <= 180):
                return False, "Invalid longitude. Must be between -180 and 180"
            
            return True, "Valid coordinates"
        except (ValueError, TypeError):
            return False, "Invalid coordinate format"
    
    @staticmethod
    def validate_session_name(session_name):
        """Validate attendance session name"""
        if not session_name:
            return False, "Session name is required"
        
        session_name = session_name.strip()
        
        if len(session_name) < 3:
            return False, "Session name must be at least 3 characters long"
        
        if len(session_name) > 100:
            return False, "Session name must not exceed 100 characters"
        
        # Allow letters, numbers, spaces, hyphens, and common punctuation
        if not re.match(r'^[a-zA-Z0-9\s\-_.,()]+$', session_name):
            return False, "Session name contains invalid characters"
        
        return True, "Valid session name"
    
    @staticmethod
    def validate_course_code(course_code):
        """Validate course code"""
        if not course_code:
            return False, "Course code is required"
        
        course_code = course_code.strip().upper()
        
        if len(course_code) < 3:
            return False, "Course code must be at least 3 characters long"
        
        if len(course_code) > 20:
            return False, "Course code must not exceed 20 characters"
        
        # Allow letters, numbers, and hyphens
        if not re.match(r'^[A-Z0-9\-]+$', course_code):
            return False, "Course code can only contain letters, numbers, and hyphens"
        
        return True, "Valid course code"
    
    @staticmethod
    def validate_sex(sex):
        """Validate sex field"""
        if not sex:
            return False, "Sex is required"
        
        sex = sex.strip()
        if sex not in ['Male', 'Female']:
            return False, "Sex must be either 'Male' or 'Female'"
        
        return True, "Valid sex"

def validate_teacher_creation_form(form_data):
    """
    Comprehensive validation for teacher creation form
    
    Args:
        form_data (dict): Form data to validate
        
    Returns:
        tuple: (is_valid, errors_dict, sanitized_data)
    """
    validator = FormValidator()
    errors = {}
    
    # Sanitize all inputs first
    sanitized_data = {}
    for key, value in form_data.items():
        sanitized_data[key] = validator.sanitize_input(value)
    
    # Validate username
    if 'username' in sanitized_data:
        is_valid, message = validator.validate_username(sanitized_data['username'])
        if not is_valid:
            errors['username'] = message
    else:
        errors['username'] = "Username is required"
    
    # Validate teacher name
    if 'full_name' in sanitized_data:
        is_valid, message = validator.validate_teacher_name(sanitized_data['full_name'])
        if not is_valid:
            errors['full_name'] = message
    else:
        errors['full_name'] = "Full name is required"
    
    # Validate email
    if 'email' in sanitized_data:
        is_valid, message = validator.validate_email(sanitized_data['email'])
        if not is_valid:
            errors['email'] = message
    else:
        errors['email'] = "Email is required"
    
    return len(errors) == 0, errors, sanitized_data

def validate_student_registration_form(form_data):
    """
    Comprehensive validation for student registration form
    
    Args:
        form_data (dict): Form data to validate
        
    Returns:
        tuple: (is_valid, errors_dict, sanitized_data)
    """
    validator = FormValidator()
    errors = {}
    
    # Sanitize all inputs first
    sanitized_data = {}
    for key, value in form_data.items():
        sanitized_data[key] = validator.sanitize_input(value) if key != 'matricule' else value.strip()
    
    # Validate student name
    if 'name' in sanitized_data:
        is_valid, message = validator.validate_student_name(sanitized_data['name'])
        if not is_valid:
            errors['name'] = message
    else:
        errors['name'] = "Student name is required"
    
    # Validate matricule (don't over-sanitize this as it has specific format)
    if 'matricule' in sanitized_data:
        is_valid, message = validator.validate_matricule(sanitized_data['matricule'])
        if not is_valid:
            errors['matricule'] = message
    else:
        errors['matricule'] = "Matricule is required"
    
    # Validate sex
    if 'sex' in sanitized_data:
        is_valid, message = validator.validate_sex(sanitized_data['sex'])
        if not is_valid:
            errors['sex'] = message
    else:
        errors['sex'] = "Sex is required"
    
    return len(errors) == 0, errors, sanitized_data

def validate_login_form(form_data):
    """
    Comprehensive validation for login forms
    
    Args:
        form_data (dict): Form data to validate
        
    Returns:
        tuple: (is_valid, errors_dict, sanitized_data)
    """
    validator = FormValidator()
    errors = {}
    
    # Sanitize all inputs first
    sanitized_data = {}
    for key, value in form_data.items():
        sanitized_data[key] = validator.sanitize_input(value)
    
    # Validate username
    if 'username' in sanitized_data:
        username = sanitized_data['username']
        if not username:
            errors['username'] = "Username is required"
        elif len(username) < 3:
            errors['username'] = "Username must be at least 3 characters long"
    
    # Validate password
    if 'password' in sanitized_data:
        password = form_data['password']  # Don't sanitize password, just validate
        if not password:
            errors['password'] = "Password is required"
        elif len(password) < 3:
            errors['password'] = "Password must be at least 3 characters long"
    
    return len(errors) == 0, errors, sanitized_data

def sanitize_all_inputs(form_data):
    """
    Sanitize all form inputs to prevent injection attacks
    
    Args:
        form_data (dict): Form data to sanitize
        
    Returns:
        dict: Sanitized form data
    """
    validator = FormValidator()
    sanitized = {}
    
    for key, value in form_data.items():
        if isinstance(value, str):
            sanitized[key] = validator.sanitize_input(value)
        else:
            sanitized[key] = value
    
    return sanitized

def validate_form_data(form_data, form_type):
    """
    Comprehensive form validation dispatcher
    Returns: (is_valid, errors_dict)
    """
    errors = {}
    validator = FormValidator()
    
    if form_type == 'teacher_login':
        # Validate username
        username = form_data.get('username', '').strip()
        is_valid, message = validator.validate_username(username)
        if not is_valid:
            errors['username'] = message
        
        # Validate password exists
        password = form_data.get('password', '')
        if not password:
            errors['password'] = "Password is required"
    
    elif form_type == 'admin_login':
        # Validate admin code
        admin_code = form_data.get('admin_code', '').strip()
        is_valid, message = validator.validate_admin_code(admin_code)
        if not is_valid:
            errors['admin_code'] = message
    
    elif form_type == 'create_teacher':
        # Validate full name
        full_name = form_data.get('full_name', '').strip()
        is_valid, message = validator.validate_teacher_name(full_name)
        if not is_valid:
            errors['full_name'] = message
        
        # Validate username
        username = form_data.get('username', '').strip()
        is_valid, message = validator.validate_username(username)
        if not is_valid:
            errors['username'] = message
        
        # Validate email
        email = form_data.get('email', '').strip()
        is_valid, message = validator.validate_email(email)
        if not is_valid:
            errors['email'] = message
    
    elif form_type == 'student_registration':
        # Validate name
        name = form_data.get('name', '').strip()
        is_valid, message = validator.validate_student_name(name)
        if not is_valid:
            errors['name'] = message
        
        # Validate matricule
        matricule = form_data.get('matricule', '').strip()
        is_valid, message = validator.validate_matricule(matricule)
        if not is_valid:
            errors['matricule'] = message
        
        # Validate sex
        sex = form_data.get('sex', '').strip()
        if sex not in ['Male', 'Female']:
            errors['sex'] = "Please select a valid gender"
    
    elif form_type == 'change_password':
        # Validate current password exists
        current_password = form_data.get('current_password', '')
        if not current_password:
            errors['current_password'] = "Current password is required"
        
        # Validate new password
        new_password = form_data.get('new_password', '')
        is_valid, message = validator.validate_password(new_password)
        if not is_valid:
            errors['new_password'] = message
        
        # Validate password confirmation
        confirm_password = form_data.get('confirm_password', '')
        if new_password != confirm_password:
            errors['confirm_password'] = "Password confirmation does not match"
    
    elif form_type == 'create_course':
        # Validate course name
        name = form_data.get('name', '').strip()
        is_valid, message = validator.validate_name(name)
        if not is_valid:
            errors['name'] = message
        
        # Validate course code
        code = form_data.get('code', '').strip()
        is_valid, message = validator.validate_course_code(code)
        if not is_valid:
            errors['code'] = message
    
    elif form_type == 'create_attendance_session':
        # Validate session name
        session_name = form_data.get('session_name', '').strip()
        is_valid, message = validator.validate_session_name(session_name)
        if not is_valid:
            errors['session_name'] = message
        
        # Validate location if provided
        latitude = form_data.get('latitude')
        longitude = form_data.get('longitude')
        if latitude and longitude:
            is_valid, message = validator.validate_location(latitude, longitude)
            if not is_valid:
                errors['location'] = message
    
    elif form_type == 'take_attendance':
        # Validate matricule selection
        selected_matricule = form_data.get('selected_matricule', '').strip()
        if not selected_matricule:
            errors['selected_matricule'] = "Please select your matricule"
        
        # Validate location
        latitude = form_data.get('latitude')
        longitude = form_data.get('longitude')
        if not latitude or not longitude:
            errors['location'] = "Location is required for attendance verification"
        else:
            is_valid, message = validator.validate_location(latitude, longitude)
            if not is_valid:
                errors['location'] = message
    
    return len(errors) == 0, errors 