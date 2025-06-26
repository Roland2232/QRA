import re
import smtplib
import dns.resolver
from email.utils import parseaddr
from werkzeug.utils import secure_filename
import bleach
from flask import flash

class FormValidator:
    """Comprehensive form validation utility class"""
    
    @staticmethod
    def validate_username(username):
        """Validate username: minimum 4 characters, alphanumeric and underscore only"""
        if not username:
            return False, "Username is required"
        
        username = username.strip()
        
        if len(username) < 4:
            return False, "Username must be at least 4 characters long"
        
        if len(username) > 20:
            return False, "Username must not exceed 20 characters"
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        if username.startswith('_') or username.endswith('_'):
            return False, "Username cannot start or end with underscore"
        
        return True, "Valid username"
    
    @staticmethod
    def validate_name(name):
        """Validate name: letters, spaces, hyphens, and apostrophes only"""
        if not name:
            return False, "Name is required"
        
        name = name.strip()
        
        if len(name) < 2:
            return False, "Name must be at least 2 characters long"
        
        if len(name) > 100:
            return False, "Name must not exceed 100 characters"
        
        # Allow letters, spaces, hyphens, apostrophes, and dots (for initials)
        if not re.match(r"^[a-zA-Z\s\-'.]+$", name):
            return False, "Name can only contain letters, spaces, hyphens, apostrophes, and dots"
        
        # Check for consecutive spaces or special characters
        if re.search(r'\s{2,}', name) or re.search(r'[-\'.]{2,}', name):
            return False, "Name cannot contain consecutive spaces or special characters"
        
        # Must start and end with a letter
        if not re.match(r'^[a-zA-Z].*[a-zA-Z]$', name) and len(name) > 1:
            return False, "Name must start and end with a letter"
        
        return True, "Valid name"
    
    @staticmethod
    def validate_matricule(matricule):
        """Validate matricule: must be 'ictu' followed by exactly 8 digits"""
        if not matricule:
            return False, "Matricule is required"
        
        matricule = matricule.strip().lower()
        
        if not re.match(r'^ictu\d{8}$', matricule):
            return False, "Matricule must be 'ictu' followed by exactly 8 digits (e.g., ictu12345678)"
        
        return True, "Valid matricule"
    
    @staticmethod
    def validate_email(email):
        """Validate email format and check if domain exists"""
        if not email:
            return False, "Email is required"
        
        email = email.strip().lower()
        
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
        
        return True, "Valid email format"
    
    @staticmethod
    def validate_email_domain(email):
        """Check if email domain has MX record (more thorough validation)"""
        try:
            domain = email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            return len(mx_records) > 0, "Email domain exists"
        except:
            return False, "Email domain does not exist or cannot be verified"
    
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
        """Sanitize input to prevent XSS and injection attacks"""
        if not text:
            return ""
        
        # Remove any HTML tags and suspicious characters
        sanitized = bleach.clean(str(text).strip(), tags=[], strip=True)
        
        # Remove SQL injection patterns
        sql_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)',
            r'([\'";])',
            r'(--|\#|\/\*|\*\/)',
            r'(\bOR\b|\bAND\b)(\s+\d+\s*=\s*\d+)',
        ]
        
        for pattern in sql_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
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
        is_valid, message = validator.validate_name(full_name)
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
        is_valid, message = validator.validate_name(name)
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


def sanitize_all_inputs(form_data):
    """Sanitize all form inputs to prevent injection attacks"""
    validator = FormValidator()
    sanitized_data = {}
    
    for key, value in form_data.items():
        if isinstance(value, str):
            sanitized_data[key] = validator.sanitize_input(value)
        else:
            sanitized_data[key] = value
    
    return sanitized_data 