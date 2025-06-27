"""
Comprehensive form validation for Render deployment
Enhanced security and user experience features
"""

import re
import bleach
import dns.resolver
from email.utils import parseaddr
from werkzeug.utils import secure_filename

class FormValidator:
    """Comprehensive form validation utility class for Render deployment"""
    
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
    def validate_email_domain(email):
        """Check if email domain has MX record (more thorough validation)"""
        try:
            domain = email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            return len(mx_records) > 0, "Email domain exists"
        except Exception as e:
            print(f"Email domain validation error: {e}")
            # Don't fail validation if DNS check fails, just log it
            return True, "Email domain check skipped"
    
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
        import html
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

def validate_form_data(form_data, form_type):
    """
    Comprehensive form validation based on form type
    
    Args:
        form_data (dict): Form data to validate
        form_type (str): Type of form ('teacher_creation', 'student_registration', 'login', etc.)
        
    Returns:
        tuple: (is_valid, errors_dict)
    """
    validator = FormValidator()
    errors = {}
    
    if form_type == 'teacher_creation' or form_type == 'create_teacher':
        # Validate teacher creation form
        if 'username' in form_data:
            is_valid, message = validator.validate_username(form_data['username'])
            if not is_valid:
                errors['username'] = message
        
        if 'full_name' in form_data:
            is_valid, message = validator.validate_teacher_name(form_data['full_name'])
            if not is_valid:
                errors['full_name'] = message
        
        if 'email' in form_data:
            is_valid, message = validator.validate_email(form_data['email'])
            if not is_valid:
                errors['email'] = message
    
    elif form_type == 'student_registration':
        # Validate student registration form
        if 'name' in form_data:
            is_valid, message = validator.validate_student_name(form_data['name'])
            if not is_valid:
                errors['name'] = message
        
        if 'matricule' in form_data:
            is_valid, message = validator.validate_matricule(form_data['matricule'])
            if not is_valid:
                errors['matricule'] = message
        
        if 'sex' in form_data:
            if form_data['sex'] not in ['Male', 'Female']:
                errors['sex'] = "Sex must be either 'Male' or 'Female'"
    
    elif form_type == 'login':
        # Validate login form
        if 'username' in form_data:
            is_valid, message = validator.validate_username(form_data['username'])
            if not is_valid:
                errors['username'] = message
        
        if 'password' in form_data:
            if not form_data['password']:
                errors['password'] = "Password is required"
        
        if 'admin_code' in form_data:
            is_valid, message = validator.validate_admin_code(form_data['admin_code'])
            if not is_valid:
                errors['admin_code'] = message
    
    elif form_type == 'password_change':
        # Validate password change form
        if 'new_password' in form_data:
            is_valid, message = validator.validate_password(form_data['new_password'])
            if not is_valid:
                errors['new_password'] = message
        
        if 'confirm_password' in form_data and 'new_password' in form_data:
            if form_data['new_password'] != form_data['confirm_password']:
                errors['confirm_password'] = "Password confirmation does not match"
    
    elif form_type == 'attendance_session':
        # Validate attendance session creation
        if 'session_name' in form_data:
            if not form_data['session_name'].strip():
                errors['session_name'] = "Session name is required"
            elif len(form_data['session_name'].strip()) < 3:
                errors['session_name'] = "Session name must be at least 3 characters long"
        
        if 'latitude' in form_data and 'longitude' in form_data:
            is_valid, message = validator.validate_location(
                form_data['latitude'], 
                form_data['longitude']
            )
            if not is_valid:
                errors['location'] = message
    
    elif form_type == 'course_creation':
        # Validate course creation form
        if 'name' in form_data:
            if not form_data['name'].strip():
                errors['name'] = "Course name is required"
            elif len(form_data['name'].strip()) < 3:
                errors['name'] = "Course name must be at least 3 characters long"
        
        if 'code' in form_data:
            code = form_data['code'].strip().upper()
            if not code:
                errors['code'] = "Course code is required"
            elif not re.match(r'^[A-Z0-9]{3,10}$', code):
                errors['code'] = "Course code must be 3-10 characters, letters and numbers only"
    
    return len(errors) == 0, errors

def sanitize_all_inputs(form_data):
    """
    Sanitize all form inputs to prevent injection attacks
    
    Args:
        form_data (dict): Raw form data
        
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
        if sanitized_data['sex'] not in ['Male', 'Female']:
            errors['sex'] = "Sex must be either 'Male' or 'Female'"
    else:
        errors['sex'] = "Sex is required"
    
    return len(errors) == 0, errors, sanitized_data

def verify_email_deliverability(email):
    """
    Advanced email validation including domain MX record check
    
    Args:
        email (str): Email address to validate
        
    Returns:
        tuple: (is_valid, message)
    """
    validator = FormValidator()
    
    # First check basic format
    is_valid, message = validator.validate_email(email)
    if not is_valid:
        return False, message
    
    # Then check domain deliverability
    try:
        return validator.validate_email_domain(email)
    except:
        # If MX check fails, just return true for basic format validation
        return True, "Email format valid (domain check skipped)" 