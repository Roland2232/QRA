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
        
        # Only allow letters (including diacritics), spaces, hyphens, apostrophes, and dots (no numbers)
        # Support French and German characters: àáâäæçèéêëìíîïñòóôöœùúûü etc.
        if not re.match(r"^[a-zA-ZàáâäæçèéêëìíîïñòóôöœùúûüÀÁÂÄÆÇÈÉÊËÌÍÎÏÑÒÓÔÖŒÙÚÛÜÿß\s\-'.]+$", name):
            return False, "Teacher name can only contain letters (including accented letters), spaces, hyphens, apostrophes, and dots (no numbers allowed)"
        
        # Check for consecutive spaces or special characters
        if re.search(r'\s{2,}', name) or re.search(r'[-\'.]{2,}', name):
            return False, "Teacher name cannot contain consecutive spaces or special characters"
        
        # Must start and end with a letter (including accented letters)
        if len(name) > 1 and not re.match(r'^[a-zA-ZàáâäæçèéêëìíîïñòóôöœùúûüÀÁÂÄÆÇÈÉÊËÌÍÎÏÑÒÓÔÖŒÙÚÛÜÿß].*[a-zA-ZàáâäæçèéêëìíîïñòóôöœùúûüÀÁÂÄÆÇÈÉÊËÌÍÎÏÑÒÓÔÖŒÙÚÛÜÿß]$', name):
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
    def validate_full_name(full_name):
        """Validate full name for admin account creation: letters, hyphens, and French/German diacritics only"""
        if not full_name:
            return False, "Full name is required"
        
        full_name = full_name.strip()
        
        if len(full_name) < 2:
            return False, "Full name must be at least 2 characters long"
        
        if len(full_name) > 100:
            return False, "Full name must not exceed 100 characters"
        
        # Only allow letters (including French/German diacritics), spaces, and hyphens
        # French: àáâäæçèéêëìíîïñòóôöœùúûüÿ
        # German: äöüß
        if not re.match(r"^[a-zA-ZàáâäæçèéêëìíîïñòóôöœùúûüÀÁÂÄÆÇÈÉÊËÌÍÎÏÑÒÓÔÖŒÙÚÛÜÿßäöüÄÖÜ\s\-]+$", full_name):
            return False, "Full name can only contain letters (including French and German accented letters), spaces, and hyphens"
        
        # Check for consecutive spaces or hyphens
        if re.search(r'\s{2,}', full_name) or re.search(r'-{2,}', full_name):
            return False, "Full name cannot contain consecutive spaces or hyphens"
        
        # Must start and end with a letter (including accented letters)
        if len(full_name) > 1 and not re.match(r'^[a-zA-ZàáâäæçèéêëìíîïñòóôöœùúûüÀÁÂÄÆÇÈÉÊËÌÍÎÏÑÒÓÔÖŒÙÚÛÜÿßäöüÄÖÜ].*[a-zA-ZàáâäæçèéêëìíîïñòóôöœùúûüÀÁÂÄÆÇÈÉÊËÌÍÎÏÑÒÓÔÖŒÙÚÛÜÿßäöüÄÖÜ]$', full_name):
            return False, "Full name must start and end with a letter"
        
        # Ensure it contains at least one space (for first and last name)
        if ' ' not in full_name:
            return False, "Full name must contain at least first and last name separated by space"
        
        return True, "Valid full name"
    
    @staticmethod
    def validate_reset_code(code):
        """Validate password reset code: 6-digit numeric code"""
        if not code:
            return False, "Reset code is required"
        
        code = code.strip()
        
        # Must be exactly 6 digits
        if not re.match(r'^\d{6}$', code):
            return False, "Reset code must be exactly 6 digits"
        
        return True, "Valid reset code"
    
    @staticmethod
    def validate_name(name):
        """Generic name validation for course names, etc."""
        if not name:
            return False, "Name is required"
        
        name = name.strip()
        
        if len(name) < 2:
            return False, "Name must be at least 2 characters long"
        
        if len(name) > 100:
            return False, "Name must not exceed 100 characters"
        
        # Allow letters, numbers, spaces, and common punctuation
        if not re.match(r'^[a-zA-Z0-9\s\-_.,()]+$', name):
            return False, "Name contains invalid characters"
        
        return True, "Valid name"
    
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
    Comprehensive form validation dispatcher
    
    Args:
        form_data (dict): Form data to validate
        form_type (str): Type of form validation to perform
        
    Returns:
        tuple: (is_valid, errors_dict)
    """
    errors = {}
    validator = FormValidator()
    
    if form_type == 'teacher_creation' or form_type == 'create_teacher':
        # Validate teacher creation form
        if 'username' in form_data:
            is_valid, message = validator.validate_username(form_data['username'])
            if not is_valid:
                errors['username'] = message
        
        if 'full_name' in form_data:
            is_valid, message = validator.validate_full_name(form_data['full_name'])
            if not is_valid:
                errors['full_name'] = message
        
        if 'email' in form_data:
            is_valid, message = validator.validate_email(form_data['email'])
            if not is_valid:
                errors['email'] = message
    
    elif form_type == 'teacher_login':
        # Validate teacher login form
        if 'username' in form_data:
            username = form_data['username'].strip()
            if not username:
                errors['username'] = "Username is required"
            elif len(username) < 3:
                errors['username'] = "Username must be at least 3 characters long"
        
        if 'password' in form_data:
            if not form_data['password']:
                errors['password'] = "Password is required"
    
    elif form_type == 'admin_login':
        # Validate admin login form
        if 'secret_code' in form_data:
            is_valid, message = validator.validate_admin_code(form_data['secret_code'])
            if not is_valid:
                errors['secret_code'] = message
    
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
        # Generic login validation
        if 'username' in form_data:
            username = form_data['username'].strip()
            if not username:
                errors['username'] = "Username is required"
        
        if 'password' in form_data:
            if not form_data['password']:
                errors['password'] = "Password is required"
        
        if 'admin_code' in form_data:
            is_valid, message = validator.validate_admin_code(form_data['admin_code'])
            if not is_valid:
                errors['admin_code'] = message
    
    elif form_type == 'change_password':
        # Validate password change form
        if 'current_password' in form_data:
            if not form_data['current_password']:
                errors['current_password'] = "Current password is required"
        
        if 'new_password' in form_data:
            is_valid, message = validator.validate_password(form_data['new_password'])
            if not is_valid:
                errors['new_password'] = message
        
        if 'confirm_password' in form_data and 'new_password' in form_data:
            if form_data['new_password'] != form_data['confirm_password']:
                errors['confirm_password'] = "Password confirmation does not match"
    
    elif form_type == 'forgot_password':
        # Validate forgot password form
        if 'email' in form_data:
            is_valid, message = validator.validate_email(form_data['email'])
            if not is_valid:
                errors['email'] = message
    
    elif form_type == 'reset_password':
        # Validate reset password form
        if 'reset_code' in form_data:
            is_valid, message = validator.validate_reset_code(form_data['reset_code'])
            if not is_valid:
                errors['reset_code'] = message
        
        if 'new_password' in form_data:
            is_valid, message = validator.validate_password(form_data['new_password'])
            if not is_valid:
                errors['new_password'] = message
        
        if 'confirm_password' in form_data and 'new_password' in form_data:
            if form_data['new_password'] != form_data['confirm_password']:
                errors['confirm_password'] = "Passwords do not match"
    
    elif form_type == 'course_creation':
        # Validate course creation form
        if 'name' in form_data:
            is_valid, message = validator.validate_name(form_data['name'])
            if not is_valid:
                errors['name'] = message
        
        if 'code' in form_data:
            code = form_data['code'].strip().upper()
            if not code:
                errors['code'] = "Course code is required"
            elif not re.match(r'^[A-Z0-9\-]{3,20}$', code):
                errors['code'] = "Course code must be 3-20 characters, letters, numbers, and hyphens only"
    
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
    
    # Validate full name (for admin account creation with French/German diacritics support)
    if 'full_name' in sanitized_data:
        is_valid, message = validator.validate_full_name(sanitized_data['full_name'])
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
    try:
        # Basic format validation first
        validator = FormValidator()
        is_valid, message = validator.validate_email(email)
        if not is_valid:
            return False, message
        
        # Extract domain
        domain = email.split('@')[1]
        
        # Check MX record
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            if len(mx_records) > 0:
                return True, "Email domain verified"
            else:
                return False, "Email domain has no MX record"
        except dns.resolver.NXDOMAIN:
            return False, "Email domain does not exist"
        except dns.resolver.NoAnswer:
            return False, "Email domain has no MX record"
        except Exception as dns_error:
            print(f"DNS check failed: {dns_error}")
            # Don't fail validation if DNS check fails
            return True, "Email format valid (DNS check skipped)"
            
    except Exception as e:
        print(f"Email validation error: {e}")
        return False, "Email validation failed"

def validate_forgot_password_form(form_data):
    """
    Validate forgot password form
    
    Args:
        form_data (dict): Form data containing email
        
    Returns:
        tuple: (is_valid, errors_dict, sanitized_data)
    """
    validator = FormValidator()
    errors = {}
    
    # Sanitize inputs
    sanitized_data = {}
    for key, value in form_data.items():
        sanitized_data[key] = validator.sanitize_input(value)
    
    # Validate email
    if 'email' in sanitized_data:
        is_valid, message = validator.validate_email(sanitized_data['email'])
        if not is_valid:
            errors['email'] = message
    else:
        errors['email'] = "Email is required"
    
    return len(errors) == 0, errors, sanitized_data

def validate_reset_password_form(form_data):
    """
    Validate reset password form with code and new password
    
    Args:
        form_data (dict): Form data containing reset_code, new_password, confirm_password
        
    Returns:
        tuple: (is_valid, errors_dict, sanitized_data)
    """
    validator = FormValidator()
    errors = {}
    
    # Sanitize inputs (except passwords)
    sanitized_data = {}
    for key, value in form_data.items():
        if key in ['new_password', 'confirm_password']:
            sanitized_data[key] = value  # Don't sanitize passwords
        else:
            sanitized_data[key] = validator.sanitize_input(value)
    
    # Validate reset code
    if 'reset_code' in sanitized_data:
        is_valid, message = validator.validate_reset_code(sanitized_data['reset_code'])
        if not is_valid:
            errors['reset_code'] = message
    else:
        errors['reset_code'] = "Reset code is required"
    
    # Validate new password
    if 'new_password' in sanitized_data:
        is_valid, message = validator.validate_password(sanitized_data['new_password'])
        if not is_valid:
            errors['new_password'] = message
    else:
        errors['new_password'] = "New password is required"
    
    # Validate password confirmation
    if 'confirm_password' in sanitized_data:
        if sanitized_data.get('new_password') != sanitized_data['confirm_password']:
            errors['confirm_password'] = "Passwords do not match"
    else:
        errors['confirm_password'] = "Password confirmation is required"
    
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