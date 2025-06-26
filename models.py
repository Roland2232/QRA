from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import secrets
import uuid

db = SQLAlchemy()

class Admin(UserMixin, db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.String(50), primary_key=True, default=lambda: secrets.token_hex(16))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Teacher(UserMixin, db.Model):
    __tablename__ = 'teacher'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=True, nullable=False)
    created_by = db.Column(db.String(50), db.ForeignKey('admin.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    courses = db.relationship('Course', backref='teacher', lazy=True, cascade='all, delete-orphan')

class Course(db.Model):
    __tablename__ = 'course'
    id = db.Column(db.String(50), primary_key=True, default=lambda: secrets.token_hex(16))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    teacher_id = db.Column(db.String(50), db.ForeignKey('teacher.id'), nullable=False)
    registration_qr_code = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    students = db.relationship('Student', backref='course', lazy=True, cascade='all, delete-orphan')
    sessions = db.relationship('AttendanceSession', backref='course', lazy=True, cascade='all, delete-orphan')

class Student(db.Model):
    __tablename__ = 'student'
    id = db.Column(db.String(50), primary_key=True, default=lambda: secrets.token_hex(16))
    name = db.Column(db.String(100), nullable=False)
    matricule = db.Column(db.String(50), nullable=False)
    sex = db.Column(db.String(10), nullable=False)
    photo_path = db.Column(db.String(255))
    course_id = db.Column(db.String(50), db.ForeignKey('course.id'), nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    attendance_records = db.relationship('Attendance', backref='student', lazy=True, cascade='all, delete-orphan')
    
    __table_args__ = (db.UniqueConstraint('matricule', 'course_id', name='unique_student_course'),)

class AttendanceSession(db.Model):
    __tablename__ = 'attendance_session'
    id = db.Column(db.String(50), primary_key=True, default=lambda: secrets.token_hex(16))
    course_id = db.Column(db.String(50), db.ForeignKey('course.id'), nullable=False)
    session_name = db.Column(db.String(100), nullable=False)
    qr_code_data = db.Column(db.Text)
    latitude = db.Column(db.Numeric(10, 8))
    longitude = db.Column(db.Numeric(11, 8))
    radius_meters = db.Column(db.Integer, default=100)
    valid_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # Session expiry (15 minutes)
    is_active = db.Column(db.Boolean, default=True)
    qr_code_path = db.Column(db.String(255))
    
    attendance_records = db.relationship('Attendance', backref='session', lazy=True, cascade='all, delete-orphan')
    
    def is_expired(self):
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False
    
    def minutes_remaining(self):
        if not self.expires_at or self.is_expired():
            return 0
        delta = self.expires_at - datetime.utcnow()
        return max(0, int(delta.total_seconds() / 60))

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.String(50), primary_key=True, default=lambda: secrets.token_hex(16))
    student_id = db.Column(db.String(50), db.ForeignKey('student.id'), nullable=False)
    session_id = db.Column(db.String(50), db.ForeignKey('attendance_session.id'), nullable=False)
    marked_at = db.Column(db.DateTime, default=datetime.utcnow)
    latitude = db.Column(db.Numeric(10, 8))
    longitude = db.Column(db.Numeric(11, 8))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('student_id', 'session_id', name='unique_student_session'),) 

