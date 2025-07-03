-- Create database user and grant privileges
CREATE USER IF NOT EXISTS 'remi'@'localhost' IDENTIFIED BY '1234';
CREATE USER IF NOT EXISTS 'remi'@'%' IDENTIFIED BY '1234';

GRANT ALL PRIVILEGES ON *.* TO 'remi'@'localhost';
GRANT ALL PRIVILEGES ON *.* TO 'remi'@'%';
FLUSH PRIVILEGES;

-- Drop tables if they exist (in correct order due to foreign keys)
DROP TABLE IF EXISTS attendance;
DROP TABLE IF EXISTS attendance_session;
DROP TABLE IF EXISTS student;
DROP TABLE IF EXISTS course;
DROP TABLE IF EXISTS teacher;
DROP TABLE IF EXISTS admin;
DROP TABLE IF EXISTS password_reset;
DROP TABLE IF EXISTS device_attendance;

-- 1. Admin Table
CREATE TABLE admin (
    id VARCHAR(50) PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Teacher Table
CREATE TABLE teacher (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    must_change_password BOOLEAN DEFAULT TRUE NOT NULL,
    created_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES admin(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Course Table
CREATE TABLE course (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(20) UNIQUE NOT NULL,
    teacher_id VARCHAR(50) NOT NULL,
    registration_qr_code TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (teacher_id) REFERENCES teacher(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Student Table
CREATE TABLE student (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    matricule VARCHAR(50) NOT NULL,
    sex VARCHAR(10) NOT NULL,
    photo_path VARCHAR(255),
    face_encoding TEXT,
    course_id VARCHAR(50) NOT NULL,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (course_id) REFERENCES course(id) ON DELETE CASCADE,
    UNIQUE KEY unique_student_course (matricule, course_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Attendance Session Table
CREATE TABLE attendance_session (
    id VARCHAR(50) PRIMARY KEY,
    course_id VARCHAR(50) NOT NULL,
    session_name VARCHAR(100) NOT NULL,
    qr_code_data TEXT,
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    radius_meters INTEGER DEFAULT 100,
    valid_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    qr_code_path VARCHAR(255),
    FOREIGN KEY (course_id) REFERENCES course(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Attendance Table
CREATE TABLE attendance (
    id VARCHAR(50) PRIMARY KEY,
    student_id VARCHAR(50) NOT NULL,
    session_id VARCHAR(50) NOT NULL,
    marked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES student(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES attendance_session(id) ON DELETE CASCADE,
    UNIQUE KEY unique_student_session (student_id, session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Password Reset Table
CREATE TABLE password_reset (
    id VARCHAR(50) PRIMARY KEY,
    teacher_id VARCHAR(36) NOT NULL,
    reset_code VARCHAR(6) NOT NULL,
    email VARCHAR(120) NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (teacher_id) REFERENCES teacher(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Device Attendance Table
CREATE TABLE device_attendance (
    id VARCHAR(50) PRIMARY KEY,
    session_id VARCHAR(50) REFERENCES attendance_session(id) NOT NULL,
    device_identifier VARCHAR(100) NOT NULL,
    student_id VARCHAR(50) REFERENCES student(id) NOT NULL,
    marked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create Indexes for better performance
CREATE INDEX idx_teacher_email ON teacher(email);
CREATE INDEX idx_teacher_username ON teacher(username);
CREATE INDEX idx_teacher_created_by ON teacher(created_by);

CREATE INDEX idx_course_teacher_id ON course(teacher_id);
CREATE INDEX idx_course_code ON course(code);

CREATE INDEX idx_student_course_id ON student(course_id);
CREATE INDEX idx_student_matricule ON student(matricule);
CREATE INDEX idx_student_sex ON student(sex);

CREATE INDEX idx_attendance_session_course_id ON attendance_session(course_id);
CREATE INDEX idx_attendance_session_active ON attendance_session(is_active);
CREATE INDEX idx_attendance_session_expires ON attendance_session(expires_at);

CREATE INDEX idx_attendance_student_id ON attendance(student_id);
CREATE INDEX idx_attendance_session_id ON attendance(session_id);
CREATE INDEX idx_attendance_marked_at ON attendance(marked_at);

CREATE INDEX idx_password_reset_code ON password_reset(reset_code);
CREATE INDEX idx_password_reset_teacher ON password_reset(teacher_id);

CREATE INDEX idx_device_attendance_session ON device_attendance(session_id);
CREATE INDEX idx_device_attendance_device ON device_attendance(device_identifier);

-- Insert default admin (optional - uncomment if needed)
-- INSERT INTO admin (id, username, email, password_hash, is_admin) 
-- VALUES ('admin001', 'admin', 'admin@school.edu', '$2b$12$hash_here', TRUE);

-- Insert default admin user (password: admin123)
INSERT IGNORE INTO admin (id, username, email, password_hash) 
-- Sample data (uncomment if needed for testing)
/*
-- Sample Teacher
INSERT INTO teacher (id, username, email, password_hash, full_name, created_by) 
VALUES ('teacher001', 'john.doe', 'john.doe@school.edu', '$2b$12$hash_here', 'John Doe', 'admin001');

-- Sample Course
INSERT INTO course (id, name, code, teacher_id) 
VALUES ('course001', 'Mathematics 101', 'MATH101', 'teacher001');

-- Sample Student
INSERT INTO student (id, name, matricule, sex, course_id) 
VALUES ('student001', 'Alice Johnson', 'STU001', 'Female', 'course001');

-- Sample Attendance Session
INSERT INTO attendance_session (id, course_id, session_name, latitude, longitude, expires_at, is_active) 
VALUES ('session001', 'course001', 'Week 1 - Algebra Basics', 6.2088, 1.2536, DATE_ADD(NOW(), INTERVAL 15 MINUTE), TRUE);

-- Sample Attendance Record
INSERT INTO attendance (id, student_id, session_id, latitude, longitude) 
VALUES ('attend001', 'student001', 'session001', 6.2088, 1.2536);
*/

-- Show table structure
SHOW TABLES;

-- Display table information
DESCRIBE admin;
DESCRIBE teacher;
DESCRIBE course;
DESCRIBE student;
DESCRIBE attendance_session;
DESCRIBE attendance;
DESCRIBE device_attendance;

-- Show indexes
SHOW INDEX FROM teacher;
SHOW INDEX FROM course;
SHOW INDEX FROM student;
SHOW INDEX FROM attendance_session;
SHOW INDEX FROM attendance;
SHOW INDEX FROM device_attendance;

-- Database schema summary
SELECT 
    'Database Schema Created Successfully' as Status,
    COUNT(*) as Total_Tables
FROM information_schema.tables 
WHERE table_schema = DATABASE()
AND table_name IN ('admin', 'teacher', 'course', 'student', 'attendance_session', 'attendance', 'device_attendance', 'password_reset'); 