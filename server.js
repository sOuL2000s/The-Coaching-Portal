// server.js (Backend)

// ----------------------
// 1. Setup & Imports
// ----------------------
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const cors = require('cors'); // For Cross-Origin Resource Sharing
const jwt = require('jsonwebtoken'); // For JSON Web Tokens (authentication)
const bcrypt = require('bcryptjs'); // For password hashing
const Database = require('better-sqlite3'); // SQLite database driver

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Ensure JWT_SECRET is set
if (!JWT_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET is not defined in .env file.');
    process.exit(1);
}

// ----------------------
// 2. Middleware
// ----------------------
app.use(cors()); // Allow requests from our frontend
app.use(express.json()); // Parse JSON request bodies

// ----------------------
// 3. Database Setup (SQLite)
// ----------------------
const db = new Database('coaching_portal.db'); // This creates/opens the database file

// Function to initialize tables if they don't exist
const initializeDb = () => {
    // Users table
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('teacher', 'student')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // Classrooms table
    db.exec(`
        CREATE TABLE IF NOT EXISTS classrooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            class_code TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    // Junction table for students and classrooms (many-to-many)
    db.exec(`
        CREATE TABLE IF NOT EXISTS student_classrooms (
            student_id INTEGER NOT NULL,
            classroom_id INTEGER NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (student_id, classroom_id),
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (classroom_id) REFERENCES classrooms(id) ON DELETE CASCADE
        );
    `);

    // New table: Attendance Records
    db.exec(`
        CREATE TABLE IF NOT EXISTS attendance_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            classroom_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            date TEXT NOT NULL, -- YYYY-MM-DD format
            status TEXT NOT NULL CHECK(status IN ('Present', 'Absent', 'Late')),
            recorded_by INTEGER NOT NULL, -- Teacher ID
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (classroom_id, student_id, date), -- Ensure only one record per student per day per class
            FOREIGN KEY (classroom_id) REFERENCES classrooms(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (recorded_by) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    // New table: Assignments
    db.exec(`
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            classroom_id INTEGER NOT NULL,
            teacher_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            due_date TEXT NOT NULL, -- YYYY-MM-DD format
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (classroom_id) REFERENCES classrooms(id) ON DELETE CASCADE,
            FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    // New table: Submissions
    db.exec(`
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assignment_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            submission_text TEXT NOT NULL, -- URL or actual text
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            grade TEXT,
            PRIMARY KEY (assignment_id, student_id), -- Only one submission per student per assignment
            FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    // New table: Class Notes
    db.exec(`
        CREATE TABLE IF NOT EXISTS class_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            classroom_id INTEGER NOT NULL,
            teacher_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (classroom_id) REFERENCES classrooms(id) ON DELETE CASCADE,
            FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    // New table: Fees
    db.exec(`
        CREATE TABLE IF NOT EXISTS fees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            classroom_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            amount_due REAL NOT NULL,
            amount_paid REAL DEFAULT 0,
            due_date TEXT, -- YYYY-MM-DD format
            status TEXT NOT NULL CHECK(status IN ('Due', 'Paid')) DEFAULT 'Due',
            paid_date TEXT, -- YYYY-MM-DD format
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (classroom_id, student_id), -- Only one fee record per student per class at a time
            FOREIGN KEY (classroom_id) REFERENCES classrooms(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    console.log('Database tables checked/created.');
};
initializeDb();

// ----------------------
// 4. Authentication Middleware
// ----------------------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ message: 'Authorization token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("JWT Verification Error:", err.message);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user; // Attach user payload (id, role) to request
        next();
    });
};

// ----------------------
// 5. Helper Functions
// ----------------------
// Generate a simple, unique class code (e.g., ABC123)
const generateClassCode = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 6; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    // In a real application, you'd want to check if this code already exists
    // and regenerate if it does, to ensure true uniqueness.
    return result;
};

// ----------------------
// 6. API Endpoints
// ----------------------

// A. User Authentication
app.post('/api/signup', async (req, res) => {
    const { fullName, email, password, role } = req.body;

    if (!fullName || !email || !password || !role) {
        return res.status(400).json({ message: 'All fields are required.' });
    }
    if (!['teacher', 'student'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role specified.' });
    }

    try {
        const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists.' });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const stmt = db.prepare('INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, ?)');
        const info = stmt.run(fullName, email, passwordHash, role);
        const userId = info.lastInsertRowid;

        const token = jwt.sign({ id: userId, role: role }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            message: 'User registered successfully!',
            token,
            user: { id: userId, fullName, email, role }
        });
    } catch (error) {
        console.error('Signup error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error during signup.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const user = db.prepare('SELECT id, full_name, email, password_hash, role FROM users WHERE email = ?').get(email);
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({
            message: 'Logged in successfully!',
            token,
            user: { id: user.id, fullName: user.full_name, email: user.email, role: user.role }
        });
    } catch (error) {
        console.error('Login error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// B. Classroom Management
app.post('/api/classrooms', authenticateToken, (req, res) => {
    if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: 'Access denied. Only teachers can create classrooms.' });
    }

    const { name, description } = req.body;
    if (!name) {
        return res.status(400).json({ message: 'Classroom name is required.' });
    }

    try {
        const teacherId = req.user.id;
        let classCode = generateClassCode();
        // Basic uniqueness check for class code (can be improved)
        let existingCode = db.prepare('SELECT id FROM classrooms WHERE class_code = ?').get(classCode);
        while (existingCode) {
            classCode = generateClassCode();
            existingCode = db.prepare('SELECT id FROM classrooms WHERE class_code = ?').get(classCode);
        }

        const stmt = db.prepare('INSERT INTO classrooms (teacher_id, name, description, class_code) VALUES (?, ?, ?, ?)');
        const info = stmt.run(teacherId, name, description, classCode);
        const classroomId = info.lastInsertRowid;

        res.status(201).json({
            message: 'Classroom created successfully!',
            classroom: { id: classroomId, teacher_id: teacherId, name, description, class_code: classCode }
        });
    } catch (error) {
        console.error('Create classroom error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error creating classroom.' });
    }
});

app.get('/api/classrooms', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        let classrooms;
        if (userRole === 'teacher') {
            // Get classrooms created by this teacher
            classrooms = db.prepare('SELECT id, name, description, class_code FROM classrooms WHERE teacher_id = ?').all(userId);
        } else if (userRole === 'student') {
            // Get classrooms this student has joined
            classrooms = db.prepare(`
                SELECT c.id, c.name, c.description, u.full_name as teacher_name
                FROM classrooms c
                JOIN student_classrooms sc ON c.id = sc.classroom_id
                JOIN users u ON c.teacher_id = u.id
                WHERE sc.student_id = ?
            `).all(userId);
        } else {
            return res.status(403).json({ message: 'Invalid user role.' });
        }
        res.status(200).json({ classrooms });
    } catch (error) {
        console.error('Get classrooms error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error fetching classrooms.' });
    }
});

// Get a single classroom's details
app.get('/api/classrooms/:id', authenticateToken, (req, res) => {
    const classroomId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        const classroom = db.prepare('SELECT id, teacher_id, name, description, class_code FROM classrooms WHERE id = ?').get(classroomId);

        if (!classroom) {
            return res.status(404).json({ message: 'Classroom not found.' });
        }

        // Verify user access to this classroom
        if (userRole === 'teacher' && classroom.teacher_id !== userId) {
            return res.status(403).json({ message: 'Access denied. You are not the teacher of this classroom.' });
        }
        if (userRole === 'student') {
            const isStudentInClass = db.prepare('SELECT 1 FROM student_classrooms WHERE student_id = ? AND classroom_id = ?').get(userId, classroomId);
            if (!isStudentInClass) {
                return res.status(403).json({ message: 'Access denied. You have not joined this classroom.' });
            }
        }

        res.status(200).json({ classroom });
    } catch (error) {
        console.error('Get single classroom error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error fetching classroom details.' });
    }
});


app.post('/api/classrooms/join', authenticateToken, (req, res) => {
    if (req.user.role !== 'student') {
        return res.status(403).json({ message: 'Access denied. Only students can join classrooms.' });
    }

    const { classCode } = req.body;
    if (!classCode) {
        return res.status(400).json({ message: 'Class code is required.' });
    }

    try {
        const studentId = req.user.id;
        const classroom = db.prepare('SELECT id FROM classrooms WHERE class_code = ?').get(classCode);

        if (!classroom) {
            return res.status(404).json({ message: 'Classroom not found with this code.' });
        }

        // Check if student already joined
        const existingJoin = db.prepare('SELECT * FROM student_classrooms WHERE student_id = ? AND classroom_id = ?').get(studentId, classroom.id);
        if (existingJoin) {
            return res.status(409).json({ message: 'You have already joined this classroom.' });
        }

        const stmt = db.prepare('INSERT INTO student_classrooms (student_id, classroom_id) VALUES (?, ?)');
        stmt.run(studentId, classroom.id);

        res.status(200).json({ message: 'Successfully joined classroom!', classroom_id: classroom.id });
    } catch (error) {
        console.error('Join classroom error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error joining classroom.' });
    }
});

// C. Attendance Management
app.post('/api/classrooms/:classroomId/attendance', authenticateToken, (req, res) => {
    const { classroomId } = req.params;
    const { date, records } = req.body; // records: [{studentId, status}]

    if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: 'Access denied. Only teachers can mark attendance.' });
    }
    if (!date || !Array.isArray(records) || records.length === 0) {
        return res.status(400).json({ message: 'Date and attendance records are required.' });
    }

    try {
        // Verify teacher owns the classroom
        const classroom = db.prepare('SELECT teacher_id FROM classrooms WHERE id = ?').get(classroomId);
        if (!classroom || classroom.teacher_id !== req.user.id) {
            return res.status(403).json({ message: 'Access denied. You do not manage this classroom.' });
        }

        db.transaction(() => {
            const insertOrUpdateStmt = db.prepare(`
                INSERT INTO attendance_records (classroom_id, student_id, date, status, recorded_by)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(classroom_id, student_id, date) DO UPDATE SET status = EXCLUDED.status, created_at = CURRENT_TIMESTAMP;
            `);

            for (const record of records) {
                if (!['Present', 'Absent', 'Late'].includes(record.status)) {
                    throw new Error(`Invalid status for student ${record.studentId}`);
                }
                insertOrUpdateStmt.run(classroomId, record.studentId, date, record.status, req.user.id);
            }
        })(); // Call the transaction function

        res.status(200).json({ message: 'Attendance recorded successfully!' });
    } catch (error) {
        console.error('Mark attendance error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error marking attendance.', error: error.message });
    }
});

app.get('/api/classrooms/:classroomId/attendance', authenticateToken, (req, res) => {
    const { classroomId } = req.params;
    const { date } = req.query; // Optional date for teachers to view specific day

    try {
        const userId = req.user.id;
        const userRole = req.user.role;

        // Basic check if user has access to the classroom
        const classroomCheck = db.prepare(`
            SELECT c.id, c.teacher_id, sc.student_id FROM classrooms c
            LEFT JOIN student_classrooms sc ON c.id = sc.classroom_id AND sc.student_id = ?
            WHERE c.id = ? AND (c.teacher_id = ? OR sc.student_id = ?)
        `).get(userId, classroomId, userId, userId);

        if (!classroomCheck) {
            return res.status(403).json({ message: 'Access denied. You do not have access to this classroom.' });
        }

        if (userRole === 'teacher') {
            let students;
            if (date) {
                // Get all students in the class, along with their attendance for the specific date
                students = db.prepare(`
                    SELECT u.id, u.full_name, ar.status AS attendance_status
                    FROM users u
                    JOIN student_classrooms sc ON u.id = sc.student_id
                    LEFT JOIN attendance_records ar ON u.id = ar.student_id AND ar.classroom_id = sc.classroom_id AND ar.date = ?
                    WHERE sc.classroom_id = ? AND u.role = 'student'
                    ORDER BY u.full_name;
                `).all(date, classroomId);
            } else {
                // Return all students without attendance status if no date is specified (for UI where teacher loads students first)
                students = db.prepare(`
                    SELECT u.id, u.full_name
                    FROM users u
                    JOIN student_classrooms sc ON u.id = sc.student_id
                    WHERE sc.classroom_id = ? AND u.role = 'student'
                    ORDER BY u.full_name;
                `).all(classroomId);
            }
            res.status(200).json({ students });
        } else if (userRole === 'student') {
            // Get student's attendance history for this classroom
            const attendanceHistory = db.prepare(`
                SELECT date, status FROM attendance_records
                WHERE student_id = ? AND classroom_id = ?
                ORDER BY date DESC;
            `).all(userId, classroomId);
            res.status(200).json({ attendance_history: attendanceHistory });
        } else {
            return res.status(403).json({ message: 'Invalid user role.' });
        }
    } catch (error) {
        console.error('Get attendance error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error fetching attendance.' });
    }
});


// D. Assignment Management
app.post('/api/classrooms/:classroomId/assignments', authenticateToken, (req, res) => {
    const { classroomId } = req.params;
    const { title, description, due_date } = req.body;

    if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: 'Access denied. Only teachers can create assignments.' });
    }
    if (!title || !due_date) {
        return res.status(400).json({ message: 'Assignment title and due date are required.' });
    }

    try {
        // Verify teacher owns the classroom
        const classroom = db.prepare('SELECT teacher_id FROM classrooms WHERE id = ?').get(classroomId);
        if (!classroom || classroom.teacher_id !== req.user.id) {
            return res.status(403).json({ message: 'Access denied. You do not manage this classroom.' });
        }

        const stmt = db.prepare('INSERT INTO assignments (classroom_id, teacher_id, title, description, due_date) VALUES (?, ?, ?, ?, ?)');
        const info = stmt.run(classroomId, req.user.id, title, description, due_date);
        res.status(201).json({ message: 'Assignment created successfully!', assignment_id: info.lastInsertRowid });
    } catch (error) {
        console.error('Create assignment error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error creating assignment.' });
    }
});

app.get('/api/classrooms/:classroomId/assignments', authenticateToken, (req, res) => {
    const { classroomId } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        // Verify user has access to the classroom
        const classroomCheck = db.prepare(`
            SELECT c.id FROM classrooms c
            LEFT JOIN student_classrooms sc ON c.id = sc.classroom_id AND sc.student_id = ?
            WHERE c.id = ? AND (c.teacher_id = ? OR sc.student_id = ?)
        `).get(userId, classroomId, userId, userId);

        if (!classroomCheck) {
            return res.status(403).json({ message: 'Access denied. You do not have access to this classroom.' });
        }

        const assignments = db.prepare('SELECT id, title, description, due_date FROM assignments WHERE classroom_id = ? ORDER BY due_date DESC').all(classroomId);
        res.status(200).json({ assignments });
    } catch (error) {
        console.error('Get assignments error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error fetching assignments.' });
    }
});

app.post('/api/assignments/:assignmentId/submit', authenticateToken, (req, res) => {
    const { assignmentId } = req.params;
    const { submission_text } = req.body;

    if (req.user.role !== 'student') {
        return res.status(403).json({ message: 'Access denied. Only students can submit assignments.' });
    }
    if (!submission_text) {
        return res.status(400).json({ message: 'Submission content is required.' });
    }

    try {
        // Verify assignment exists and student is in the associated classroom
        const assignment = db.prepare('SELECT classroom_id FROM assignments WHERE id = ?').get(assignmentId);
        if (!assignment) {
            return res.status(404).json({ message: 'Assignment not found.' });
        }
        const isStudentInClass = db.prepare('SELECT 1 FROM student_classrooms WHERE student_id = ? AND classroom_id = ?').get(req.user.id, assignment.classroom_id);
        if (!isStudentInClass) {
            return res.status(403).json({ message: 'Access denied. You are not part of this classroom.' });
        }

        const stmt = db.prepare(`
            INSERT INTO submissions (assignment_id, student_id, submission_text)
            VALUES (?, ?, ?)
            ON CONFLICT(assignment_id, student_id) DO UPDATE SET submission_text = EXCLUDED.submission_text, submitted_at = CURRENT_TIMESTAMP;
        `);
        stmt.run(assignmentId, req.user.id, submission_text);
        res.status(200).json({ message: 'Assignment submitted successfully!' });
    } catch (error) {
        console.error('Submit assignment error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error submitting assignment.' });
    }
});

app.get('/api/assignments/:assignmentId/submissions', authenticateToken, (req, res) => {
    const { assignmentId } = req.params;

    if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: 'Access denied. Only teachers can view submissions.' });
    }

    try {
        // Verify teacher owns the assignment's classroom
        const assignment = db.prepare('SELECT classroom_id FROM assignments WHERE id = ? AND teacher_id = ?').get(assignmentId, req.user.id);
        if (!assignment) {
            return res.status(403).json({ message: 'Access denied. You do not manage this assignment.' });
        }

        const submissions = db.prepare(`
            SELECT s.submission_text, s.submitted_at, s.grade, u.full_name as student_name
            FROM submissions s
            JOIN users u ON s.student_id = u.id
            WHERE s.assignment_id = ?
            ORDER BY s.submitted_at DESC;
        `).all(assignmentId);
        res.status(200).json({ submissions });
    } catch (error) {
        console.error('Get submissions error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error fetching submissions.' });
    }
});

// E. Class Notes Management
app.post('/api/classrooms/:classroomId/notes', authenticateToken, (req, res) => {
    const { classroomId } = req.params;
    const { title, content } = req.body;

    if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: 'Access denied. Only teachers can add notes.' });
    }
    if (!title || !content) {
        return res.status(400).json({ message: 'Note title and content are required.' });
    }

    try {
        // Verify teacher owns the classroom
        const classroom = db.prepare('SELECT teacher_id FROM classrooms WHERE id = ?').get(classroomId);
        if (!classroom || classroom.teacher_id !== req.user.id) {
            return res.status(403).json({ message: 'Access denied. You do not manage this classroom.' });
        }

        const stmt = db.prepare('INSERT INTO class_notes (classroom_id, teacher_id, title, content) VALUES (?, ?, ?, ?)');
        const info = stmt.run(classroomId, req.user.id, title, content);
        res.status(201).json({ message: 'Note added successfully!', note_id: info.lastInsertRowid });
    } catch (error) {
        console.error('Add note error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error adding note.' });
    }
});

app.get('/api/classrooms/:classroomId/notes', authenticateToken, (req, res) => {
    const { classroomId } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        // Verify user has access to the classroom
        const classroomCheck = db.prepare(`
            SELECT c.id FROM classrooms c
            LEFT JOIN student_classrooms sc ON c.id = sc.classroom_id AND sc.student_id = ?
            WHERE c.id = ? AND (c.teacher_id = ? OR sc.student_id = ?)
        `).get(userId, classroomId, userId, userId);

        if (!classroomCheck) {
            return res.status(403).json({ message: 'Access denied. You do not have access to this classroom.' });
        }

        const notes = db.prepare(`
            SELECT cn.title, cn.content, cn.created_at, u.full_name as teacher_name
            FROM class_notes cn
            JOIN users u ON cn.teacher_id = u.id
            WHERE cn.classroom_id = ?
            ORDER BY cn.created_at DESC;
        `).all(classroomId);
        res.status(200).json({ notes });
    } catch (error) {
        console.error('Get notes error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error fetching notes.' });
    }
});

// F. Fees Management
// For simplicity, this endpoint manages a single "current" fee for a student in a class.
// A more complex system would handle multiple invoices/payment schedules.

app.post('/api/classrooms/:classroomId/fees', authenticateToken, (req, res) => {
    const { classroomId } = req.params;
    const { studentId, amount_due, due_date } = req.body; // For teacher to set initial fee

    if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: 'Access denied. Only teachers can manage fees.' });
    }
    if (!studentId || !amount_due) { // due_date is optional
        return res.status(400).json({ message: 'Student ID and amount due are required.' });
    }

    try {
        // Verify teacher owns the classroom
        const classroom = db.prepare('SELECT teacher_id FROM classrooms WHERE id = ?').get(classroomId);
        if (!classroom || classroom.teacher_id !== req.user.id) {
            return res.status(403).json({ message: 'Access denied. You do not manage this classroom.' });
        }

        // Verify student is in this classroom
        const studentInClass = db.prepare('SELECT 1 FROM student_classrooms WHERE student_id = ? AND classroom_id = ?').get(studentId, classroomId);
        if (!studentInClass) {
            return res.status(400).json({ message: 'Student is not enrolled in this classroom.' });
        }

        const stmt = db.prepare(`
            INSERT INTO fees (classroom_id, student_id, amount_due, due_date, status, amount_paid, paid_date)
            VALUES (?, ?, ?, ?, 'Due', 0, NULL)
            ON CONFLICT(classroom_id, student_id) DO UPDATE SET
                amount_due = EXCLUDED.amount_due,
                due_date = EXCLUDED.due_date,
                status = 'Due', -- Reset status to 'Due' if amount or due date is updated
                amount_paid = 0,
                paid_date = NULL,
                created_at = CURRENT_TIMESTAMP;
        `);
        const info = stmt.run(classroomId, studentId, amount_due, due_date);
        res.status(200).json({ message: 'Fee updated successfully!', fee_id: info.lastInsertRowid });
    } catch (error) {
        console.error('Set fee error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error setting fee.' });
    }
});


app.get('/api/classrooms/:classroomId/fees', authenticateToken, (req, res) => {
    const { classroomId } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        // Verify user has access to the classroom
        const classroomCheck = db.prepare(`
            SELECT c.id FROM classrooms c
            LEFT JOIN student_classrooms sc ON c.id = sc.classroom_id AND sc.student_id = ?
            WHERE c.id = ? AND (c.teacher_id = ? OR sc.student_id = ?)
        `).get(userId, classroomId, userId, userId);

        if (!classroomCheck) {
            return res.status(403).json({ message: 'Access denied. You do not have access to this classroom.' });
        }

        if (userRole === 'teacher') {
            // Get all students in the class with their fee status
            const feesSummary = db.prepare(`
                SELECT u.id as student_id, u.full_name as student_name,
                       f.id as fee_id, f.amount_due, f.status, f.paid_date
                FROM users u
                JOIN student_classrooms sc ON u.id = sc.student_id
                LEFT JOIN fees f ON u.id = f.student_id AND f.classroom_id = sc.classroom_id
                WHERE sc.classroom_id = ? AND u.role = 'student'
                ORDER BY u.full_name;
            `).all(classroomId);

            res.status(200).json({ fees_summary: feesSummary });
        } else if (userRole === 'student') {
            // Get student's fee status for this classroom
            const myFees = db.prepare(`
                SELECT id, amount_due, status, paid_date
                FROM fees
                WHERE student_id = ? AND classroom_id = ?;
            `).all(userId, classroomId); // Use .all() as there might be future multi-fee system

            res.status(200).json({ my_fees: myFees });
        } else {
            return res.status(403).json({ message: 'Invalid user role.' });
        }
    } catch (error) {
        console.error('Get fees error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error fetching fees information.' });
    }
});

app.post('/api/fees/:feeId/pay', authenticateToken, (req, res) => {
    const { feeId } = req.params;
    const userId = req.user.id;
    const userRole = req.user.role;
    const current_date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

    try {
        const fee = db.prepare('SELECT classroom_id, student_id, status FROM fees WHERE id = ?').get(feeId);
        if (!fee) {
            return res.status(404).json({ message: 'Fee record not found.' });
        }

        // Authorization check: Teacher of the class, or the student themselves
        const classroom = db.prepare('SELECT teacher_id FROM classrooms WHERE id = ?').get(fee.classroom_id);
        if (!classroom) {
             return res.status(404).json({ message: 'Associated classroom not found.' });
        }

        if (userRole === 'teacher' && classroom.teacher_id !== userId) {
            return res.status(403).json({ message: 'Access denied. You are not the teacher of this classroom.' });
        }
        if (userRole === 'student' && fee.student_id !== userId) {
            return res.status(403).json({ message: 'Access denied. This fee record does not belong to you.' });
        }

        if (fee.status === 'Paid') {
            return res.status(409).json({ message: 'This fee is already marked as paid.' });
        }

        const stmt = db.prepare('UPDATE fees SET status = ?, amount_paid = amount_due, paid_date = ? WHERE id = ?');
        stmt.run('Paid', current_date, feeId);

        res.status(200).json({ message: 'Fee marked as paid successfully!' });
    } catch (error) {
        console.error('Pay fee error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error processing payment.' });
    }
});


// ----------------------
// 7. Start Server
// ----------------------
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});