// index.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

let pool;
(async function initDb(){
  try {
    pool = await mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });
    console.log('DB pool created');
  } catch (err) {
    console.error('Failed to create DB pool:', err.message || err);
    process.exit(1);
  }
})();

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// ----- Validation schemas -----
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

// register schema (self signup)
const registerSchema = Joi.object({
  full_name: Joi.string().min(3).max(255).required(),
  email: Joi.string().email().required(),
  password: Joi.string().pattern(new RegExp(passwordRegex)).required(),
  role: Joi.string().valid('student','instructor','admin').required(),
  student_number: Joi.string().max(50).optional().allow(null, ''),
  faculty_id: Joi.string().max(50).optional().allow(null, ''),
  contact: Joi.string().max(100).optional().allow(null, ''),
  program_id: Joi.number().integer().optional().allow(null),
  // created_by is ignored for self-register (server sets null)
  role_requested: Joi.string().max(20).optional().allow(null, '')
});

// admin create schema (admin uses this to create other accounts)
const adminCreateSchema = Joi.object({
  full_name: Joi.string().min(3).max(255).required(),
  email: Joi.string().email().required(),
  password: Joi.string().pattern(new RegExp(passwordRegex)).required(),
  role: Joi.string().valid('student','instructor','admin').required(),
  student_number: Joi.string().max(50).optional().allow(null, ''),
  faculty_id: Joi.string().max(50).optional().allow(null, ''),
  contact: Joi.string().max(100).optional().allow(null, ''),
  program_id: Joi.number().integer().optional().allow(null),
  // optionally provide the admin id to be recorded as created_by
  created_by_admin_id: Joi.number().integer().optional().allow(null),
  role_requested: Joi.string().max(20).optional().allow(null, '')
});

// ----- Helpers -----
function adminSecretCheck(req, res, next) {
  const header = req.headers['x-admin-secret'];
  if (!process.env.ADMIN_SECRET) {
    return res.status(500).json({ error: 'Server misconfiguration: ADMIN_SECRET not set' });
  }
  if (!header || header !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized: invalid admin secret' });
  }
  next();
}

// ----- Routes -----
// Self-register (public)
app.post('/api/auth/register', async (req, res) => {
  try {
    const payload = await registerSchema.validateAsync(req.body, { abortEarly: false });

    // check unique email (email column has UNIQUE in your schema)
    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [payload.email]);
    if (existing.length > 0) return res.status(409).json({ error: 'Email already registered' });

    // Optional uniqueness checks (uncomment if you want to enforce)
    // if (payload.student_number) { /* check student_number uniqueness */ }
    // if (payload.faculty_id) { /* check faculty_id uniqueness */ }

    // hash password
    const password_hash = await bcrypt.hash(payload.password, 10);

    // For self-register, created_by should be NULL
    const createdBy = null;
    const roleRequested = payload.role_requested || null;

    // Insert using your users columns
    const [result] = await pool.execute(
      `INSERT INTO users
       (full_name, email, password_hash, role, student_number, faculty_id, contact, program_id, created_by, role_requested)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        payload.full_name,
        payload.email,
        password_hash,
        payload.role,
        payload.student_number || null,
        payload.faculty_id || null,
        payload.contact || null,
        payload.program_id || null,
        createdBy,
        roleRequested
      ]
    );

    return res.status(201).json({
      id: result.insertId,
      full_name: payload.full_name,
      email: payload.email,
      role: payload.role
    });
  } catch (err) {
    if (err.isJoi) return res.status(400).json({ error: 'Validation failed', details: err.details.map(d => d.message) });
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Admin-only create user (protected by ADMIN_SECRET header)
app.post('/api/admin/create-user', adminSecretCheck, async (req, res) => {
  try {
    const payload = await adminCreateSchema.validateAsync(req.body, { abortEarly: false });

    // unique email
    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [payload.email]);
    if (existing.length > 0) return res.status(409).json({ error: 'Email already registered' });

    // If created_by_admin_id provided, verify it exists and is admin
    let createdBy = null;
    if (payload.created_by_admin_id) {
      const [adminRow] = await pool.execute('SELECT id, role FROM users WHERE id = ? LIMIT 1', [payload.created_by_admin_id]);
      if (adminRow.length === 0) {
        return res.status(400).json({ error: 'created_by_admin_id does not exist' });
      }
      if (adminRow[0].role !== 'admin') {
        return res.status(403).json({ error: 'created_by_admin_id is not an admin' });
      }
      createdBy = adminRow[0].id;
    }

    // hash password
    const password_hash = await bcrypt.hash(payload.password, 10);
    const roleRequested = payload.role_requested || null;

    const [result] = await pool.execute(
      `INSERT INTO users
       (full_name, email, password_hash, role, student_number, faculty_id, contact, program_id, created_by, role_requested)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        payload.full_name,
        payload.email,
        password_hash,
        payload.role,
        payload.student_number || null,
        payload.faculty_id || null,
        payload.contact || null,
        payload.program_id || null,
        createdBy,
        roleRequested
      ]
    );

    return res.status(201).json({
      id: result.insertId,
      full_name: payload.full_name,
      email: payload.email,
      role: payload.role,
      created_by: createdBy
    });
  } catch (err) {
    if (err.isJoi) return res.status(400).json({ error: 'Validation failed', details: err.details.map(d => d.message) });
    console.error('Admin create user error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ---------- JWT helpers + auth middleware ----------
function signToken(payload) {
  const secret = process.env.JWT_SECRET;
  const expiresIn = process.env.JWT_EXPIRES_IN || '1h';
  return jwt.sign(payload, secret, { expiresIn });
}

async function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [rows] = await pool.execute('SELECT id, full_name, email, role FROM users WHERE id = ? LIMIT 1', [decoded.id]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid token: user not found' });

    req.user = rows[0];
    next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const [rows] = await pool.execute('SELECT id, full_name, email, password_hash, role FROM users WHERE email = ? LIMIT 1', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ id: user.id, role: user.role });

    return res.json({
      token,
      user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});
// ----------------- role helpers -----------------
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (req.user.role !== role) return res.status(403).json({ error: 'Forbidden: requires ' + role });
    next();
  };
}

// Admin: create program
app.post('/api/programs', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const { name, code } = req.body;
    if (!name) return res.status(400).json({ error: 'Program name required' });
    const [result] = await pool.execute('INSERT INTO programs (name, code) VALUES (?, ?)', [name, code || null]);
    return res.status(201).json({ id: result.insertId, name, code });
  } catch (err) {
    console.error('Create program error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});
// Admin creates a subject and assigns instructor
app.post('/api/subjects', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const { code, title, description, program_id, instructor_id, semester, class_code } = req.body;
    if (!code || !title) return res.status(400).json({ error: 'code and title required' });

    const [result] = await pool.execute(
      `INSERT INTO subjects (code, title, description, program_id, semester, instructor_id, class_code)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [code, title, description || null, program_id || null, semester || null, instructor_id || null, class_code || null]
    );
    return res.status(201).json({ id: result.insertId, code, title });
  } catch (err) {
    console.error('Create subject error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Admin approves a join request
app.post('/api/join-requests/:id/approve', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const reqId = parseInt(req.params.id, 10);
    if (!reqId) return res.status(400).json({ error: 'Invalid id' });

    const [jr] = await pool.execute('SELECT subject_id, student_id, status FROM join_requests WHERE id = ? LIMIT 1', [reqId]);
    if (jr.length === 0) return res.status(404).json({ error: 'Join request not found' });
    if (jr[0].status !== 'pending') return res.status(400).json({ error: 'Join request not pending' });

    // Insert enrollment if not existing
    await pool.execute('INSERT IGNORE INTO enrollments (student_id, subject_id) VALUES (?, ?)', [jr[0].student_id, jr[0].subject_id]);

    // update join_request status
    await pool.execute('UPDATE join_requests SET status = ?, reviewed_by = ?, reviewed_at = NOW() WHERE id = ?', ['approved', req.user.id, reqId]);

    return res.json({ ok: true, id: reqId });
  } catch (err) {
    console.error('Approve join request error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Admin change user role
app.put('/api/users/:id/role', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const uid = parseInt(req.params.id, 10);
    const { role } = req.body;
    if (!uid || !role) return res.status(400).json({ error: 'Missing user id or role' });

    if (!['student','instructor','admin'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

    await pool.execute('UPDATE users SET role = ? WHERE id = ?', [role, uid]);
    return res.json({ ok: true, id: uid, role });
  } catch (err) {
    console.error('Update role error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Instructor-only (strict) routes ----------

// Create assignment (only subject's instructor)
app.post('/api/subjects/:subjectId/assignments', authMiddleware, ensureInstructorOwnsSubject, async (req, res) => {
  try {
    const subjectId = parseInt(req.params.subjectId, 10);
    const { title, description, due_date, max_score, rubric_json } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });

    const [result] = await pool.execute(
      `INSERT INTO assignments (subject_id, title, description, due_date, max_score, rubric_json, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [subjectId, title, description || null, due_date || null, max_score || 100, rubric_json ? JSON.stringify(rubric_json) : null, req.user.id]
    );
    return res.status(201).json({ id: result.insertId, subject_id: subjectId, title });
  } catch (err) {
    console.error('Create assignment error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Create quiz (only subject's instructor)
app.post('/api/subjects/:subjectId/quizzes', authMiddleware, ensureInstructorOwnsSubject, async (req, res) => {
  try {
    const subjectId = parseInt(req.params.subjectId, 10);
    const { title, instructions, due_date, time_limit } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });

    const [result] = await pool.execute(
      `INSERT INTO quizzes (subject_id, title, instructions, due_date, time_limit, created_by)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [subjectId, title, instructions || null, due_date || null, time_limit || null, req.user.id]
    );
    return res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error('Create quiz error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Create module (only subject's instructor)
app.post('/api/subjects/:subjectId/modules', authMiddleware, ensureInstructorOwnsSubject, async (req, res) => {
  try {
    const subjectId = parseInt(req.params.subjectId, 10);
    const { title, description, file_url, file_type } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });

    const [result] = await pool.execute(
      `INSERT INTO modules (subject_id, title, description, file_url, file_type, uploaded_by)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [subjectId, title, description || null, file_url || null, file_type || null, req.user.id]
    );
    return res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error('Create module error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ---------- Optional helper endpoint for testing token -->
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ me: req.user });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API listening on http://localhost:${port}`));


