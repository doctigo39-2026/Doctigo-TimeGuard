require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'timeguard-dev-secret-CHANGE-IN-PRODUCTION';

// ── DATABASE ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(100) DEFAULT '',
        organisation VARCHAR(200) DEFAULT '',
        industry VARCHAR(50) DEFAULT 'general',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS entries (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(300) DEFAULT '',
        content TEXT DEFAULT '',
        tag VARCHAR(50) DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS cases (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(300) NOT NULL,
        type VARCHAR(100) DEFAULT '',
        priority VARCHAR(20) DEFAULT 'Medium',
        stage VARCHAR(50) DEFAULT 'Intake',
        assigned_to VARCHAR(200) DEFAULT '',
        due_date DATE,
        description TEXT DEFAULT '',
        tags TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS resources (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(200) NOT NULL,
        category VARCHAR(100) DEFAULT '',
        quantity NUMERIC DEFAULT 0,
        unit VARCHAR(50) DEFAULT '',
        min_level NUMERIC DEFAULT 0,
        max_level NUMERIC DEFAULT 0,
        notes TEXT DEFAULT '',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS assets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(200) NOT NULL,
        category VARCHAR(100) DEFAULT '',
        description TEXT DEFAULT ''
      );
      CREATE TABLE IF NOT EXISTS bookings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        booked_date DATE NOT NULL,
        booked_time VARCHAR(20) NOT NULL,
        booked_by VARCHAR(200) DEFAULT '',
        purpose TEXT DEFAULT '',
        status VARCHAR(30) DEFAULT 'Confirmed',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(asset_id, booked_date, booked_time)
      );
      CREATE TABLE IF NOT EXISTS requests (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(300) NOT NULL,
        type VARCHAR(100) DEFAULT 'General',
        priority VARCHAR(20) DEFAULT 'Medium',
        requested_by VARCHAR(200) DEFAULT '',
        assigned_to VARCHAR(200) DEFAULT '',
        due_date DATE,
        description TEXT NOT NULL,
        status VARCHAR(30) DEFAULT 'Open',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sops (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(300) NOT NULL,
        category VARCHAR(100) DEFAULT '',
        description TEXT DEFAULT '',
        steps TEXT NOT NULL,
        owner VARCHAR(200) DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(200) NOT NULL,
        detail TEXT DEFAULT '',
        icon VARCHAR(10) DEFAULT '📝',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log('✓ Doctigo Timeguard — database tables ready');
  } finally {
    client.release();
  }
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*', credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
const aiLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
app.use('/api/', limiter);

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Unauthorized — no token provided' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

async function log(userId, action, detail = '', icon = '📝') {
  try { await pool.query('INSERT INTO audit_log (user_id,action,detail,icon) VALUES ($1,$2,$3,$4)', [userId, action, detail, icon]); } catch {}
}

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'online', service: 'Doctigo Timeguard API', version: '1.0.0', db: 'connected', ts: new Date().toISOString() });
  } catch (e) { res.status(500).json({ status: 'degraded', db: 'disconnected', error: e.message }); }
});

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password, role, organisation } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      'INSERT INTO users (name,email,password_hash,role,organisation) VALUES ($1,$2,$3,$4,$5) RETURNING id,name,email,role,organisation,industry,created_at',
      [name.trim(), email.toLowerCase().trim(), hash, role || '', organisation || '']
    );
    const user = r.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    await log(user.id, 'Account registered', name, '🎉');
    res.json({ token, user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'An account with this email already exists' });
    res.status(500).json({ error: 'Server error — please try again' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid email or password' });
    const user = r.rows[0];
    if (!await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    await log(user.id, 'Signed in', '', '🔑');
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, organisation: user.organisation, industry: user.industry } });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/demo', authLimiter, async (req, res) => {
  try {
    const demoEmail = 'demo@timeguard.app';
    let r = await pool.query('SELECT id,name,email,role,organisation,industry FROM users WHERE email=$1', [demoEmail]);
    if (!r.rows.length) {
      const hash = await bcrypt.hash('demo1234', 12);
      r = await pool.query(
        'INSERT INTO users (name,email,password_hash,role,organisation) VALUES ($1,$2,$3,$4,$5) RETURNING id,name,email,role,organisation,industry',
        ['Demo User', demoEmail, hash, 'Operations Manager', 'Demo Organisation']
      );
      const uid = r.rows[0].id;
      await pool.query(`INSERT INTO entries (user_id,title,content,tag) VALUES
        ($1,'Q1 Planning Session','Roadmap priorities for Q1.\n\nFocus areas:\n- Workflow automation\n- Team expansion\n- Client onboarding\n\nActions:\n- Hire 2 ops staff by Feb\n- Launch portal by March','Planning'),
        ($1,'Client Meeting — Acme Corp','Requirements gathered:\n- Custom dashboard\n- API integration\n- Weekly status calls\n\nNext: send proposal Friday','Meeting'),
        ($1,'Process Improvement Notes','Bottlenecks found:\n1. Manual email chains\n2. No request visibility\n3. No standard templates\n\nFix: use Requests module','Research')`, [uid]);
      await pool.query(`INSERT INTO cases (user_id,title,type,priority,stage,assigned_to,description,tags) VALUES
        ($1,'Acme Corp Onboarding','Client','High','In Progress','Demo User','Enterprise client onboarding','enterprise,priority'),
        ($1,'Annual Compliance Audit','Compliance','Critical','Intake','Legal Team','Annual regulatory review','legal,urgent'),
        ($1,'Office Renovation Approval','Internal','Medium','Review','Operations','Budget approval needed','facilities'),
        ($1,'Website Redesign','Project','Low','Done','Design Team','Completed overhaul','design')`, [uid]);
      await pool.query(`INSERT INTO resources (user_id,name,category,quantity,unit,min_level,max_level,notes) VALUES
        ($1,'A4 Paper','Stationery',45,'reams',10,100,'Order from Staples'),
        ($1,'Software Licenses','Digital',18,'seats',5,30,'Annual renewal June'),
        ($1,'Server Storage','Infrastructure',250,'GB',50,500,'Cloud bucket'),
        ($1,'Printer Ink','Stationery',3,'units',5,20,'HP 305XL — LOW STOCK')`, [uid]);
      await pool.query(`INSERT INTO assets (user_id,name,category,description) VALUES
        ($1,'Conference Room A','Room','12-person capacity, projector, whiteboard'),
        ($1,'Delivery Van 1','Vehicle','Ford Transit — MH02AB1234'),
        ($1,'Laptop Pool Unit 3','Equipment','Dell XPS 15 — available for loan')`, [uid]);
      await pool.query(`INSERT INTO requests (user_id,title,type,priority,requested_by,assigned_to,description,status) VALUES
        ($1,'Purchase ergonomic chairs','Purchase','Medium','HR Team','Demo User','Need 5 chairs for new joiners','Open'),
        ($1,'IT access for new hire','Access','High','New Hire','IT Admin','Need access to CRM, email, Timeguard','In Review'),
        ($1,'Q4 Report sign-off','Approval','High','Finance','Demo User','Q4 report ready for board','Approved')`, [uid]);
      await pool.query(`INSERT INTO sops (user_id,title,category,description,steps,owner) VALUES
        ($1,'Employee Onboarding','HR','Standard procedure for all new hires',E'Prepare workstation and equipment\nCreate email and system accounts\nSend welcome email\nSchedule intro calls with team leads\nAssign buddy / mentor\nComplete compliance training\nWeek 1 check-in meeting','HR Team'),
        ($1,'Client Intake Process','Operations','From first contact to active client',E'Log enquiry\nSchedule discovery call within 48 hours\nConduct needs assessment\nSend proposal\nCollect signed agreement\nCreate case in tracker\nAssign account manager','Sales & Ops'),
        ($1,'Purchase Request Approval','Finance','Approval process for purchases',E'Submit request via Requests module\nManager reviews within 2 business days\nAmounts over 50k need Finance Director approval\nRaise purchase order\nSend to supplier\nReceive and verify goods\nProcess payment','Finance Team')`, [uid]);
      await log(uid, 'Demo account created', 'Seeded with sample data', '🚀');
    }
    const user = r.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch (e) {
    console.error('[Demo]', e.message);
    res.status(500).json({ error: 'Could not create demo account: ' + e.message });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT id,name,email,role,organisation,industry FROM users WHERE id=$1', [req.user.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.patch('/api/auth/industry', auth, async (req, res) => {
  const { industry } = req.body;
  await pool.query('UPDATE users SET industry=$1 WHERE id=$2', [industry, req.user.id]);
  await log(req.user.id, 'Industry changed', industry, '🏭');
  res.json({ ok: true });
});

// ── STATS ─────────────────────────────────────────────────────────────────────
app.get('/api/stats', auth, async (req, res) => {
  const uid = req.user.id;
  const [ent, cas, res_, req_, sop, bk] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM entries WHERE user_id=$1', [uid]),
    pool.query('SELECT COUNT(*) FROM cases WHERE user_id=$1', [uid]),
    pool.query('SELECT COUNT(*) FROM resources WHERE user_id=$1', [uid]),
    pool.query("SELECT COUNT(*) FROM requests WHERE user_id=$1 AND status IN ('Open','In Review')", [uid]),
    pool.query('SELECT COUNT(*) FROM sops WHERE user_id=$1', [uid]),
    pool.query('SELECT COUNT(*) FROM bookings WHERE user_id=$1', [uid]),
  ]);
  res.json({
    entries: parseInt(ent.rows[0].count),
    cases: parseInt(cas.rows[0].count),
    resources: parseInt(res_.rows[0].count),
    open_requests: parseInt(req_.rows[0].count),
    sops: parseInt(sop.rows[0].count),
    bookings: parseInt(bk.rows[0].count),
  });
});

// ── NOTEBOOK ENTRIES ──────────────────────────────────────────────────────────
app.get('/api/entries', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM entries WHERE user_id=$1 ORDER BY updated_at DESC', [req.user.id]);
  res.json(r.rows);
});
app.post('/api/entries', auth, async (req, res) => {
  try {
    const { title, content, tag } = req.body;
    const r = await pool.query('INSERT INTO entries (user_id,title,content,tag) VALUES ($1,$2,$3,$4) RETURNING *', [req.user.id, title||'', content||'', tag||'']);
    await log(req.user.id, 'Entry created', title||'Untitled', '📓');
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.put('/api/entries/:id', auth, async (req, res) => {
  try {
    const { title, content, tag } = req.body;
    const r = await pool.query('UPDATE entries SET title=$1,content=$2,tag=$3,updated_at=NOW() WHERE id=$4 AND user_id=$5 RETURNING *', [title||'', content||'', tag||'', req.params.id, req.user.id]);
    res.json(r.rows[0] || {});
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/entries/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM entries WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  await log(req.user.id, 'Entry deleted', '', '🗑️');
  res.json({ ok: true });
});

// ── CASES ─────────────────────────────────────────────────────────────────────
app.get('/api/cases', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM cases WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json(r.rows);
});
app.post('/api/cases', auth, async (req, res) => {
  try {
    const { title, type, priority, stage, assigned_to, due_date, description, tags } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const r = await pool.query('INSERT INTO cases (user_id,title,type,priority,stage,assigned_to,due_date,description,tags) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [req.user.id, title, type||'', priority||'Medium', stage||'Intake', assigned_to||'', due_date||null, description||'', tags||'']);
    await log(req.user.id, 'Case created', title, '📦');
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.put('/api/cases/:id', auth, async (req, res) => {
  try {
    const { title, type, priority, stage, assigned_to, due_date, description, tags } = req.body;
    const r = await pool.query('UPDATE cases SET title=$1,type=$2,priority=$3,stage=$4,assigned_to=$5,due_date=$6,description=$7,tags=$8 WHERE id=$9 AND user_id=$10 RETURNING *',
      [title, type||'', priority||'Medium', stage||'Intake', assigned_to||'', due_date||null, description||'', tags||'', req.params.id, req.user.id]);
    await log(req.user.id, 'Case updated', title, '✏️');
    res.json(r.rows[0] || {});
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.patch('/api/cases/:id/stage', auth, async (req, res) => {
  const { stage } = req.body;
  const r = await pool.query('UPDATE cases SET stage=$1 WHERE id=$2 AND user_id=$3 RETURNING *', [stage, req.params.id, req.user.id]);
  await log(req.user.id, 'Case moved to ' + stage, '', '→');
  res.json(r.rows[0] || {});
});
app.delete('/api/cases/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM cases WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  await log(req.user.id, 'Case deleted', '', '🗑️');
  res.json({ ok: true });
});

// ── RESOURCES ─────────────────────────────────────────────────────────────────
app.get('/api/resources', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM resources WHERE user_id=$1 ORDER BY name', [req.user.id]);
  res.json(r.rows);
});
app.post('/api/resources', auth, async (req, res) => {
  try {
    const { name, category, quantity, unit, min_level, max_level, notes } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const r = await pool.query('INSERT INTO resources (user_id,name,category,quantity,unit,min_level,max_level,notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [req.user.id, name, category||'', quantity||0, unit||'', min_level||0, max_level||0, notes||'']);
    await log(req.user.id, 'Resource added', name, '🗃️');
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.put('/api/resources/:id', auth, async (req, res) => {
  try {
    const { name, category, quantity, unit, min_level, max_level, notes } = req.body;
    const r = await pool.query('UPDATE resources SET name=$1,category=$2,quantity=$3,unit=$4,min_level=$5,max_level=$6,notes=$7,updated_at=NOW() WHERE id=$8 AND user_id=$9 RETURNING *',
      [name, category||'', quantity||0, unit||'', min_level||0, max_level||0, notes||'', req.params.id, req.user.id]);
    res.json(r.rows[0] || {});
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.patch('/api/resources/:id/quantity', auth, async (req, res) => {
  const { quantity } = req.body;
  const r = await pool.query('UPDATE resources SET quantity=$1,updated_at=NOW() WHERE id=$2 AND user_id=$3 RETURNING *', [quantity, req.params.id, req.user.id]);
  await log(req.user.id, 'Quantity adjusted', '', '±');
  res.json(r.rows[0] || {});
});
app.delete('/api/resources/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM resources WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  await log(req.user.id, 'Resource deleted', '', '🗑️');
  res.json({ ok: true });
});

// ── ASSETS & BOOKINGS ─────────────────────────────────────────────────────────
app.get('/api/assets', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM assets WHERE user_id=$1 ORDER BY name', [req.user.id]);
  res.json(r.rows);
});
app.post('/api/assets', auth, async (req, res) => {
  try {
    const { name, category, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const r = await pool.query('INSERT INTO assets (user_id,name,category,description) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.user.id, name, category||'', description||'']);
    await log(req.user.id, 'Asset added', name, '🔧');
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/assets/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM assets WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ ok: true });
});
app.get('/api/bookings', auth, async (req, res) => {
  const r = await pool.query('SELECT b.*,a.name as asset_name FROM bookings b JOIN assets a ON a.id=b.asset_id WHERE b.user_id=$1 ORDER BY b.booked_date DESC,b.booked_time', [req.user.id]);
  res.json(r.rows);
});
app.post('/api/bookings', auth, async (req, res) => {
  try {
    const { asset_id, booked_date, booked_time, booked_by, purpose } = req.body;
    if (!asset_id || !booked_date || !booked_time) return res.status(400).json({ error: 'Asset, date and time required' });
    const asset = await pool.query('SELECT name FROM assets WHERE id=$1 AND user_id=$2', [asset_id, req.user.id]);
    if (!asset.rows.length) return res.status(404).json({ error: 'Asset not found' });
    const r = await pool.query('INSERT INTO bookings (asset_id,user_id,booked_date,booked_time,booked_by,purpose) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [asset_id, req.user.id, booked_date, booked_time, booked_by||'', purpose||'']);
    await log(req.user.id, 'Booked: ' + asset.rows[0].name, booked_time, '📅');
    res.json({ ...r.rows[0], asset_name: asset.rows[0].name });
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ error: 'That slot is already booked' });
    res.status(500).json({ error: 'Server error' });
  }
});
app.delete('/api/bookings/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM bookings WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  await log(req.user.id, 'Booking cancelled', '', '✕');
  res.json({ ok: true });
});

// ── REQUESTS ──────────────────────────────────────────────────────────────────
app.get('/api/requests', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM requests WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
  res.json(r.rows);
});
app.post('/api/requests', auth, async (req, res) => {
  try {
    const { title, type, priority, requested_by, assigned_to, due_date, description } = req.body;
    if (!title || !description) return res.status(400).json({ error: 'Title and description required' });
    const r = await pool.query('INSERT INTO requests (user_id,title,type,priority,requested_by,assigned_to,due_date,description) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [req.user.id, title, type||'General', priority||'Medium', requested_by||'', assigned_to||'', due_date||null, description]);
    await log(req.user.id, 'Request submitted', title, '📬');
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.patch('/api/requests/:id/status', auth, async (req, res) => {
  const { status } = req.body;
  const r = await pool.query('UPDATE requests SET status=$1 WHERE id=$2 AND user_id=$3 RETURNING *', [status, req.params.id, req.user.id]);
  await log(req.user.id, 'Request ' + status.toLowerCase(), '', status === 'Approved' ? '✅' : status === 'Rejected' ? '❌' : '👀');
  res.json(r.rows[0] || {});
});
app.delete('/api/requests/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM requests WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ ok: true });
});

// ── SOPs ──────────────────────────────────────────────────────────────────────
app.get('/api/sops', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM sops WHERE user_id=$1 ORDER BY title', [req.user.id]);
  res.json(r.rows);
});
app.post('/api/sops', auth, async (req, res) => {
  try {
    const { title, category, description, steps, owner } = req.body;
    if (!title || !steps) return res.status(400).json({ error: 'Title and steps required' });
    const r = await pool.query('INSERT INTO sops (user_id,title,category,description,steps,owner) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.user.id, title, category||'', description||'', steps, owner||'']);
    await log(req.user.id, 'SOP created', title, '📋');
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.put('/api/sops/:id', auth, async (req, res) => {
  try {
    const { title, category, description, steps, owner } = req.body;
    const r = await pool.query('UPDATE sops SET title=$1,category=$2,description=$3,steps=$4,owner=$5 WHERE id=$6 AND user_id=$7 RETURNING *',
      [title, category||'', description||'', steps, owner||'', req.params.id, req.user.id]);
    await log(req.user.id, 'SOP updated', title, '✏️');
    res.json(r.rows[0] || {});
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});
app.delete('/api/sops/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM sops WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ ok: true });
});

// ── AUDIT ─────────────────────────────────────────────────────────────────────
app.get('/api/audit', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM audit_log WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100', [req.user.id]);
  res.json(r.rows);
});

// ── AI PROXY ──────────────────────────────────────────────────────────────────
const AI_PROMPTS = {
  general:  'You are Doctigo Timeguard AI — a universal work management assistant. Help users with any professional task: planning, organising, writing, or analysis. Be concise, practical, and genuinely helpful.',
  planning: 'You are Doctigo Timeguard in Planning mode. Help users plan projects, create roadmaps, set priorities, and structure work efficiently. Be specific and actionable.',
  writing:  'You are Doctigo Timeguard in Writing mode. Help users write professional documents, emails, reports, and summaries clearly and effectively.',
  analysis: 'You are Doctigo Timeguard in Analysis mode. Provide structured, evidence-based analysis with clear frameworks and actionable insights.',
  sop:      'You are Doctigo Timeguard in SOP Builder mode. Always format as: Title, Objective (1 sentence), numbered steps (clear and actionable), Owner, and Notes. Make every step unambiguous and executable.',
};

app.post('/api/ai/chat', auth, aiLimiter, async (req, res) => {
  const { messages, mode = 'general', max_tokens = 1000 } = req.body;
  if (!messages || !messages.length) return res.status(400).json({ error: 'Messages required' });
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'AI not configured — add ANTHROPIC_API_KEY to Vercel environment variables' });
  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens, system: AI_PROMPTS[mode] || AI_PROMPTS.general, messages }),
    });
    const data = await upstream.json();
    if (!upstream.ok) return res.status(upstream.status).json({ error: data.error?.message || 'AI API error' });
    await log(req.user.id, 'AI chat', mode + ' mode', '🤖');
    res.json({ content: data.content[0]?.text || '' });
  } catch (e) {
    console.error('[AI]', e.message);
    res.status(500).json({ error: 'AI service error — please try again' });
  }
});

// ── CATCH-ALL ─────────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── START ─────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🟢 Doctigo Timeguard  →  http://localhost:${PORT}`);
    console.log(`   DB  : ${process.env.DATABASE_URL ? '✓ Configured' : '✗ DATABASE_URL missing'}`);
    console.log(`   AI  : ${process.env.ANTHROPIC_API_KEY ? '✓ Ready' : '✗ ANTHROPIC_API_KEY missing'}`);
    console.log(`   JWT : ${process.env.JWT_SECRET ? '✓ Set' : '⚠ Using default (set JWT_SECRET in production!)'}\n`);
  });
}).catch(e => { console.error('❌ DB init failed:', e.message); process.exit(1); });

module.exports = app;
