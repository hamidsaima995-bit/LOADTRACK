'use strict';
require('dotenv').config();

// ════════════════════════════════════════════════════════════════
//  BiltyTrack v3.0 — Production Server
//  100+ users ready · PostgreSQL · Gemini AI · Auth · Security
// ════════════════════════════════════════════════════════════════

const express     = require('express');
const helmet      = require('helmet');
const session     = require('express-session');
const pgSession   = require('connect-pg-simple')(session);
const rateLimit   = require('express-rate-limit');
const multer      = require('multer');
const { Pool }    = require('pg');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const path        = require('path');

// ── Startup Validation ────────────────────────────────────────
const REQUIRED = ['APP_PASSWORD', 'SESSION_SECRET', 'DATABASE_URL'];
const missing  = REQUIRED.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`\n❌  Missing .env variables: ${missing.join(', ')}`);
  console.error('    Copy .env.example to .env and fill in values.\n');
  process.exit(1);
}

if (!process.env.GEMINI_API_KEY) {
  console.warn('⚠️   GEMINI_API_KEY not set — AI extract will be disabled.');
}

const IS_PROD = process.env.NODE_ENV === 'production';
const PORT    = parseInt(process.env.PORT) || 3000;

// ── PostgreSQL Pool ───────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: false } : false,
  max:             20,    // max 20 concurrent connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

// Test connection on startup
pool.connect()
  .then(client => {
    console.log('✅  PostgreSQL connected');
    client.release();
  })
  .catch(err => {
    console.error('❌  PostgreSQL connection failed:', err.message);
    process.exit(1);
  });

// ── Initialize Tables ─────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bilty (
      id           SERIAL PRIMARY KEY,
      bilty_number VARCHAR(100) NOT NULL,
      weight       VARCHAR(50)  NOT NULL DEFAULT '',
      destination  VARCHAR(100) NOT NULL DEFAULT '',
      status       VARCHAR(20)  NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','in-transit','delivered','cancelled')),
      source       VARCHAR(10)  NOT NULL DEFAULT 'manual'
                   CHECK (source IN ('manual','ai')),
      created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_bilty_number ON bilty(bilty_number);
    CREATE INDEX IF NOT EXISTS idx_destination  ON bilty(destination);
    CREATE INDEX IF NOT EXISTS idx_status       ON bilty(status);
    CREATE INDEX IF NOT EXISTS idx_created_at   ON bilty(created_at DESC);
  `);
  console.log('✅  Database tables ready');
}

// ── Gemini AI ─────────────────────────────────────────────────
const genAI = process.env.GEMINI_API_KEY
  ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
  : null;

// ── Express App ───────────────────────────────────────────────
const app = express();
if (IS_PROD) app.set('trust proxy', 1);

// ── Helmet ────────────────────────────────────────────────────
// CSP disabled — was blocking inline onclick buttons (login, save, etc.)
// Other Helmet security protections still active.
app.use(helmet({
  contentSecurityPolicy: false
}));

// ── Body Parsers ──────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// ── Sessions (stored in PostgreSQL) ───────────────────────────
app.use(session({
  store: new pgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }),
  secret:            process.env.SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  name:              'bt.sid',
  cookie: {
    httpOnly: true,
    secure:   IS_PROD,
    sameSite: 'lax',
    maxAge:   8 * 60 * 60 * 1000   // 8 hours
  }
}));

// ── Rate Limiters ─────────────────────────────────────────────
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      300,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { success: false, message: 'Bahut zyada requests. 15 min baad try karein.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      10,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { success: false, message: '10 galat login. 15 min baad try karein.' }
});

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max:      15,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { success: false, message: 'AI limit. 1 minute baad try karein.' }
});

app.use(generalLimiter);

// ── Multer — memory only, no disk writes ──────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype)
      ? cb(null, true)
      : cb(new Error('Sirf JPG, PNG, WEBP images allowed hain.'));
  }
});

const uploadMiddleware = (req, res, next) => {
  upload.single('file')(req, res, err => {
    if (err instanceof multer.MulterError) {
      const msg = err.code === 'LIMIT_FILE_SIZE'
        ? 'File 10MB se badi hai.' : err.message;
      return res.status(400).json({ success: false, message: msg });
    }
    if (err) return res.status(400).json({ success: false, message: err.message });
    next();
  });
};

// ── Static Files ──────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  etag:   true,
  maxAge: IS_PROD ? '2h' : 0
}));

// ── Auth Middleware ───────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  res.status(401).json({ success: false, message: 'Login zaroori hai.' });
}

// ════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /auth/login
app.post('/auth/login', loginLimiter, (req, res) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string' || password.length > 200) {
    return res.status(400).json({ success: false, message: 'Password daalen.' });
  }
  if (password !== process.env.APP_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Password galat hai.' });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ success: false, message: 'Session error.' });
    req.session.authenticated = true;
    req.session.loginAt = new Date().toISOString();
    res.json({ success: true });
  });
});

// POST /auth/logout
app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('bt.sid');
    res.json({ success: true });
  });
});

// GET /auth/check
app.get('/auth/check', (req, res) => {
  res.json({ authenticated: !!req.session?.authenticated });
});

// ════════════════════════════════════════════════════════════════
//  BILTY API (all protected)
// ════════════════════════════════════════════════════════════════

// POST /api/extract — AI image read (extract only, does NOT save)
app.post('/api/extract', requireAuth, aiLimiter, uploadMiddleware, async (req, res) => {
  if (!genAI) {
    return res.status(503).json({
      success: false,
      message: 'GEMINI_API_KEY set nahi hai.'
    });
  }
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'Image nahi mili.' });
  }

  try {
    const base64 = req.file.buffer.toString('base64');
    const model  = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });

    const result = await model.generateContent([
      `You are analyzing a Pakistani transport bilty (shipping document).
Extract ONLY these fields and return a single raw JSON object — no markdown, no backticks, no extra text:
{
  "bilty_number": "the bilty or consignment number",
  "weight": "weight with unit e.g. 150 KG",
  "destination": "destination city name only",
  "status": "pending"
}
If a field is not clearly visible, use empty string "".`,
      { inlineData: { data: base64, mimeType: req.file.mimetype } }
    ]);

    const raw     = result.response.text();
    const cleaned = raw.replace(/```json|```/gi, '').trim();
    const match   = cleaned.match(/\{[\s\S]*\}/);

    if (!match) {
      return res.status(422).json({
        success: false,
        message: 'AI se valid data nahi mila. Clear image try karein.'
      });
    }

    const parsed = JSON.parse(match[0]);
    res.json({
      success: true,
      data: {
        bilty_number: String(parsed.bilty_number ?? '').trim().slice(0, 100),
        weight:       String(parsed.weight        ?? '').trim().slice(0, 50),
        destination:  String(parsed.destination   ?? '').trim().slice(0, 100),
        status:       'pending'
      }
    });

  } catch (err) {
    console.error('[POST /api/extract]', err.message);
    if (err.message?.includes('401') || err.message?.includes('API key')) {
      return res.status(401).json({ success: false, message: 'Gemini API key galat hai.' });
    }
    if (err.message?.includes('429')) {
      return res.status(429).json({ success: false, message: 'Gemini rate limit. Baad mein try karein.' });
    }
    if (err instanceof SyntaxError) {
      return res.status(422).json({ success: false, message: 'AI response parse nahi hua.' });
    }
    res.status(500).json({ success: false, message: 'AI error. Dobara try karein.' });
  }
});

// POST /api/bilty — save new bilty
app.post('/api/bilty', requireAuth, async (req, res) => {
  const { bilty_number, weight, destination, status, source } = req.body;

  if (!bilty_number?.trim()) {
    return res.status(400).json({ success: false, message: 'Bilty Number zaroori hai.' });
  }

  const validStatus = ['pending', 'in-transit', 'delivered', 'cancelled'];
  const validSource = ['manual', 'ai'];
  const safeStatus  = validStatus.includes(status) ? status : 'pending';
  const safeSource  = validSource.includes(source)  ? source  : 'manual';

  try {
    const result = await pool.query(
      `INSERT INTO bilty (bilty_number, weight, destination, status, source)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        bilty_number.trim().slice(0, 100),
        String(weight      ?? '').trim().slice(0, 50),
        String(destination ?? '').trim().slice(0, 100),
        safeStatus,
        safeSource
      ]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('[POST /api/bilty]', err.message);
    res.status(500).json({ success: false, message: 'Save nahi hua. Dobara try karein.' });
  }
});

// GET /api/bilty — all records or search
app.get('/api/bilty', requireAuth, async (req, res) => {
  const q = req.query.q?.trim();
  try {
    let result;
    if (q) {
      const like = `%${q}%`;
      result = await pool.query(
        `SELECT * FROM bilty
         WHERE  bilty_number ILIKE $1
             OR destination  ILIKE $1
             OR status       ILIKE $1
         ORDER BY id DESC LIMIT 200`,
        [like]
      );
    } else {
      result = await pool.query(
        `SELECT * FROM bilty ORDER BY id DESC LIMIT 200`
      );
    }
    res.json({ success: true, data: result.rows, count: result.rowCount });
  } catch (err) {
    console.error('[GET /api/bilty]', err.message);
    res.status(500).json({ success: false, message: 'Records load nahi hue.' });
  }
});

// PATCH /api/bilty/:id/status — update status
app.patch('/api/bilty/:id/status', requireAuth, async (req, res) => {
  const id     = parseInt(req.params.id, 10);
  const status = req.body?.status;
  const valid  = ['pending', 'in-transit', 'delivered', 'cancelled'];

  if (!Number.isFinite(id))   return res.status(400).json({ success: false, message: 'ID galat hai.' });
  if (!valid.includes(status)) return res.status(400).json({ success: false, message: 'Status galat hai.' });

  try {
    const result = await pool.query(
      `UPDATE bilty
       SET status = $1, updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [status, id]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ success: false, message: 'Record nahi mila.' });
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('[PATCH /api/bilty/status]', err.message);
    res.status(500).json({ success: false, message: 'Update nahi hua.' });
  }
});

// DELETE /api/bilty/:id
app.delete('/api/bilty/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id))
    return res.status(400).json({ success: false, message: 'ID galat hai.' });

  try {
    const result = await pool.query(
      `DELETE FROM bilty WHERE id = $1`, [id]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ success: false, message: 'Record nahi mila.' });
    res.json({ success: true, deleted_id: id });
  } catch (err) {
    console.error('[DELETE /api/bilty]', err.message);
    res.status(500).json({ success: false, message: 'Delete nahi hua.' });
  }
});

// GET /api/stats
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*)                                            AS total,
        COUNT(*) FILTER (WHERE status = 'pending')         AS pending,
        COUNT(*) FILTER (WHERE status = 'in-transit')      AS transit,
        COUNT(*) FILTER (WHERE DATE(created_at) = CURRENT_DATE) AS today
      FROM bilty
    `);
    const r = result.rows[0];
    res.json({
      success: true,
      total:   parseInt(r.total),
      pending: parseInt(r.pending),
      transit: parseInt(r.transit),
      today:   parseInt(r.today)
    });
  } catch (err) {
    console.error('[GET /api/stats]', err.message);
    res.status(500).json({ success: false, message: 'Stats load nahi hue.' });
  }
});

// Catch-all → serve index.html
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global error handler
app.use((err, _req, res, _next) => {
  console.error('[Unhandled Error]', err);
  res.status(500).json({ success: false, message: 'Server error.' });
});

// ── Graceful Shutdown ─────────────────────────────────────────
async function shutdown(signal) {
  console.log(`\n${signal} — Shutting down...`);
  await pool.end();
  process.exit(0);
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException',  err => { console.error('Uncaught:', err.message); shutdown('uncaughtException'); });
process.on('unhandledRejection', err => { console.error('Unhandled:', err); });

// ── Start ─────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🚀  BiltyVault v1.0`);
    console.log(`📡  http://localhost:${PORT}`);
    console.log(`🔐  Auth:     ✅ Password + Session`);
    console.log(`🛡️   Security: ✅ Helmet + Rate Limits`);
    console.log(`🗄️   Database: ✅ PostgreSQL (100+ users ready)`);
    console.log(`🤖  Gemini:   ${process.env.GEMINI_API_KEY ? '✅ Connected' : '❌ No key'}\n`);
  });
}).catch(err => {
  console.error('Failed to initialize DB:', err.message);
  process.exit(1);
});
