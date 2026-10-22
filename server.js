'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const pg = require('pg');
const bcrypt = require('bcryptjs');
const PgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const OpenAI = require('openai');
const crypto = require('crypto');

const app = express();
const { Pool } = pg;

const PORT = Number(process.env.PORT) || 10000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is missing from the environment.');
}

if (!process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET is missing from the environment.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PRODUCTION ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      mediaSrc: ["'self'", 'https:', 'blob:'],
      connectSrc: ["'self'", 'https:'],
      upgradeInsecureRequests: IS_PRODUCTION ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(express.json({ limit: '100kb' }));

app.use(session({
  store: new PgSession({
    pool,
    tableName: 'session',
    createTableIfMissing: true
  }),
  name: 'taskforge.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

/* -------------------- HELPERS -------------------- */

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

function money(value) {
  return '$' + Number(value || 0).toFixed(2);
}

function csrfField(req) {
  return `<input type="hidden" name="_csrf" value="${esc(req.session.csrfToken)}">`;
}

function page(title, body, user = null, req = null) {
  const token = req?.session?.csrfToken || '';

  const navigation = user
    ? `
      <a href="/dashboard">Dashboard</a>
      <a href="/tasks">Tasks</a>
      <a href="/screening">Screening</a>
      <a href="/payouts">Payouts</a>
      ${user.role === 'admin' ? '<a href="/admin">Admin</a>' : ''}
      <form method="POST" action="/logout" class="logout-form">
        <input type="hidden" name="_csrf" value="${esc(token)}">
        <button class="nav-button" type="submit">Log out</button>
      </form>`
    : `
      <a href="/login">Log in</a>
      <a class="nav-cta" href="/register">Get started</a>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#101329">
<title>${esc(title)} · TaskForge AI</title>
<style>
:root {
  color-scheme: dark;
  --bg:#0b0d19;
  --panel:#14172a;
  --panel2:#1a1e35;
  --text:#f3f4ff;
  --muted:#a4abc6;
  --purple:#9575ff;
  --cyan:#67e8f9;
  --border:#2b304c;
  --green:#67e8a5;
  --red:#ff8d9a;
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;
  background:radial-gradient(ellipse at top,#1c1b42 0,transparent 48%),var(--bg);
  color:var(--text);
  min-height:100vh;
}
a{color:var(--cyan);text-decoration:none}
a:hover{opacity:.85}
header{
  position:sticky;top:0;z-index:5;
  background:rgba(11,13,25,.94);
  backdrop-filter:blur(15px);
  border-bottom:1px solid var(--border);
}
.nav{
  max-width:1180px;margin:auto;padding:15px 20px;
  display:flex;align-items:center;justify-content:space-between;gap:16px;
}
.brand{font-size:21px;font-weight:900;letter-spacing:-1px;color:white}
.brand span{color:var(--purple)}
.nav-links{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.nav-links a,.nav-button{font-size:13px;color:var(--muted)}
.nav-cta{background:var(--purple);color:#fff!important;padding:10px 14px;border-radius:10px}
.logout-form{display:inline;margin:0}
.nav-button{border:0;background:none;cursor:pointer;padding:4px}
main{max-width:1180px;margin:0 auto;padding:36px 20px 70px}
h1{font-size:clamp(30px,5vw,48px);letter-spacing:-1.8px;line-height:1.08;margin:0 0 14px}
h2{letter-spacing:-.6px}
h3{margin-top:0}
p{line-height:1.65}
.muted,.sub{color:var(--muted)}
.hero{padding:35px 0 28px;max-width:820px}
.eyebrow{color:var(--cyan);text-transform:uppercase;letter-spacing:2px;font-size:11px;font-weight:800}
.hero p{font-size:17px;color:var(--muted);max-width:700px}
.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:25px}
.btn,button.btn{
  display:inline-flex;justify-content:center;align-items:center;
  border:0;border-radius:11px;padding:12px 17px;
  background:linear-gradient(120deg,#9575ff,#7554e8);
  color:white;font-weight:750;cursor:pointer;font-size:14px;
}
.btn.secondary{background:var(--panel2);border:1px solid var(--border)}
.btn.danger{background:#542735}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:17px;margin:22px 0}
.grid.two{grid-template-columns:repeat(2,minmax(0,1fr))}
.card{
  min-width:0;background:linear-gradient(145deg,rgba(26,30,53,.97),rgba(17,20,37,.97));
  border:1px solid var(--border);border-radius:18px;padding:22px;
  box-shadow:0 14px 38px rgba(0,0,0,.12);
}
.card p{color:var(--muted)}
.stat{font-size:30px;font-weight:900;letter-spacing:-1px;margin:9px 0}
.stat-label{color:var(--muted);font-size:13px}
.pill{display:inline-block;padding:5px 9px;border-radius:999px;background:#282442;color:#d4c8ff;font-size:11px;font-weight:800}
.success{color:var(--green)}
.error{color:var(--red)}
.notice{border:1px solid var(--border);border-radius:12px;padding:14px 16px;background:var(--panel);margin:15px 0}
form.stack{display:grid;gap:14px}
label{display:grid;gap:7px;color:#d9dcf0;font-size:13px;font-weight:650}
input,textarea,select{
  width:100%;background:#0c0f20;color:var(--text);
  border:1px solid #363b59;border-radius:10px;padding:12px;
  font:inherit;outline:none;min-width:0;
}
input:focus,textarea:focus,select:focus{border-color:var(--purple)}
textarea{min-height:120px;resize:vertical}
input[type=checkbox]{width:auto}
.check{display:flex;align-items:center;gap:9px}
hr{border:0;border-top:1px solid var(--border);margin:22px 0}
table{width:100%;border-collapse:collapse;min-width:600px}
th,td{text-align:left;padding:12px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:top}
th{color:var(--muted)}
.table-wrap{overflow-x:auto}
.media{max-width:100%;max-height:360px;border-radius:12px}
.task-title{font-size:20px;font-weight:850}
footer{text-align:center;padding:25px;color:var(--muted);font-size:12px;border-top:1px solid var(--border)}
.small{font-size:12px}
.inline-form{display:inline-block;margin:4px}
.empty{padding:30px;text-align:center;border:1px dashed var(--border);border-radius:15px;color:var(--muted)}
@media(max-width:820px){
 .grid{grid-template-columns:repeat(2,minmax(0,1fr))}
 .nav{align-items:flex-start}
 .nav-links{gap:10px}
}
@media(max-width:560px){
 .grid,.grid.two{grid-template-columns:1fr}
 main{padding:25px 14px 50px}
 .nav{padding:13px 14px;display:block}
 .nav-links{margin-top:13px}
 .brand{display:inline-block}
 .card{padding:18px}
}
</style>
</head>
<body>
<header><div class="nav">
  <a class="brand" href="/">TaskForge<span> AI</span></a>
  <nav class="nav-links">${navigation}</nav>
</div></header>
<main>${body}</main>
<footer>TaskForge AI · Human intelligence powering better AI</footer>
</body>
</html>`;
}

function render(res, title, body, req, status = 200) {
  res.status(status).send(page(title, body, req.session.user || null, req));
}

function notice(text, type = 'info') {
  return `<div class="notice ${type === 'error' ? 'error' : type === 'success' ? 'success' : ''}">${esc(text)}</div>`;
}

function redirectMessage(res, path, text) {
  res.redirect(`${path}${path.includes('?') ? '&' : '?'}message=${encodeURIComponent(text)}`);
}

function validId(value) {
  return /^\d+$/.test(String(value || '')) && Number(value) > 0;
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return redirectMessage(res, '/login', 'Please log in to continue.');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return redirectMessage(res, '/login', 'Please log in first.');
  }
  if (req.session.user.role !== 'admin') {
    return render(res, 'Access denied',
      '<div class="card"><h1>Access denied</h1><p>You do not have permission to view this page.</p><a href="/dashboard">Return to dashboard</a></div>',
      req, 403);
  }
  next();
}

function getMessage(req) {
  return req.query.message ? notice(req.query.message) : '';
}

/* CSRF protection for all form submissions. */
app.use((req, res, next) => {
  if (req.method !== 'POST') return next();

  const sent = String(req.body?._csrf || '');
  const expected = String(req.session?.csrfToken || '');

  if (
    !sent ||
    !expected ||
    sent.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected))
  ) {
    return render(
      res,
      'Security check',
      '<div class="card"><h1>Security check failed</h1><p>Please go back, refresh the page, and try again.</p><a href="/">Return home</a></div>',
      req,
      403
    );
  }

  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: 'Too many attempts. Please wait and try again.'
});

/* -------------------- PUBLIC PAGES -------------------- */

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'TaskForge AI' });
  } catch {
    res.status(503).json({ ok: false, service: 'TaskForge AI' });
  }
});

app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');

  render(res, 'AI task platform', `
    <section class="hero">
      <div class="eyebrow">Human intelligence. Better AI.</div>
      <h1>Turn your skills into work that helps build AI.</h1>
      <p>TaskForge AI connects contributors with structured data tasks, review workflows and transparent submission tracking.</p>
      <div class="actions">
        <a class="btn" href="/register">Create your account</a>
        <a class="btn secondary" href="/login">Sign in</a>
      </div>
    </section>
    <div class="grid">
      <article class="card"><span class="pill">01 · CONTRIBUTE</span><h2>Useful tasks</h2><p>Work on available annotation, transcription, text and AI evaluation tasks.</p></article>
      <article class="card"><span class="pill">02 · REVIEW</span><h2>Quality matters</h2><p>Submissions are reviewed before rewards are credited.</p></article>
      <article class="card"><span class="pill">03 · TRACK</span><h2>Clear progress</h2><p>Check your tasks, screening status and payout requests in one dashboard.</p></article>
    </div>
    <div class="notice">Task availability, review times and earnings depend on the tasks offered and the review process. Creating an account does not guarantee paid work.</div>
  `, req);
});

app.get('/register', (req, res) => {
  render(res, 'Create account', `
    <div class="card" style="max-width:540px;margin:auto">
      <div class="eyebrow">Join TaskForge AI</div><h1>Create account</h1>
      ${getMessage(req)}
      <form class="stack" method="POST" action="/register">
        ${csrfField(req)}
        <label>Full name<input name="name" maxlength="120" required autocomplete="name"></label>
        <label>Email address<input type="email" name="email" maxlength="255" required autocomplete="email"></label>
        <label>Password<input type="password" name="password" minlength="10" maxlength="128" required autocomplete="new-password"></label>
        <button class="btn" type="submit">Create account</button>
      </form>
      <p class="small muted">Use at least 10 characters for your password.</p>
      <p>Already registered? <a href="/login">Log in</a></p>
    </div>
  `, req);
});

app.post('/register', authLimiter, async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (name.length < 2 || name.length > 120) {
      return redirectMessage(res, '/register', 'Enter a valid name.');
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 255) {
      return redirectMessage(res, '/register', 'Enter a valid email address.');
    }
    if (password.length < 10 || password.length > 128) {
      return redirectMessage(res, '/register', 'Password must be 10–128 characters.');
    }

    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)`,
      [name, email, hash]
    );

    redirectMessage(res, '/login', 'Account created. You can now log in.');
  } catch (error) {
    if (error.code === '23505') {
      return redirectMessage(res, '/register', 'That email is already registered.');
    }
    next(error);
  }
});

app.get('/login', (req, res) => {
  render(res, 'Log in', `
    <div class="card" style="max-width:520px;margin:auto">
      <div class="eyebrow">Welcome back</div><h1>Log in</h1>
      ${getMessage(req)}
      <form class="stack" method="POST" action="/login">
        ${csrfField(req)}
        <label>Email address<input type="email" name="email" maxlength="255" required autocomplete="email"></label>
        <label>Password<input type="password" name="password" required maxlength="128" autocomplete="current-password"></label>
        <button class="btn" type="submit">Log in securely</button>
      </form>
      <p>New to TaskForge AI? <a href="/register">Create an account</a></p>
    </div>
  `, req);
});

app.post('/login', authLimiter, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const result = await pool.query(
      `SELECT id, name, email, password_hash, role
       FROM users WHERE email = $1`,
      [email]
    );

    const user = result.rows[0];
    const valid = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!valid) {
      return redirectMessage(res, '/login', 'Email or password is incorrect.');
    }

    await new Promise((resolve, reject) => {
      req.session.regenerate(error => error ? reject(error) : resolve());
    });

    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.user = {
      id: String(user.id),
      name: user.name,
      email: user.email,
      role: user.role
    };

    req.session.save(error => {
      if (error) return next(error);
      res.redirect('/dashboard');
    });
  } catch (error) {
    next(error);
  }
});

app.post('/logout', (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie('taskforge.sid', {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: 'lax'
    });
    res.redirect('/');
  });
});

/* -------------------- WORKER DASHBOARD -------------------- */

app.get('/dashboard', requireLogin, async (req, res, next) => {
  try {
    const userId = req.session.user.id;

    const [taskCount, submissionCount, approvedCount, earnings, screening] =
      await Promise.all([
        pool.query('SELECT COUNT(*) FROM tasks WHERE published = TRUE'),
        pool.query('SELECT COUNT(*) FROM submissions WHERE user_id = $1', [userId]),
        pool.query(
          `SELECT COUNT(*) FROM submissions
           WHERE user_id = $1 AND status = 'approved'`,
          [userId]
        ),
        pool.query(
          `SELECT COALESCE(SUM(t.reward_usd), 0) AS total
           FROM submissions s JOIN tasks t ON t.id = s.task_id
           WHERE s.user_id = $1 AND s.status = 'approved'`,
          [userId]
        ),
        pool.query(
          `SELECT status, submitted_at FROM screenings
           WHERE user_id = $1 ORDER BY submitted_at DESC LIMIT 1`,
          [userId]
        )
      ]);

    const screeningStatus = screening.rows[0]
      ? esc(screening.rows[0].status)
      : 'not submitted';

    render(res, 'Dashboard', `
      <div class="hero">
        <div class="eyebrow">Your workspace</div>
        <h1>Hello, ${esc(req.session.user.name.split(' ')[0])}.</h1>
        <p>Keep track of your work and your progress on TaskForge AI.</p>
      </div>
      ${getMessage(req)}
      <div class="grid">
        <div class="card"><div class="stat">${Number(taskCount.rows[0].count)}</div><div class="stat-label">Published tasks</div></div>
        <div class="card"><div class="stat">${Number(submissionCount.rows[0].count)}</div><div class="stat-label">Your submissions</div></div>
        <div class="card"><div class="stat">${money(earnings.rows[0].total)}</div><div class="stat-label">Approved earnings</div></div>
      </div>
      <div class="grid two">
        <div class="card"><h2>Start working</h2><p>Browse available tasks and submit your completed work.</p><a class="btn" href="/tasks">Browse tasks</a></div>
        <div class="card"><h2>Screening status</h2><p>Your latest screening: <strong>${screeningStatus}</strong></p><a class="btn secondary" href="/screening">Open screening</a></div>
      </div>
      <div class="card"><h2>Approved submissions</h2><p>${Number(approvedCount.rows[0].count)} submission(s) approved so far.</p><a href="/submissions">View submission history →</a></div>
    `, req);
  } catch (error) {
    next(error);
  }
});

/* -------------------- SCREENING -------------------- */

app.get('/screening', requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, answers, status, submitted_at, review_notes
       FROM screenings WHERE user_id = $1
       ORDER BY submitted_at DESC LIMIT 10`,
      [req.session.user.id]
    );

    const rows = result.rows.map(item => `
      <tr>
        <td>${esc(item.status)}</td>
        <td>${esc(new Date(item.submitted_at).toLocaleString())}</td>
        <td>${esc(item.review_notes || 'No review notes yet')}</td>
      </tr>`).join('');

    render(res, 'Worker screening', `
      <div class="hero"><div class="eyebrow">Quality and eligibility</div><h1>Worker screening</h1>
      <p>Complete the screening questions so the team can review your readiness for tasks.</p></div>
      ${getMessage(req)}
      <div class="card">
        <h2>Submit screening answers</h2>
        <form class="stack" method="POST" action="/screening">
          ${csrfField(req)}
          <label>1. Describe how you would accurately transcribe a recording.
            <textarea name="q1" maxlength="4000" required></textarea>
          </label>
          <label>2. What would you do if a recording was unclear?
            <textarea name="q2" maxlength="4000" required></textarea>
          </label>
          <label>3. Why is following task instructions important?
            <textarea name="q3" maxlength="4000" required></textarea>
          </label>
          <button class="btn" type="submit">Submit screening</button>
        </form>
      </div>
      <div class="card"><h2>Previous screenings</h2>
        <div class="table-wrap"><table><thead><tr><th>Status</th><th>Submitted</th><th>Review notes</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="3">No screenings submitted yet.</td></tr>'}</tbody></table></div>
      </div>
    `, req);
  } catch (error) {
    next(error);
  }
});

app.post('/screening', requireLogin, async (req, res, next) => {
  try {
    const answers = {
      q1: String(req.body.q1 || '').trim(),
      q2: String(req.body.q2 || '').trim(),
      q3: String(req.body.q3 || '').trim()
    };

    if (Object.values(answers).some(answer => answer.length < 10)) {
      return redirectMessage(res, '/screening', 'Please give a more complete answer to every question.');
    }

    await pool.query(
      `INSERT INTO screenings (user_id, answers)
       VALUES ($1, $2::jsonb)`,
      [req.session.user.id, JSON.stringify(answers)]
    );

    redirectMessage(res, '/screening', 'Screening submitted for review.');
  } catch (error) {
    next(error);
  }
});

/* -------------------- TASKS -------------------- */

app.get('/tasks', requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT t.id, t.title, t.description, t.task_type,
              t.media_url, t.media_type, t.reward_usd, t.created_at
       FROM tasks t
       WHERE t.published = TRUE
       AND NOT EXISTS (
         SELECT 1 FROM submissions s
         WHERE s.task_id = t.id AND s.user_id = $1
       )
       ORDER BY t.created_at DESC`,
      [req.session.user.id]
    );

    const cards = result.rows.map(task => `
      <article class="card">
        <span class="pill">${esc(task.task_type)}</span>
        <h2>${esc(task.title)}</h2>
        <p>${esc(task.description)}</p>
        ${task.media_url ? `
          <p><a href="${esc(task.media_url)}" target="_blank" rel="noopener noreferrer">Open task media ↗</a></p>
          ${task.media_type === 'video' ? `<video class="media" controls preload="metadata" src="${esc(task.media_url)}"></video>` : ''}
          ${task.media_type === 'audio' ? `<audio controls preload="metadata" src="${esc(task.media_url)}" style="width:100%"></audio>` : ''}
          ${task.media_type === 'image' ? `<img class="media" src="${esc(task.media_url)}" alt="Task media">` : ''}
        ` : ''}
        <div class="stat">${money(task.reward_usd)}</div>
        <a class="btn" href="/tasks/${task.id}">Open task</a>
      </article>`).join('');

    render(res, 'Available tasks', `
      <div class="hero"><div class="eyebrow">Your opportunities</div><h1>Available tasks</h1>
      <p>Read every instruction carefully and submit your best work.</p></div>
      ${getMessage(req)}
      <div class="grid">${cards || '<div class="empty">No new tasks are available right now. Check again later.</div>'}</div>
    `, req);
  } catch (error) {
    next(error);
  }
});

app.get('/tasks/:id', requireLogin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(404).send('Task not found.');

    const result = await pool.query(
      `SELECT t.* FROM tasks t
       WHERE t.id = $1 AND t.published = TRUE
       AND NOT EXISTS (
         SELECT 1 FROM submissions s
         WHERE s.task_id = t.id AND s.user_id = $2
       )`,
      [req.params.id, req.session.user.id]
    );

    const task = result.rows[0];
    if (!task) return render(res, 'Task unavailable',
      '<div class="card"><h1>Task unavailable</h1><p>This task may have been removed or already submitted.</p><a href="/tasks">Back to tasks</a></div>',
      req, 404);

    const type = String(task.task_type || '').toLowerCase();
    let input = '';

    if (type.includes('audio') || type.includes('transcription')) {
      input = `<label>Your transcription<textarea name="answer" maxlength="30000" required placeholder="Type the words you hear..."></textarea></label>`;
    } else if (type.includes('image') || type.includes('video') || type.includes('annotation')) {
      input = `<label>Describe what you observe<textarea name="answer" maxlength="12000" required placeholder="Describe the visible actions or events accurately..."></textarea></label>`;
    } else {
      input = `<label>Your response<textarea name="answer" maxlength="20000" required placeholder="Enter your answer here..."></textarea></label>`;
    }

    render(res, task.title, `
      <div class="card">
        <div class="eyebrow">${esc(task.task_type)}</div>
        <h1>${esc(task.title)}</h1>
        <p>${esc(task.description)}</p>
        ${task.media_url ? `
          <p><a href="${esc(task.media_url)}" target="_blank" rel="noopener noreferrer">Open full media ↗</a></p>
          ${task.media_type === 'video' ? `<video class="media" controls preload="metadata" src="${esc(task.media_url)}"></video>` : ''}
          ${task.media_type === 'audio' ? `<audio controls preload="metadata" src="${esc(task.media_url)}" style="width:100%"></audio>` : ''}
          ${task.media_type === 'image' ? `<img class="media" src="${esc(task.media_url)}" alt="Task media">` : ''}
        ` : ''}
        <hr>
        <div class="stat">${money(task.reward_usd)}</div>
        <p class="muted small">Reward is credited only after the submission is approved.</p>
        <form class="stack" method="POST" action="/tasks/${task.id}/submit">
          ${csrfField(req)}
          ${input}
          <button class="btn" type="submit">Submit for review</button>
        </form>
      </div>
    `, req);
  } catch (error) {
    next(error);
  }
});

app.post('/tasks/:id/submit', requireLogin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(404).send('Task not found.');

    const answer = String(req.body.answer || '').trim();
    if (!answer || answer.length > 30000) {
      return redirectMessage(res, `/tasks/${req.params.id}`, 'Please enter a valid response.');
    }

    const task = await pool.query(
      'SELECT id FROM tasks WHERE id = $1 AND published = TRUE',
      [req.params.id]
    );

    if (!task.rows.length) {
      return redirectMessage(res, '/tasks', 'That task is no longer available.');
    }

    await pool.query(
      `INSERT INTO submissions (user_id, task_id, response)
       VALUES ($1, $2, $3::jsonb)`,
      [req.session.user.id, req.params.id, JSON.stringify({ answer })]
    );

    redirectMessage(res, '/submissions', 'Your work has been submitted for review.');
  } catch (error) {
    if (error.code === '23505') {
      return redirectMessage(res, '/submissions', 'You have already submitted this task.');
    }
    next(error);
  }
});

/* -------------------- SUBMISSION HISTORY -------------------- */

app.get('/submissions', requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.status, s.submitted_at, s.reviewed_at,
              s.review_notes, s.response, t.title, t.reward_usd
       FROM submissions s
       JOIN tasks t ON t.id = s.task_id
       WHERE s.user_id = $1
       ORDER BY s.submitted_at DESC`,
      [req.session.user.id]
    );

    const rows = result.rows.map(item => {
      const answer = typeof item.response === 'object'
        ? item.response?.answer
        : '';

      return `<tr>
        <td>${esc(item.title)}</td>
        <td>${esc(item.status)}</td>
        <td>${esc(money(item.reward_usd))}</td>
        <td>${esc(new Date(item.submitted_at).toLocaleString())}</td>
        <td>${esc(answer || '')}</td>
        <td>${esc(item.review_notes || 'Awaiting review')}</td>
      </tr>`;
    }).join('');

    render(res, 'Submission history', `
      <div class="hero"><div class="eyebrow">Your work</div><h1>Submission history</h1>
      <p>Review your submitted tasks and their current status.</p></div>
      <div class="card"><div class="table-wrap"><table>
        <thead><tr><th>Task</th><th>Status</th><th>Reward</th><th>Submitted</th><th>Response</th><th>Review notes</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6">You have not submitted any tasks yet.</td></tr>'}</tbody>
      </table></div></div>
    `, req);
  } catch (error) {
    next(error);
  }
});

/* -------------------- PAYOUTS -------------------- */

app.get('/payouts', requireLogin, async (req, res, next) => {
  try {
    const userId = req.session.user.id;

    const [earningsResult, payoutsResult, userResult] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(t.reward_usd), 0) AS total
         FROM submissions s JOIN tasks t ON t.id = s.task_id
         WHERE s.user_id = $1 AND s.status = 'approved'`,
        [userId]
      ),
      pool.query(
        `SELECT id, amount_usd, paypal_email, status, transaction_id,
                requested_at, paid_at, admin_notes
         FROM payouts WHERE user_id = $1 ORDER BY requested_at DESC`,
        [userId]
      ),
      pool.query('SELECT paypal_email FROM users WHERE id = $1', [userId])
    ]);

    const paidOrPending = payoutsResult.rows
      .filter(p => ['paid', 'pending'].includes(p.status))
      .reduce((sum, p) => sum + Number(p.amount_usd), 0);

    const earned = Number(earningsResult.rows[0].total);
    const available = Math.max(0, earned - paidOrPending);

    const rows = payoutsResult.rows.map(p => `<tr>
      <td>${esc(money(p.amount_usd))}</td>
      <td>${esc(p.paypal_email)}</td>
      <td>${esc(p.status)}</td>
      <td>${esc(new Date(p.requested_at).toLocaleString())}</td>
      <td>${esc(p.transaction_id || '—')}</td>
      <td>${esc(p.admin_notes || '—')}</td>
    </tr>`).join('');

    render(res, 'Payouts', `
      <div class="hero"><div class="eyebrow">Payments</div><h1>Your payouts</h1>
      <p>Approved work contributes to your earnings balance. Payout requests are handled manually.</p></div>
      ${getMessage(req)}
      <div class="grid">
        <div class="card"><div class="stat">${money(earned)}</div><div class="stat-label">Approved earnings</div></div>
        <div class="card"><div class="stat">${money(available)}</div><div class="stat-label">Available after paid and pending requests</div></div>
      </div>
      <div class="card">
        <h2>Request a PayPal payout</h2>
        <p class="muted">Only request funds from approved submissions. Requests are not automatic payments.</p>
        <form class="stack" method="POST" action="/payouts">
          ${csrfField(req)}
          <label>PayPal email<input type="email" name="paypal_email" maxlength="255" required value="${esc(userResult.rows[0]?.paypal_email || '')}"></label>
          <label>Amount in USD<input type="number" name="amount" min="1" max="${Math.floor(available * 100) / 100}" step="0.01" required></label>
          <button class="btn" type="submit" ${available < 1 ? 'disabled' : ''}>Request payout</button>
        </form>
      </div>
      <div class="card"><h2>Payout history</h2><div class="table-wrap"><table>
        <thead><tr><th>Amount</th><th>PayPal email</th><th>Status</th><th>Requested</th><th>Transaction</th><th>Notes</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6">No payout requests yet.</td></tr>'}</tbody>
      </table></div></div>
    `, req);
  } catch (error) {
    next(error);
  }
});

app.post('/payouts', requireLogin, async (req, res, next) => {
  const client = await pool.connect();

  try {
    const amount = Number(req.body.amount);
    const paypalEmail = String(req.body.paypal_email || '').trim();

    if (!Number.isFinite(amount) || amount <= 0 || amount > 100000) {
      return redirectMessage(res, '/payouts', 'Enter a valid payout amount.');
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(paypalEmail) || paypalEmail.length > 255) {
      return redirectMessage(res, '/payouts', 'Enter a valid PayPal email.');
    }

    await client.query('BEGIN');

    const earnedResult = await client.query(
      `SELECT COALESCE(SUM(t.reward_usd), 0) AS total
       FROM submissions s JOIN tasks t ON t.id = s.task_id
       WHERE s.user_id = $1 AND s.status = 'approved'`,
      [req.session.user.id]
    );

    const reservedResult = await client.query(
      `SELECT COALESCE(SUM(amount_usd), 0) AS total
       FROM payouts WHERE user_id = $1 AND status IN ('pending', 'paid')`,
      [req.session.user.id]
    );

    const available = Number(earnedResult.rows[0].total) -
      Number(reservedResult.rows[0].total);

    if (amount > available + 0.0001) {
      await client.query('ROLLBACK');
      return redirectMessage(res, '/payouts', 'The requested amount exceeds your available balance.');
    }

    await client.query(
      'UPDATE users SET paypal_email = $1 WHERE id = $2',
      [paypalEmail, req.session.user.id]
    );

    await client.query(
      `INSERT INTO payouts (user_id, amount_usd, paypal_email)
       VALUES ($1, $2, $3)`,
      [req.session.user.id, amount.toFixed(2), paypalEmail]
    );

    await client.query('COMMIT');
    redirectMessage(res, '/payouts', 'Payout request submitted for manual review.');
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    next(error);
  } finally {
    client.release();
  }
});

/* -------------------- ADMIN HOME -------------------- */

app.get('/admin', requireAdmin, async (req, res, next) => {
  try {
    const [users, tasks, pendingSubmissions, pendingScreenings, pendingPayouts, drafts] =
      await Promise.all([
        pool.query('SELECT COUNT(*) FROM users'),
        pool.query('SELECT COUNT(*) FROM tasks'),
        pool.query("SELECT COUNT(*) FROM submissions WHERE status = 'pending'"),
        pool.query("SELECT COUNT(*) FROM screenings WHERE status = 'pending'"),
        pool.query("SELECT COUNT(*) FROM payouts WHERE status = 'pending'"),
        pool.query("SELECT COUNT(*) FROM ai_task_queue WHERE status = 'draft'")
      ]);

    render(res, 'Admin control centre', `
      <div class="hero"><div class="eyebrow">Administration</div><h1>Control centre</h1>
      <p>Manage tasks, review worker quality and handle payout requests.</p></div>
      ${getMessage(req)}
      <div class="grid">
        <div class="card"><div class="stat">${Number(users.rows[0].count)}</div><div class="stat-label">Registered users</div></div>
        <div class="card"><div class="stat">${Number(tasks.rows[0].count)}</div><div class="stat-label">All tasks</div></div>
        <div class="card"><div class="stat">${Number(pendingSubmissions.rows[0].count)}</div><div class="stat-label">Submissions awaiting review</div></div>
        <div class="card"><div class="stat">${Number(pendingScreenings.rows[0].count)}</div><div class="stat-label">Screenings awaiting review</div></div>
        <div class="card"><div class="stat">${Number(pendingPayouts.rows[0].count)}</div><div class="stat-label">Payouts awaiting review</div></div>
        <div class="card"><div class="stat">${Number(drafts.rows[0].count)}</div><div class="stat-label">AI task drafts</div></div>
      </div>
      <div class="grid two">
        <div class="card"><h2>Task management</h2><p>Create and publish work opportunities.</p><a class="btn" href="/admin/tasks">Manage tasks</a></div>
        <div class="card"><h2>AI task drafts</h2><p>Generate draft task instructions for review before publication.</p><a class="btn" href="/admin/ai">Open AI workspace</a></div>
        <div class="card"><h2>Review submissions</h2><p>Approve or reject completed work.</p><a class="btn" href="/admin/submissions">Review work</a></div>
        <div class="card"><h2>Screenings</h2><p>Review worker screening answers.</p><a class="btn" href="/admin/screenings">Review screenings</a></div>
        <div class="card"><h2>Payouts</h2><p>Process payout requests and record transaction IDs.</p><a class="btn" href="/admin/payouts">Manage payouts</a></div>
      </div>
    `, req);
  } catch (error) {
    next(error);
  }
});

/* -------------------- ADMIN TASK MANAGEMENT -------------------- */

app.get('/admin/tasks', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tasks ORDER BY created_at DESC LIMIT 200'
    );

    const rows = result.rows.map(t => `<tr>
      <td>${esc(t.id)}</td><td>${esc(t.title)}</td>
      <td>${esc(t.task_type)}</td><td>${esc(money(t.reward_usd))}</td>
      <td>${t.published ? '<span class="success">Published</span>' : 'Draft'}</td>
      <td>
        <form method="POST" action="/admin/tasks/${t.id}/toggle" class="inline-form">
          ${csrfField(req)}
          <button class="btn secondary" type="submit">${t.published ? 'Unpublish' : 'Publish'}</button>
        </form>
      </td>
    </tr>`).join('');

    render(res, 'Manage tasks', `
      <div class="hero"><div class="eyebrow">Admin · Tasks</div><h1>Manage tasks</h1></div>
      ${getMessage(req)}
      <div class="card"><h2>Create a task</h2>
        <form class="stack" method="POST" action="/admin/tasks">
          ${csrfField(req)}
          <label>Task title<input name="title" maxlength="200" required></label>
          <label>Instructions<textarea name="description" maxlength="10000" required></textarea></label>
          <label>Task type
            <select name="task_type" required>
              <option value="text">Text task</option>
              <option value="transcription">Audio transcription</option>
              <option value="video_annotation">Video annotation</option>
              <option value="image_annotation">Image annotation</option>
              <option value="evaluation">AI evaluation</option>
            </select>
          </label>
          <label>Media URL (optional)<input type="url" name="media_url" maxlength="2000" placeholder="https://..."></label>
          <label>Media type
            <select name="media_type">
              <option value="">No media</option><option value="audio">Audio</option>
              <option value="video">Video</option><option value="image">Image</option>
            </select>
          </label>
          <label>Reward in USD<input type="number" name="reward_usd" min="0" max="50" step="0.01" value="1.00" required></label>
          <label class="check"><input type="checkbox" name="published"> Publish immediately</label>
          <button class="btn" type="submit">Create task</button>
        </form>
      </div>
      <div class="card"><h2>Existing tasks</h2><div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Title</th><th>Type</th><th>Reward</th><th>Status</th><th>Action</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6">No tasks created.</td></tr>'}</tbody>
      </table></div></div>
    `, req);
  } catch (error) {
    next(error);
  }
});

app.post('/admin/tasks', requireAdmin, async (req, res, next) => {
  try {
    const title = String(req.body.title || '').trim();
    const description = String(req.body.description || '').trim();
    const taskType = String(req.body.task_type || '').trim();
    const mediaUrl = String(req.body.media_url || '').trim();
    const mediaType = String(req.body.media_type || '').trim() || null;
    const reward = Number(req.body.reward_usd);
    const allowedTypes = [
      'text', 'transcription', 'video_annotation',
      'image_annotation', 'evaluation'
    ];

    if (!title || title.length > 200 || description.length < 10 || description.length > 10000) {
      return redirectMessage(res, '/admin/tasks', 'Enter a title and complete instructions.');
    }
    if (!allowedTypes.includes(taskType)) {
      return redirectMessage(res, '/admin/tasks', 'Choose a valid task type.');
    }
    if (!Number.isFinite(reward) || reward < 0 || reward > 50) {
      return redirectMessage(res, '/admin/tasks', 'Reward must be between $0 and $50.');
    }
    if (mediaUrl && !/^https:\/\//i.test(mediaUrl)) {
      return redirectMessage(res, '/admin/tasks', 'Media URLs must use HTTPS.');
    }
    if (mediaType && !['audio', 'video', 'image'].includes(mediaType)) {
      return redirectMessage(res, '/admin/tasks', 'Choose a valid media type.');
    }

    await pool.query(
      `INSERT INTO tasks
       (title, description, task_type, media_url, media_type, reward_usd, published)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [title, description, taskType, mediaUrl || null, mediaType, reward, req.body.published === 'on']
    );

    redirectMessage(res, '/admin/tasks', 'Task created successfully.');
  } catch (error) {
    next(error);
  }
});

app.post('/admin/tasks/:id/toggle', requireAdmin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).send('Invalid task ID.');

    await pool.query(
      'UPDATE tasks SET published = NOT published WHERE id = $1',
      [req.params.id]
    );

    redirectMessage(res, '/admin/tasks', 'Task publication status updated.');
  } catch (error) {
    next(error);
  }
});

/* -------------------- ADMIN SUBMISSION REVIEWS -------------------- */

app.get('/admin/submissions', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.status, s.submitted_at, s.response, s.review_notes,
              u.name, u.email, t.title, t.reward_usd
       FROM submissions s
       JOIN users u ON u.id = s.user_id
       JOIN tasks t ON t.id = s.task_id
       ORDER BY CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END,
                s.submitted_at DESC LIMIT 200`
    );

    const rows = result.rows.map(s => {
      const answer = typeof s.response === 'object'
        ? s.response?.answer
        : '';

      return `<tr>
        <td>${esc(s.id)}</td><td>${esc(s.name)}<br><span class="muted">${esc(s.email)}</span></td>
        <td>${esc(s.title)}</td><td>${esc(s.status)}</td>
        <td>${esc(answer || '')}</td>
        <td>${esc(money(s.reward_usd))}</td>
        <td>
          <form class="stack" method="POST" action="/admin/submissions/${s.id}/review">
            ${csrfField(req)}
            <select name="status"><option value="approved">Approve</option><option value="rejected">Reject</option></select>
            <input name="review_notes" maxlength="2000" placeholder="Review notes">
            <button class="btn" type="submit">Save review</button>
          </form>
        </td>
      </tr>`;
    }).join('');

    render(res, 'Review submissions', `
      <div class="hero"><div class="eyebrow">Admin · Quality</div><h1>Submission reviews</h1></div>
      ${getMessage(req)}
      <div class="card"><div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Worker</th><th>Task</th><th>Status</th><th>Response</th><th>Reward</th><th>Review</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7">No submissions found.</td></tr>'}</tbody>
      </table></div></div>
    `, req);
  } catch (error) {
    next(error);
  }
});

app.post('/admin/submissions/:id/review', requireAdmin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).send('Invalid submission ID.');

    const status = String(req.body.status || '');
    const notes = String(req.body.review_notes || '').trim().slice(0, 2000);

    if (!['approved', 'rejected'].includes(status)) {
      return redirectMessage(res, '/admin/submissions', 'Choose approve or reject.');
    }

    await pool.query(
      `UPDATE submissions
       SET status = $1, review_notes = $2, reviewed_at = NOW()
       WHERE id = $3`,
      [status, notes || null, req.params.id]
    );

    redirectMessage(res, '/admin/submissions', 'Submission review saved.');
  } catch (error) {
    next(error);
  }
});

/* -------------------- ADMIN SCREENING REVIEWS -------------------- */

app.get('/admin/screenings', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT s.id, s.answers, s.status, s.submitted_at, s.review_notes,
              u.name, u.email
       FROM screenings s JOIN users u ON u.id = s.user_id
       ORDER BY CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END,
                s.submitted_at DESC LIMIT 200`
    );

    const rows = result.rows.map(s => `<tr>
      <td>${esc(s.id)}</td>
      <td>${esc(s.name)}<br><span class="muted">${esc(s.email)}</span></td>
      <td>${esc(JSON.stringify(s.answers))}</td>
      <td>${esc(s.status)}</td>
      <td><form class="stack" method="POST" action="/admin/screenings/${s.id}/review">
        ${csrfField(req)}
        <select name="status"><option value="approved">Approve</option><option value="rejected">Reject</option></select>
        <input name="review_notes" maxlength="2000" placeholder="Review notes">
        <button class="btn" type="submit">Save</button>
      </form></td>
    </tr>`).join('');

    render(res, 'Screening reviews', `
      <div class="hero"><div class="eyebrow">Admin · Eligibility</div><h1>Screening reviews</h1></div>
      ${getMessage(req)}
      <div class="card"><div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Worker</th><th>Answers</th><th>Status</th><th>Review</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5">No screening submissions found.</td></tr>'}</tbody>
      </table></div></div>
    `, req);
  } catch (error) {
    next(error);
  }
});

app.post('/admin/screenings/:id/review', requireAdmin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).send('Invalid screening ID.');

    const status = String(req.body.status || '');
    const notes = String(req.body.review_notes || '').trim().slice(0, 2000);

    if (!['approved', 'rejected'].includes(status)) {
      return redirectMessage(res, '/admin/screenings', 'Choose approve or reject.');
    }

    await pool.query(
      `UPDATE screenings SET status = $1, review_notes = $2, reviewed_at = NOW()
       WHERE id = $3`,
      [status, notes || null, req.params.id]
    );

    redirectMessage(res, '/admin/screenings', 'Screening review saved.');
  } catch (error) {
    next(error);
  }
});

/* -------------------- ADMIN PAYOUT PROCESSING -------------------- */

app.get('/admin/payouts', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.name, u.email
       FROM payouts p JOIN users u ON u.id = p.user_id
       ORDER BY CASE WHEN p.status = 'pending' THEN 0 ELSE 1 END,
                p.requested_at DESC LIMIT 200`
    );

    const rows = result.rows.map(p => `<tr>
      <td>${esc(p.id)}</td><td>${esc(p.name)}<br><span class="muted">${esc(p.email)}</span></td>
      <td>${esc(money(p.amount_usd))}</td><td>${esc(p.paypal_email)}</td><td>${esc(p.status)}</td>
      <td>${esc(p.transaction_id || '—')}</td>
      <td><form class="stack" method="POST" action="/admin/payouts/${p.id}/review">
        ${csrfField(req)}
        <select name="status"><option value="paid">Mark paid</option><option value="rejected">Reject</option><option value="pending">Keep pending</option></select>
        <input name="transaction_id" maxlength="500" placeholder="Transaction ID (if paid)">
        <input name="admin_notes" maxlength="2000" placeholder="Admin notes">
        <button class="btn" type="submit">Update payout</button>
      </form></td>
    </tr>`).join('');

    render(res, 'Manage payouts', `
      <div class="hero"><div class="eyebrow">Admin · Finance</div><h1>Payout requests</h1></div>
      ${getMessage(req)}
      <div class="notice">Mark a request as paid only after confirming that the transfer has actually been completed.</div>
      <div class="card"><div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Worker</th><th>Amount</th><th>PayPal</th><th>Status</th><th>Transaction</th><th>Action</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7">No payout requests found.</td></tr>'}</tbody>
      </table></div></div>
    `, req);
  } catch (error) {
    next(error);
  }
});

app.post('/admin/payouts/:id/review', requireAdmin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).send('Invalid payout ID.');

    const status = String(req.body.status || '');
    const transactionId = String(req.body.transaction_id || '').trim().slice(0, 500);
    const notes = String(req.body.admin_notes || '').trim().slice(0, 2000);

    if (!['paid', 'rejected', 'pending'].includes(status)) {
      return redirectMessage(res, '/admin/payouts', 'Choose a valid payout status.');
    }
    if (status === 'paid' && !transactionId) {
      return redirectMessage(res, '/admin/payouts', 'Enter the transaction ID before marking a payout paid.');
    }

    await pool.query(
      `UPDATE payouts SET status = $1,
         transaction_id = $2,
         admin_notes = $3,
         paid_at = CASE WHEN $1 = 'paid' THEN COALESCE(paid_at, NOW()) ELSE NULL END
       WHERE id = $4`,
      [status, transactionId || null, notes || null, req.params.id]
    );

    redirectMessage(res, '/admin/payouts', 'Payout status updated.');
  } catch (error) {
    next(error);
  }
});

/* -------------------- AI TASK DRAFT WORKSPACE -------------------- */

app.get('/admin/ai', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT * FROM ai_task_queue ORDER BY created_at DESC LIMIT 100`
    );

    const rows = result.rows.map(d => `<tr>
      <td>${esc(d.id)}</td><td>${esc(d.title)}</td>
      <td>${esc(d.task_type)}</td><td>${esc(money(d.reward_usd))}</td>
      <td>${esc(d.status)}</td><td>${esc(d.description)}</td>
      <td>${d.status === 'draft' ? `
        <form method="POST" action="/admin/ai/${d.id}/publish" class="inline-form">
          ${csrfField(req)}<button class="btn" type="submit">Publish task</button>
        </form>
        <form method="POST" action="/admin/ai/${d.id}/delete" class="inline-form">
          ${csrfField(req)}<button class="btn secondary" type="submit">Delete draft</button>
        </form>` : '—'}</td>
    </tr>`).join('');

    render(res, 'AI task workspace', `
      <div class="hero"><div class="eyebrow">Admin · AI studio</div><h1>AI task drafts</h1>
      <p>Generate draft instructions with AI. Review every draft before publishing it to workers.</p></div>
      ${getMessage(req)}
      ${openai ? '' : notice('OPENAI_API_KEY is not configured. Add it in Render environment variables to enable AI draft generation.', 'error')}
      <div class="card"><h2>Generate drafts</h2>
        <form class="stack" method="POST" action="/admin/ai/generate">
          ${csrfField(req)}
          <label>Task category
            <select name="task_type">
              <option value="text">Text tasks</option>
              <option value="transcription">Audio transcription</option>
              <option value="video_annotation">Video annotation</option>
              <option value="image_annotation">Image annotation</option>
              <option value="evaluation">AI evaluation</option>
            </select>
          </label>
          <label>How many drafts?
            <select name="count"><option value="1">1 draft</option><option value="3">3 drafts</option><option value="5">5 drafts</option></select>
          </label>
          <label>Extra instructions (optional)<textarea name="extra" maxlength="2000" placeholder="Example: focus on clear instructions and realistic quality checks."></textarea></label>
          <button class="btn" type="submit" ${openai ? '' : 'disabled'}>Generate drafts with AI</button>
        </form>
      </div>
      <div class="card"><h2>Draft queue</h2><div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>Title</th><th>Type</th><th>Reward</th><th>Status</th><th>Instructions</th><th>Action</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7">No AI drafts yet.</td></tr>'}</tbody>
      </table></div></div>
    `, req);
  } catch (error) {
    next(error);
  }
});

app.post('/admin/ai/generate', requireAdmin, async (req, res, next) => {
  try {
    if (!openai) {
      return redirectMessage(res, '/admin/ai', 'AI is not configured. Add OPENAI_API_KEY in Render.');
    }

    const taskType = String(req.body.task_type || '');
    const allowedTypes = [
      'text', 'transcription', 'video_annotation',
      'image_annotation', 'evaluation'
    ];

    if (!allowedTypes.includes(taskType)) {
      return redirectMessage(res, '/admin/ai', 'Choose a valid task category.');
    }

    const count = Math.min(5, Math.max(1, Number(req.body.count) || 1));
    const extra = String(req.body.extra || '').trim().slice(0, 2000);

    const completion = await openai.responses.create({
      model: process.env.OPENAI_MODEL || 'gpt-4.1-mini',
      input: [
        {
          role: 'system',
          content: `You create professional, realistic data-task drafts for a human AI training platform.
Return only valid JSON with this exact structure:
{"tasks":[{"title":"...","description":"...","reward_usd":1.00}]}
Generate the requested number of distinct tasks.
Each description must contain clear worker instructions and quality criteria.
Do not claim that media exists if no media URL is provided.
Rewards must be realistic and between 0.25 and 50 USD.
These are drafts for administrator review, not published jobs.`
        },
        {
          role: 'user',
          content: `Create ${count} task drafts.
Task category: ${taskType}
Additional guidance: ${extra || 'Use general professional quality standards.'}
Each title must be under 200 characters.
Each description must be detailed and practical.`
        }
      ]
    });

    const output = String(completion.output_text || '').trim();
    const cleaned = output.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
    const parsed = JSON.parse(cleaned);

    if (!Array.isArray(parsed.tasks) || parsed.tasks.length === 0) {
      throw new Error('AI returned no task drafts.');
    }

    let inserted = 0;

    for (const item of parsed.tasks.slice(0, count)) {
      const title = String(item.title || '').trim().slice(0, 200);
      const description = String(item.description || '').trim().slice(0, 10000);
      const reward = Number(item.reward_usd);

      if (!title || description.length < 20 || !Number.isFinite(reward)) continue;

      const safeReward = Math.min(50, Math.max(0.25, reward));

      await pool.query(
        `INSERT INTO ai_task_queue
         (title, description, task_type, reward_usd, status, created_by)
         VALUES ($1, $2, $3, $4, 'draft', $5)`,
        [title, description, taskType, safeReward, req.session.user.id]
      );

      inserted++;
    }

    if (!inserted) throw new Error('No usable drafts were returned.');

    redirectMessage(res, '/admin/ai', `${inserted} AI draft(s) generated. Review them before publishing.`);
  } catch (error) {
    console.error('AI draft generation failed:', error.message);
    redirectMessage(res, '/admin/ai', 'Draft generation failed. Check Render logs and your OpenAI configuration.');
  }
});

app.post('/admin/ai/:id/publish', requireAdmin, async (req, res, next) => {
  const client = await pool.connect();

  try {
    if (!validId(req.params.id)) {
      client.release();
      return res.status(400).send('Invalid draft ID.');
    }

    await client.query('BEGIN');

    const result = await client.query(
      `SELECT * FROM ai_task_queue
       WHERE id = $1 AND status = 'draft' FOR UPDATE`,
      [req.params.id]
    );

    if (!result.rows.length) {
      await client.query('ROLLBACK');
      client.release();
      return redirectMessage(res, '/admin/ai', 'Draft not found or already processed.');
    }

    const draft = result.rows[0];

    const inserted = await client.query(
      `INSERT INTO tasks
       (title, description, task_type, reward_usd, published)
       VALUES ($1, $2, $3, $4, TRUE)
       RETURNING id`,
      [draft.title, draft.description, draft.task_type, draft.reward_usd]
    );

    await client.query(
      `UPDATE ai_task_queue
       SET status = 'published', published_task_id = $1
       WHERE id = $2`,
      [inserted.rows[0].id, draft.id]
    );

    await client.query('COMMIT');
    client.release();

    redirectMessage(res, '/admin/ai', 'AI draft published as a task.');
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    client.release();
    next(error);
  }
});

app.post('/admin/ai/:id/delete', requireAdmin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).send('Invalid draft ID.');

    await pool.query(
      `UPDATE ai_task_queue SET status = 'deleted'
       WHERE id = $1 AND status = 'draft'`,
      [req.params.id]
    );

    redirectMessage(res, '/admin/ai', 'Draft removed from the active queue.');
  } catch (error) {
    next(error);
  }
});

/* -------------------- DATABASE AND STARTUP -------------------- */

async function initDatabase() {
  /*
   * The original application tables are intentionally NOT dropped,
   * recreated or altered here. Existing worker data is preserved.
   */
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_task_queue (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      description TEXT NOT NULL,
      task_type VARCHAR(40) NOT NULL,
      reward_usd NUMERIC(10,2) NOT NULL DEFAULT 1.00
        CHECK (reward_usd >= 0 AND reward_usd <= 50),
      status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'published', 'deleted')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      published_task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL
    )
  `);

  const checks = [
    ['users', 'password_hash'],
    ['users', 'role'],
    ['screenings', 'submitted_at'],
    ['screenings', 'review_notes'],
    ['tasks', 'published'],
    ['tasks', 'reward_usd'],
    ['submissions', 'response'],
    ['submissions', 'submitted_at'],
    ['submissions', 'review_notes'],
    ['payouts', 'amount_usd'],
    ['payouts', 'requested_at']
  ];

  for (const [table, column] of checks) {
    const result = await pool.query(
      `SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`,
      [table, column]
    );

    if (!result.rows.length) {
      throw new Error(
        `Database schema check failed: public.${table}.${column} is missing. ` +
        'Check the existing database schema; do not drop your tables.'
      );
    }
  }

  /*
   * If the configured admin email already exists, promote that account
   * without changing its password. If it does not exist, create it using
   * ADMIN_PASSWORD. Existing account passwords are never reset here.
   */
  const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');

  if (adminEmail && adminPassword) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail)) {
      throw new Error('ADMIN_EMAIL is not a valid email address.');
    }

    if (adminPassword.length < 10 || adminPassword.length > 128) {
      throw new Error('ADMIN_PASSWORD must be 10–128 characters.');
    }

    const existing = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [adminEmail]
    );

    if (existing.rows.length) {
      await pool.query(
        "UPDATE users SET role = 'admin' WHERE email = $1",
        [adminEmail]
      );
    } else {
      const hash = await bcrypt.hash(adminPassword, 12);
      await pool.query(
        `INSERT INTO users (name, email, password_hash, role)
         VALUES ('TaskForge Administrator', $1, $2, 'admin')`,
        [adminEmail, hash]
      );
      console.log('Initial administrator account created.');
    }
  } else {
    console.warn('ADMIN_EMAIL or ADMIN_PASSWORD is not configured; admin bootstrap skipped.');
  }

  console.log('Database schema checks passed.');
}

app.use((req, res) => {
  render(res, 'Page not found', `
    <div class="card"><h1>Page not found</h1>
      <p>The page you requested does not exist.</p>
      <a class="btn" href="${req.session.user ? '/dashboard' : '/'}">Return</a>
    </div>`, req, 404);
});

app.use((error, req, res, next) => {
  console.error('Request error:', error.message);

  if (res.headersSent) return next(error);

  render(res, 'Something went wrong', `
    <div class="card"><h1>Something went wrong</h1>
      <p>The request could not be completed. Please try again.</p>
      <a class="btn" href="${req.session.user ? '/dashboard' : '/'}">Return</a>
    </div>`, req, 500);
});

async function start() {
  try {
    await pool.query('SELECT 1');
    await initDatabase();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`TaskForge AI listening on port ${PORT}`);
    });
  } catch (error) {
    console.error('Startup failed:', error.message);
    process.exit(1);
  }
}

start();
