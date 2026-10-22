'use strict';

const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const OpenAI = require('openai');

const app = express();
const PORT = Number(process.env.PORT) || 10000;

if (!process.env.DATABASE_URL) {
  throw new Error('Missing DATABASE_URL environment variable');
}
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must contain at least 32 characters');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000
});

pool.on('error', err => {
  console.error('Unexpected PostgreSQL pool error:', err.message);
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
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'https:', 'data:'],
      mediaSrc: ["'self'", 'https:', 'blob:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none''],
      upgradeInsecureRequests:
        process.env.NODE_ENV === 'production' ? [] : null
    }
  }
}));

app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(express.json({ limit: '100kb' }));

app.use(session({
  name: 'taskforge.sid',
  store: new PgSession({
    pool,
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
}[c]));

const money = value => Number(value || 0).toFixed(2);

const validId = value => {
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
};

const validEmail = value =>
  typeof value === 'string' &&
  value.length <= 255 &&
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

const message = (res, path, text) =>
  res.redirect(path + '?message=' + encodeURIComponent(text));

function csrf(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return `<input type="hidden" name="_csrf" value="${esc(req.session.csrfToken)}">`;
}

function page(title, body, user = null) {
  const adminLink = user && user.role === 'admin'
    ? '<a href="/admin">Admin</a>'
    : '';

  const nav = user
    ? `<a href="/dashboard">Dashboard</a>
       <a href="/tasks">Tasks</a>
       <a href="/payout">Payouts</a>
       ${adminLink}
       <form class="logout" method="post" action="/logout">
         ${csrf({ session: { csrfToken: crypto.randomBytes(16).toString('hex') } })}
       </form>`
    : '<a href="/login">Log in</a><a class="nav-cta" href="/register">Get started</a>';

  // Logout form is built separately below so its token belongs to the real session.
  const realNav = user
    ? `<a href="/dashboard">Dashboard</a>
       <a href="/tasks">Tasks</a>
       <a href="/payout">Payouts</a>
       ${adminLink}
       <form class="logout" method="post" action="/logout">
         <input type="hidden" name="_csrf" value="${esc(user.csrfToken || '')}">
         <button class="nav-logout">Log out</button>
       </form>`
    : nav;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#11162d">
<meta name="description" content="TaskForge AI — data annotation and AI training tasks.">
<title>${esc(title)} | TaskForge AI</title>
<style>
:root{
--bg:#f5f6fc;--surface:#fff;--ink:#171d36;--muted:#737b94;
--brand:#7054f5;--brand2:#5135d8;--nav:#11162d;--border:#e6e8f2;
--green:#137b55;--red:#b42332;--radius:18px
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(ellipse at 95% 0%,#e9e4ff 0,transparent 34%),var(--bg);color:var(--ink);font:15px/1.7 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}
header{position:sticky;top:0;z-index:10;background:#11162df5;color:#fff;padding:14px max(4%,calc((100% - 1120px)/2));display:flex;align-items:center;justify-content:space-between;gap:15px;flex-wrap:wrap;box-shadow:0 4px 24px #11162d20;backdrop-filter:blur(12px)}
.brand{color:#fff;text-decoration:none;font-size:21px;font-weight:850;letter-spacing:-.7px}
.brand-mark{display:inline-grid;place-items:center;background:linear-gradient(135deg,#a697ff,#7054f5);width:34px;height:34px;border-radius:11px;margin-right:8px}
nav{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
nav a{color:#e7e8ff;text-decoration:none;font-size:13px;font-weight:650;padding:7px 10px;border-radius:9px}
nav a:hover{background:#ffffff18;color:white}
nav .nav-cta{background:var(--brand);color:#fff}
main{max-width:1120px;margin:38px auto 75px;padding:0 20px}
h1,h2,h3{color:var(--ink);line-height:1.25;letter-spacing:-.45px}
h1{font-size:clamp(30px,5vw,46px);font-weight:850;margin:0 0 16px}
h2{font-size:22px;margin:0 0 15px}
h3{font-size:18px;margin:0 0 10px}
p{margin:9px 0}
a{color:var(--brand2)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:clamp(19px,4vw,30px);margin:17px 0;box-shadow:0 9px 30px #20284c08;overflow-wrap:anywhere}
.hero{padding:clamp(28px,7vw,68px);border:1px solid #e2dcff;border-radius:26px;background:linear-gradient(135deg,#fff 10%,#f0edff 100%);box-shadow:0 16px 48px #5236d20b}
.eyebrow{display:inline-block;color:var(--brand2);background:#ece8ff;border-radius:30px;padding:5px 12px;font-size:12px;font-weight:800;letter-spacing:.6px;text-transform:uppercase;margin-bottom:15px}
.hero p{max-width:660px;color:#626b84;font-size:17px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,235px),1fr));gap:16px}
.stat{background:#fff;border:1px solid var(--border);padding:22px;border-radius:16px}
.stat strong{display:block;font-size:29px;letter-spacing:-.7px;color:var(--brand2)}
.stat span{font-size:13px;color:var(--muted)}
button,.btn{display:inline-flex;align-items:center;justify-content:center;min-height:44px;gap:8px;margin:5px 6px 5px 0;padding:10px 17px;border:1px solid transparent;border-radius:10px;background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;font:inherit;font-size:14px;font-weight:750;text-decoration:none;cursor:pointer;box-shadow:0 5px 14px #7054f522;transition:transform .18s,box-shadow .18s}
button:hover,.btn:hover{transform:translateY(-1px);box-shadow:0 8px 19px #7054f533}
button.secondary,.btn.secondary{background:#eeeff8;color:var(--ink);box-shadow:none}
button.danger{background:var(--red);box-shadow:none}
label{display:block;font-size:14px;font-weight:700;margin-top:12px}
input:not([type=checkbox]),textarea,select{display:block;width:100%;min-height:45px;margin:6px 0 14px;padding:11px 13px;border:1px solid #dce0ed;border-radius:10px;background:#fcfcff;color:var(--ink);font:inherit}
textarea{min-height:115px;resize:vertical}
input:focus,textarea:focus,select:focus{outline:3px solid #7054f51c;border-color:var(--brand)}
input[type=checkbox]{accent-color:var(--brand);width:18px;height:18px}
.muted{color:var(--muted)}
.notice{background:#f0edff;border:1px solid #ded6ff;padding:13px 16px;border-radius:12px;margin:14px 0}
.status{display:inline-block;border-radius:30px;background:#eeeff8;color:#424a63;padding:3px 10px;font-size:12px;font-weight:750}
.status.approved,.status.paid{background:#e4f7ed;color:#137b55}
.status.pending{background:#fff4d7;color:#805a00}
.status.rejected{background:#ffe8e9;color:#b42332}
pre{white-space:pre-wrap;overflow-wrap:anywhere;overflow-x:auto;padding:14px;background:#f7f8fc;border:1px solid var(--border);border-radius:10px}
.logout{display:inline-flex;margin:0}
.nav-logout{min-height:auto;margin:0;padding:7px 10px;background:transparent;box-shadow:none;font-size:13px}
footer{text-align:center;color:var(--muted);padding:25px;font-size:13px}
@media(max-width:600px){
header{position:relative;padding:13px 15px}
.brand{font-size:19px}
nav{width:100%;gap:3px}
nav a{padding:7px;font-size:12px}
main{margin:23px auto 45px;padding:0 13px}
.card{padding:19px 16px;margin:13px 0;border-radius:15px}
.hero{padding:28px 20px}
h1{font-size:31px}
button,.btn{min-height:44px}
}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<header>
<a class="brand" href="/"><span class="brand-mark">✦</span>TaskForge AI</a>
<nav>${realNav}</nav>
</header>
<main>${body}</main>
<footer>TaskForge AI · AI training and data quality platform</footer>
</body></html>`;
}

function box(title, content) {
  return `<section class="card"><h2>${title}</h2>${content}</section>`;
}

function flash(req) {
  return req.query.message
    ? `<div class="notice">${esc(req.query.message)}</div>`
    : '';
}

function link(path, label, secondary = false) {
  return `<a class="btn${secondary ? ' secondary' : ''}" href="${path}">${label}</a>`;
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send(page(
      'Access denied',
      '<section class="card"><h1>Access denied</h1><p>This area is restricted to administrators.</p></section>',
      req.session.user
    ));
  }
  next();
}

// CSRF validation for every form-changing request.
app.use((req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();

  const sent = req.body && req.body._csrf;
  const expected = req.session.csrfToken;

  if (!sent || !expected || !crypto.timingSafeEqual(
    Buffer.from(String(sent)),
    Buffer.from(String(expected))
  )) {
    return res.status(403).send(page(
      'Security check',
      '<section class="card"><h1>Security check failed</h1><p>Refresh the page and try again.</p></section>',
      req.session.user
    ));
  }
  next();
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (err) {
    console.error('Health check:', err.message);
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.get('/', (req, res) => {
  const body = `
<section class="hero">
<span class="eyebrow">AI training · Human expertise</span>
<h1>Turn your skills into meaningful work.</h1>
<p>Help improve AI through thoughtful data annotation, transcription, and evaluation tasks. Submit quality work and track approved earnings from one simple dashboard.</p>
${req.session.user ? link('/dashboard', 'Open your dashboard') : link('/register', 'Create your account')}
${link('/login', 'Sign in', true)}
</section>
<div class="grid" style="margin-top:22px">
<div class="stat"><strong>01</strong><span>Apply and complete screening</span></div>
<div class="stat"><strong>02</strong><span>Complete available tasks</span></div>
<div class="stat"><strong>03</strong><span>Submit work for review</span></div>
<div class="stat"><strong>04</strong><span>Request approved earnings</span></div>
</div>
${box('Built for quality', '<p>Clear instructions, reviewed submissions, and transparent task rewards help workers understand the process.</p><p class="muted">Task availability and earnings are not guaranteed. Submissions and payouts require review.</p>')}
`;
  res.send(page('Home', body, req.session.user));
});

app.get('/register', (req, res) => {
  res.send(page('Create account', `${flash(req)}
${box('Create your account', `
<form method="post" action="/register">
${csrf(req)}
<label>Full name</label><input name="name" maxlength="120" autocomplete="name" required>
<label>Email address</label><input name="email" type="email" maxlength="255" autocomplete="email" required>
<label>Password (minimum 10 characters)</label><input name="password" type="password" minlength="10" maxlength="200" autocomplete="new-password" required>
<button>Create account</button>
</form>
<p class="muted">Already registered? <a href="/login">Sign in</a>.</p>
`)}`));
});

app.post('/register', async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!name || name.length > 120 || !validEmail(email) ||
      password.length < 10 || password.length > 200) {
    return message(res, '/register', 'Check your details and password length.');
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      'INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3)',
      [name, email, hash]
    );
    message(res, '/login', 'Account created. You can now sign in.');
  } catch (err) {
    if (err.code === '23505') return message(res, '/register', 'That email is already registered.');
    console.error('Register:', err.message);
    res.status(500).send(page('Error', '<section class="card"><h1>Could not register</h1><p>Please try again later.</p></section>'));
  }
});

app.get('/login', (req, res) => {
  res.send(page('Sign in', `${flash(req)}
${box('Welcome back', `
<form method="post" action="/login">
${csrf(req)}
<label>Email address</label><input name="email" type="email" autocomplete="email" required>
<label>Password</label><input name="password" type="password" autocomplete="current-password" required>
<button>Sign in securely</button>
</form>
<p class="muted">New to TaskForge? <a href="/register">Create an account</a>.</p>
`)}`));
});

app.post('/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.password_hash))) {
      return message(res, '/login', 'Invalid email or password.');
    }

    req.session.regenerate(err => {
      if (err) return res.status(500).send('Could not start session.');
      req.session.user = {
        id: String(user.id),
        name: user.name,
        email: user.email,
        role: user.role
      };
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.save(err2 => {
        if (err2) return res.status(500).send('Could not save session.');
        res.redirect('/dashboard');
      });
    });
  } catch (err) {
    console.error('Login:', err.message);
    res.status(500).send(page('Error', '<section class="card"><h1>Login unavailable</h1><p>Please try again later.</p></section>'));
  }
});

app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('taskforge.sid');
    res.redirect('/');
  });
});

async function isScreeningApproved(userId) {
  const r = await pool.query(
    "SELECT id FROM screenings WHERE user_id=$1 AND status='approved' ORDER BY submitted_at DESC LIMIT 1",
    [userId]
  );
  return r.rowCount > 0;
}

app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.id;

    const [screen, earned, count, payout] = await Promise.all([
      pool.query('SELECT status,review_notes FROM screenings WHERE user_id=$1 ORDER BY submitted_at DESC LIMIT 1', [uid]),
      pool.query("SELECT COALESCE(SUM(t.reward_usd),0) AS total FROM submissions s JOIN tasks t ON t.id=s.task_id WHERE s.user_id=$1 AND s.status='approved'", [uid]),
      pool.query('SELECT COUNT(*)::int AS total FROM submissions WHERE user_id=$1', [uid]),
      pool.query("SELECT COALESCE(SUM(amount_usd),0) AS total FROM payouts WHERE user_id=$1 AND status IN ('pending','paid')", [uid])
    ]);

    const s = screen.rows[0];
    const balance = Math.max(0, Number(earned.rows[0].total) - Number(payout.rows[0].total));

    res.send(page('Dashboard', `
<h1>Welcome back, ${esc(req.session.user.name)}</h1>
<p class="muted">Your TaskForge workspace at a glance.</p>
<div class="grid">
<div class="stat"><strong>$${money(earned.rows[0].total)}</strong><span>Approved task earnings</span></div>
<div class="stat"><strong>$${money(balance)}</strong><span>Available balance before payout review</span></div>
<div class="stat"><strong>${count.rows[0].total}</strong><span>Total submissions</span></div>
</div>
${box('Worker screening', s
  ? `<p>Status: <span class="status ${esc(s.status)}">${esc(s.status)}</span></p><p>${esc(s.review_notes || 'Your screening status is shown above.')}</p>`
  : '<p>Complete your screening to unlock available tasks.</p>')}
<div class="grid">
${box('Find tasks', '<p>Browse available assignments and follow each task’s instructions.</p>' + link('/tasks', 'Browse tasks'))}
${box('Your payouts', '<p>Save your PayPal email and request a payout from your approved balance.</p>' + link('/payout', 'Manage payouts'))}
${box('Screening', '<p>View your screening status or submit your answers.</p>' + link('/screening', 'Open screening'))}
</div>
`, req.session.user));
  } catch (err) {
    console.error('Dashboard:', err.message);
    res.status(500).send(page('Error', '<section class="card"><h1>Dashboard unavailable</h1><p>Check the server logs for details.</p></section>', req.session.user));
  }
});

app.get('/screening', requireAuth, async (req, res) => {
  const r = await pool.query(
    'SELECT status,review_notes,submitted_at FROM screenings WHERE user_id=$1 ORDER BY submitted_at DESC LIMIT 1',
    [req.session.user.id]
  );
  const s = r.rows[0];

  res.send(page('Worker screening', `${flash(req)}
${box('Your screening status', s
  ? `<p><span class="status ${esc(s.status)}">${esc(s.status)}</span></p><p>${esc(s.review_notes || '')}</p>`
  : '<p>No screening has been submitted yet.</p>')}
${box('Demonstrate your skills', `<form method="post" action="/screening">
${csrf(req)}
<label>Video annotation</label><textarea name="video" maxlength="3000" placeholder="Describe how you would label a person walking through a video." required></textarea>
<label>Audio transcription</label><textarea name="audio" maxlength="3000" placeholder="Provide a short transcription example." required></textarea>
<label>Quality control</label><textarea name="quality" maxlength="3000" placeholder="Explain how you would check a submission for errors." required></textarea>
<button>Submit screening</button>
</form><p class="muted">An administrator must review and approve your screening before you can access tasks.</p>`)}
`, req.session.user));
});

app.post('/screening', requireAuth, async (req, res) => {
  const answers = {
    video: String(req.body.video || '').trim(),
    audio: String(req.body.audio || '').trim(),
    quality: String(req.body.quality || '').trim()
  };
  if (Object.values(answers).some(v => !v || v.length > 3000)) {
    return message(res, '/screening', 'Complete every field within the character limit.');
  }
  await pool.query(
    "INSERT INTO screenings(user_id,answers,status) VALUES($1,$2::jsonb,'pending')",
    [req.session.user.id, JSON.stringify(answers)]
  );
  message(res, '/screening', 'Screening submitted for review.');
});

app.get('/tasks', requireAuth, async (req, res) => {
  if (!(await isScreeningApproved(req.session.user.id))) return res.redirect('/screening');

  const r = await pool.query(`
    SELECT t.* FROM tasks t
    WHERE t.published=TRUE
      AND NOT EXISTS (
        SELECT 1 FROM submissions s
        WHERE s.task_id=t.id AND s.user_id=$1
      )
    ORDER BY t.created_at DESC LIMIT 100
  `, [req.session.user.id]);

  const list = r.rows.map(t => `
    <article class="card">
      <span class="eyebrow">${esc(t.task_type)}</span>
      <h2>${esc(t.title)}</h2>
      <p>${esc(t.description)}</p>
      <p><strong>Reward: $${money(t.reward_usd)}</strong></p>
      ${link('/tasks/' + t.id, 'Open task')}
    </article>
  `).join('');

  res.send(page('Available tasks', `<h1>Available tasks</h1><p class="muted">Choose a task and read its instructions carefully.</p>${list || box('No tasks available', '<p>There are no new tasks at the moment. Please check again later.</p>')}`, req.session.user));
});

app.get('/tasks/:id', requireAuth, async (req, res) => {
  if (!(await isScreeningApproved(req.session.user.id))) return res.redirect('/screening');

  const id = validId(req.params.id);
  if (!id) return res.status(404).send(page('Not found', '<h1>Task not found</h1>', req.session.user));

  const [result, existing] = await Promise.all([
    pool.query('SELECT * FROM tasks WHERE id=$1 AND published=TRUE', [id]),
    pool.query('SELECT id FROM submissions WHERE task_id=$1 AND user_id=$2', [id, req.session.user.id])
  ]);

  if (!result.rowCount || existing.rowCount) return res.redirect('/tasks');

  const t = result.rows[0];
  const media = t.media_url
    ? `<p>${esc(t.media_type || 'Reference')} file: <a href="${esc(t.media_url)}" target="_blank" rel="noopener noreferrer">Open task media</a></p>`
    : '<p class="muted">No media attachment is provided for this task.</p>';

  res.send(page(t.title, `${box(esc(t.title), `
<p>${esc(t.description)}</p>
<p>Task type: <strong>${esc(t.task_type)}</strong></p>
<p>Reward: <strong>$${money(t.reward_usd)}</strong></p>
${media}
<form method="post" action="/tasks/${id}/submit">
${csrf(req)}
<label>Your answer or annotation</label>
<textarea name="answer" maxlength="20000" required placeholder="Enter your completed work here..."></textarea>
<button>Submit work for review</button>
</form>
`)} `, req.session.user));
});

app.post('/tasks/:id/submit', requireAuth, async (req, res) => {
  if (!(await isScreeningApproved(req.session.user.id))) return res.redirect('/screening');

  const id = validId(req.params.id);
  const answer = String(req.body.answer || '').trim();
  if (!id || !answer || answer.length > 20000) {
    return message(res, '/tasks', 'Enter a valid task answer.');
  }

  try {
    const r = await pool.query(`
      INSERT INTO submissions(user_id,task_id,response)
      SELECT $1,id,$3::jsonb FROM tasks WHERE id=$2 AND published=TRUE
      ON CONFLICT(user_id,task_id) DO NOTHING
      RETURNING id
    `, [req.session.user.id, id, JSON.stringify({ answer })]);

    message(res, '/dashboard', r.rowCount
      ? 'Work submitted for review.'
      : 'This task was already submitted or is no longer available.');
  } catch (err) {
    console.error('Task submission:', err.message);
    res.status(500).send(page('Error', '<section class="card"><h1>Submission failed</h1><p>Please try again later.</p></section>', req.session.user));
  }
});

app.get('/payout', requireAuth, async (req, res) => {
  const uid = req.session.user.id;
  const [user, earnings, payouts] = await Promise.all([
    pool.query('SELECT paypal_email FROM users WHERE id=$1', [uid]),
    pool.query("SELECT COALESCE(SUM(t.reward_usd),0) AS total FROM submissions s JOIN tasks t ON t.id=s.task_id WHERE s.user_id=$1 AND s.status='approved'", [uid]),
    pool.query('SELECT * FROM payouts WHERE user_id=$1 ORDER BY requested_at DESC LIMIT 30', [uid])
  ]);

  const spent = payouts.rows
    .filter(p => ['pending', 'paid'].includes(p.status))
    .reduce((sum, p) => sum + Number(p.amount_usd), 0);
  const balance = Math.max(0, Number(earnings.rows[0].total) - spent);

  const history = payouts.rows.map(p => `
    <article class="card">
      <p><strong>$${money(p.amount_usd)}</strong> · <span class="status ${esc(p.status)}">${esc(p.status)}</span></p>
      <p class="muted">Requested: ${esc(p.requested_at)}</p>
      ${p.transaction_id ? `<p>Transaction: ${esc(p.transaction_id)}</p>` : ''}
      ${p.admin_notes ? `<p>Admin note: ${esc(p.admin_notes)}</p>` : ''}
    </article>
  `).join('') || '<p>No payout requests yet.</p>';

  res.send(page('Payouts', `${flash(req)}
${box('Available balance', `<div class="stat"><strong>$${money(balance)}</strong><span>Based on approved tasks less pending and completed payouts</span></div>`)}
${box('Request a manual PayPal payout', `<form method="post" action="/payout">
${csrf(req)}
<label>PayPal email</label><input type="email" name="paypal_email" maxlength="255" value="${esc(user.rows[0].paypal_email || '')}" required>
<label>Amount (USD)</label><input type="number" name="amount" min="0.01" max="500" step="0.01" required>
<button>Submit payout request</button>
</form><p class="muted">Payouts are manually reviewed. A request is not a guarantee of payment.</p>`)}
${box('Payout history', history)}
`, req.session.user));
});

app.post('/payout', requireAuth, async (req, res) => {
  const email = String(req.body.paypal_email || '').trim();
  const amount = Number(req.body.amount);
  if (!validEmail(email) || !Number.isFinite(amount) || amount <= 0 || amount > 500) {
    return message(res, '/payout', 'Enter a valid PayPal email and amount.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const earned = await client.query(`
      SELECT COALESCE(SUM(t.reward_usd),0) AS total
      FROM submissions s JOIN tasks t ON t.id=s.task_id
      WHERE s.user_id=$1 AND s.status='approved'
    `, [req.session.user.id]);

    const used = await client.query(`
      SELECT COALESCE(SUM(amount_usd),0) AS total
      FROM payouts WHERE user_id=$1 AND status IN ('pending','paid')
    `, [req.session.user.id]);

    const available = Number(earned.rows[0].total) - Number(used.rows[0].total);
    if (amount > available + 0.000001) {
      await client.query('ROLLBACK');
      return message(res, '/payout', 'The amount exceeds your available approved balance.');
    }

    await client.query('UPDATE users SET paypal_email=$1 WHERE id=$2', [email, req.session.user.id]);
    await client.query(
      "INSERT INTO payouts(user_id,amount_usd,paypal_email,status) VALUES($1,$2,$3,'pending')",
      [req.session.user.id, amount.toFixed(2), email]
    );

    await client.query('COMMIT');
    message(res, '/payout', 'Payout request submitted for manual review.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Payout request:', err.message);
    res.status(500).send(page('Error', '<section class="card"><h1>Payout request failed</h1><p>Please try again later.</p></section>', req.session.user));
  } finally {
    client.release();
  }
});

app.get('/admin', requireAdmin, async (req, res) => {
  const [users, tasks, submissions, screenings, payouts, drafts] = await Promise.all([
    pool.query('SELECT COUNT(*)::int AS n FROM users'),
    pool.query('SELECT COUNT(*)::int AS n FROM tasks'),
    pool.query("SELECT COUNT(*)::int AS n FROM submissions WHERE status='pending'"),
    pool.query("SELECT COUNT(*)::int AS n FROM screenings WHERE status='pending'"),
    pool.query("SELECT COUNT(*)::int AS n FROM payouts WHERE status='pending'"),
    pool.query("SELECT COUNT(*)::int AS n FROM ai_task_queue WHERE status='draft'")
  ]);

  const stat = (title, value) => `<div class="stat"><strong>${esc(value)}</strong><span>${esc(title)}</span></div>`;

  res.send(page('Admin dashboard', `
<h1>Admin workspace</h1>
<p class="muted">Manage tasks, review worker submissions, and track payout requests.</p>
${flash(req)}
<div class="grid">
${stat('Registered users', users.rows[0].n)}
${stat('Total tasks', tasks.rows[0].n)}
${stat('Pending submissions', submissions.rows[0].n)}
${stat('Pending screenings', screenings.rows[0].n)}
${stat('Pending payouts', payouts.rows[0].n)}
${stat('AI drafts', drafts.rows[0].n)}
</div>
<div class="grid">
${box('Task management', '<p>Create, publish, unpublish and manage assignments.</p>' + link('/admin/tasks', 'Manage tasks'))}
${box('Quality review', '<p>Review screening answers and submitted work.</p>' + link('/admin/reviews', 'Review work'))}
${box('Payout operations', '<p>Track payout requests and transaction references.</p>' + link('/admin/payouts', 'Manage payouts'))}
${box('AI task studio', '<p>Generate draft instructions for administrator approval.</p>' + link('/admin/ai', 'Open AI studio'))}
</div>
`, req.session.user));
});

app.get('/admin/tasks', requireAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM tasks ORDER BY created_at DESC LIMIT 100');
  const list = r.rows.map(t => box(esc(t.title), `
<p>${esc(t.description)}</p>
<p>Type: ${esc(t.task_type)} · Reward: <strong>$${money(t.reward_usd)}</strong></p>
<p>Status: <span class="status ${t.published ? 'approved' : 'pending'}">${t.published ? 'Published' : 'Draft'}</span></p>
<form method="post" action="/admin/tasks/${t.id}/publish">${csrf(req)}<button>${t.published ? 'Unpublish' : 'Publish'}</button></form>
<form method="post" action="/admin/tasks/${t.id}/delete">${csrf(req)}<button class="danger">Delete task</button></form>
`)).join('');

  res.send(page('Task management', `<h1>Task management</h1>${flash(req)}
${list || '<p>No tasks created yet.</p>'}
${box('Create a task', `<form method="post" action="/admin/tasks">
${csrf(req)}
<label>Task title</label><input name="title" maxlength="200" required>
<label>Instructions</label><textarea name="description" maxlength="10000" required></textarea>
<label>Task type</label><select name="task_type">
<option value="text">Text</option><option value="evaluation">Evaluation</option>
<option value="audio_transcription">Audio transcription</option><option value="video_annotation">Video annotation</option>
</select>
<label>Media URL (optional)</label><input type="url" name="media_url" placeholder="https://...">
<label>Media type</label><select name="media_type"><option value="">None</option><option value="audio">Audio</option><option value="video">Video</option></select>
<label>Reward in USD (maximum $50)</label><input type="number" name="reward_usd" min="0" max="50" step="0.01" required>
<label><input type="checkbox" name="published" value="yes"> Publish immediately</label>
<button>Create task</button>
</form>`)}
`, req.session.user));
});

app.post('/admin/tasks', requireAdmin, async (req, res) => {
  const title = String(req.body.title || '').trim();
  const description = String(req.body.description || '').trim();
  const type = String(req.body.task_type || '');
  const url = String(req.body.media_url || '').trim() || null;
  const mediaType = String(req.body.media_type || '') || null;
  const reward = Number(req.body.reward_usd);

  if (!title || title.length > 200 || !description || description.length > 10000 ||
      !['text','evaluation','audio_transcription','video_annotation'].includes(type) ||
      !Number.isFinite(reward) || reward < 0 || reward > 50 ||
      (url && !/^https:\/\/\S+$/i.test(url)) ||
      ![null,'audio','video'].includes(mediaType)) {
    return message(res, '/admin/tasks', 'Invalid task details. Rewards must be between $0 and $50.');
  }

  await pool.query(`
    INSERT INTO tasks(title,description,task_type,media_url,media_type,reward_usd,published)
    VALUES($1,$2,$3,$4,$5,$6,$7)
  `, [title, description, type, url, mediaType, reward.toFixed(2), req.body.published === 'yes']);

  message(res, '/admin/tasks', 'Task created.');
});

app.post('/admin/tasks/:id/publish', requireAdmin, async (req, res) => {
  const id = validId(req.params.id);
  if (!id) return res.status(400).send('Invalid task ID');
  await pool.query('UPDATE tasks SET published=NOT published WHERE id=$1', [id]);
  message(res, '/admin/tasks', 'Task publishing status updated.');
});

app.post('/admin/tasks/:id/delete', requireAdmin, async (req, res) => {
  const id = validId(req.params.id);
  if (!id) return res.status(400).send('Invalid task ID');

  const submitted = await pool.query('SELECT id FROM submissions WHERE task_id=$1 LIMIT 1', [id]);
  if (submitted.rowCount) {
    return message(res, '/admin/tasks', 'This task has submissions. Unpublish it instead of deleting it.');
  }

  await pool.query('DELETE FROM tasks WHERE id=$1', [id]);
  message(res, '/admin/tasks', 'Task deleted if it existed.');
});

app.get('/admin/reviews', requireAdmin, async (req, res) => {
  const [submissions, screenings] = await Promise.all([
    pool.query(`
      SELECT s.id,s.response,s.submitted_at,u.email,t.title
      FROM submissions s JOIN users u ON u.id=s.user_id
      JOIN tasks t ON t.id=s.task_id
      WHERE s.status='pending' ORDER BY s.submitted_at LIMIT 100
    `),
    pool.query(`
      SELECT s.id,s.answers,s.submitted_at,u.email
      FROM screenings s JOIN users u ON u.id=s.user_id
      WHERE s.status='pending' ORDER BY s.submitted_at LIMIT 100
    `)
  ]);

  const subHtml = submissions.rows.map(s => box('Submission #' + s.id, `
<p>${esc(s.email)} · ${esc(s.title)}</p>
<pre>${esc(JSON.stringify(s.response, null, 2))}</pre>
<form method="post" action="/admin/submissions/${s.id}">
${csrf(req)}
<label>Decision</label><select name="status"><option value="approved">Approve</option><option value="rejected">Reject</option></select>
<label>Review notes</label><input name="review_notes" maxlength="2000">
<button>Save review</button>
</form>`)).join('') || '<p>No pending submissions.</p>';

  const screenHtml = screenings.rows.map(s => box('Screening #' + s.id, `
<p>${esc(s.email)}</p><pre>${esc(JSON.stringify(s.answers, null, 2))}</pre>
<form method="post" action="/admin/screenings/${s.id}">
${csrf(req)}
<label>Decision</label><select name="status"><option value="approved">Approve</option><option value="rejected">Reject</option></select>
<label>Review notes</label><input name="review_notes" maxlength="2000">
<button>Save screening review</button>
</form>`)).join('') || '<p>No pending screenings.</p>';

  res.send(page('Quality review', `<h1>Quality review</h1>${flash(req)}${box('Worker submissions', subHtml)}${box('Worker screenings', screenHtml)}`, req.session.user));
});

app.post('/admin/submissions/:id', requireAdmin, async (req, res) => {
  const id = validId(req.params.id);
  const status = String(req.body.status || '');
  if (!id || !['approved','rejected'].includes(status)) return message(res, '/admin/reviews', 'Invalid review.');
  await pool.query(`
    UPDATE submissions SET status=$1,review_notes=$2,reviewed_at=NOW()
    WHERE id=$3 AND status='pending'
  `, [status, String(req.body.review_notes || '').slice(0, 2000), id]);
  message(res, '/admin/reviews', 'Submission review saved.');
});

app.post('/admin/screenings/:id', requireAdmin, async (req, res) => {
  const id = validId(req.params.id);
  const status = String(req.body.status || '');
  if (!id || !['approved','rejected'].includes(status)) return message(res, '/admin/reviews', 'Invalid screening review.');
  await pool.query(`
    UPDATE screenings SET status=$1,review_notes=$2,reviewed_at=NOW()
    WHERE id=$3 AND status='pending'
  `, [status, String(req.body.review_notes || '').slice(0, 2000), id]);
  message(res, '/admin/reviews', 'Screening review saved.');
});

app.get('/admin/payouts', requireAdmin, async (req, res) => {
  const r = await pool.query(`
    SELECT p.*,u.email FROM payouts p JOIN users u ON u.id=p.user_id
    ORDER BY p.requested_at DESC LIMIT 100
  `);

  const list = r.rows.map(p => box('Payout #' + p.id, `
<p>${esc(p.email)} · <strong>$${money(p.amount_usd)}</strong></p>
<p>PayPal: ${esc(p.paypal_email)}</p>
<p>Status: <span class="status ${esc(p.status)}">${esc(p.status)}</span></p>
<form method="post" action="/admin/payouts/${p.id}">
${csrf(req)}
<label>Update status</label><select name="status"><option value="pending">Pending</option><option value="paid">Paid</option><option value="rejected">Rejected</option></select>
<label>Transaction ID</label><input name="transaction_id" maxlength="500">
<label>Admin notes</label><input name="admin_notes" maxlength="2000">
<button>Save payout update</button>
</form>`)).join('') || '<p>No payout requests.</p>';

  res.send(page('Payout management', `<h1>Payout management</h1>${flash(req)}${list}`, req.session.user));
});

app.post('/admin/payouts/:id', requireAdmin, async (req, res) => {
  const id = validId(req.params.id);
  const status = String(req.body.status || '');
  if (!id || !['pending','paid','rejected'].includes(status)) return message(res, '/admin/payouts', 'Invalid payout update.');

  await pool.query(`
    UPDATE payouts SET status=$1,transaction_id=$2,admin_notes=$3,
      paid_at=CASE WHEN $1='paid' THEN COALESCE(paid_at,NOW()) ELSE NULL END
    WHERE id=$4
  `, [
    status,
    String(req.body.transaction_id || '').slice(0, 500) || null,
    String(req.body.admin_notes || '').slice(0, 2000) || null,
    id
  ]);
  message(res, '/admin/payouts', 'Payout record updated.');
});

app.get('/admin/ai', requireAdmin, async (req, res) => {
  const drafts = await pool.query(
    "SELECT * FROM ai_task_queue WHERE status='draft' ORDER BY created_at DESC LIMIT 50"
  );

  const list = drafts.rows.map(d => {
    const p = d.payload || {};
    return box(esc(p.title || 'Untitled draft'), `
<p>${esc(p.description || '')}</p>
<p>Type: ${esc(p.task_type || d.task_type)} · Reward: $${money(p.reward_usd)}</p>
<form method="post" action="/admin/ai/${d.id}/publish">${csrf(req)}<button>Publish task</button></form>
<form method="post" action="/admin/ai/${d.id}/delete">${csrf(req)}<button class="danger">Delete draft</button></form>
`);
  }).join('') || '<p>No AI drafts awaiting review.</p>';

  res.send(page('AI task studio', `<h1>AI task studio</h1>${flash(req)}
${box('Generate task drafts', `<p>Generate up to 10 draft instructions for review. This does not automatically create real audio or video recordings.</p>
<form method="post" action="/admin/ai/generate">
${csrf(req)}
<label>Number of drafts</label><input type="number" name="count" min="1" max="10" value="5" required>
<label>Task type</label><select name="task_type"><option value="text">Text</option><option value="evaluation">Evaluation</option><option value="audio_transcription">Audio transcription (media needed separately)</option><option value="video_annotation">Video annotation (media needed separately)</option></select>
<button>Generate drafts</button>
</form>`)}
<h2>Draft queue</h2>${list}`, req.session.user));
});

app.post('/admin/ai/generate', requireAdmin, async (req, res) => {
  if (!openai) return message(res, '/admin/ai', 'OPENAI_API_KEY is not configured.');

  const count = Math.max(1, Math.min(10, parseInt(req.body.count, 10) || 5));
  const type = String(req.body.task_type || 'text');
  const allowed = ['text','evaluation','audio_transcription','video_annotation'];
  if (!allowed.includes(type)) return message(res, '/admin/ai', 'Invalid task type.');

  try {
    const response = await openai.responses.create({
      model: process.env.OPENAI_MODEL || 'gpt-4.1-mini',
      instructions: 'Create safe, original data-labeling task drafts. Return only a JSON array. Every item must have title, description, task_type, reward_usd. Use the requested task type. Rewards must be between 0.10 and 50 USD. Do not invent media URLs or claim to create recordings.',
      input: `Generate exactly ${count} original ${type} task drafts with clear worker instructions. Return a JSON array only.`,
      max_output_tokens: 5000
    });

    const drafts = JSON.parse(response.output_text);
    if (!Array.isArray(drafts)) throw new Error('AI response was not an array.');

    let saved = 0;
    for (const d of drafts.slice(0, count)) {
      const title = String(d.title || '').trim().slice(0, 200);
      const description = String(d.description || '').trim().slice(0, 10000);
      const reward = Number(d.reward_usd);
      if (!title || !description || !Number.isFinite(reward)) continue;

      const payload = {
        title,
        description,
        task_type: type,
        reward_usd: Math.max(0.1, Math.min(50, reward)),
        media_url: null,
        media_type: null
      };

      await pool.query(
        "INSERT INTO ai_task_queue(task_type,payload,status) VALUES($1,$2::jsonb,'draft')",
        [type, JSON.stringify(payload)]
      );
      saved++;
    }

    message(res, '/admin/ai', `Saved ${saved} draft(s). Review each draft before publishing.`);
  } catch (err) {
    console.error('AI draft generation failed:', err.message);
    message(res, '/admin/ai', 'AI generation failed. Check the Render logs and OPENAI_MODEL/API access.');
  }
});

app.post('/admin/ai/:id/publish', requireAdmin, async (req, res) => {
  const id = validId(req.params.id);
  if (!id) return message(res, '/admin/ai', 'Invalid draft ID.');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const r = await client.query(
      "SELECT * FROM ai_task_queue WHERE id=$1 AND status='draft' FOR UPDATE",
      [id]
    );

    if (!r.rowCount) {
      await client.query('ROLLBACK');
      return message(res, '/admin/ai', 'Draft not found.');
    }

    const p = r.rows[0].payload || {};
    const title = String(p.title || '').trim().slice(0, 200);
    const description = String(p.description || '').trim().slice(0, 10000);
    const type = String(p.task_type || r.rows[0].task_type);
    const reward = Number(p.reward_usd);

    if (!title || !description ||
        !['text','evaluation','audio_transcription','video_annotation'].includes(type) ||
        !Number.isFinite(reward) || reward < 0 || reward > 50) {
      await client.query('ROLLBACK');
      return message(res, '/admin/ai', 'Draft details are invalid.');
    }

    await client.query(`
      INSERT INTO tasks(title,description,task_type,reward_usd,published)
      VALUES($1,$2,$3,$4,FALSE)
    `, [title, description, type, reward.toFixed(2)]);

    await client.query(
      "UPDATE ai_task_queue SET status='published' WHERE id=$1",
      [id]
    );

    await client.query('COMMIT');
    message(res, '/admin/tasks', 'Task created as an unpublished task. Review and publish it from Task Management.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('AI draft publish:', err.message);
    res.status(500).send(page('Error', '<section class="card"><h1>Could not publish draft</h1></section>', req.session.user));
  } finally {
    client.release();
  }
});

app.post('/admin/ai/:id/delete', requireAdmin, async (req, res) => {
  const id = validId(req.params.id);
  if (!id) return message(res, '/admin/ai', 'Invalid draft ID.');

  await pool.query(
    "UPDATE ai_task_queue SET status='deleted' WHERE id=$1 AND status='draft'",
    [id]
  );
  message(res, '/admin/ai', 'Draft marked as deleted.');
});

// Safe startup: do not recreate, drop or modify existing application tables.
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_task_queue (
      id BIGSERIAL PRIMARY KEY,
      task_type VARCHAR(40) NOT NULL,
      payload JSONB NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','published','deleted')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Verify the expected existing schema without modifying user data.
  const required = {
    users: ['id','name','email','password_hash','role'],
    screenings: ['id','user_id','answers','status','submitted_at','review_notes'],
    tasks: ['id','title','description','task_type','reward_usd','published','created_at'],
    submissions: ['id','user_id','task_id','response','status','submitted_at','review_notes'],
    payouts: ['id','user_id','amount_usd','paypal_email','status','requested_at']
  };

  for (const [table, columns] of Object.entries(required)) {
    const result = await pool.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_schema='public' AND table_name=$1`,
      [table]
    );
    const existing = new Set(result.rows.map(row => row.column_name));
    const missing = columns.filter(column => !existing.has(column));
    if (missing.length) {
      throw new Error(
        `Schema check failed for ${table}; missing columns: ${missing.join(', ')}. No existing tables were changed.`
      );
    }
  }

  // Promote the configured administrator without creating duplicate users.
  // The configured email must already be a valid administrator account or a
  // trusted account selected by the owner. Password is set from Render env.
  const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');

  if (adminEmail && adminPassword.length >= 10 && validEmail(adminEmail)) {
    const existing = await pool.query(
      'SELECT id FROM users WHERE email=$1',
      [adminEmail]
    );

    if (existing.rowCount) {
      const hash = await bcrypt.hash(adminPassword, 12);
      await pool.query(
        "UPDATE users SET role='admin',password_hash=$1 WHERE id=$2",
        [hash, existing.rows[0].id]
      );
      console.log('Configured administrator account updated.');
    } else {
      console.warn('ADMIN_EMAIL has no existing user. Register that email first, then redeploy to promote it.');
    }
  } else {
    console.warn('Admin seed skipped: check ADMIN_EMAIL and ADMIN_PASSWORD in Render environment settings.');
  }
}

app.use((req, res) => {
  res.status(404).send(page(
    'Page not found',
    '<section class="card"><h1>Page not found</h1><p>The page may have moved or does not exist.</p><a class="btn" href="/">Return home</a></section>',
    req.session.user
  ));
});

app.use((err, req, res, next) => {
  console.error('Unhandled request error:', err.message);
  if (res.headersSent) return next(err);
  res.status(500).send(page(
    'Server error',
    '<section class="card"><h1>Something went wrong</h1><p>Please try again later.</p></section>',
    req.session.user
  ));
});

initDatabase()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`TaskForge AI listening on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Database initialization failed:', err.message);
    process.exit(1);
  });
