'use strict';

const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const OpenAI = require('openai');

const app = express();
const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required');
}
if (!process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET is required');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(express.json({ limit: '100kb' }));

app.use(session({
  store: new pgSession({
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
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;',
  '"': '&quot;', "'": '&#39;'
}[c]));

const page = (title, body, user = null) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · TaskForge AI</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f3f5fb;color:#172033;font:16px Arial,sans-serif}
header{background:#182747;color:white;padding:16px 5%;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
header a{color:white;margin-right:12px}main{max-width:1000px;margin:24px auto;padding:0 14px}
.card{background:white;padding:20px;margin:14px 0;border-radius:14px;box-shadow:0 3px 15px #18274712}
input,textarea,select{width:100%;padding:12px;margin:7px 0 14px;border:1px solid #ccd3e0;border-radius:8px;font:inherit}
button,.btn{display:inline-block;background:#315ce8;color:white;border:0;border-radius:8px;padding:11px 16px;cursor:pointer;text-decoration:none;font:inherit}
.secondary{background:#526078}.danger{background:#b42318}.muted{color:#667085}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
small{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}
</style>
</head>
<body>
<header><strong>TaskForge AI</strong><nav>
<a href="/">Home</a>
${user ? '<a href="/dashboard">Dashboard</a><a href="/tasks">Tasks</a><a href="/logout">Log out</a>' : '<a href="/login">Log in</a><a href="/register">Register</a>'}
${user && user.role === 'admin' ? '<a href="/admin">Admin</a>' : ''}
</nav></header>
<main>${body}</main>
</body></html>`;

const box = (title, body) =>
  `<section class="card"><h2>${title}</h2>${body}</section>`;

const link = (url, label) =>
  `<a class="btn" href="${url}">${label}</a>`;

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send(page('Forbidden', '<h2>Admin access required</h2>', req.session.user));
  }
  next();
}
function redirectMessage(res, path, message) {
  return res.redirect(path + '?message=' + encodeURIComponent(message));
}
function flash(req) {
  return req.query.message
    ? `<p class="card">${esc(req.query.message)}</p>`
    : '';
}
function csrf(req) {
  if (!req.session.csrf) {
    req.session.csrf = require('crypto').randomBytes(24).toString('hex');
  }
  return `<input type="hidden" name="_csrf" value="${esc(req.session.csrf)}">`;
}
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const sent = req.body && req.body._csrf;
    if (!sent || !req.session.csrf || sent !== req.session.csrf) {
      return res.status(403).send(page(
        'Security check',
        '<h2>Security check failed</h2><p>Go back, refresh the form and try again.</p>',
        req.session.user
      ));
    }
  }
  next();
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (e) {
    console.error('Health check failed:', e.message);
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.get('/', (req, res) => res.send(page('Home', `
<section class="card">
<h1>Welcome to TaskForge AI</h1>
<p>Complete available data tasks, submit your work for review and track approved earnings.</p>
${req.session.user ? link('/dashboard', 'Open dashboard') : link('/register', 'Create worker account')}
</section>
${box('How it works', '<p>1. Register. 2. Complete screening. 3. Wait for approval. 4. Complete tasks and submit work. 5. Request a payout after approval.</p>')}
`, req.session.user)));

app.get('/register', (req, res) => res.send(page('Register', `
${flash(req)}
${box('Create account', `<form method="post" action="/register">
${csrf(req)}
<label>Name</label><input name="name" maxlength="120" required>
<label>Email</label><input type="email" name="email" maxlength="255" required>
<label>Password (at least 10 characters)</label><input type="password" name="password" minlength="10" required>
<button>Create account</button></form>`)}
`)));

app.post('/register', async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!name || name.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 255 || password.length < 10 || password.length > 200) {
    return redirectMessage(res, '/register', 'Check your details and use a password of at least 10 characters.');
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      'INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3)',
      [name, email, hash]
    );
    return redirectMessage(res, '/login', 'Account created. Please log in.');
  } catch (e) {
    if (e.code === '23505') return redirectMessage(res, '/register', 'That email is already registered.');
    console.error('Registration failed:', e.message);
    return res.status(500).send(page('Error', '<p>Could not create account. Try again later.</p>'));
  }
});

app.get('/login', (req, res) => res.send(page('Log in', `
${flash(req)}
${box('Log in', `<form method="post" action="/login">
${csrf(req)}
<label>Email</label><input type="email" name="email" required>
<label>Password</label><input type="password" name="password" required>
<button>Log in</button></form>`)}
`)));

app.post('/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.password_hash))) {
      return redirectMessage(res, '/login', 'Invalid email or password.');
    }
    req.session.regenerate(err => {
      if (err) return res.status(500).send('Could not start session.');
      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      };
      req.session.save(err2 => {
        if (err2) return res.status(500).send('Could not save session.');
        res.redirect('/dashboard');
      });
    });
  } catch (e) {
    console.error('Login failed:', e.message);
    res.status(500).send(page('Error', '<p>Login failed. Try again later.</p>'));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

async function screeningApproved(userId) {
  const r = await pool.query(
    "SELECT id FROM screenings WHERE user_id=$1 AND status='approved' ORDER BY submitted_at DESC LIMIT 1",
    [userId]
  );
  return r.rowCount > 0;
}

app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const uid = req.session.user.id;
    const [screen, earnings, submissions, payout] = await Promise.all([
      pool.query('SELECT status,submitted_at,review_notes FROM screenings WHERE user_id=$1 ORDER BY submitted_at DESC LIMIT 1', [uid]),
      pool.query("SELECT COALESCE(SUM(t.reward_usd),0) AS total FROM submissions s JOIN tasks t ON t.id=s.task_id WHERE s.user_id=$1 AND s.status='approved'", [uid]),
      pool.query('SELECT COUNT(*)::int AS total FROM submissions WHERE user_id=$1', [uid]),
      pool.query("SELECT COALESCE(SUM(amount_usd),0) AS total FROM payouts WHERE user_id=$1 AND status='pending'", [uid])
    ]);
    const sc = screen.rows[0];
    res.send(page('Dashboard', `
<h1>Hello, ${esc(req.session.user.name)}</h1>
${box('Screening', sc ? `<p>Status: <strong>${esc(sc.status)}</strong></p><p>${esc(sc.review_notes || '')}</p>` : '<p>You must complete screening before accessing tasks.</p>')}
${box('Your account', `<p>Approved task earnings: $${Number(earnings.rows[0].total).toFixed(2)}</p><p>Submissions: ${submissions.rows[0].total}</p><p>Pending payout requests: $${Number(payout.rows[0].total).toFixed(2)}</p>`)}
${link('/screening', 'Screening')}
${link('/tasks', 'Browse tasks')}
${link('/payout', 'Request payout')}
`, req.session.user));
  } catch (e) {
    console.error('Dashboard failed:', e.message);
    res.status(500).send(page('Error', '<p>Dashboard could not load.</p>', req.session.user));
  }
});

app.get('/screening', requireAuth, async (req, res) => {
  const r = await pool.query(
    'SELECT status,review_notes,submitted_at FROM screenings WHERE user_id=$1 ORDER BY submitted_at DESC LIMIT 1',
    [req.session.user.id]
  );
  const latest = r.rows[0];
  res.send(page('Screening', `
${flash(req)}
${box('Worker screening', latest ? `<p>Latest status: <strong>${esc(latest.status)}</strong></p><p>${esc(latest.review_notes || '')}</p>` : '<p>No screening submitted yet.</p>')}
${box('Submit screening', `<form method="post" action="/screening">
${csrf(req)}
<label>Describe how you would label a person walking across a video.</label>
<textarea name="video" required maxlength="3000"></textarea>
<label>Write a short sample transcription of speech.</label>
<textarea name="audio" required maxlength="3000"></textarea>
<label>How would you check your work for errors?</label>
<textarea name="quality" required maxlength="3000"></textarea>
<button>Submit screening</button></form><p>Screenings are reviewed by an administrator. Approval is not automatic.</p>`)}
`, req.session.user));
});

app.post('/screening', requireAuth, async (req, res) => {
  const answers = {
    video: String(req.body.video || '').trim(),
    audio: String(req.body.audio || '').trim(),
    quality: String(req.body.quality || '').trim()
  };
  if (Object.values(answers).some(x => !x || x.length > 3000)) {
    return redirectMessage(res, '/screening', 'Please complete every screening field.');
  }
  await pool.query(
    "INSERT INTO screenings(user_id,answers,status) VALUES($1,$2::jsonb,'pending')",
    [req.session.user.id, JSON.stringify(answers)]
  );
  redirectMessage(res, '/screening', 'Screening submitted for review.');
});

app.get('/tasks', requireAuth, async (req, res) => {
  if (!(await screeningApproved(req.session.user.id))) {
    return res.redirect('/screening');
  }
  const tasks = await pool.query(
    `SELECT t.* FROM tasks t
     WHERE t.published=TRUE
     AND NOT EXISTS (SELECT 1 FROM submissions s WHERE s.task_id=t.id AND s.user_id=$1)
     ORDER BY t.created_at DESC LIMIT 100`,
    [req.session.user.id]
  );
  const html = tasks.rows.map(t => `<article class="card">
<h3>${esc(t.title)}</h3><p>${esc(t.description)}</p>
<p>Type: ${esc(t.task_type)} · Reward: $${Number(t.reward_usd).toFixed(2)}</p>
${link('/tasks/' + t.id, 'Open task')}</article>`).join('') || '<p>No available tasks right now.</p>';
  res.send(page('Tasks', `<h1>Available tasks</h1>${html}`, req.session.user));
});

app.get('/tasks/:id', requireAuth, async (req, res) => {
  if (!(await screeningApproved(req.session.user.id))) return res.redirect('/screening');
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(404).send('Task not found');
  const r = await pool.query('SELECT * FROM tasks WHERE id=$1 AND published=TRUE', [id]);
  if (!r.rowCount) return res.status(404).send('Task not found');
  const task = r.rows[0];
  const existing = await pool.query('SELECT id FROM submissions WHERE task_id=$1 AND user_id=$2', [id, req.session.user.id]);
  if (existing.rowCount) return res.redirect('/tasks');
  const media = task.media_url
    ? `<p>${task.media_type === 'video' ? 'Video' : task.media_type === 'audio' ? 'Audio' : 'Reference'}: <a href="${esc(task.media_url)}" target="_blank" rel="noopener">Open task media</a></p>`
    : '';
  res.send(page(task.title, `
${box(esc(task.title), `<p>${esc(task.description)}</p><p>Task type: ${esc(task.task_type)}</p><p>Reward: $${Number(task.reward_usd).toFixed(2)}</p>${media}
<form method="post" action="/tasks/${id}/submit">
${csrf(req)}
<label>Your answer / annotation</label>
<textarea name="answer" rows="8" required maxlength="20000"></textarea>
<button>Submit work</button></form>`)}
`, req.session.user));
});

app.post('/tasks/:id/submit', requireAuth, async (req, res) => {
  if (!(await screeningApproved(req.session.user.id))) return res.redirect('/screening');
  const id = Number(req.params.id);
  const answer = String(req.body.answer || '').trim();
  if (!Number.isSafeInteger(id) || id < 1 || !answer || answer.length > 20000) {
    return redirectMessage(res, '/tasks', 'Please enter a valid answer.');
  }
  try {
    await pool.query(
      `INSERT INTO submissions(user_id,task_id,response)
       SELECT $1,id,$3::jsonb FROM tasks WHERE id=$2 AND published=TRUE
       ON CONFLICT(user_id,task_id) DO NOTHING`,
      [req.session.user.id, id, JSON.stringify({ answer })]
    );
    redirectMessage(res, '/dashboard', 'Submission saved for review.');
  } catch (e) {
    console.error('Submission failed:', e.message);
    res.status(500).send(page('Error', '<p>Could not submit this task.</p>', req.session.user));
  }
});

app.get('/payout', requireAuth, async (req, res) => {
  const [user, totals, requests] = await Promise.all([
    pool.query('SELECT paypal_email FROM users WHERE id=$1', [req.session.user.id]),
    pool.query("SELECT COALESCE(SUM(t.reward_usd),0) AS total FROM submissions s JOIN tasks t ON t.id=s.task_id WHERE s.user_id=$1 AND s.status='approved'", [req.session.user.id]),
    pool.query('SELECT * FROM payouts WHERE user_id=$1 ORDER BY requested_at DESC LIMIT 20', [req.session.user.id])
  ]);
  const list = requests.rows.map(p => `<p>$${Number(p.amount_usd).toFixed(2)} — ${esc(p.status)} — ${esc(p.requested_at)}</p>`).join('') || '<p>No payout requests yet.</p>';
  res.send(page('Payout', `
${flash(req)}
${box('Request PayPal payout', `<p>Approved earnings: $${Number(totals.rows[0].total).toFixed(2)}</p>
<form method="post" action="/payout">
${csrf(req)}
<label>PayPal email</label><input type="email" name="paypal_email" maxlength="255" value="${esc(user.rows[0].paypal_email || '')}" required>
<label>Amount in USD</label><input type="number" name="amount" min="1" max="500" step="0.01" required>
<button>Request payout</button></form><p>Payouts are manually reviewed and are not automatic.</p>`)}
${box('Payout history', list)}
`, req.session.user));
});

app.post('/payout', requireAuth, async (req, res) => {
  const email = String(req.body.paypal_email || '').trim();
  const amount = Number(req.body.amount);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 255 ||
      !Number.isFinite(amount) || amount <= 0 || amount > 500) {
    return redirectMessage(res, '/payout', 'Enter a valid PayPal email and amount.');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE users SET paypal_email=$1 WHERE id=$2', [email, req.session.user.id]);
    const approved = await client.query(
      "SELECT COALESCE(SUM(t.reward_usd),0) AS total FROM submissions s JOIN tasks t ON t.id=s.task_id WHERE s.user_id=$1 AND s.status='approved'",
      [req.session.user.id]
    );
    const pending = await client.query(
      "SELECT COALESCE(SUM(amount_usd),0) AS total FROM payouts WHERE user_id=$1 AND status='pending'",
      [req.session.user.id]
    );
    if (amount > Number(approved.rows[0].total) - Number(pending.rows[0].total)) {
      await client.query('ROLLBACK');
      return redirectMessage(res, '/payout', 'Requested amount exceeds your available approved balance.');
    }
    await client.query(
      "INSERT INTO payouts(user_id,amount_usd,paypal_email,status) VALUES($1,$2,$3,'pending')",
      [req.session.user.id, amount.toFixed(2), email]
    );
    await client.query('COMMIT');
    redirectMessage(res, '/payout', 'Payout request submitted for manual review.');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Payout request failed:', e.message);
    res.status(500).send(page('Error', '<p>Could not request payout.</p>', req.session.user));
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
  res.send(page('Admin', `
<h1>Admin dashboard</h1>${flash(req)}
<div class="grid">
${box('Users', `<p>${users.rows[0].n}</p>`)}
${box('Tasks', `<p>${tasks.rows[0].n}</p>`)}
${box('Pending submissions', `<p>${submissions.rows[0].n}</p>`)}
${box('Pending screenings', `<p>${screenings.rows[0].n}</p>`)}
${box('Pending payouts', `<p>${payouts.rows[0].n}</p>`)}
${box('AI drafts', `<p>${drafts.rows[0].n}</p>`)}
</div>
${link('/admin/tasks', 'Manage tasks')}
${link('/admin/reviews', 'Review submissions and screenings')}
${link('/admin/payouts', 'Manage payouts')}
${link('/admin/ai', 'Generate AI task drafts')}
`, req.session.user));
});

app.get('/admin/tasks', requireAdmin, async (req, res) => {
  const tasks = await pool.query('SELECT * FROM tasks ORDER BY created_at DESC LIMIT 100');
  const list = tasks.rows.map(t => box(esc(t.title), `<p>${esc(t.description)}</p>
<p>${esc(t.task_type)} · $${Number(t.reward_usd).toFixed(2)} · ${t.published ? 'Published' : 'Draft'}</p>
<form method="post" action="/admin/tasks/${t.id}/publish">${csrf(req)}<button>${t.published ? 'Unpublish' : 'Publish'}</button></form>
<form method="post" action="/admin/tasks/${t.id}/delete">${csrf(req)}<button class="danger">Delete task</button></form>`)).join('');
  res.send(page('Manage tasks', `<h1>Manage tasks</h1>${flash(req)}${list}
${box('Create task', `<form method="post" action="/admin/tasks">
${csrf(req)}
<label>Title</label><input name="title" maxlength="200" required>
<label>Description</label><textarea name="description" maxlength="10000" required></textarea>
<label>Task type</label><select name="task_type"><option value="text">Text</option><option value="audio_transcription">Audio transcription</option><option value="video_annotation">Video annotation</option><option value="evaluation">Evaluation</option></select>
<label>Media URL (optional, must be a trusted URL)</label><input type="url" name="media_url">
<label>Media type</label><select name="media_type"><option value="">None</option><option value="audio">Audio</option><option value="video">Video</option></select>
<label>Reward USD (max $50)</label><input type="number" name="reward_usd" min="0" max="50" step="0.01" required>
<label><input style="width:auto" type="checkbox" name="published" value="yes"> Publish immediately</label>
<button>Create task</button></form>`)}
`, req.session.user));
});

app.post('/admin/tasks', requireAdmin, async (req, res) => {
  const title = String(req.body.title || '').trim();
  const description = String(req.body.description || '').trim();
  const taskType = String(req.body.task_type || '');
  const mediaUrl = String(req.body.media_url || '').trim() || null;
  const mediaType = String(req.body.media_type || '').trim() || null;
  const reward = Number(req.body.reward_usd);
  const allowed = ['text', 'audio_transcription', 'video_annotation', 'evaluation'];
  if (!title || title.length > 200 || !description || description.length > 10000 ||
      !allowed.includes(taskType) || !Number.isFinite(reward) || reward < 0 || reward > 50 ||
      (mediaUrl && !/^https:\/\/\S+$/i.test(mediaUrl)) ||
      ![null, 'audio', 'video'].includes(mediaType)) {
    return redirectMessage(res, '/admin/tasks', 'Invalid task details. Rewards must be $0–$50.');
  }
  await pool.query(
    'INSERT INTO tasks(title,description,task_type,media_url,media_type,reward_usd,published) VALUES($1,$2,$3,$4,$5,$6,$7)',
    [title, description, taskType, mediaUrl, mediaType, reward.toFixed(2), req.body.published === 'yes']
  );
  redirectMessage(res, '/admin/tasks', 'Task created.');
});

app.post('/admin/tasks/:id/publish', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).send('Invalid task ID');
  await pool.query('UPDATE tasks SET published=NOT published WHERE id=$1', [id]);
  redirectMessage(res, '/admin/tasks', 'Task publishing status updated.');
});

app.post('/admin/tasks/:id/delete', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).send('Invalid task ID');
  const exists = await pool.query('SELECT id FROM submissions WHERE task_id=$1 LIMIT 1', [id]);
  if (exists.rowCount) return redirectMessage(res, '/admin/tasks', 'Cannot delete a task with submissions. Unpublish it instead.');
  await pool.query('DELETE FROM tasks WHERE id=$1', [id]);
  redirectMessage(res, '/admin/tasks', 'Task deleted if it existed.');
});

app.get('/admin/reviews', requireAdmin, async (req, res) => {
  const [subs, screens] = await Promise.all([
    pool.query(`SELECT s.id,s.response,s.submitted_at,s.user_id,s.task_id,u.email,t.title
      FROM submissions s JOIN users u ON u.id=s.user_id JOIN tasks t ON t.id=s.task_id
      WHERE s.status='pending' ORDER BY s.submitted_at LIMIT 100`),
    pool.query(`SELECT s.id,s.answers,s.submitted_at,s.user_id,u.email
      FROM screenings s JOIN users u ON u.id=s.user_id
      WHERE s.status='pending' ORDER BY s.submitted_at LIMIT 100`)
  ]);
  const subHtml = subs.rows.map(s => box(`Submission #${s.id}`, `<p>${esc(s.email)} · ${esc(s.title)}</p>
<pre>${esc(JSON.stringify(s.response, null, 2))}</pre>
<form method="post" action="/admin/submissions/${s.id}">
${csrf(req)}
<select name="status"><option value="approved">Approve</option><option value="rejected">Reject</option></select>
<input name="review_notes" maxlength="2000" placeholder="Review notes">
<button>Save review</button></form>`)).join('') || '<p>No pending submissions.</p>';
  const screenHtml = screens.rows.map(s => box(`Screening #${s.id}`, `<p>${esc(s.email)}</p><pre>${esc(JSON.stringify(s.answers, null, 2))}</pre>
<form method="post" action="/admin/screenings/${s.id}">
${csrf(req)}
<select name="status"><option value="approved">Approve</option><option value="rejected">Reject</option></select>
<input name="review_notes" maxlength="2000" placeholder="Review notes">
<button>Save screening review</button></form>`)).join('') || '<p>No pending screenings.</p>';
  res.send(page('Reviews', `<h1>Review work</h1>${box('Submissions', subHtml)}${box('Screenings', screenHtml)}`, req.session.user));
});

app.post('/admin/submissions/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body.status || '');
  if (!Number.isSafeInteger(id) || id < 1 || !['approved', 'rejected'].includes(status)) {
    return redirectMessage(res, '/admin/reviews', 'Invalid review.');
  }
  await pool.query(
    'UPDATE submissions SET status=$1,review_notes=$2,reviewed_at=NOW() WHERE id=$3 AND status=$4',
    [status, String(req.body.review_notes || '').slice(0, 2000), id, 'pending']
  );
  redirectMessage(res, '/admin/reviews', 'Submission review saved.');
});

app.post('/admin/screenings/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body.status || '');
  if (!Number.isSafeInteger(id) || id < 1 || !['approved', 'rejected'].includes(status)) {
    return redirectMessage(res, '/admin/reviews', 'Invalid screening review.');
  }
  await pool.query(
    'UPDATE screenings SET status=$1,review_notes=$2,reviewed_at=NOW() WHERE id=$3 AND status=$4',
    [status, String(req.body.review_notes || '').slice(0, 2000), id, 'pending']
  );
  redirectMessage(res, '/admin/reviews', 'Screening review saved.');
});

app.get('/admin/payouts', requireAdmin, async (req, res) => {
  const r = await pool.query(`SELECT p.*,u.email FROM payouts p JOIN users u ON u.id=p.user_id
    ORDER BY p.requested_at DESC LIMIT 100`);
  const list = r.rows.map(p => box(`Payout #${p.id}`, `<p>${esc(p.email)} · $${Number(p.amount_usd).toFixed(2)} · ${esc(p.paypal_email)}</p><p>Status: ${esc(p.status)}</p>
<form method="post" action="/admin/payouts/${p.id}">
${csrf(req)}
<select name="status"><option value="paid">Mark paid</option><option value="rejected">Reject</option><option value="pending">Keep pending</option></select>
<input name="transaction_id" maxlength="500" placeholder="Transaction ID (if paid)">
<input name="admin_notes" maxlength="2000" placeholder="Admin notes">
<button>Update payout</button></form>`)).join('') || '<p>No payout requests.</p>';
  res.send(page('Payouts', `<h1>Manage payouts</h1>${list}`, req.session.user));
});

app.post('/admin/payouts/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body.status || '');
  if (!Number.isSafeInteger(id) || id < 1 || !['paid', 'rejected', 'pending'].includes(status)) {
    return redirectMessage(res, '/admin/payouts', 'Invalid payout update.');
  }
  await pool.query(
    `UPDATE payouts SET status=$1,transaction_id=$2,admin_notes=$3,
     paid_at=CASE WHEN $1='paid' THEN COALESCE(paid_at,NOW()) ELSE NULL END
     WHERE id=$4`,
    [status, String(req.body.transaction_id || '').slice(0, 500) || null,
     String(req.body.admin_notes || '').slice(0, 2000) || null, id]
  );
  redirectMessage(res, '/admin/payouts', 'Payout updated.');
});

app.get('/admin/ai', requireAdmin, async (req, res) => {
  const drafts = await pool.query("SELECT * FROM ai_task_queue WHERE status='draft' ORDER BY created_at DESC LIMIT 30");
  const html = drafts.rows.map(d => {
    const p = d.payload || {};
    return box(esc(p.title || 'AI task draft'), `<p>${esc(p.description || '')}</p>
<p>Type: ${esc(p.task_type || 'text')} · Reward: $${Number(p.reward_usd || 0).toFixed(2)}</p>
<form method="post" action="/admin/ai/${d.id}/publish">${csrf(req)}<button>Publish task</button></form>
<form method="post" action="/admin/ai/${d.id}/delete">${csrf(req)}<button class="danger">Delete draft</button></form>`);
  }).join('') || '<p>No drafts waiting.</p>';
  res.send(page('AI task generation', `<h1>AI task drafts</h1>${flash(req)}
${box('Generate drafts', `<p>Creates up to 10 text-based drafts for admin review. It does not generate or host real audio/video files.</p>
<form method="post" action="/admin/ai/generate">${csrf(req)}
<label>Number of drafts</label><input type="number" name="count" min="1" max="10" value="5" required>
<label>Task type</label><select name="task_type"><option value="text">Text</option><option value="evaluation">Evaluation</option><option value="audio_transcription">Audio transcription (requires media added separately)</option><option value="video_annotation">Video annotation (requires media added separately)</option></select>
<button>Generate drafts</button></form>`)}
${html}`, req.session.user));
});

app.post('/admin/ai/generate', requireAdmin, async (req, res) => {
  if (!openai) return redirectMessage(res, '/admin/ai', 'OPENAI_API_KEY is not configured.');
  const count = Math.max(1, Math.min(10, Number.parseInt(req.body.count, 10) || 5));
  const type = String(req.body.task_type || 'text');
  if (!['text', 'evaluation', 'audio_transcription', 'video_annotation'].includes(type)) {
    return redirectMessage(res, '/admin/ai', 'Invalid task type.');
  }
  try {
    const response = await openai.responses.create({
      model: process.env.OPENAI_MODEL || 'gpt-5.5',
      instructions: 'Generate safe, original data-labeling task drafts. Return only a JSON array. Each item must contain title, description, task_type, reward_usd. Use only the requested task_type. Keep rewards between 0.10 and 50 USD. Do not claim to create or attach real media files.',
      input: `Create exactly ${count} task drafts of type ${type}. Each description should include clear worker instructions and an example where helpful. Return JSON array only.`,
      max_output_tokens: 5000
    });
    let drafts;
    try {
      drafts = JSON.parse(response.output_text);
    } catch {
      throw new Error('AI did not return valid JSON. Try again.');
    }
    if (!Array.isArray(drafts)) throw new Error('AI response was not a list.');
    let saved = 0;
    for (const d of drafts.slice(0, count)) {
      const title = String(d.title || '').trim().slice(0, 200);
      const description = String(d.description || '').trim().slice(0, 10000);
      const reward = Number(d.reward_usd);
      if (!title || !description || !Number.isFinite(reward)) continue;
      const payload = {
        title, description, task_type: type,
        reward_usd: Math.max(0.1, Math.min(50, reward)),
        media_url: null, media_type: null
      };
      await pool.query(
        "INSERT INTO ai_task_queue(task_type,payload,status) VALUES($1,$2::jsonb,'draft')",
        [type, JSON.stringify(payload)]
      );
      saved++;
    }
    redirectMessage(res, '/admin/ai', `Saved ${saved} draft(s). Review before publishing.`);
  } catch (e) {
    console.error('AI generation failed:', e.message);
    redirectMessage(res, '/admin/ai', 'AI generation failed. Check Render logs and OPENAI_MODEL/API access.');
  }
});

app.post('/admin/ai/:id/publish', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).send('Invalid draft ID');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query(
      "SELECT * FROM ai_task_queue WHERE id=$1 AND status='draft' FOR UPDATE",
      [id]
    );
    if (!r.rowCount) {
      await client.query('ROLLBACK');
      return redirectMessage(res, '/admin/ai', 'Draft not found.');
    }
    const p = r.rows[0].payload || {};
    const title = String(p.title || '').slice(0, 200);
    const description = String(p.description || '').slice(0, 10000);
    const type = String(p.task_type || r.rows[0].task_type);
    const reward = Number(p.reward_usd);
    if (!title || !description || !['text','evaluation','audio_transcription','video_annotation'].includes(type) ||
        !Number.isFinite(reward) || reward < 0 || reward > 50) {
      await client.query('ROLLBACK');
      return redirectMessage(res, '/admin/ai', 'Draft data is invalid.');
    }
    await client.query(
      'INSERT INTO tasks(title,description,task_type,reward_usd,published) VALUES($1,$2,$3,$4,TRUE)',
      [title, description, type, reward.toFixed(2)]
    );
    await client.query("UPDATE ai_task_queue SET status='published' WHERE id=$1", [id]);
    await client.query('COMMIT');
    redirectMessage(res, '/admin/ai', 'Task published.');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Publish AI task failed:', e.message);
    res.status(500).send(page('Error', '<p>Could not publish draft.</p>', req.session.user));
  } finally {
    client.release();
  }
});

app.post('/admin/ai/:id/delete', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).send('Invalid draft ID');
  await pool.query("UPDATE ai_task_queue SET status='deleted' WHERE id=$1 AND status='draft'", [id]);
  redirectMessage(res, '/admin/ai', 'Draft deleted if it existed.');
});

async function initDatabase() {
  // Do not redefine or drop existing application tables.
  // These columns match the existing schema.sql supplied for TaskForge AI.
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
}

app.use((req, res) => {
  res.status(404).send(page('Not found', '<h1>Page not found</h1>', req.session.user));
});

app.use((err, req, res, next) => {
  console.error('Unhandled request error:', err.message);
  if (res.headersSent) return next(err);
  res.status(500).send(page('Server error', '<h1>Something went wrong</h1><p>Please try again later.</p>', req.session.user));
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
