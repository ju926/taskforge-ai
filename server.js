'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const OpenAI = require('openai');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const required = [
  'DATABASE_URL',
  'SESSION_SECRET',
  'ADMIN_EMAIL',
  'ADMIN_PASSWORD'
];

for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : undefined
});

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

app.set('trust proxy', 1);
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public'));

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

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[c]);
}

function page(title, body, user = null) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} | TaskForge AI</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f3f5fa;color:#172033;
font-family:Arial,sans-serif}
header{background:#172554;color:white;padding:18px}
header a{color:white;margin-right:14px}
main{max-width:1000px;margin:22px auto;padding:16px}
.card{background:white;padding:20px;margin:14px 0;
border-radius:12px;box-shadow:0 2px 12px #0000000c}
input,select,textarea,button{width:100%;padding:12px;
margin:7px 0;border:1px solid #ccd2df;border-radius:7px}
button,.btn{background:#2563eb;color:white;border:0;
padding:12px;display:inline-block;text-decoration:none;
border-radius:7px;cursor:pointer}
.muted{color:#64748b;font-size:14px}
.tag{display:inline-block;background:#dbeafe;padding:5px 8px;
border-radius:6px;margin:4px}
a{color:#1d4ed8}
pre{white-space:pre-wrap;overflow-wrap:anywhere}
</style>
</head>
<body>
<header>
<strong>TaskForge AI</strong>
<nav style="margin-top:12px">
<a href="/">Home</a>
${user ? '<a href="/dashboard">Dashboard</a><a href="/logout">Logout</a>' : '<a href="/login">Login</a><a href="/register">Register</a>'}
${user && user.role === 'admin' ? '<a href="/admin">Admin</a>' : ''}
</nav>
</header>
<main>${body}</main>
</body>
</html>`;
}

function notice(message) {
  return `<div class="card">${escapeHtml(message)}</div>`;
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send(page(
      'Forbidden',
      notice('Administrator access required.'),
      req.session.user
    ));
  }
  next();
}

function csrfToken(req) {
  if (!req.session.csrf) {
    req.session.csrf = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrf;
}

function csrfField(req) {
  return `<input type="hidden" name="_csrf" value="${escapeHtml(csrfToken(req))}">`;
}

app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const supplied = req.body && req.body._csrf;
    const expected = req.session.csrf;

    if (
      !supplied ||
      !expected ||
      supplied.length !== expected.length ||
      !crypto.timingSafeEqual(
        Buffer.from(supplied),
        Buffer.from(expected)
      )
    ) {
      return res.status(403).send(
        page('Security check', notice('Security token expired. Go back and try again.'), req.session.user)
      );
    }
  }
  next();
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'worker',
      paypal_email TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      task_type TEXT NOT NULL,
      reward NUMERIC(10,2) NOT NULL DEFAULT 0,
      media_url TEXT,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      status TEXT NOT NULL DEFAULT 'draft',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS submissions (
      id BIGSERIAL PRIMARY KEY,
      task_id BIGINT NOT NULL REFERENCES tasks(id),
      user_id BIGINT NOT NULL REFERENCES users(id),
      answer TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      reviewer_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      UNIQUE(task_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS screenings (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      answers JSONB NOT NULL DEFAULT '{}'::jsonb,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS payouts (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      amount NUMERIC(10,2) NOT NULL,
      paypal_email TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      transaction_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ai_task_queue (
      id BIGSERIAL PRIMARY KEY,
      task_type TEXT NOT NULL,
      payload JSONB NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS tasks_status_idx ON tasks(status);
    CREATE INDEX IF NOT EXISTS submissions_status_idx ON submissions(status);
    CREATE INDEX IF NOT EXISTS ai_queue_status_idx ON ai_task_queue(status);
  `);

  const adminEmail = process.env.ADMIN_EMAIL.trim().toLowerCase();
  const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);

  await pool.query(`
    INSERT INTO users (name, email, password_hash, role)
    VALUES ($1, $2, $3, 'admin')
    ON CONFLICT (email) DO UPDATE SET role = 'admin'
  `, ['TaskForge Administrator', adminEmail, passwordHash]);

  console.log('Database tables ready.');
}

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'ok',
      platform: 'TaskForge AI',
      database: 'connected',
      aiConfigured: Boolean(openai)
    });
  } catch {
    res.status(503).json({ status: 'error', database: 'disconnected' });
  }
});

app.get('/', (req, res) => {
  res.send(page('Home', `
    <section class="card">
      <h1>TaskForge AI</h1>
      <p>Complete data tasks, transcription exercises and AI evaluation work.</p>
      <p>Register an account to view available tasks.</p>
      <a class="btn" href="/register">Create account</a>
      <a class="btn" href="/login">Login</a>
    </section>
    <section class="card">
      <h2>Task categories</h2>
      <p><span class="tag">Text</span><span class="tag">Audio</span>
      <span class="tag">Video annotation</span><span class="tag">Evaluation</span></p>
      <p class="muted">Tasks are subject to review and approval. Rewards are not guaranteed until a submission is approved.</p>
    </section>
  `, req.session.user));
});

app.get('/register', (req, res) => {
  res.send(page('Register', `
    <section class="card">
      <h1>Create worker account</h1>
      <form method="post" action="/register">
        ${csrfField(req)}
        <input name="name" placeholder="Full name" maxlength="100" required>
        <input name="email" type="email" placeholder="Email address" maxlength="254" required>
        <input name="password" type="password" placeholder="Password (at least 10 characters)" minlength="10" required>
        <button type="submit">Register</button>
      </form>
    </section>
  `));
});

app.post('/register', loginLimiter, async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!name || name.length > 100 || !email || email.length > 254 || password.length < 10) {
      return res.status(400).send(page('Register', notice('Enter a valid name, email and password of at least 10 characters.')));
    }

    const hash = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)`,
      [name, email, hash]
    );

    res.redirect('/login');
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).send(page('Register', notice('That email is already registered.')));
    }
    next(err);
  }
});

app.get('/login', (req, res) => {
  res.send(page('Login', `
    <section class="card">
      <h1>Login</h1>
      <form method="post" action="/login">
        ${csrfField(req)}
        <input name="email" type="email" placeholder="Email address" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit">Login</button>
      </form>
    </section>
  `));
});

app.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const result = await pool.query(
      'SELECT id, name, email, password_hash, role FROM users WHERE email = $1',
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).send(page('Login', notice('Invalid email or password.')));
    }

    req.session.regenerate(err => {
      if (err) return next(err);

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      };

      req.session.csrf = crypto.randomBytes(32).toString('hex');
      res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
    });
  } catch (err) {
    next(err);
  }
});

app.get('/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.redirect('/');
  });
});

app.get('/dashboard', requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT id, title, description, task_type, reward
      FROM tasks
      WHERE status = 'published'
      ORDER BY created_at DESC
      LIMIT 100
    `);

    const cards = result.rows.map(t => `
      <section class="card">
        <h3>${escapeHtml(t.title)}</h3>
        <p>${escapeHtml(t.description)}</p>
        <p>Type: ${escapeHtml(t.task_type)} | Reward: $${Number(t.reward).toFixed(2)}</p>
        <a class="btn" href="/tasks/${t.id}">Open task</a>
      </section>
    `).join('');

    res.send(page('Worker dashboard', `
      <h1>Welcome, ${escapeHtml(req.session.user.name)}</h1>
      <section class="card">
        <h2>Available tasks</h2>
        ${cards || '<p>No published tasks are available right now.</p>'}
      </section>
      <section class="card">
        <h2>Screening</h2>
        <p>Complete the screening form before working on platform tasks.</p>
        <a class="btn" href="/screening">Open screening</a>
      </section>
      <section class="card">
        <h2>PayPal payout details</h2>
        <form method="post" action="/paypal-email">
          ${csrfField(req)}
          <input type="email" name="paypal_email" placeholder="Your PayPal email" maxlength="254" required>
          <button type="submit">Save PayPal email</button>
        </form>
      </section>
    `, req.session.user));
  } catch (err) {
    next(err);
  }
});

app.get('/tasks/:id', requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT * FROM tasks WHERE id = $1 AND status = 'published'`,
      [req.params.id]
    );

    const task = result.rows[0];
    if (!task) return res.status(404).send(page('Task', notice('Task not found.'), req.session.user));

    const media = task.media_url
      ? `<p><a href="${escapeHtml(task.media_url)}" target="_blank" rel="noopener">Open task media</a></p>`
      : '';

    res.send(page('Task', `
      <section class="card">
        <h1>${escapeHtml(task.title)}</h1>
        <p>${escapeHtml(task.description)}</p>
        ${media}
        <p>Type: ${escapeHtml(task.task_type)} | Reward: $${Number(task.reward).toFixed(2)}</p>
        <form method="post" action="/tasks/${task.id}/submit">
          ${csrfField(req)}
          <textarea name="answer" rows="7" maxlength="20000" placeholder="Your answer" required></textarea>
          <button type="submit">Submit for review</button>
        </form>
      </section>
    `, req.session.user));
  } catch (err) {
    next(err);
  }
});

app.post('/tasks/:id/submit', requireLogin, async (req, res, next) => {
  try {
    const answer = String(req.body.answer || '').trim();
    if (!answer || answer.length > 20000) {
      return res.status(400).send(page('Submit', notice('Please enter an answer under 20,000 characters.'), req.session.user));
    }

    const result = await pool.query(
      `SELECT id FROM tasks WHERE id = $1 AND status = 'published'`,
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).send(page('Submit', notice('Task is not available.'), req.session.user));
    }

    await pool.query(`
      INSERT INTO submissions (task_id, user_id, answer)
      VALUES ($1, $2, $3)
      ON CONFLICT (task_id, user_id) DO UPDATE
      SET answer = EXCLUDED.answer, status = 'pending',
          reviewer_note = NULL, created_at = NOW(), reviewed_at = NULL
    `, [req.params.id, req.session.user.id, answer]);

    res.redirect('/dashboard');
  } catch (err) {
    next(err);
  }
});

app.get('/screening', requireLogin, (req, res) => {
  res.send(page('Screening', `
    <section class="card">
      <h1>Worker screening</h1>
      <p>Answer these sample questions. An administrator must review your screening before access is approved.</p>
      <form method="post" action="/screening">
        ${csrfField(req)}
        <label>1. Explain why you should follow task instructions.</label>
        <textarea name="q1" maxlength="3000" required></textarea>
        <label>2. What would you do if a recording is unclear?</label>
        <textarea name="q2" maxlength="3000" required></textarea>
        <label>3. How do you protect private information?</label>
        <textarea name="q3" maxlength="3000" required></textarea>
        <button type="submit">Submit screening</button>
      </form>
    </section>
  `, req.session.user));
});

app.post('/screening', requireLogin, async (req, res, next) => {
  try {
    const answers = {
      q1: String(req.body.q1 || '').slice(0, 3000),
      q2: String(req.body.q2 || '').slice(0, 3000),
      q3: String(req.body.q3 || '').slice(0, 3000)
    };

    if (!answers.q1.trim() || !answers.q2.trim() || !answers.q3.trim()) {
      return res.status(400).send(page('Screening', notice('Answer all screening questions.'), req.session.user));
    }

    await pool.query(`
      INSERT INTO screenings (user_id, answers)
      VALUES ($1, $2)
    `, [req.session.user.id, JSON.stringify(answers)]);

    res.send(page('Screening submitted', notice('Your screening is awaiting administrator review.'), req.session.user));
  } catch (err) {
    next(err);
  }
});

app.post('/paypal-email', requireLogin, async (req, res, next) => {
  try {
    const email = String(req.body.paypal_email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 254) {
      return res.status(400).send(page('PayPal', notice('Enter a valid PayPal email.'), req.session.user));
    }

    await pool.query('UPDATE users SET paypal_email = $1 WHERE id = $2', [
      email,
      req.session.user.id
    ]);

    res.redirect('/dashboard');
  } catch (err) {
    next(err);
  }
});

app.get('/admin', requireAdmin, async (req, res, next) => {
  try {
    const [users, tasks, queue, submissions, screenings, payouts] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS n FROM users WHERE role = $1', ['worker']),
      pool.query('SELECT COUNT(*)::int AS n FROM tasks'),
      pool.query('SELECT COUNT(*)::int AS n FROM ai_task_queue WHERE status = $1', ['draft']),
      pool.query('SELECT COUNT(*)::int AS n FROM submissions WHERE status = $1', ['pending']),
      pool.query('SELECT COUNT(*)::int AS n FROM screenings WHERE status = $1', ['pending']),
      pool.query('SELECT COUNT(*)::int AS n FROM payouts WHERE status = $1', ['pending'])
    ]);

    res.send(page('Admin', `
      <h1>Admin dashboard</h1>
      <section class="card">
        <p>Workers: ${users.rows[0].n}</p>
        <p>Tasks: ${tasks.rows[0].n}</p>
        <p>AI drafts waiting to publish: ${queue.rows[0].n}</p>
        <p>Pending submissions: ${submissions.rows[0].n}</p>
        <p>Pending screenings: ${screenings.rows[0].n}</p>
        <p>Pending payouts: ${payouts.rows[0].n}</p>
      </section>

      <section class="card">
        <h2>Generate AI task queue</h2>
        <p>Creates a small batch of drafts for review. Generation may incur API charges.</p>
        <form method="post" action="/admin/generate">
          ${csrfField(req)}
          <label>Number of tasks (1–10)</label>
          <input type="number" name="count" min="1" max="10" value="3" required>
          <label>Task category</label>
          <select name="task_type">
            <option value="text">Text</option>
            <option value="evaluation">Evaluation</option>
            <option value="audio">Audio instructions</option>
            <option value="video">Video annotation instructions</option>
          </select>
          <label>Reward per task in USD</label>
          <input type="number" name="reward" min="0.10" max="50" step="0.10" value="1.00" required>
          <button type="submit">Generate draft queue</button>
        </form>
      </section>

      <section class="card">
        <h2>Review AI drafts</h2>
        <a class="btn" href="/admin/queue">Open AI queue</a>
      </section>

      <section class="card">
        <h2>Review submissions and screening</h2>
        <a class="btn" href="/admin/reviews">Open reviews</a>
      </section>

      <section class="card">
        <h2>Payouts</h2>
        <a class="btn" href="/admin/payouts">Manage payouts</a>
      </section>

      <section class="card">
        <h2>Create a task manually</h2>
        <form method="post" action="/admin/tasks">
          ${csrfField(req)}
          <input name="title" placeholder="Task title" maxlength="200" required>
          <textarea name="description" placeholder="Instructions" maxlength="10000" required></textarea>
          <select name="task_type">
            <option value="text">Text</option>
            <option value="evaluation">Evaluation</option>
            <option value="audio">Audio</option>
            <option value="video">Video annotation</option>
          </select>
          <input name="reward" type="number" min="0" max="50" step="0.01" value="1.00" required>
          <input name="media_url" type="url" placeholder="Optional public media URL">
          <button type="submit">Save as draft</button>
        </form>
      </section>
    `, req.session.user));
  } catch (err) {
    next(err);
  }
});

app.post('/admin/generate', requireAdmin, async (req, res, next) => {
  try {
    if (!openai) {
      return res.status(503).send(page('AI queue', notice('OpenAI is not configured. Add OPENAI_API_KEY in Render.'), req.session.user));
    }

    const count = Math.max(1, Math.min(10, Number.parseInt(req.body.count, 10) || 3));
    const type = String(req.body.task_type || 'text');
    const allowed = ['text', 'evaluation', 'audio', 'video'];

    if (!allowed.includes(type)) {
      return res.status(400).send(page('AI queue', notice('Invalid task category.'), req.session.user));
    }

    const reward = Number(req.body.reward);
    if (!Number.isFinite(reward) || reward < 0.10 || reward > 50) {
      return res.status(400).send(page('AI queue', notice('Reward must be between $0.10 and $50.'), req.session.user));
    }

    const response = await openai.responses.create({
      model: process.env.OPENAI_MODEL || 'gpt-5.5',
      instructions: [
        'You create clear, fair and original tasks for an AI data work platform.',
        'Return only valid JSON.',
        'Do not create tasks requiring private data, real customer information, dangerous acts, or copyrighted source material.',
        'For audio or video categories, create task instructions and a suggested asset prompt only. Do not claim an audio/video file has been generated.',
        'Each task must have title, description, task_type, and payload.',
        'payload must be a JSON object with task-specific instructions, expected answer format, and a short quality checklist.'
      ].join(' '),
      input: `Create exactly ${count} distinct ${type} tasks. Return JSON as {"tasks":[{"title":"...","description":"...","task_type":"${type}","payload":{"instructions":"...","answer_format":"...","quality_checklist":["..."]}}]}. Keep instructions practical and self-contained.`
    });

    let parsed;
    try {
      parsed = JSON.parse(response.output_text);
    } catch {
      throw new Error('The AI response was not valid JSON. Please retry with a smaller batch.');
    }

    if (!parsed || !Array.isArray(parsed.tasks) || parsed.tasks.length === 0) {
      throw new Error('The AI did not return any tasks. Please try again.');
    }

    const created = [];
    for (const item of parsed.tasks.slice(0, count)) {
      const title = String(item.title || '').trim().slice(0, 200);
      const description = String(item.description || '').trim().slice(0, 10000);
      if (!title || !description) continue;

      const taskType = allowed.includes(item.task_type) ? item.task_type : type;
      const payload = item.payload && typeof item.payload === 'object' ? item.payload : {};

      const result = await pool.query(`
        INSERT INTO ai_task_queue (task_type, payload, status)
        VALUES ($1, $2, 'draft')
        RETURNING id
      `, [
        taskType,
        JSON.stringify({
          title,
          description,
          reward,
          media_url: null,
          task_payload: payload
        })
      ]);

      created.push(result.rows[0].id);
    }

    if (!created.length) {
      throw new Error('No valid tasks were created. Please retry.');
    }

    res.send(page('AI queue created', `
      <section class="card">
        <h1>AI draft queue created</h1>
        <p>${created.length} draft task(s) saved. They are not visible to workers until you publish them.</p>
        <a class="btn" href="/admin/queue">Review drafts</a>
        <p class="muted">Audio/video tasks currently contain task instructions only; they do not automatically contain generated media.</p>
      </section>
    `, req.session.user));
  } catch (err) {
    console.error('AI task generation failed:', err.message);
    next(err);
  }
});

app.get('/admin/queue', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT id, task_type, payload, created_at
      FROM ai_task_queue
      WHERE status = 'draft'
      ORDER BY created_at DESC
      LIMIT 100
    `);

    const cards = result.rows.map(row => {
      const payload = row.payload || {};
      return `
        <section class="card">
          <h3>${escapeHtml(payload.title || 'Untitled task')}</h3>
          <p>${escapeHtml(payload.description || '')}</p>
          <p>Type: ${escapeHtml(row.task_type)} | Reward: $${Number(payload.reward || 0).toFixed(2)}</p>
          <form method="post" action="/admin/queue/${row.id}/publish">
            ${csrfField(req)}
            <button type="submit">Publish task</button>
          </form>
          <form method="post" action="/admin/queue/${row.id}/delete">
            ${csrfField(req)}
            <button type="submit" style="background:#b91c1c">Delete draft</button>
          </form>
        </section>`;
    }).join('');

    res.send(page('AI queue', `
      <h1>AI-generated draft queue</h1>
      ${cards || '<section class="card">No drafts waiting for review.</section>'}
      <a class="btn" href="/admin">Back to admin</a>
    `, req.session.user));
  } catch (err) {
    next(err);
  }
});

app.post('/admin/queue/:id/publish', requireAdmin, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const result = await client.query(
      `SELECT * FROM ai_task_queue WHERE id = $1 AND status = 'draft' FOR UPDATE`,
      [req.params.id]
    );

    const row = result.rows[0];
    if (!row) {
      await client.query('ROLLBACK');
      return res.status(404).send(page('Publish', notice('Draft not found.'), req.session.user));
    }

    const p = row.payload || {};
    if (!p.title || !p.description) {
      await client.query('ROLLBACK');
      return res.status(400).send(page('Publish', notice('Draft is missing a title or description.'), req.session.user));
    }

    await client.query(`
      INSERT INTO tasks (title, description, task_type, reward, media_url, payload, status)
      VALUES ($1, $2, $3, $4, $5, $6, 'published')
    `, [
      p.title,
      p.description,
      row.task_type,
      Math.min(50, Math.max(0, Number(p.reward) || 0)),
      p.media_url || null,
      JSON.stringify(p.task_payload || {})
    ]);

    await client.query(
      `UPDATE ai_task_queue SET status = 'published' WHERE id = $1`,
      [row.id]
    );

    await client.query('COMMIT');
    res.redirect('/admin/queue');
  } catch (err) {
    await client.query('ROLLBACK');
    next(err);
  } finally {
    client.release();
  }
});

app.post('/admin/queue/:id/delete', requireAdmin, async (req, res, next) => {
  try {
    await pool.query(
      `DELETE FROM ai_task_queue WHERE id = $1 AND status = 'draft'`,
      [req.params.id]
    );
    res.redirect('/admin/queue');
  } catch (err) {
    next(err);
  }
});

app.post('/admin/tasks', requireAdmin, async (req, res, next) => {
  try {
    const title = String(req.body.title || '').trim().slice(0, 200);
    const description = String(req.body.description || '').trim().slice(0, 10000);
    const type = String(req.body.task_type || 'text');
    const reward = Number(req.body.reward);
    const mediaUrl = String(req.body.media_url || '').trim();

    if (!title || !description || !['text', 'evaluation', 'audio', 'video'].includes(type)) {
      return res.status(400).send(page('Create task', notice('Check the title, instructions and category.'), req.session.user));
    }

    if (!Number.isFinite(reward) || reward < 0 || reward > 50) {
      return res.status(400).send(page('Create task', notice('Reward must be between $0 and $50.'), req.session.user));
    }

    if (mediaUrl) {
      const u = new URL(mediaUrl);
      if (u.protocol !== 'https:') {
        return res.status(400).send(page('Create task', notice('Media links must use HTTPS.'), req.session.user));
      }
    }

    await pool.query(`
      INSERT INTO tasks (title, description, task_type, reward, media_url, status)
      VALUES ($1, $2, $3, $4, $5, 'draft')
    `, [title, description, type, reward, mediaUrl || null]);

    res.redirect('/admin');
  } catch (err) {
    next(err);
  }
});

app.get('/admin/reviews', requireAdmin, async (req, res, next) => {
  try {
    const [submissions, screenings] = await Promise.all([
      pool.query(`
        SELECT s.id, s.answer, s.created_at, u.name, t.title
        FROM submissions s
        JOIN users u ON u.id = s.user_id
        JOIN tasks t ON t.id = s.task_id
        WHERE s.status = 'pending'
        ORDER BY s.created_at ASC LIMIT 100
      `),
      pool.query(`
        SELECT s.id, s.answers, s.created_at, u.name, u.email
        FROM screenings s
        JOIN users u ON u.id = s.user_id
        WHERE s.status = 'pending'
        ORDER BY s.created_at ASC LIMIT 100
      `)
    ]);

    const submissionCards = submissions.rows.map(s => `
      <section class="card">
        <h3>${escapeHtml(s.title)}</h3>
        <p>Worker: ${escapeHtml(s.name)}</p>
        <pre>${escapeHtml(s.answer)}</pre>
        <form method="post" action="/admin/submissions/${s.id}/review">
          ${csrfField(req)}
          <textarea name="note" maxlength="2000" placeholder="Review note (optional)"></textarea>
          <button name="decision" value="approved">Approve</button>
          <button name="decision" value="rejected" style="background:#b91c1c">Reject</button>
        </form>
      </section>
    `).join('');

    const screeningCards = screenings.rows.map(s => `
      <section class="card">
        <h3>Screening: ${escapeHtml(s.name)}</h3>
        <p>${escapeHtml(s.email)}</p>
        <pre>${escapeHtml(JSON.stringify(s.answers, null, 2))}</pre>
        <form method="post" action="/admin/screenings/${s.id}/review">
          ${csrfField(req)}
          <button name="decision" value="approved">Approve screening</button>
          <button name="decision" value="rejected" style="background:#b91c1c">Reject screening</button>
        </form>
      </section>
    `).join('');

    res.send(page('Reviews', `
      <h1>Pending screening reviews</h1>
      ${screeningCards || '<section class="card">No pending screenings.</section>'}
      <h1>Pending task submissions</h1>
      ${submissionCards || '<section class="card">No pending submissions.</section>'}
    `, req.session.user));
  } catch (err) {
    next(err);
  }
});

app.post('/admin/submissions/:id/review', requireAdmin, async (req, res, next) => {
  try {
    const decision = String(req.body.decision || '');
    if (!['approved', 'rejected'].includes(decision)) {
      return res.status(400).send(page('Review', notice('Invalid review decision.'), req.session.user));
    }

    await pool.query(`
      UPDATE submissions SET status = $1, reviewer_note = $2, reviewed_at = NOW()
      WHERE id = $3 AND status = 'pending'
    `, [decision, String(req.body.note || '').slice(0, 2000), req.params.id]);

    res.redirect('/admin/reviews');
  } catch (err) {
    next(err);
  }
});

app.post('/admin/screenings/:id/review', requireAdmin, async (req, res, next) => {
  try {
    const decision = String(req.body.decision || '');
    if (!['approved', 'rejected'].includes(decision)) {
      return res.status(400).send(page('Screening review', notice('Invalid decision.'), req.session.user));
    }

    await pool.query(`
      UPDATE screenings SET status = $1, reviewed_at = NOW()
      WHERE id = $2 AND status = 'pending'
    `, [decision, req.params.id]);

    res.redirect('/admin/reviews');
  } catch (err) {
    next(err);
  }
});

app.get('/admin/payouts', requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT p.id, p.amount, p.paypal_email, p.status,
             p.transaction_id, p.created_at, u.name
      FROM payouts p JOIN users u ON u.id = p.user_id
      ORDER BY p.created_at DESC LIMIT 100
    `);

    const cards = result.rows.map(p => `
      <section class="card">
        <h3>${escapeHtml(p.name)}</h3>
        <p>Amount: $${Number(p.amount).toFixed(2)}</p>
        <p>PayPal: ${escapeHtml(p.paypal_email)}</p>
        <p>Status: ${escapeHtml(p.status)}</p>
        <form method="post" action="/admin/payouts/${p.id}">
          ${csrfField(req)}
          <input name="transaction_id" placeholder="PayPal transaction ID" maxlength="200">
          <button name="decision" value="paid">Mark paid</button>
          <button name="decision" value="rejected" style="background:#b91c1c">Reject payout</button>
        </form>
      </section>
    `).join('');

    res.send(page('Payouts', `
      <h1>Manual PayPal payouts</h1>
      <p>Send payments yourself through PayPal, then record the transaction here.</p>
      ${cards || '<section class="card">No payout requests.</section>'}
    `, req.session.user));
  } catch (err) {
    next(err);
  }
});

app.post('/admin/payouts/:id', requireAdmin, async (req, res, next) => {
  try {
    const decision = String(req.body.decision || '');
    if (!['paid', 'rejected'].includes(decision)) {
      return res.status(400).send(page('Payout', notice('Invalid payout status.'), req.session.user));
    }

    const txId = String(req.body.transaction_id || '').trim().slice(0, 200);

    if (decision === 'paid' && !txId) {
      return res.status(400).send(page('Payout', notice('Enter the PayPal transaction ID before marking paid.'), req.session.user));
    }

    await pool.query(`
      UPDATE payouts SET status = $1, transaction_id = $2
      WHERE id = $3 AND status = 'pending'
    `, [decision, txId || null, req.params.id]);

    res.redirect('/admin/payouts');
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error('Request failed:', err.message);
  if (res.headersSent) return next(err);

  res.status(500).send(page(
    'Server error',
    notice('Something went wrong. Check Render logs for details. Do not share passwords or API keys.'),
    req.session.user
  ));
});

async function start() {
  try {
    await pool.query('SELECT 1');
    await initDatabase();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`TaskForge AI listening on port ${PORT}`);
      console.log(`OpenAI configured: ${Boolean(openai)}`);
    });
  } catch (err) {
    console.error('Startup failed:', err.message);
    process.exit(1);
  }
}

start();
