
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  throw new Error("DATABASE_URL and SESSION_SECRET are required.");
}

if (
  !process.env.ADMIN_EMAIL ||
  !process.env.ADMIN_PASSWORD
) {
  throw new Error("ADMIN_EMAIL and ADMIN_PASSWORD are required.");
}

if (
  !process.env.CLOUDINARY_CLOUD_NAME ||
  !process.env.CLOUDINARY_API_KEY ||
  !process.env.CLOUDINARY_API_SECRET
) {
  throw new Error("Cloudinary environment variables are required.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: "30kb" }));
app.use(express.json({ limit: "30kb" }));

app.use(session({
  name: "taskforge.sid",
  store: new PgSession({
    pool,
    createTableIfMissing: true,
    tableName: "session"
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 1
  },
  fileFilter: (req, file, callback) => {
    const allowed = [
      "video/mp4",
      "video/webm",
      "video/quicktime",
      "audio/mpeg",
      "audio/mp3",
      "audio/wav",
      "audio/x-wav",
      "audio/mp4",
      "audio/ogg",
      "audio/webm",
      "audio/aac",
      "audio/flac"
    ];

    if (!allowed.includes(file.mimetype)) {
      return callback(
        new Error("Use a supported MP4/WebM/MOV video or audio file.")
      );
    }

    callback(null, true);
  }
});

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function page(title, content, user = null) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#101827">
<title>${escapeHtml(title)} | TaskForge AI</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1120;color:#edf2ff;
font:16px system-ui,-apple-system,sans-serif}
header{padding:18px 5%;background:#121d31;
display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
header a,.links a{color:#9fc3ff;text-decoration:none}
main{max-width:1000px;margin:30px auto;padding:0 16px 40px}
.card{background:#131f33;border:1px solid #293952;border-radius:16px;
padding:22px;margin-bottom:18px}
h1,h2{line-height:1.25}
p{line-height:1.6;color:#c4cfe1}
label{display:block;margin:15px 0 7px;font-weight:600}
input,textarea,select{width:100%;padding:13px;border-radius:9px;
border:1px solid #3a4b65;background:#0b1425;color:#fff;font:inherit}
textarea{min-height:115px;resize:vertical}
button,.button{display:inline-block;background:#3478f6;color:white;
border:0;border-radius:9px;padding:13px 18px;font:inherit;
font-weight:700;text-decoration:none;cursor:pointer;margin-top:14px}
.secondary{background:#253650}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}
.muted{color:#a8b7cd;font-size:14px}
.status{display:inline-block;background:#253650;border-radius:30px;
padding:5px 10px;font-size:13px}
video,audio{width:100%;margin-top:12px}
hr{border:0;border-top:1px solid #293952;margin:20px 0}
</style>
</head>
<body>
<header>
<a href="/"><strong>TaskForge AI</strong></a>
<nav class="links">
<a href="/">Home</a>
${user ? ` &nbsp; <a href="/dashboard">Dashboard</a>
&nbsp; <a href="/admin">Admin</a>` : ""}
</nav>
</header>
<main>${content}</main>
</body>
</html>`;
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send(page(
      "Access denied",
      '<section class="card"><h1>Admin access required</h1>' +
      '<p>Please sign in using your authorized administrator account.</p>' +
      '<a class="button" href="/login">Sign in</a></section>'
    ));
  }
  next();
}

function csrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrfToken;
}

function csrfField(req) {
  return `<input type="hidden" name="_csrf" value="${csrfToken(req)}">`;
}

function requireCsrf(req, res, next) {
  const submitted = req.body && req.body._csrf;
  const stored = req.session.csrfToken;

  if (
    typeof submitted !== "string" ||
    typeof stored !== "string" ||
    !crypto.timingSafeEqual(
      Buffer.from(submitted),
      Buffer.from(stored)
    )
  ) {
    return res.status(403).send(page(
      "Session expired",
      '<section class="card"><h1>Form expired</h1>' +
      '<p>Reload the page and try again.</p>' +
      '<a class="button" href="/login">Continue</a></section>'
    ));
  }
  next();
}

function uploadToCloudinary(file) {
  const isVideo = file.mimetype.startsWith("video/");
  const resourceType = isVideo ? "video" : "video";

  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream({
      resource_type: resourceType,
      folder: "taskforge-ai/tasks",
      use_filename: false
    }, (error, result) => {
      if (error) return reject(error);
      resolve(result);
    });

    stream.end(file.buffer);
  });
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "ok",
      platform: "TaskForge AI",
      database: "connected"
    });
  } catch (error) {
    console.error("Health check failed:", error.message);
    res.status(503).json({ status: "error" });
  }
});

app.get("/", (req, res) => {
  res.send(page("Home", `
    <section class="card">
      <span class="status">AI training platform</span>
      <h1>Turn your skills into meaningful work.</h1>
      <p>Complete screening, work on video annotation and transcription
      tasks, and submit quality work for review.</p>
      <a class="button" href="/register">Create worker account</a>
      <a class="button secondary" href="/login">Sign in</a>
    </section>
    <section class="grid">
      <div class="card"><h2>Video annotation</h2>
      <p>Describe actions, movements and events in video clips.</p></div>
      <div class="card"><h2>Audio transcription</h2>
      <p>Transcribe speech from supplied recordings.</p></div>
      <div class="card"><h2>Quality review</h2>
      <p>Submissions require review before rewards are approved.</p></div>
    </section>
  `, req.session.user));
});

app.get("/register", (req, res) => {
  res.send(page("Register", `
    <section class="card">
      <h1>Create your worker account</h1>
      <form method="post" action="/register">
        ${csrfField(req)}
        <label>Full name</label>
        <input name="name" maxlength="120" required autocomplete="name">
        <label>Email</label>
        <input type="email" name="email" maxlength="255" required autocomplete="email">
        <label>Password (at least 10 characters)</label>
        <input type="password" name="password" minlength="10" required autocomplete="new-password">
        <label>PayPal email for future payout requests</label>
        <input type="email" name="paypal_email" maxlength="255" autocomplete="email">
        <button type="submit">Create account</button>
      </form>
      <p><a href="/login">Already registered? Sign in</a></p>
    </section>
  `));
});

app.post("/register", loginLimiter, requireCsrf, async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const paypalEmail = String(req.body.paypal_email || "").trim().toLowerCase();

    if (
      name.length < 2 ||
      name.length > 120 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 10 ||
      password.length > 200 ||
      (paypalEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(paypalEmail))
    ) {
      return res.status(400).send(page(
        "Check your details",
        '<section class="card"><h1>Check your details</h1>' +
        '<p>Enter a valid name and email, and a password of at least 10 characters.</p>' +
        '<a class="button" href="/register">Try again</a></section>'
      ));
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users (name,email,password_hash,paypal_email)
       VALUES ($1,$2,$3,$4)`,
      [name, email, passwordHash, paypalEmail || null]
    );

    res.redirect("/login?registered=1");
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).send(page(
        "Account exists",
        '<section class="card"><h1>Email already registered</h1>' +
        '<a class="button" href="/login">Sign in</a></section>'
      ));
    }
    next(error);
  }
});

app.get("/login", (req, res) => {
  const notice = req.query.registered
    ? "<p>Your account was created. Please sign in.</p>"
    : "";

  res.send(page("Sign in", `
    <section class="card">
      <h1>Welcome back</h1>
      ${notice}
      <form method="post" action="/login">
        ${csrfField(req)}
        <label>Email</label>
        <input type="email" name="email" required autocomplete="username">
        <label>Password</label>
        <input type="password" name="password" required autocomplete="current-password">
        <button type="submit">Sign in</button>
      </form>
      <p><a href="/register">Create a worker account</a></p>
    </section>
  `));
});

app.post("/login", loginLimiter, requireCsrf, async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    let user = null;

    const adminEmail = process.env.ADMIN_EMAIL.trim().toLowerCase();

    if (
      email === adminEmail &&
      password.length <= 200 &&
      password === process.env.ADMIN_PASSWORD
    ) {
      user = {
        id: "admin",
        name: "Administrator",
        email: adminEmail,
        role: "admin"
      };
    } else {
      const result = await pool.query(
        `SELECT id, name, email, password_hash, role
         FROM users WHERE email = $1`,
        [email]
      );

      if (
        result.rows.length &&
        result.rows[0].role === "worker" &&
        await bcrypt.compare(password, result.rows[0].password_hash)
      ) {
        user = result.rows[0];
      }
    }

    if (!user) {
      return res.status(401).send(page(
        "Sign-in failed",
        '<section class="card"><h1>Unable to sign in</h1>' +
        '<p>Check your credentials and try again.</p>' +
        '<a class="button" href="/login">Try again</a></section>'
      ));
    }

    req.session.regenerate(error => {
      if (error) return next(error);

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      };

      req.session.csrfToken = crypto.randomBytes(32).toString("hex");

      req.session.save(error => {
        if (error) return next(error);
        res.redirect(user.role === "admin" ? "/admin" : "/dashboard");
      });
    });
  } catch (error) {
    next(error);
  }
});

app.get("/dashboard", requireLogin, async (req, res, next) => {
  try {
    const userId = req.session.user.id;

    const screening = await pool.query(
      `SELECT status FROM screenings
       WHERE user_id = $1 ORDER BY submitted_at DESC LIMIT 1`,
      [userId]
    );

    const screeningStatus = screening.rows[0]
      ? escapeHtml(screening.rows[0].status)
      : "not started";

    const tasks = await pool.query(
      `SELECT t.id, t.title, t.description, t.task_type,
              t.media_url, t.media_type, t.reward_usd
       FROM tasks t
       WHERE t.published = TRUE
       AND NOT EXISTS (
         SELECT 1 FROM submissions s
         WHERE s.task_id = t.id AND s.user_id = $1
       )
       ORDER BY t.created_at DESC LIMIT 50`,
      [userId]
    );

    const taskCards = tasks.rows.map(task => `
      <article class="card">
        <span class="status">${escapeHtml(task.task_type)}</span>
        <h2>${escapeHtml(task.title)}</h2>
        <p>${escapeHtml(task.description)}</p>
        <p><strong>$${Number(task.reward_usd).toFixed(2)} USD</strong></p>
        ${task.media_url ? `
          ${task.media_type === "video"
            ? `<video controls preload="metadata" src="${escapeHtml(task.media_url)}"></video>`
            : `<audio controls preload="metadata" src="${escapeHtml(task.media_url)}"></audio>`}
        ` : ""}
        <p class="muted">Task completion and submission forms are still being developed.</p>
      </article>
    `).join("");

    res.send(page("Worker dashboard", `
      <section class="card">
        <h1>Hello, ${escapeHtml(req.session.user.name)}</h1>
        <p>Screening status: <strong>${screeningStatus}</strong></p>
        <p class="muted">Only tasks shown below have been published by an administrator.
        Worker submission is not yet enabled.</p>
      </section>
      <h2>Available tasks</h2>
      ${taskCards || '<section class="card"><p>No published tasks yet.</p></section>'}
      <form method="post" action="/logout">
        ${csrfField(req)}
        <button class="secondary" type="submit">Sign out</button>
      </form>
    `, req.session.user));
  } catch (error) {
    next(error);
  }
});

app.get("/admin", requireAdmin, async (req, res, next) => {
  try {
    const counts = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users WHERE role = 'worker') AS workers,
        (SELECT COUNT(*) FROM tasks) AS tasks,
        (SELECT COUNT(*) FROM tasks WHERE published = TRUE) AS published,
        (SELECT COUNT(*) FROM submissions WHERE status = 'pending') AS pending_submissions,
        (SELECT COUNT(*) FROM screenings WHERE status = 'pending') AS pending_screenings,
        (SELECT COUNT(*) FROM payouts WHERE status = 'pending') AS pending_payouts
    `);

    const c = counts.rows[0];

    const taskResult = await pool.query(
      `SELECT id, title, task_type, reward_usd, published, media_url, media_type
       FROM tasks ORDER BY created_at DESC LIMIT 100`
    );

    const taskList = taskResult.rows.map(task => `
      <article class="card">
        <h3>${escapeHtml(task.title)}</h3>
        <p>${escapeHtml(task.task_type)} · $${Number(task.reward_usd).toFixed(2)} USD</p>
        <p><span class="status">${task.published ? "Published" : "Draft"}</span></p>
        ${task.media_url ? `<a href="${escapeHtml(task.media_url)}" target="_blank" rel="noopener noreferrer">Open media</a>` : ""}
        <form method="post" action="/admin/tasks/${Number(task.id)}/publish">
          ${csrfField(req)}
          <input type="hidden" name="published" value="${task.published ? "false" : "true"}">
          <button class="${task.published ? "secondary" : ""}" type="submit">
            ${task.published ? "Unpublish" : "Publish task"}
          </button>
        </form>
      </article>
    `).join("");

    res.send(page("Admin", `
      <section class="card">
        <h1>Admin dashboard</h1>
        <p>Manage tasks and publish media-based work for workers.</p>
        <div class="grid">
          <div><h2>${c.workers}</h2><p>Workers</p></div>
          <div><h2>${c.tasks}</h2><p>Total tasks</p></div>
          <div><h2>${c.published}</h2><p>Published tasks</p></div>
          <div><h2>${c.pending_screenings}</h2><p>Pending screenings</p></div>
          <div><h2>${c.pending_submissions}</h2><p>Pending submissions</p></div>
          <div><h2>${c.pending_payouts}</h2><p>Pending payouts</p></div>
        </div>
      </section>

      <section class="card">
        <h2>Create a task</h2>
        <p>Upload one video or audio file up to 50 MB. Larger video uploads
        need a separate chunked-upload implementation.</p>
        <form method="post" action="/admin/tasks" enctype="multipart/form-data">
          ${csrfField(req)}
          <label>Task title</label>
          <input name="title" maxlength="200" required>

          <label>Instructions for workers</label>
          <textarea name="description" maxlength="10000" required
          placeholder="Describe exactly what the worker must do."></textarea>

          <label>Task type</label>
          <select name="task_type" required>
            <option value="video_annotation">Video annotation</option>
            <option value="audio_transcription">Audio transcription</option>
            <option value="movement_description">Movement description</option>
            <option value="meeting_transcription">Meeting transcription</option>
            <option value="content_evaluation">Content evaluation</option>
          </select>

          <label>Reward (USD)</label>
          <input name="reward_usd" type="number" min="0.01"
          max="1000" step="0.01" value="1.00" required>

          <label>Video or audio file</label>
          <input name="media" type="file"
          accept="video/mp4,video/webm,video/quicktime,audio/mpeg,audio/mp3,audio/wav,audio/x-wav,audio/mp4,audio/ogg,audio/webm,audio/aac,audio/flac" required>

          <label>
            <input style="width:auto" type="checkbox" name="publish_now" value="yes">
            Publish immediately after upload
          </label>

          <button type="submit">Upload and create task</button>
        </form>
      </section>

      <h2>Existing tasks</h2>
      ${taskList || '<section class="card"><p>No tasks created yet.</p></section>'}

      <form method="post" action="/logout">
        ${csrfField(req)}
        <button class="secondary" type="submit">Sign out</button>
      </form>
    `, req.session.user));
  } catch (error) {
    next(error);
  }
});

app.post(
  "/admin/tasks",
  requireAdmin,
  (req, res, next) => {
    upload.single("media")(req, res, error => {
      if (error) {
        return res.status(400).send(page(
          "Upload error",
          `<section class="card"><h1>Upload error</h1>
          <p>${escapeHtml(error.message)}</p>
          <a class="button" href="/admin">Return to admin</a></section>`,
          req.session.user
        ));
      }
      next();
    });
  },
  requireCsrf,
  async (req, res, next) => {
    let uploadedAsset = null;

    try {
      const title = String(req.body.title || "").trim();
      const description = String(req.body.description || "").trim();
      const taskType = String(req.body.task_type || "");
      const reward = Number(req.body.reward_usd);
      const allowedTypes = [
        "video_annotation",
        "audio_transcription",
        "movement_description",
        "meeting_transcription",
        "content_evaluation"
      ];

      if (
        title.length < 3 ||
        title.length > 200 ||
        description.length < 10 ||
        description.length > 10000 ||
        !allowedTypes.includes(taskType) ||
        !Number.isFinite(reward) ||
        reward < 0.01 ||
        reward > 1000 ||
        !req.file
      ) {
        return res.status(400).send(page(
          "Invalid task",
          '<section class="card"><h1>Check the task details</h1>' +
          '<p>Provide a valid title, detailed instructions, reward and media file.</p>' +
          '<a class="button" href="/admin">Return to admin</a></section>',
          req.session.user
        ));
      }

      const isVideo = req.file.mimetype.startsWith("video/");
      const mediaType = isVideo ? "video" : "audio";

      uploadedAsset = await uploadToCloudinary(req.file);

      const result = await pool.query(
        `INSERT INTO tasks
         (title, description, task_type, media_url, media_type,
          reward_usd, published)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         RETURNING id`,
        [
          title,
          description,
          taskType,
          uploadedAsset.secure_url,
          mediaType,
          reward.toFixed(2),
          req.body.publish_now === "yes"
        ]
      );

      res.redirect("/admin?created=" + result.rows[0].id);
    } catch (error) {
      if (uploadedAsset && uploadedAsset.public_id) {
        cloudinary.uploader.destroy(uploadedAsset.public_id, {
          resource_type: uploadedAsset.resource_type || "video"
        }).catch(() => {});
      }
      next(error);
    }
  }
);

app.post(
  "/admin/tasks/:id/publish",
  requireAdmin,
  requireCsrf,
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      const published = req.body.published === "true";

      if (!Number.isSafeInteger(id) || id <= 0) {
        return res.status(400).send("Invalid task ID.");
      }

      await pool.query(
        "UPDATE tasks SET published = $1 WHERE id = $2",
        [published, id]
      );

      res.redirect("/admin");
    } catch (error) {
      next(error);
    }
  }
);

app.post("/logout", requireLogin, requireCsrf, (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie("taskforge.sid");
    res.redirect("/");
  });
});

app.use((req, res) => {
  res.status(404).send(page(
    "Page not found",
    '<section class="card"><h1>Page not found</h1>' +
    '<a class="button" href="/">Return home</a></section>',
    req.session.user
  ));
});

app.use((error, req, res, next) => {
  console.error("Request failed:", error.message);

  if (res.headersSent) return next(error);

  res.status(500).send(page(
    "Something went wrong",
    '<section class="card"><h1>Something went wrong</h1>' +
    '<p>Please try again. If this continues, check the Render logs.</p>' +
    '<a class="button" href="/">Return home</a></section>',
    req.session.user
  ));
});

async function start() {
  const schema = `
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      paypal_email VARCHAR(255),
      role VARCHAR(20) NOT NULL DEFAULT 'worker'
        CHECK (role IN ('worker','admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS screenings (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      answers JSONB NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected')),
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      review_notes TEXT
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      description TEXT NOT NULL,
      task_type VARCHAR(40) NOT NULL,
      media_url TEXT,
      media_type VARCHAR(20),
      reward_usd NUMERIC(10,2) NOT NULL DEFAULT 0
        CHECK (reward_usd >= 0),
      published BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS submissions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      task_id BIGINT NOT NULL REFERENCES tasks(id),
      response JSONB NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected')),
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      review_notes TEXT,
      UNIQUE (user_id, task_id)
    );

    CREATE TABLE IF NOT EXISTS payouts (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      amount_usd NUMERIC(10,2) NOT NULL CHECK (amount_usd > 0),
      paypal_email VARCHAR(255) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','paid','rejected')),
      transaction_id TEXT,
      requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMPTZ,
      admin_notes TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_screenings_status
      ON screenings(status);
    CREATE INDEX IF NOT EXISTS idx_tasks_published
      ON tasks(published);
    CREATE INDEX IF NOT EXISTS idx_submissions_status
      ON submissions(status);
    CREATE INDEX IF NOT EXISTS idx_payouts_status
      ON payouts(status);
  `;

  await pool.query(schema);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`TaskForge AI listening on port ${PORT}`);
  });
}

start().catch(error => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
