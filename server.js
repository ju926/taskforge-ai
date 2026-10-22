const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  throw new Error("DATABASE_URL and SESSION_SECRET must be configured.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.set("trust proxy", 1);
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));

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
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

app.use("/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
}));

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function page(title, content) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} | TaskForge AI</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1020;color:#f5f7ff;font-family:Arial,sans-serif}
header{padding:20px;background:#151d35;border-bottom:1px solid #303a59}
header a{color:white;text-decoration:none}
main{max-width:850px;margin:auto;padding:28px 18px}
.panel{background:#151d35;padding:22px;border-radius:14px;margin:18px 0}
h1{font-size:32px}
p{color:#c4cce0;line-height:1.7}
a{color:#aaa5ff}
button,.button{display:inline-block;border:0;border-radius:8px;background:#7067ff;color:white;padding:12px 18px;text-decoration:none;cursor:pointer}
input{display:block;width:100%;padding:13px;margin:8px 0 16px;border-radius:7px;border:1px solid #465171;background:#0b1020;color:white}
footer{padding:25px;text-align:center;color:#9ba6c4}
</style>
</head>
<body>
<header><a href="/">⚡ <strong>TaskForge AI</strong></a></header>
<main>${content}</main>
<footer>TaskForge AI · AI training and annotation platform</footer>
</body>
</html>`;
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send(page(
      "Access denied",
      "<h1>Access denied</h1><p>Administrator access is required.</p>"
    ));
  }
  next();
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "ok",
      platform: "TaskForge AI",
      database: "connected"
    });
  } catch {
    res.status(503).json({
      status: "error",
      database: "unavailable"
    });
  }
});

app.get("/", (req, res) => {
  res.send(page("Welcome", `
    <section class="panel">
      <h1>Turn your skills into AI training work.</h1>
      <p>TaskForge AI is being built for video annotation,
      audio transcription, movement descriptions and AI evaluation.</p>
      <p>Workers will complete screening before task access.
      Submitted work must be reviewed before rewards are credited.</p>
      <a class="button" href="/register">Create worker account</a>
      <p><a href="/login">Sign in</a></p>
    </section>
  `));
});

app.get("/register", (req, res) => {
  res.send(page("Create account", `
    <section class="panel">
      <h1>Create your worker account</h1>
      <form method="post" action="/register">
        <label>Full name</label>
        <input name="name" maxlength="120" required>
        <label>Email</label>
        <input name="email" type="email" maxlength="255" required>
        <label>Password (at least 12 characters)</label>
        <input name="password" type="password" minlength="12" required>
        <label>PayPal email for manual payouts</label>
        <input name="paypal_email" type="email" maxlength="255" required>
        <button>Create account</button>
      </form>
    </section>
  `));
});

app.post("/register", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const paypal = String(req.body.paypal_email || "").trim().toLowerCase();

    if (
      !name || name.length > 120 ||
      !email || email.length > 255 ||
      password.length < 12 || password.length > 200 ||
      !paypal || paypal.length > 255
    ) {
      return res.status(400).send(page(
        "Check details",
        "<h1>Please check your details</h1><p>Use valid email addresses and a password of at least 12 characters.</p><a href='/register'>Try again</a>"
      ));
    }

    const hash = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users (name, email, password_hash, paypal_email)
       VALUES ($1, $2, $3, $4)`,
      [name, email, hash, paypal]
    );

    res.redirect("/login");
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).send(page(
        "Account exists",
        "<h1>Account already exists</h1><p>Try signing in instead.</p><a href='/login'>Sign in</a>"
      ));
    }
    next(error);
  }
});

app.get("/login", (req, res) => {
  res.send(page("Sign in", `
    <section class="panel">
      <h1>Sign in</h1>
      <form method="post" action="/login">
        <label>Email</label>
        <input name="email" type="email" maxlength="255" required>
        <label>Password</label>
        <input name="password" type="password" required>
        <button>Sign in</button>
      </form>
    </section>
  `));
});

app.post("/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    let user = null;

    if (
      process.env.ADMIN_EMAIL &&
      process.env.ADMIN_PASSWORD &&
      email === process.env.ADMIN_EMAIL.trim().toLowerCase() &&
      password === process.env.ADMIN_PASSWORD
    ) {
      user = {
        id: "admin",
        name: "Administrator",
        email,
        role: "admin"
      };
    } else {
      const result = await pool.query(
        "SELECT id, name, email, password_hash, role FROM users WHERE email = $1",
        [email]
      );

      const candidate = result.rows[0];

      if (
        !candidate ||
        !(await bcrypt.compare(password, candidate.password_hash))
      ) {
        return res.status(401).send(page(
          "Sign in failed",
          "<h1>Sign in failed</h1><p>Check your email and password.</p><a href='/login'>Try again</a>"
        ));
      }

      user = candidate;
    }

    req.session.regenerate(error => {
      if (error) return next(error);

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      };

      req.session.save(error => {
        if (error) return next(error);
        res.redirect(user.role === "admin" ? "/admin" : "/dashboard");
      });
    });
  } catch (error) {
    next(error);
  }
});

app.get("/dashboard", requireLogin, (req, res) => {
  if (req.session.user.role === "admin") return res.redirect("/admin");

  res.send(page("Worker dashboard", `
    <section class="panel">
      <h1>Welcome, ${escapeHtml(req.session.user.name)}</h1>
      <p>Your account is registered. Screening and task access are not yet
      enabled in this application version.</p>
      <p>Creating an account does not itself earn rewards.</p>
      <form method="post" action="/logout"><button>Sign out</button></form>
    </section>
  `));
});

app.get("/admin", requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users WHERE role = 'worker') AS workers,
        (SELECT COUNT(*) FROM tasks) AS tasks,
        (SELECT COUNT(*) FROM submissions WHERE status = 'pending') AS pending_submissions,
        (SELECT COUNT(*) FROM screenings WHERE status = 'pending') AS pending_screenings,
        (SELECT COUNT(*) FROM payouts WHERE status = 'pending') AS pending_payouts
    `);

    const stats = result.rows[0];

    res.send(page("Admin dashboard", `
      <section class="panel">
        <h1>TaskForge AI administration</h1>
        <p>Signed in as ${escapeHtml(req.session.user.email)}.</p>
        <p>Registered workers: ${stats.workers}</p>
        <p>Tasks: ${stats.tasks}</p>
        <p>Screenings awaiting review: ${stats.pending_screenings}</p>
        <p>Submissions awaiting review: ${stats.pending_submissions}</p>
        <p>Payouts awaiting processing: ${stats.pending_payouts}</p>
        <p>Management forms and media-upload workflows are still to be built.</p>
        <form method="post" action="/logout"><button>Sign out</button></form>
      </section>
    `));
  } catch (error) {
    next(error);
  }
});

app.post("/logout", (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

app.use((err, req, res, next) => {
  console.error("Application error:", err.message);
  if (res.headersSent) return next(err);

  res.status(500).send(page(
    "Server error",
    "<h1>Something went wrong</h1><p>Please try again later.</p>"
  ));
});

async function start() {
  const schema = fs.readFileSync(
    path.join(__dirname, "schema.sql"),
    "utf8"
  );

  await pool.query(schema);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`TaskForge AI listening on port ${PORT}`);
  });
}

start().catch(error => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
