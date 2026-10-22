const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>TaskForge AI</title>
      <style>
        body {
          margin: 0;
          font-family: Arial, sans-serif;
          background: #0b1020;
          color: white;
          text-align: center;
        }
        header {
          padding: 22px;
          background: #151d35;
          font-size: 24px;
          font-weight: bold;
        }
        main { padding: 60px 20px; }
        h1 { font-size: 36px; }
        p { color: #c3cce0; line-height: 1.7; }
        .button {
          display: inline-block;
          margin-top: 20px;
          padding: 14px 24px;
          border-radius: 8px;
          background: #6c63ff;
          color: white;
          text-decoration: none;
        }
      </style>
    </head>
    <body>
      <header>TaskForge AI</header>
      <main>
        <h1>Build the future with AI</h1>
        <p>Complete video annotation, audio transcription, and AI evaluation tasks.</p>
        <p>Sign up, complete screening, and work on available tasks.</p>
        <a class="button" href="/health">Check platform status</a>
      </main>
    </body>
    </html>
  `);
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", platform: "TaskForge AI" });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`TaskForge AI running on port ${PORT}`);
});
