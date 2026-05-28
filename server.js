const express = require("express");

const app = express();
const port = Number(process.env.PORT || 3000);

app.use(express.urlencoded({ extended: false }));

/*
 * SECURITY EDUCATION NOTE
 *
 * This local application is intentionally vulnerable. It grants access to the
 * dashboard when the browser sends a plaintext cookie named user_role with the
 * value admin. That is insecure because cookies are client-side state; a user,
 * browser extension, local proxy, or devtools session can modify any non-HttpOnly
 * cookie and make the server accept a forged authorization state.
 *
 * Production mitigation:
 * - Keep authorization decisions server-side with real session records.
 * - Store only an opaque, high-entropy session identifier in the browser.
 * - Mark session cookies HttpOnly, Secure, and SameSite=Lax or SameSite=Strict.
 * - If client-carried claims are unavoidable, cryptographically sign and verify
 *   them server-side, keep them short-lived, and never trust unsigned values.
 * - Re-check authorization against server-side policy on every protected request.
 */

app.get("/", (request, response) => {
  response.redirect("/login");
});

app.get("/login", (request, response) => {
  const denied = request.query.denied === "1";
  response.type("html").send(renderPage("Local Cookie Login", `
    <main class="panel">
      <h1>Local Cookie Login</h1>
      ${denied ? `<p class="notice error">Access denied. The dashboard requires <code>user_role=admin</code>.</p>` : ""}
      <p class="notice">This intentionally flawed demo uses client-controlled cookie state for authorization.</p>
      <form method="post" action="/login">
        <label>
          Username
          <input name="username" autocomplete="username" value="student">
        </label>
        <label>
          Password
          <input name="password" type="password" autocomplete="current-password" value="demo">
        </label>
        <button type="submit">Sign in as Guest</button>
      </form>
      <a class="link" href="/dashboard">Open dashboard</a>
    </main>
  `));
});

app.post("/login", (request, response) => {
  response.cookie("user_role", "guest", {
    httpOnly: false,
    sameSite: "lax",
    secure: false,
    path: "/"
  });
  response.redirect("/dashboard");
});

app.get("/dashboard", (request, response) => {
  const cookies = parseCookies(request.headers.cookie || "");
  if (cookies.user_role !== "admin") {
    response.redirect("/login?denied=1");
    return;
  }

  response.type("html").send(renderPage("Admin Dashboard", `
    <main class="panel success">
      <h1>Admin Dashboard</h1>
      <p class="notice good">Access granted because the request included <code>user_role=admin</code>.</p>
      <p>This proves the vulnerability: the server trusted editable client-side state instead of verifying a real server-side session.</p>
      <form method="post" action="/logout">
        <button type="submit">Reset Demo Cookie</button>
      </form>
      <a class="link" href="/login">Back to login</a>
    </main>
  `));
});

app.post("/logout", (request, response) => {
  response.clearCookie("user_role", { path: "/" });
  response.redirect("/login");
});

app.listen(port, () => {
  console.log(`Vulnerable demo app running at http://localhost:${port}`);
});

function parseCookies(cookieHeader) {
  return cookieHeader.split(";").reduce((cookies, pair) => {
    const separatorIndex = pair.indexOf("=");
    if (separatorIndex === -1) {
      return cookies;
    }

    const name = decodeURIComponent(pair.slice(0, separatorIndex).trim());
    const value = decodeURIComponent(pair.slice(separatorIndex + 1).trim());
    cookies[name] = value;
    return cookies;
  }, {});
}

function renderPage(title, body) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>
      :root {
        color-scheme: light dark;
        --bg: #eef3f8;
        --surface: #ffffff;
        --text: #17202f;
        --muted: #5f6c7b;
        --border: #d9e1ea;
        --primary: #2563eb;
        --success: #12805c;
        --danger: #b42318;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --bg: #10151d;
          --surface: #171d27;
          --text: #edf2f7;
          --muted: #9aa8bb;
          --border: #2d3748;
          --primary: #6ea8ff;
          --success: #4cc38a;
          --danger: #ff7b72;
        }
      }
      * { box-sizing: border-box; }
      body {
        min-height: 100vh;
        margin: 0;
        display: grid;
        place-items: center;
        padding: 24px;
        background: var(--bg);
        color: var(--text);
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      .panel {
        width: min(100%, 440px);
        display: grid;
        gap: 18px;
        padding: 28px;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: var(--surface);
        box-shadow: 0 18px 42px rgba(23, 32, 47, 0.14);
      }
      h1 { margin: 0; font-size: 28px; letter-spacing: 0; }
      p { margin: 0; color: var(--muted); line-height: 1.55; }
      code {
        padding: 2px 5px;
        border-radius: 5px;
        background: color-mix(in srgb, var(--primary) 14%, transparent);
        color: var(--text);
      }
      form { display: grid; gap: 12px; }
      label { display: grid; gap: 6px; color: var(--muted); font-size: 14px; font-weight: 700; }
      input {
        min-height: 42px;
        border: 1px solid var(--border);
        border-radius: 7px;
        background: transparent;
        color: var(--text);
        font: inherit;
        padding: 0 12px;
      }
      button,
      .link {
        min-height: 42px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: 1px solid var(--primary);
        border-radius: 7px;
        background: var(--primary);
        color: #ffffff;
        font: inherit;
        font-weight: 800;
        text-decoration: none;
        cursor: pointer;
      }
      .link {
        background: transparent;
        color: var(--primary);
      }
      .notice {
        padding: 10px 12px;
        border: 1px solid var(--border);
        border-radius: 7px;
        background: color-mix(in srgb, var(--primary) 8%, transparent);
      }
      .notice.error {
        border-color: color-mix(in srgb, var(--danger) 45%, var(--border));
        background: color-mix(in srgb, var(--danger) 12%, transparent);
      }
      .notice.good {
        border-color: color-mix(in srgb, var(--success) 45%, var(--border));
        background: color-mix(in srgb, var(--success) 12%, transparent);
      }
    </style>
  </head>
  <body>
    ${body}
  </body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
