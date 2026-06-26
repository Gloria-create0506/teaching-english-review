const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { URL, URLSearchParams } = require("url");

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 8765);
const SESSION_HOURS = Math.max(1, Number(process.env.SESSION_HOURS || 24));
const VERIFY_TOKEN_HOURS = Math.max(1, Number(process.env.VERIFY_TOKEN_HOURS || 24));
const RESET_TOKEN_MINUTES = Math.max(5, Number(process.env.RESET_TOKEN_MINUTES || 30));
const ALLOWED_EMAIL_DOMAINS = String(process.env.ALLOWED_EMAIL_DOMAINS || "")
  .split(",")
  .map((item) => item.trim().toLowerCase())
  .filter(Boolean);
const APP_BASE_URL = String(process.env.APP_BASE_URL || "").replace(/\/+$/, "");
const RESEND_API_KEY = String(process.env.RESEND_API_KEY || "").trim();
const EMAIL_FROM = String(process.env.EMAIL_FROM || "").trim();
const STATE_FILE = process.env.AUTH_STATE_FILE
  ? path.resolve(ROOT, process.env.AUTH_STATE_FILE)
  : path.join(ROOT, "auth-state.json");
const COOKIE_NAME = "jtwauth";

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".png": "image/png",
  ".gif": "image/gif",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
};

const BLOCKED_FILES = new Set([
  "server.js",
  "auth-state.json",
  ".gitignore",
]);

function createEmptyState() {
  return {
    users: {},
    sessions: {},
    verificationTokens: {},
    resetTokens: {},
  };
}

function readState() {
  try {
    const data = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    return {
      users: data.users && typeof data.users === "object" ? data.users : {},
      sessions: data.sessions && typeof data.sessions === "object" ? data.sessions : {},
      verificationTokens: data.verificationTokens && typeof data.verificationTokens === "object" ? data.verificationTokens : {},
      resetTokens: data.resetTokens && typeof data.resetTokens === "object" ? data.resetTokens : {},
    };
  } catch {
    return createEmptyState();
  }
}

function writeState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), "utf8");
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function looksLikeEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getEmailDomain(email) {
  const normalized = normalizeEmail(email);
  const atIndex = normalized.lastIndexOf("@");
  return atIndex === -1 ? "" : normalized.slice(atIndex + 1);
}

function isAllowedRegistrationEmail(email) {
  if (!ALLOWED_EMAIL_DOMAINS.length) return true;
  return ALLOWED_EMAIL_DOMAINS.includes(getEmailDomain(email));
}

function allowedDomainsLabel() {
  return ALLOWED_EMAIL_DOMAINS.join(", ");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, user) {
  if (!user || !user.passwordSalt || !user.passwordHash) return false;
  const expected = Buffer.from(user.passwordHash, "hex");
  const actual = crypto.scryptSync(String(password), user.passwordSalt, 64);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function isHttpsRequest(request) {
  const forwardedProto = request.headers["x-forwarded-proto"];
  const proto = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto;
  return proto === "https" || Boolean(request.socket.encrypted);
}

function getBaseUrl(request) {
  if (APP_BASE_URL) return APP_BASE_URL;
  const forwardedProto = request.headers["x-forwarded-proto"];
  const forwardedHost = request.headers["x-forwarded-host"];
  const proto = (Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto) || (isHttpsRequest(request) ? "https" : "http");
  const host = (Array.isArray(forwardedHost) ? forwardedHost[0] : forwardedHost) || request.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`;
}

function getClientIp(request) {
  const forwarded = request.headers["x-forwarded-for"];
  const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  const ip = (raw ? raw.split(",")[0] : request.socket.remoteAddress || "").trim();
  if (ip === "::1" || ip === "0:0:0:0:0:0:0:1") return "127.0.0.1";
  return ip.replace(/^::ffff:/, "") || "unknown";
}

function parseCookies(request) {
  const cookies = {};
  const header = request.headers.cookie || "";
  header.split(";").forEach((pair) => {
    const index = pair.indexOf("=");
    if (index === -1) return;
    const name = pair.slice(0, index).trim();
    const value = pair.slice(index + 1).trim();
    if (name) cookies[name] = decodeURIComponent(value);
  });
  return cookies;
}

function buildSessionCookie(token, maxAge, request) {
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${maxAge}`,
  ];

  if (isHttpsRequest(request)) parts.push("Secure");
  return parts.join("; ");
}

function clearSessionCookie(request) {
  const parts = [
    `${COOKIE_NAME}=`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=0",
  ];

  if (isHttpsRequest(request)) parts.push("Secure");
  return parts.join("; ");
}

function cleanExpiredState(state) {
  const now = Date.now();
  const sessionTtl = SESSION_HOURS * 60 * 60 * 1000;

  Object.entries(state.sessions).forEach(([token, session]) => {
    if (!session || now - Number(session.lastSeen || session.createdAt || 0) > sessionTtl) {
      delete state.sessions[token];
    }
  });

  Object.entries(state.verificationTokens).forEach(([tokenHash, record]) => {
    if (!record || Number(record.expiresAt || 0) <= now) {
      delete state.verificationTokens[tokenHash];
    }
  });

  Object.entries(state.resetTokens).forEach(([tokenHash, record]) => {
    if (!record || Number(record.expiresAt || 0) <= now) {
      delete state.resetTokens[tokenHash];
    }
  });
}

function isAuthenticated(request, state) {
  cleanExpiredState(state);
  const token = parseCookies(request)[COOKIE_NAME];
  if (!token || !state.sessions[token]) return false;
  const session = state.sessions[token];
  if (session.ip !== getClientIp(request)) return false;
  session.lastSeen = Date.now();
  return true;
}

function createSession(state, email, request) {
  const token = crypto.randomBytes(32).toString("hex");
  state.sessions[token] = {
    email,
    ip: getClientIp(request),
    createdAt: Date.now(),
    lastSeen: Date.now(),
  };
  return token;
}

function clearSessionsForEmail(state, email) {
  Object.entries(state.sessions).forEach(([token, session]) => {
    if (session && session.email === email) {
      delete state.sessions[token];
    }
  });
}

function clearTokensForEmail(store, email) {
  Object.entries(store).forEach(([tokenHash, record]) => {
    if (record && record.email === email) {
      delete store[tokenHash];
    }
  });
}

function issueToken(store, email, ttlMs) {
  clearTokensForEmail(store, email);
  const token = crypto.randomBytes(32).toString("hex");
  store[hashToken(token)] = {
    email,
    createdAt: Date.now(),
    expiresAt: Date.now() + ttlMs,
  };
  return token;
}

function consumeToken(store, token) {
  const tokenHash = hashToken(token);
  const record = store[tokenHash];
  if (!record) return null;
  delete store[tokenHash];
  if (Number(record.expiresAt || 0) <= Date.now()) return null;
  return record;
}

function peekToken(store, token) {
  const tokenHash = hashToken(token);
  const record = store[tokenHash];
  if (!record) return null;
  if (Number(record.expiresAt || 0) <= Date.now()) {
    delete store[tokenHash];
    return null;
  }
  return record;
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 20_000) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

function send(response, statusCode, body, type = "text/html; charset=utf-8", headers = {}) {
  response.writeHead(statusCode, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end(body);
}

function redirect(response, location, headers = {}) {
  response.writeHead(302, {
    Location: location,
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end();
}

function renderAuthLayout(options) {
  const {
    title,
    subtitle,
    formHtml = "",
    message = "",
    messageTone = "error",
    helperHtml = "",
    sideTitle = "Journey Review",
    sideText = "Sign in with your verified email to open the lesson hub and continue your review.",
  } = options;

  const safeMessage = message ? `<div class="message ${escapeHtml(messageTone)}">${escapeHtml(message)}</div>` : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      --ink: #22304a;
      --muted: #5f6f87;
      --sky: #3186d9;
      --leaf: #2f9a70;
      --sun: #f3b332;
      --paper: #fff8e7;
      --card: rgba(255, 255, 255, 0.94);
      --line: rgba(66, 91, 130, 0.16);
      --shadow: 0 24px 70px rgba(34, 48, 74, 0.18);
      --success: #137333;
      --error: #b42318;
      --info: #0d5f8f;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 28px;
      color: var(--ink);
      font-family: "Segoe UI", "Microsoft YaHei", Arial, sans-serif;
      background:
        radial-gradient(circle at 14% 16%, rgba(243, 179, 50, 0.28), transparent 30%),
        radial-gradient(circle at 82% 22%, rgba(49, 134, 217, 0.25), transparent 34%),
        linear-gradient(135deg, #fff8e7 0%, #e7f5ff 48%, #f1fff6 100%);
    }

    .card {
      width: min(940px, 100%);
      display: grid;
      grid-template-columns: 1fr 1.08fr;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 30px;
      background: var(--card);
      box-shadow: var(--shadow);
    }

    .visual {
      position: relative;
      min-height: 560px;
      padding: 34px;
      background:
        linear-gradient(160deg, rgba(49, 134, 217, 0.15), rgba(47, 154, 112, 0.12)),
        #ffffff;
      display: grid;
      align-content: space-between;
    }

    .visual::before {
      content: "";
      position: absolute;
      inset: 28px;
      border-radius: 26px;
      border: 2px dashed rgba(49, 134, 217, 0.22);
    }

    .badge {
      position: relative;
      z-index: 1;
      width: fit-content;
      padding: 10px 16px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.9);
      color: var(--info);
      font-size: 0.95rem;
      font-weight: 800;
      letter-spacing: 0.04em;
    }

    .monkey {
      position: relative;
      z-index: 1;
      width: 230px;
      height: 230px;
      margin: 0 auto;
      display: grid;
      place-items: center;
      border-radius: 50%;
      background: radial-gradient(circle at 45% 34%, #fff1ba 0 16%, #f3b332 17% 42%, #b86e2c 43% 100%);
      box-shadow: 0 18px 50px rgba(184, 110, 44, 0.28);
      font-size: 6rem;
    }

    .monkey::after {
      content: "🐒";
      transform: translateY(4px);
    }

    .visual-copy {
      position: relative;
      z-index: 1;
      padding: 20px 22px;
      border-radius: 22px;
      background: rgba(255, 241, 186, 0.92);
      border: 1px solid rgba(243, 179, 50, 0.42);
      color: #694309;
    }

    .visual-copy h2 {
      margin: 0 0 10px;
      font-size: 1.35rem;
    }

    .visual-copy p {
      margin: 0;
      line-height: 1.6;
      font-size: 1rem;
    }

    .content {
      padding: 50px 50px 44px;
      display: grid;
      align-content: center;
      gap: 20px;
    }

    h1 {
      margin: 0;
      font-size: clamp(2rem, 4vw, 3.5rem);
      line-height: 1.08;
    }

    .subtitle {
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
      font-size: 1.04rem;
    }

    form {
      display: grid;
      gap: 14px;
      margin-top: 2px;
    }

    .field {
      display: grid;
      gap: 8px;
    }

    label {
      font-size: 1rem;
      font-weight: 800;
    }

    input {
      width: 100%;
      min-height: 58px;
      padding: 0 18px;
      border: 2px solid rgba(49, 134, 217, 0.24);
      border-radius: 16px;
      color: var(--ink);
      background: #fff;
      font-size: 1.05rem;
      outline: none;
    }

    input:focus {
      border-color: var(--sky);
      box-shadow: 0 0 0 4px rgba(49, 134, 217, 0.12);
    }

    button {
      min-height: 58px;
      border: 0;
      border-radius: 16px;
      color: #fff;
      background: linear-gradient(135deg, var(--sky), var(--leaf));
      box-shadow: 0 14px 26px rgba(49, 134, 217, 0.24);
      font-size: 1.08rem;
      font-weight: 800;
      cursor: pointer;
    }

    .message {
      padding: 14px 16px;
      border-radius: 16px;
      font-size: 0.97rem;
      font-weight: 700;
      line-height: 1.6;
    }

    .message.error {
      color: var(--error);
      background: rgba(180, 35, 24, 0.08);
      border: 1px solid rgba(180, 35, 24, 0.18);
    }

    .message.success {
      color: var(--success);
      background: rgba(19, 115, 51, 0.08);
      border: 1px solid rgba(19, 115, 51, 0.18);
    }

    .message.info {
      color: var(--info);
      background: rgba(13, 95, 143, 0.08);
      border: 1px solid rgba(13, 95, 143, 0.18);
    }

    .helper {
      color: var(--muted);
      font-size: 0.96rem;
      line-height: 1.7;
    }

    .helper a, .links a {
      color: var(--sky);
      text-decoration: none;
      font-weight: 700;
    }

    .links {
      display: flex;
      flex-wrap: wrap;
      gap: 10px 16px;
      font-size: 0.96rem;
    }

    .links span {
      color: var(--muted);
    }

    @media (max-width: 820px) {
      body { padding: 16px; }
      .card { grid-template-columns: 1fr; }
      .visual { min-height: 280px; gap: 20px; }
      .monkey { width: 150px; height: 150px; font-size: 4rem; }
      .content { padding: 32px 24px; }
    }
  </style>
</head>
<body>
  <main class="card">
    <section class="visual" aria-hidden="true">
      <div class="badge">Journey to the West Review</div>
      <div class="monkey"></div>
      <div class="visual-copy">
        <h2>${escapeHtml(sideTitle)}</h2>
        <p>${escapeHtml(sideText)}</p>
      </div>
    </section>
    <section class="content">
      <h1>${escapeHtml(title)}</h1>
      <p class="subtitle">${escapeHtml(subtitle)}</p>
      ${safeMessage}
      ${formHtml}
      ${helperHtml}
    </section>
  </main>
</body>
</html>`;
}

function renderLoginPage(message = "", tone = "error", defaults = {}) {
  const emailValue = defaults.email ? escapeHtml(defaults.email) : "";
  return renderAuthLayout({
    title: "Sign in",
    subtitle: "Use your verified email account to open the lesson hub.",
    message,
    messageTone: tone,
    formHtml: `
      <form method="post" action="/login">
        <div class="field">
          <label for="email">Email</label>
          <input id="email" name="email" type="email" autocomplete="email" required value="${emailValue}">
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required>
        </div>
        <button type="submit">Sign in</button>
      </form>
    `,
    helperHtml: `
      <div class="links">
        <span>Need an account?</span><a href="/register">Create one</a>
        <span>Forgot password?</span><a href="/forgot-password">Reset it</a>
      </div>
    `,
  });
}

function renderRegisterPage(message = "", tone = "error", defaults = {}) {
  const emailValue = defaults.email ? escapeHtml(defaults.email) : "";
  const domainHint = ALLOWED_EMAIL_DOMAINS.length
    ? `Only these email domains can register: ${escapeHtml(allowedDomainsLabel())}.`
    : "Any valid email address can register.";
  return renderAuthLayout({
    title: "Create account",
    subtitle: "Register with your email, then verify it before signing in.",
    message,
    messageTone: tone,
    formHtml: `
      <form method="post" action="/register">
        <div class="field">
          <label for="email">Email</label>
          <input id="email" name="email" type="email" autocomplete="email" required value="${emailValue}">
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required>
        </div>
        <div class="field">
          <label for="confirmPassword">Confirm password</label>
          <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required>
        </div>
        <button type="submit">Create account</button>
      </form>
    `,
    helperHtml: `
      <div class="helper">Password must be at least 8 characters. After registration we will send a verification link to your email.</div>
      <div class="helper">${domainHint}</div>
      <div class="links">
        <span>Already registered?</span><a href="/login">Back to sign in</a>
      </div>
    `,
  });
}

function renderForgotPasswordPage(message = "", tone = "error", defaults = {}) {
  const emailValue = defaults.email ? escapeHtml(defaults.email) : "";
  return renderAuthLayout({
    title: "Reset password",
    subtitle: "Enter your email and we will send a password reset link.",
    message,
    messageTone: tone,
    formHtml: `
      <form method="post" action="/forgot-password">
        <div class="field">
          <label for="email">Email</label>
          <input id="email" name="email" type="email" autocomplete="email" required value="${emailValue}">
        </div>
        <button type="submit">Send reset link</button>
      </form>
    `,
    helperHtml: `
      <div class="links">
        <a href="/login">Back to sign in</a>
        <a href="/register">Create account</a>
      </div>
    `,
  });
}

function renderResetPasswordPage(token, message = "", tone = "error") {
  return renderAuthLayout({
    title: "Choose a new password",
    subtitle: "Set a new password for your account.",
    message,
    messageTone: tone,
    formHtml: `
      <form method="post" action="/reset-password">
        <input type="hidden" name="token" value="${escapeHtml(token)}">
        <div class="field">
          <label for="password">New password</label>
          <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required>
        </div>
        <div class="field">
          <label for="confirmPassword">Confirm new password</label>
          <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required>
        </div>
        <button type="submit">Save new password</button>
      </form>
    `,
    helperHtml: `
      <div class="links">
        <a href="/login">Back to sign in</a>
      </div>
    `,
  });
}

function renderNoticePage(title, subtitle, message, tone = "info", links = []) {
  const linkHtml = links.length
    ? `<div class="links">${links.map((item) => `<a href="${escapeHtml(item.href)}">${escapeHtml(item.label)}</a>`).join("")}</div>`
    : "";

  return renderAuthLayout({
    title,
    subtitle,
    message,
    messageTone: tone,
    helperHtml: linkHtml,
  });
}

function emailServiceConfigured() {
  return Boolean(RESEND_API_KEY && EMAIL_FROM);
}

async function sendEmailMessage(payload) {
  if (!emailServiceConfigured()) {
    throw new Error("Email service is not configured. Set RESEND_API_KEY and EMAIL_FROM first.");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: EMAIL_FROM,
      to: [payload.to],
      subject: payload.subject,
      html: payload.html,
      text: payload.text,
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data && data.message ? data.message : JSON.stringify(data);
    throw new Error(`Email delivery failed: ${detail}`);
  }

  return data;
}

function verificationEmailContent(baseUrl, token, email) {
  const verifyUrl = `${baseUrl}/verify-email?token=${encodeURIComponent(token)}`;
  return {
    subject: "Verify your Journey Review account",
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.7; color: #22304a;">
        <h2>Verify your email</h2>
        <p>Hello,</p>
        <p>You created an account for the Journey to the West review site with <strong>${escapeHtml(email)}</strong>.</p>
        <p>Please verify your email by clicking the button below:</p>
        <p><a href="${verifyUrl}" style="display:inline-block;padding:12px 18px;border-radius:10px;background:#3186d9;color:#ffffff;text-decoration:none;font-weight:700;">Verify email</a></p>
        <p>If the button does not work, copy this link into your browser:</p>
        <p>${verifyUrl}</p>
        <p>This link expires in ${VERIFY_TOKEN_HOURS} hour(s).</p>
      </div>
    `,
    text: `Verify your email for Journey Review: ${verifyUrl} (expires in ${VERIFY_TOKEN_HOURS} hour(s))`,
  };
}

function resetEmailContent(baseUrl, token, email) {
  const resetUrl = `${baseUrl}/reset-password?token=${encodeURIComponent(token)}`;
  return {
    subject: "Reset your Journey Review password",
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.7; color: #22304a;">
        <h2>Reset your password</h2>
        <p>Hello,</p>
        <p>We received a password reset request for <strong>${escapeHtml(email)}</strong>.</p>
        <p>Click the button below to set a new password:</p>
        <p><a href="${resetUrl}" style="display:inline-block;padding:12px 18px;border-radius:10px;background:#2f9a70;color:#ffffff;text-decoration:none;font-weight:700;">Reset password</a></p>
        <p>If the button does not work, copy this link into your browser:</p>
        <p>${resetUrl}</p>
        <p>This link expires in ${RESET_TOKEN_MINUTES} minute(s).</p>
      </div>
    `,
    text: `Reset your Journey Review password: ${resetUrl} (expires in ${RESET_TOKEN_MINUTES} minute(s))`,
  };
}

function getSafeFilePath(urlPath) {
  const decodedPath = decodeURIComponent(urlPath.split("?")[0]);
  const cleanPath = decodedPath === "/" ? "/index.html" : decodedPath;
  const relativePath = cleanPath.replace(/^\/+/, "");
  const resolvedPath = path.resolve(ROOT, relativePath);
  const relativeToRoot = path.relative(ROOT, resolvedPath);
  if (relativeToRoot.startsWith("..") || path.isAbsolute(relativeToRoot)) return null;
  if (relativePath.startsWith(".git") || BLOCKED_FILES.has(path.basename(resolvedPath))) return null;
  return resolvedPath;
}

function serveStatic(request, response) {
  const filePath = getSafeFilePath(request.url);
  if (!filePath || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    send(response, 404, "Not found", "text/plain; charset=utf-8");
    return;
  }

  const extension = path.extname(filePath).toLowerCase();
  const type = MIME_TYPES[extension] || "application/octet-stream";
  response.writeHead(200, { "Content-Type": type });
  fs.createReadStream(filePath).pipe(response);
}

async function handleLogin(request, response, state) {
  const form = new URLSearchParams(await readRequestBody(request));
  const email = normalizeEmail(form.get("email"));
  const password = form.get("password") || "";
  const user = state.users[email];

  if (!looksLikeEmail(email) || !password) {
    send(response, 400, renderLoginPage("Enter both email and password.", "error", { email }));
    return;
  }

  if (!user || !verifyPassword(password, user)) {
    send(response, 401, renderLoginPage("Incorrect email or password.", "error", { email }));
    return;
  }

  if (!user.verifiedAt) {
    send(response, 403, renderLoginPage("This email is not verified yet. Please open the verification email first.", "error", { email }));
    return;
  }

  const token = createSession(state, email, request);
  user.lastLoginAt = Date.now();
  user.updatedAt = Date.now();
  writeState(state);

  redirect(response, "/chapters", {
    "Set-Cookie": buildSessionCookie(token, SESSION_HOURS * 60 * 60, request),
  });
}

async function handleRegister(request, response, state) {
  const form = new URLSearchParams(await readRequestBody(request));
  const email = normalizeEmail(form.get("email"));
  const password = form.get("password") || "";
  const confirmPassword = form.get("confirmPassword") || "";

  if (!looksLikeEmail(email)) {
    send(response, 400, renderRegisterPage("Enter a valid email address.", "error", { email }));
    return;
  }

  if (!isAllowedRegistrationEmail(email)) {
    const suffix = ALLOWED_EMAIL_DOMAINS.length
      ? `Allowed domains: ${allowedDomainsLabel()}.`
      : "This email domain is not allowed.";
    send(response, 403, renderRegisterPage(`This email domain cannot register. ${suffix}`, "error", { email }));
    return;
  }

  if (!emailServiceConfigured()) {
    send(response, 500, renderRegisterPage("Email service is not configured yet. Set RESEND_API_KEY and EMAIL_FROM before opening registration.", "error", { email }));
    return;
  }

  if (password.length < 8) {
    send(response, 400, renderRegisterPage("Password must be at least 8 characters long.", "error", { email }));
    return;
  }

  if (password !== confirmPassword) {
    send(response, 400, renderRegisterPage("The two passwords do not match.", "error", { email }));
    return;
  }

  const existing = state.users[email];
  if (existing && existing.verifiedAt) {
    send(response, 409, renderRegisterPage("This email is already registered. Please sign in instead.", "error", { email }));
    return;
  }

  const passwordRecord = createPasswordRecord(password);
  state.users[email] = {
    email,
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    verifiedAt: existing ? existing.verifiedAt || null : null,
    createdAt: existing ? existing.createdAt : Date.now(),
    updatedAt: Date.now(),
    lastLoginAt: existing ? existing.lastLoginAt || null : null,
  };

  const token = issueToken(state.verificationTokens, email, VERIFY_TOKEN_HOURS * 60 * 60 * 1000);
  writeState(state);

  try {
    const content = verificationEmailContent(getBaseUrl(request), token, email);
    await sendEmailMessage({ to: email, ...content });
  } catch (error) {
    send(response, 500, renderRegisterPage(error.message, "error", { email }));
    return;
  }

  send(
    response,
    200,
    renderNoticePage(
      "Check your email",
      "Your account was created. One more step is required before sign-in.",
      `A verification email has been sent to ${email}. Open the link in that email, then come back to sign in.`,
      "success",
      [
        { href: "/login", label: "Back to sign in" },
        { href: "/register", label: "Register another email" },
      ]
    )
  );
}

async function handleForgotPassword(request, response, state) {
  if (!emailServiceConfigured()) {
    send(response, 500, renderForgotPasswordPage("Email service is not configured yet. Set RESEND_API_KEY and EMAIL_FROM before using password reset.", "error"));
    return;
  }

  const form = new URLSearchParams(await readRequestBody(request));
  const email = normalizeEmail(form.get("email"));

  if (!looksLikeEmail(email)) {
    send(response, 400, renderForgotPasswordPage("Enter a valid email address.", "error", { email }));
    return;
  }

  const user = state.users[email];
  if (user && user.verifiedAt) {
    const token = issueToken(state.resetTokens, email, RESET_TOKEN_MINUTES * 60 * 1000);
    writeState(state);
    try {
      const content = resetEmailContent(getBaseUrl(request), token, email);
      await sendEmailMessage({ to: email, ...content });
    } catch (error) {
      send(response, 500, renderForgotPasswordPage(error.message, "error", { email }));
      return;
    }
  }

  send(
    response,
    200,
    renderNoticePage(
      "Check your email",
      "If that email is registered, the reset link is on its way.",
      "For security, we always show the same result here. If the account exists and is verified, the reset email has been sent.",
      "success",
      [{ href: "/login", label: "Back to sign in" }]
    )
  );
}

async function handleResetPassword(request, response, state) {
  const form = new URLSearchParams(await readRequestBody(request));
  const token = form.get("token") || "";
  const password = form.get("password") || "";
  const confirmPassword = form.get("confirmPassword") || "";

  const tokenRecord = peekToken(state.resetTokens, token);
  if (!tokenRecord) {
    send(response, 400, renderNoticePage("Reset link expired", "Request a fresh password reset email and try again.", "This reset link is invalid or has expired.", "error", [
      { href: "/forgot-password", label: "Request a new reset link" },
      { href: "/login", label: "Back to sign in" },
    ]));
    return;
  }

  if (password.length < 8) {
    send(response, 400, renderResetPasswordPage(token, "Password must be at least 8 characters long.", "error"));
    return;
  }

  if (password !== confirmPassword) {
    send(response, 400, renderResetPasswordPage(token, "The two passwords do not match.", "error"));
    return;
  }

  const consumed = consumeToken(state.resetTokens, token);
  if (!consumed) {
    send(response, 400, renderNoticePage("Reset link expired", "Request a fresh password reset email and try again.", "This reset link is invalid or has expired.", "error", [
      { href: "/forgot-password", label: "Request a new reset link" },
      { href: "/login", label: "Back to sign in" },
    ]));
    return;
  }

  const user = state.users[consumed.email];
  if (!user) {
    send(response, 400, renderNoticePage("Account not found", "Please register again if needed.", "The account for this reset link no longer exists.", "error", [
      { href: "/register", label: "Create account" },
      { href: "/login", label: "Back to sign in" },
    ]));
    return;
  }

  const passwordRecord = createPasswordRecord(password);
  user.passwordSalt = passwordRecord.salt;
  user.passwordHash = passwordRecord.hash;
  user.updatedAt = Date.now();
  clearSessionsForEmail(state, consumed.email);
  clearTokensForEmail(state.resetTokens, consumed.email);
  writeState(state);

  send(
    response,
    200,
    renderNoticePage(
      "Password updated",
      "Your password has been reset successfully.",
      "You can now sign in with your new password.",
      "success",
      [{ href: "/login", label: "Sign in now" }]
    )
  );
}

function handleVerifyEmail(request, response, state, token) {
  const record = consumeToken(state.verificationTokens, token);
  if (!record) {
    send(response, 400, renderNoticePage("Verification link expired", "Please request a new verification email by registering again.", "This verification link is invalid or has expired.", "error", [
      { href: "/register", label: "Register again" },
      { href: "/login", label: "Back to sign in" },
    ]));
    return;
  }

  const user = state.users[record.email];
  if (!user) {
    send(response, 400, renderNoticePage("Account not found", "Please create your account again.", "The account for this verification link no longer exists.", "error", [
      { href: "/register", label: "Create account" },
      { href: "/login", label: "Back to sign in" },
    ]));
    return;
  }

  user.verifiedAt = Date.now();
  user.updatedAt = Date.now();
  clearTokensForEmail(state.verificationTokens, record.email);
  writeState(state);

  send(
    response,
    200,
    renderNoticePage(
      "Email verified",
      "Your account is ready.",
      `The email ${record.email} has been verified. You can sign in now.`,
      "success",
      [{ href: "/login", label: "Go to sign in" }]
    )
  );
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  const state = readState();
  cleanExpiredState(state);

  try {
    if (url.pathname === "/healthz") {
      send(response, 200, JSON.stringify({ ok: true }), "application/json; charset=utf-8");
      return;
    }

    if (url.pathname === "/login" && request.method === "GET") {
      if (isAuthenticated(request, state)) {
        writeState(state);
        redirect(response, "/chapters");
        return;
      }

      const message = url.searchParams.get("logged_out") === "1"
        ? "You have signed out successfully."
        : "";
      send(response, 200, renderLoginPage(message, message ? "success" : "error"));
      return;
    }

    if (url.pathname === "/login" && request.method === "POST") {
      await handleLogin(request, response, state);
      return;
    }

    if (url.pathname === "/register" && request.method === "GET") {
      if (isAuthenticated(request, state)) {
        writeState(state);
        redirect(response, "/chapters");
        return;
      }
      send(response, 200, renderRegisterPage());
      return;
    }

    if (url.pathname === "/register" && request.method === "POST") {
      await handleRegister(request, response, state);
      return;
    }

    if (url.pathname === "/verify-email" && request.method === "GET") {
      handleVerifyEmail(request, response, state, url.searchParams.get("token") || "");
      return;
    }

    if (url.pathname === "/forgot-password" && request.method === "GET") {
      send(response, 200, renderForgotPasswordPage());
      return;
    }

    if (url.pathname === "/forgot-password" && request.method === "POST") {
      await handleForgotPassword(request, response, state);
      return;
    }

    if (url.pathname === "/reset-password" && request.method === "GET") {
      const token = url.searchParams.get("token") || "";
      if (!peekToken(state.resetTokens, token)) {
        send(response, 400, renderNoticePage("Reset link expired", "Request a fresh password reset email and try again.", "This reset link is invalid or has expired.", "error", [
          { href: "/forgot-password", label: "Request a new reset link" },
          { href: "/login", label: "Back to sign in" },
        ]));
        return;
      }
      send(response, 200, renderResetPasswordPage(token));
      return;
    }

    if (url.pathname === "/reset-password" && request.method === "POST") {
      await handleResetPassword(request, response, state);
      return;
    }

    if (url.pathname === "/logout") {
      const token = parseCookies(request)[COOKIE_NAME];
      if (token) delete state.sessions[token];
      writeState(state);
      redirect(response, "/login?logged_out=1", {
        "Set-Cookie": clearSessionCookie(request),
      });
      return;
    }

    if (!isAuthenticated(request, state)) {
      writeState(state);
      redirect(response, "/login");
      return;
    }

    writeState(state);

    if (url.pathname === "/") {
      redirect(response, "/chapters");
      return;
    }

    if (url.pathname === "/chapters") {
      request.url = "/chapters.html";
    }

    serveStatic(request, response);
  } catch (error) {
    send(response, 500, `Server error: ${error.message}`, "text/plain; charset=utf-8");
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Journey review server: http://localhost:${PORT}/`);
  console.log(`Session length: ${SESSION_HOURS} hour(s)`);
  console.log(`Email verification window: ${VERIFY_TOKEN_HOURS} hour(s)`);
  console.log(`Reset link window: ${RESET_TOKEN_MINUTES} minute(s)`);
  if (ALLOWED_EMAIL_DOMAINS.length) {
    console.log(`Allowed registration domains: ${allowedDomainsLabel()}`);
  } else {
    console.log("Allowed registration domains: any");
  }
  if (!emailServiceConfigured()) {
    console.log("Warning: registration email is disabled until RESEND_API_KEY and EMAIL_FROM are configured.");
  } else {
    console.log(`Email sender: ${EMAIL_FROM}`);
  }
});
