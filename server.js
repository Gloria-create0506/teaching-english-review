const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { URLSearchParams } = require("url");

const ROOT = __dirname;
const PORT = Number(process.env.PORT || 8765);
const ACCESS_PASSWORD = process.env.ACCESS_PASSWORD || "monkey2026";
const MAX_IPS_PER_PASSWORD = Math.max(1, Number(process.env.MAX_IPS_PER_PASSWORD || 2));
const SESSION_HOURS = Math.max(1, Number(process.env.SESSION_HOURS || 8));
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

function passwordHash(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

function readState() {
  try {
    const data = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    return {
      passwordIps: data.passwordIps && typeof data.passwordIps === "object" ? data.passwordIps : {},
      sessions: data.sessions && typeof data.sessions === "object" ? data.sessions : {},
    };
  } catch {
    return { passwordIps: {}, sessions: {} };
  }
}

function writeState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), "utf8");
}

function isHttpsRequest(request) {
  const forwardedProto = request.headers["x-forwarded-proto"];
  const proto = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto;
  return proto === "https" || Boolean(request.socket.encrypted);
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

function cleanExpiredSessions(state) {
  const now = Date.now();
  const maxAge = SESSION_HOURS * 60 * 60 * 1000;
  Object.entries(state.sessions).forEach(([token, session]) => {
    if (!session || now - Number(session.createdAt || 0) > maxAge) {
      delete state.sessions[token];
    }
  });
}

function isAuthenticated(request, state) {
  cleanExpiredSessions(state);
  const token = parseCookies(request)[COOKIE_NAME];
  if (!token || !state.sessions[token]) return false;
  const session = state.sessions[token];
  if (session.ip !== getClientIp(request)) return false;
  session.lastSeen = Date.now();
  return true;
}

function send(response, statusCode, body, type = "text/html; charset=utf-8", headers = {}) {
  response.writeHead(statusCode, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end(body);
}

function redirect(response, location) {
  response.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  response.end();
}

function buildSessionCookie(token, maxAge, request) {
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${maxAge}`,
  ];

  if (isHttpsRequest(request)) {
    parts.push("Secure");
  }

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

  if (isHttpsRequest(request)) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 10_000) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

function renderLoginPage(message = "") {
  const templatePath = path.join(ROOT, "login.html");
  const template = fs.readFileSync(templatePath, "utf8");
  return template.replace("{{MESSAGE}}", message).replace("{{SERVER_MODE}}", "1");
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
  const body = await readRequestBody(request);
  const form = new URLSearchParams(body);
  const password = form.get("password") || "";
  const currentHash = passwordHash(ACCESS_PASSWORD);

  if (passwordHash(password) !== currentHash) {
    send(response, 401, renderLoginPage("密码不正确，请再试一次。"));
    return;
  }

  const ip = getClientIp(request);
  const ips = new Set(state.passwordIps[currentHash] || []);
  if (!ips.has(ip) && ips.size >= MAX_IPS_PER_PASSWORD) {
    send(response, 403, renderLoginPage(`这个密码已经绑定 ${MAX_IPS_PER_PASSWORD} 个 IP。请老师重置后再登录。`));
    return;
  }

  ips.add(ip);
  state.passwordIps[currentHash] = Array.from(ips);
  const token = crypto.randomBytes(32).toString("hex");
  state.sessions[token] = {
    passwordHash: currentHash,
    ip,
    createdAt: Date.now(),
    lastSeen: Date.now(),
  };
  writeState(state);

  const maxAge = SESSION_HOURS * 60 * 60;
  response.writeHead(302, {
    Location: "/chapters",
    "Set-Cookie": buildSessionCookie(token, maxAge, request),
    "Cache-Control": "no-store",
  });
  response.end();
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  const state = readState();

  try {
    if (url.pathname === "/healthz") {
      send(response, 200, JSON.stringify({ ok: true }), "application/json; charset=utf-8");
      return;
    }

    if (url.pathname === "/login" && request.method === "GET") {
      const message = url.searchParams.get("logged_out") === "1" ? "已退出登录，需要继续上课请重新输入密码。" : "";
      send(response, 200, renderLoginPage(message));
      return;
    }

    if (url.pathname === "/login" && request.method === "POST") {
      await handleLogin(request, response, state);
      return;
    }

    if (url.pathname === "/logout") {
      response.writeHead(302, {
        Location: "/login?logged_out=1",
        "Set-Cookie": clearSessionCookie(request),
        "Cache-Control": "no-store",
      });
      response.end();
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
  const passwordNote = process.env.ACCESS_PASSWORD ? "已使用自定义密码" : "当前使用默认密码 monkey2026，请上课前修改";
  console.log(`Journey review server: http://localhost:${PORT}/`);
  console.log(`${passwordNote}；同一密码最多绑定 ${MAX_IPS_PER_PASSWORD} 个 IP。`);
});
