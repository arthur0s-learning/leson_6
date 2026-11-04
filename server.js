'use strict';

const { createHmac, randomBytes, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');

const scryptAsync = promisify(scrypt);
const ROOT = __dirname;
const SESSION_COOKIE = 'atelier_session';
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000;
const sessions = new Map();

function loadEnvFile() {
  try {
    const contents = fs.readFileSync(path.join(ROOT, '.env'), 'utf8');
    for (const line of contents.split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
      if (!match || Object.hasOwn(process.env, match[1])) continue;
      process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

loadEnvFile();
const pepper = process.env.AUTH_PEPPER;
if (!pepper || Buffer.byteLength(pepper) < 32) {
  throw new Error('AUTH_PEPPER doit contenir au moins 32 octets. Configurez cette variable dans .env.');
}

const databasePath = path.resolve(process.env.JSON_DB_PATH || path.join(ROOT, 'db.json'));
const dataServerPort = Number(process.env.JSON_SERVER_PORT || 3001);
const dataServerUrl = `http://127.0.0.1:${dataServerPort}`;
const dataServerEntry = path.join(ROOT, 'node_modules', 'json-server', 'lib', 'bin.js');
let dataServerProcess;

async function getUsers() {
  const response = await fetch(`${dataServerUrl}/users`);
  if (!response.ok) throw new Error(`JSON Server a répondu avec le statut ${response.status}.`);
  return response.json();
}

async function saveUser(user) {
  const response = await fetch(`${dataServerUrl}/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(user)
  });
  if (!response.ok) throw new Error(`Impossible d'enregistrer l'utilisateur (HTTP ${response.status}).`);
  return response.json();
}

function sendJson(response, status, payload, headers = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  response.end(JSON.stringify(payload));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', chunk => {
      body += chunk;
      if (body.length > 8192) {
        reject(Object.assign(new Error('Requête trop volumineuse.'), { status: 413 }));
        request.destroy();
      }
    });
    request.on('end', () => {
      try {
        resolve(JSON.parse(body || '{}'));
      } catch {
        reject(Object.assign(new Error('Corps JSON invalide.'), { status: 400 }));
      }
    });
    request.on('error', reject);
  });
}

function getSession(request) {
  const cookie = request.headers.cookie || '';
  const token = cookie.split(';').map(part => part.trim()).find(part => part.startsWith(`${SESSION_COOKIE}=`))?.slice(SESSION_COOKIE.length + 1);
  const session = token && sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    if (token) sessions.delete(token);
    return null;
  }
  return session;
}

function cookieHeader(value, maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${SESSION_COOKIE}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

async function hashPassword(password, salt) {
  const pepperedPassword = createHmac('sha256', pepper).update(password, 'utf8').digest();
  const hash = await scryptAsync(pepperedPassword, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return hash.toString('hex');
}

function validCredentials(body) {
  if (typeof body.email !== 'string' || typeof body.password !== 'string') return false;
  const email = body.email.trim();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    && body.password.length >= 8 && body.password.length <= 1024;
}

function createSession(response, userId) {
  const token = randomBytes(32).toString('hex');
  const now = Date.now();
  for (const [key, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(key);
  }
  sessions.set(token, { userId, expiresAt: now + SESSION_DURATION_MS });
  return cookieHeader(token, SESSION_DURATION_MS / 1000);
}

async function handleApi(request, response, url) {
  if (request.method === 'POST' && (url.pathname === '/api/register' || url.pathname === '/api/login')) {
    let body;
    try {
      body = await readJson(request);
    } catch (error) {
      if (!response.destroyed) sendJson(response, error.status || 400, { error: error.message });
      return;
    }

    if (!validCredentials(body)) {
      sendJson(response, 400, { error: 'Saisissez une adresse e-mail valide et un mot de passe de 8 caractères minimum.' });
      return;
    }

    const email = body.email.trim().toLowerCase();
    if (url.pathname === '/api/register') {
      const users = await getUsers();
      if (users.some(user => user.email.toLowerCase() === email)) {
        sendJson(response, 409, { error: 'Un compte existe déjà avec cette adresse e-mail.' });
        return;
      }

      const salt = randomBytes(16);
      const passwordHash = await hashPassword(body.password, salt);
      const user = await saveUser({
        email,
        password_hash: passwordHash,
        password_salt: salt.toString('hex'),
        created_at: new Date().toISOString()
      });
      const setCookie = createSession(response, String(user.id));
      sendJson(response, 201, { user: { email } }, { 'Set-Cookie': setCookie });
      return;
    }

    const user = (await getUsers()).find(candidate => candidate.email.toLowerCase() === email);
    if (!user) {
      sendJson(response, 401, { error: 'Adresse e-mail ou mot de passe incorrect.' });
      return;
    }
    const expectedHash = Buffer.from(await hashPassword(body.password, Buffer.from(user.password_salt, 'hex')), 'hex');
    const storedHash = Buffer.from(user.password_hash, 'hex');
    if (expectedHash.length !== storedHash.length || !timingSafeEqual(expectedHash, storedHash)) {
      sendJson(response, 401, { error: 'Adresse e-mail ou mot de passe incorrect.' });
      return;
    }
    sendJson(response, 200, { user: { email: user.email } }, { 'Set-Cookie': createSession(response, user.id) });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/api/me') {
    const session = getSession(request);
    const user = session && (await getUsers()).find(candidate => String(candidate.id) === session.userId);
    sendJson(response, user ? 200 : 401, user ? { user } : { error: 'Non connecté.' });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/logout') {
    const cookie = request.headers.cookie || '';
    const token = cookie.split(';').map(part => part.trim()).find(part => part.startsWith(`${SESSION_COOKIE}=`))?.slice(SESSION_COOKIE.length + 1);
    if (token) sessions.delete(token);
    sendJson(response, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
    return;
  }

  sendJson(response, 404, { error: 'Route introuvable.' });
}

function serveStatic(request, response, url) {
  const session = getSession(request);
  if (url.pathname === '/index.html' && !session) {
    response.writeHead(302, { Location: '/login.html', 'Cache-Control': 'no-store' });
    response.end();
    return;
  }
  if (url.pathname === '/' && session) {
    response.writeHead(302, { Location: '/index.html', 'Cache-Control': 'no-store' });
    response.end();
    return;
  }

  const filename = url.pathname === '/' ? 'login.html' : url.pathname.slice(1);
  const allowedFiles = new Set(['login.html', 'index.html', 'style.css', 'app.js']);
  if (!allowedFiles.has(filename)) {
    response.writeHead(404);
    response.end('Not found');
    return;
  }

  const contentTypes = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };
  response.writeHead(200, {
    'Content-Type': contentTypes[path.extname(filename)],
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin'
  });
  fs.createReadStream(path.join(ROOT, filename)).pipe(response);
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) {
    handleApi(request, response, url).catch(error => {
      console.error(error);
      if (!response.headersSent) sendJson(response, 500, { error: 'Erreur interne du serveur.' });
      else response.destroy();
    });
    return;
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { Allow: 'GET, HEAD' });
    response.end();
    return;
  }
  serveStatic(request, response, url);
});

async function startDataServer() {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  if (!fs.existsSync(databasePath)) {
    fs.writeFileSync(databasePath, `${JSON.stringify({ users: [] }, null, 2)}\n`, { flag: 'wx' });
  }

  dataServerProcess = spawn(process.execPath, [dataServerEntry, databasePath, '--host', '127.0.0.1', '--port', String(dataServerPort)], {
    cwd: ROOT,
    stdio: 'inherit'
  });

  let lastError;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (dataServerProcess.exitCode !== null) {
      throw new Error(`JSON Server s'est arrêté avec le code ${dataServerProcess.exitCode}.`);
    }
    try {
      const response = await fetch(`${dataServerUrl}/users`, { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`JSON Server ne répond pas sur ${dataServerUrl}. ${lastError?.message || ''}`);
}

const port = Number(process.env.PORT || 3000);
startDataServer().then(() => {
  server.listen(port, '0.0.0.0', () => {
    console.log(`Site disponible sur http://localhost:${port}`);
    console.log(`API JSON Server : ${dataServerUrl}`);
    console.log(`Base JSON : ${databasePath}`);
  });
}).catch(error => {
  console.error(error);
  dataServerProcess?.kill('SIGTERM');
  process.exitCode = 1;
});

function shutdown() {
  server.close(() => {
    dataServerProcess?.kill('SIGTERM');
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);