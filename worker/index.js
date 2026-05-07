// Password Vault Sync Worker
// Paste this into the Cloudflare Workers editor, then bind a D1 database named DB

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}

function respond(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  })
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
    key, 256
  )
  let out = ''
  for (const b of new Uint8Array(bits)) out += String.fromCharCode(b)
  return btoa(out)
}

function makeToken() {
  let out = ''
  for (const b of crypto.getRandomValues(new Uint8Array(32))) out += String.fromCharCode(b)
  return btoa(out)
}

async function getUserId(db, authHeader) {
  if (!authHeader?.startsWith('Bearer ')) return null
  const token = authHeader.slice(7)
  const now = new Date().toISOString()
  const row = await db.prepare('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?').bind(token, now).first()
  return row?.user_id ?? null
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS })

    const { pathname } = new URL(request.url)

    // POST /api/register
    if (pathname === '/api/register' && request.method === 'POST') {
      const { username, password } = await request.json()
      if (!username || !password || username.length < 3 || password.length < 8)
        return respond({ error: 'Username min 3 chars, password min 8 chars' }, 400)

      const exists = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()
      if (exists) return respond({ error: 'Username already taken' }, 409)

      const salt = crypto.randomUUID()
      const hash = await hashPassword(password, salt + username)
      const userId = crypto.randomUUID()
      await env.DB.prepare('INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)')
        .bind(userId, username, `${salt}:${hash}`, new Date().toISOString()).run()

      const token = makeToken()
      const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString()
      await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, userId, expiresAt).run()
      return respond({ token })
    }

    // POST /api/login
    if (pathname === '/api/login' && request.method === 'POST') {
      const { username, password } = await request.json()
      const user = await env.DB.prepare('SELECT id, password_hash FROM users WHERE username = ?').bind(username).first()
      if (!user) return respond({ error: 'Invalid credentials' }, 401)

      const [salt] = user.password_hash.split(':')
      const hash = await hashPassword(password, salt + username)
      if (user.password_hash !== `${salt}:${hash}`) return respond({ error: 'Invalid credentials' }, 401)

      const token = makeToken()
      const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString()
      await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, user.id, expiresAt).run()
      return respond({ token })
    }

    // GET /api/vault
    if (pathname === '/api/vault' && request.method === 'GET') {
      const userId = await getUserId(env.DB, request.headers.get('Authorization'))
      if (!userId) return respond({ error: 'Unauthorized' }, 401)
      const vault = await env.DB.prepare('SELECT encrypted_blob, updated_at FROM vaults WHERE user_id = ?').bind(userId).first()
      return respond(vault ? { blob: vault.encrypted_blob, updatedAt: vault.updated_at } : { blob: null })
    }

    // PUT /api/vault
    if (pathname === '/api/vault' && request.method === 'PUT') {
      const userId = await getUserId(env.DB, request.headers.get('Authorization'))
      if (!userId) return respond({ error: 'Unauthorized' }, 401)
      const { blob } = await request.json()
      if (!blob) return respond({ error: 'Missing blob' }, 400)
      const now = new Date().toISOString()
      await env.DB.prepare('INSERT OR REPLACE INTO vaults (user_id, encrypted_blob, updated_at) VALUES (?, ?, ?)').bind(userId, blob, now).run()
      return respond({ ok: true })
    }

    return respond({ error: 'Not found' }, 404)
  },
}
