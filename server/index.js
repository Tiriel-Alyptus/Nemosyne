import fs from 'fs'
import dotenv from 'dotenv'
import express from 'express'
import path from 'path'
import cron from 'node-cron'
import helmet from 'helmet'
import rateLimit, { ipKeyGenerator } from 'express-rate-limit'
import crypto from 'crypto'
import argon2 from 'argon2'
import nodemailer from 'nodemailer'
import speakeasy from 'speakeasy'
import qrcode from 'qrcode'
import { Pool } from 'pg'

// Load env vars from .env, then let .env.local override if present (mirrors CRA-style behavior).
dotenv.config()
const localEnvPath = path.resolve(process.cwd(), '.env.local')
if (fs.existsSync(localEnvPath)) {
  dotenv.config({ path: localEnvPath, override: true })
}

const app = express()
const port = Number(process.env.PORT || 8787)

const isProd = process.env.NODE_ENV === 'production'
const cookieSecure = process.env.COOKIE_SECURE === 'true' || isProd
const sessionSecret =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex')
const appUrl = process.env.APP_URL || `http://localhost:${port}`
const fieldCryptoSeed = process.env.DATA_ENCRYPTION_KEY || sessionSecret
const fieldCryptoKey = crypto
  .createHash('sha256')
  .update(fieldCryptoSeed)
  .digest()
const fieldCipherVersion = 'enc-v1'

const databaseUrl = process.env.DATABASE_URL
if (!databaseUrl) {
  throw new Error('DATABASE_URL is required')
}
// Default to relaxed SSL to avoid SELF_SIGNED errors with Supabase; opt-in strict verify via DB_SSL_MODE=verify.
const dbSslMode = process.env.DB_SSL_MODE || 'relaxed'
const dbSsl =
  process.env.DB_SSL === 'false'
    ? false
    : dbSslMode === 'relaxed'
        ? { rejectUnauthorized: false }
        : { rejectUnauthorized: true }

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: dbSsl,
  max: 10,
})

// In production on managed DBs, avoid running DDL as non-owner.
const shouldMigrate = process.env.RUN_MIGRATIONS === 'true'

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY,
      email text UNIQUE NOT NULL,
      password_hash text NOT NULL,
      created_at_ts bigint NOT NULL,
      verified boolean NOT NULL DEFAULT FALSE,
      verify_token_hash text,
      verify_token_expires_at bigint,
      mfa_enabled boolean NOT NULL DEFAULT FALSE,
      mfa_secret text,
      mfa_temp_secret text,
      display_name text,
      avatar_url text,
      ui_theme text NOT NULL DEFAULT 'light',
      ui_density text NOT NULL DEFAULT 'comfortable',
      ui_language text NOT NULL DEFAULT 'fr',
      notif_email boolean NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id uuid PRIMARY KEY,
      owner_type text NOT NULL,
      owner_id uuid NOT NULL,
      created_at_ts bigint NOT NULL,
      last_seen_ts bigint NOT NULL
    );
    CREATE TABLE IF NOT EXISTS pushes (
      id uuid PRIMARY KEY,
      owner_type text NOT NULL,
      owner_id uuid NOT NULL,
      kind text NOT NULL,
      label text NOT NULL,
      created_at_ts bigint NOT NULL,
      expires_at_ts bigint NOT NULL,
      views_left integer NOT NULL,
      cipher text NOT NULL,
      iv text NOT NULL,
      salt text,
      requires_passphrase boolean NOT NULL,
      filename text,
      mime text,
      size integer
    );
    CREATE INDEX IF NOT EXISTS idx_pushes_owner ON pushes(owner_type, owner_id, created_at_ts DESC);
    CREATE INDEX IF NOT EXISTS idx_pushes_expiry ON pushes(expires_at_ts);
    CREATE INDEX IF NOT EXISTS idx_users_verify_hash ON users(verify_token_hash);
  `)

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_hash text;
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS display_name text;
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS avatar_url text;
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS ui_theme text NOT NULL DEFAULT 'light';
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS ui_density text NOT NULL DEFAULT 'comfortable';
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS ui_language text NOT NULL DEFAULT 'fr';
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS notif_email boolean NOT NULL DEFAULT TRUE;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash);
  `)

  // One-time backfill: replace clear-text emails with encrypted values and add lookup hash.
  const usersResult = await pool.query('SELECT id, email, email_hash FROM users')
  for (const row of usersResult.rows) {
    const rawEmail = typeof row.email === 'string' ? row.email : ''
    if (!rawEmail) continue
    const decryptedEmail = decryptField(rawEmail) || rawEmail
    const normalizedEmail = decryptedEmail.toLowerCase().trim()
    if (!normalizedEmail) continue
    const nextEncryptedEmail = isEncryptedField(rawEmail)
      ? rawEmail
      : encryptField(normalizedEmail)
    const nextEmailHash = row.email_hash || hashLookup(normalizedEmail)
    if (nextEncryptedEmail !== rawEmail || nextEmailHash !== row.email_hash) {
      await pool.query(
        'UPDATE users SET email = $1, email_hash = $2 WHERE id = $3',
        [nextEncryptedEmail, nextEmailHash, row.id],
      )
    }
  }
}

const dbReady = shouldMigrate
  ? initDb().catch((error) => {
      console.error('Failed to initialize database', error)
      throw error
    })
  : Promise.resolve()

const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com'
const smtpPort = Number(process.env.SMTP_PORT || 465)
const smtpUser = process.env.SMTP_USER
const smtpPass = process.env.SMTP_PASS
const smtpFrom = process.env.SMTP_FROM || smtpUser
const smtpEnabled = Boolean(smtpUser && smtpPass && smtpFrom)

const mailer =
  smtpUser && smtpPass
    ? nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: {
          user: smtpUser,
          pass: smtpPass,
        },
      })
    : null

if (!smtpEnabled) {
  console.warn(
    '[email] SMTP non configure: definir SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS et SMTP_FROM.',
  )
}

app.disable('x-powered-by')
app.set('trust proxy', 1)
const enableHsts = process.env.ENABLE_HSTS === 'true' || isProd
const enableCsp = process.env.ENABLE_CSP === 'true'

app.use(
  helmet({
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    contentSecurityPolicy: enableCsp
      ? {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", 'data:', 'https://fonts.gstatic.com'],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            frameAncestors: ["'none'"],
          },
        }
      : false,
    crossOriginEmbedderPolicy: false,
    hsts: enableHsts,
  }),
)
app.use(express.json({ limit: '10mb' }))

const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
})

const createLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
})

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
})

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
})

const revealLimiterByIp = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
})

const revealLimiterById = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => `${ipKeyGenerator(req)}:${req.params.id || 'unknown'}`,
})

app.use('/api', limiter)
app.use('/api', (_req, res, next) => {
  res.set('Cache-Control', 'no-store')
  next()
})

const base64Pattern = /^[A-Za-z0-9+/=]+$/
const maxFileBytes = 5 * 1024 * 1024
const maxCipherBase64Len = Math.ceil((maxFileBytes * 4) / 3) + 8
const maxTtlMs = 7 * 24 * 60 * 60 * 1000
const maxViews = 20
const maxLabelLength = 64
const idPattern = /^[0-9a-fA-F-]{36}$/
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const minPasswordLength = 12
const maxPasswordLength = 128
const verifyTokenTtlMs = 1000 * 60 * 60
const maxDisplayNameLength = 80
const maxAvatarUrlLength = 2048
const allowedUiThemes = new Set(['light', 'dark'])
const allowedUiDensities = new Set(['comfortable', 'compact'])
const allowedUiLanguages = new Set(['fr', 'en'])

function mapUser(row) {
  if (!row) return null
  const decryptedEmail = decryptField(row.email)
  const uiTheme = allowedUiThemes.has(row.ui_theme) ? row.ui_theme : 'light'
  const uiDensity = allowedUiDensities.has(row.ui_density)
    ? row.ui_density
    : 'comfortable'
  const uiLanguage = allowedUiLanguages.has(row.ui_language)
    ? row.ui_language
    : 'fr'
  return {
    id: row.id,
    email: decryptedEmail || row.email,
    emailHash: row.email_hash,
    passwordHash: row.password_hash,
    createdAtTs: Number(row.created_at_ts),
    verified: row.verified,
    verifyTokenHash: row.verify_token_hash,
    verifyTokenExpiresAt: row.verify_token_expires_at
      ? Number(row.verify_token_expires_at)
      : null,
    mfaEnabled: row.mfa_enabled,
    mfaSecret: row.mfa_secret,
    mfaTempSecret: row.mfa_temp_secret,
    displayName: typeof row.display_name === 'string' ? row.display_name : null,
    avatarUrl: typeof row.avatar_url === 'string' ? row.avatar_url : null,
    uiTheme,
    uiDensity,
    uiLanguage,
    notifEmail: row.notif_email !== false,
  }
}

function normalizeDisplayName(value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.slice(0, maxDisplayNameLength)
}

function normalizeAvatarUrl(value) {
  if (value === null) return { ok: true, value: null }
  if (typeof value !== 'string') return { ok: false }
  const trimmed = value.trim()
  if (!trimmed) return { ok: true, value: null }
  if (trimmed.length > maxAvatarUrlLength) return { ok: false }
  try {
    const parsed = new URL(trimmed)
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return { ok: false }
    }
    return { ok: true, value: parsed.toString() }
  } catch {
    return { ok: false }
  }
}

function normalizeUiTheme(value) {
  if (typeof value !== 'string') return null
  return allowedUiThemes.has(value) ? value : null
}

function normalizeUiDensity(value) {
  if (typeof value !== 'string') return null
  return allowedUiDensities.has(value) ? value : null
}

function normalizeUiLanguage(value) {
  if (typeof value !== 'string') return null
  return allowedUiLanguages.has(value) ? value : null
}

function mapUserPreferences(user) {
  return {
    theme: user?.uiTheme || 'light',
    density: user?.uiDensity || 'comfortable',
    language: user?.uiLanguage || 'fr',
    emailNotifications: user?.notifEmail !== false,
  }
}

function buildSessionResponse(session, user) {
  return {
    authenticated: Boolean(user),
    email: user?.email ?? null,
    ownerType: session.ownerType,
    verified: user?.verified ?? false,
    mfaEnabled: user?.mfaEnabled ?? false,
    user: user
      ? {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          avatarUrl: user.avatarUrl,
          preferences: mapUserPreferences(user),
        }
      : null,
  }
}

function mapSession(row) {
  if (!row) return null
  return {
    id: row.id,
    ownerType: row.owner_type,
    ownerId: row.owner_id,
    createdAtTs: Number(row.created_at_ts),
    lastSeenTs: Number(row.last_seen_ts),
  }
}

function mapPush(row) {
  if (!row) return null
  const decryptedLabel = decryptField(row.label)
  const decryptedFilename = decryptField(row.filename)
  const decryptedMime = decryptField(row.mime)
  return {
    id: row.id,
    ownerType: row.owner_type,
    ownerId: row.owner_id,
    kind: row.kind,
    label: decryptedLabel || 'Secret',
    createdAtTs: Number(row.created_at_ts),
    expiresAtTs: Number(row.expires_at_ts),
    viewsLeft: row.views_left,
    cipher: row.cipher,
    iv: row.iv,
    salt: row.salt,
    requiresPassphrase: row.requires_passphrase,
    filename: decryptedFilename || row.filename,
    mime: decryptedMime || row.mime,
    size: row.size,
  }
}

function getSummary(item) {
  return {
    id: item.id,
    label: item.label,
    createdAtTs: item.createdAtTs,
    expiresAtTs: item.expiresAtTs,
    viewsLeft: item.viewsLeft,
    requiresPassphrase: item.requiresPassphrase,
  }
}

async function purgeExpiredPushes() {
  await dbReady
  const now = Date.now()
  await pool.query(
    'DELETE FROM pushes WHERE expires_at_ts <= $1 OR views_left <= 0',
    [now],
  )
}

function isSafeBase64(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxCipherBase64Len &&
    base64Pattern.test(value)
  )
}

function normalizeLabel(label) {
  if (typeof label !== 'string') return 'Secret'
  return label.trim().slice(0, maxLabelLength) || 'Secret'
}

function isValidId(value) {
  return typeof value === 'string' && idPattern.test(value)
}

function isValidEmail(value) {
  return typeof value === 'string' && value.length <= 160 && emailPattern.test(value)
}

async function hashPassword(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 3,
    parallelism: 1,
  })
}

async function verifyPassword(hash, password) {
  try {
    return await argon2.verify(hash, password)
  } catch {
    return false
  }
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex')
}

function hashLookup(value) {
  return crypto
    .createHmac('sha256', fieldCryptoKey)
    .update(String(value || ''))
    .digest('hex')
}

function isEncryptedField(value) {
  return typeof value === 'string' && value.startsWith(`${fieldCipherVersion}:`)
}

function encryptField(value) {
  if (typeof value !== 'string') return null
  const plain = value.trim()
  if (!plain) return null
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', fieldCryptoKey, iv)
  const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `${fieldCipherVersion}:${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`
}

function decryptField(value) {
  if (typeof value !== 'string' || !value) return null
  if (!isEncryptedField(value)) return value
  const parts = value.split(':')
  if (parts.length !== 4) return null
  try {
    const iv = Buffer.from(parts[1], 'base64')
    const tag = Buffer.from(parts[2], 'base64')
    const cipherText = Buffer.from(parts[3], 'base64')
    const decipher = crypto.createDecipheriv('aes-256-gcm', fieldCryptoKey, iv)
    decipher.setAuthTag(tag)
    const plain = Buffer.concat([decipher.update(cipherText), decipher.final()])
    return plain.toString('utf8')
  } catch {
    return null
  }
}

function normalizeBaseUrl(value, defaultProtocol = 'https') {
  if (typeof value !== 'string' || !value.trim()) return null
  const trimmed = value.trim().replace(/\/$/, '')
  const withProtocol = /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `${defaultProtocol}://${trimmed}`
  try {
    return new URL(withProtocol).origin
  } catch {
    return null
  }
}

function isLocalOrigin(value) {
  try {
    const origin = new URL(value)
    return ['localhost', '127.0.0.1', '::1'].includes(origin.hostname)
  } catch {
    return false
  }
}

function getRequestBase(req) {
  const explicitAppUrl = normalizeBaseUrl(process.env.APP_URL, 'http')
  if (explicitAppUrl && !(isProd && isLocalOrigin(explicitAppUrl))) {
    return explicitAppUrl
  }

  if (isProd) {
    const productionDomain = normalizeBaseUrl(
      process.env.VERCEL_PROJECT_PRODUCTION_URL,
    )
    if (productionDomain) {
      return productionDomain
    }
  }

  const forwardedProto = req.headers['x-forwarded-proto']
  const forwardedHost = req.headers['x-forwarded-host']
  const proto = Array.isArray(forwardedProto)
    ? forwardedProto[0]
    : forwardedProto || req.protocol || 'http'
  const host = Array.isArray(forwardedHost)
    ? forwardedHost[0]
    : forwardedHost || req.headers.host
  if (!host) {
    const deploymentUrl = normalizeBaseUrl(process.env.VERCEL_URL)
    if (deploymentUrl) {
      return deploymentUrl
    }
    if (explicitAppUrl) {
      return explicitAppUrl
    }
    return appUrl.replace(/\/$/, '')
  }
  return `${proto}://${host}`.replace(/\/$/, '')
}

function buildVerifyLink(baseUrl, token) {
  return `${baseUrl}/verify?token=${encodeURIComponent(token)}`
}

async function sendVerificationEmail(email, token, baseUrl) {
  const link = buildVerifyLink(baseUrl, token)
  if (!mailer || !smtpFrom) {
    console.warn(`[email] Verification non envoyee (SMTP absent) pour ${email}`)
    if (!isProd) {
      console.info(`[email] Lien verification dev: ${link}`)
    }
    return {
      sent: false,
      reason: 'smtp-not-configured',
      previewLink: !isProd ? link : null,
    }
  }
  try {
    await mailer.sendMail({
      from: smtpFrom,
      to: email,
      subject: 'Verification de votre email Nemosyne',
      text: `Cliquez sur ce lien pour verifier votre email: ${link}`,
      html: `<p>Cliquez sur ce lien pour verifier votre email:</p><p><a href="${link}">${link}</a></p>`,
    })
    return { sent: true, reason: null, previewLink: null }
  } catch (error) {
    console.error('[email] Echec envoi verification', error)
    if (!isProd) {
      console.info(`[email] Lien verification dev: ${link}`)
    }
    return {
      sent: false,
      reason: 'smtp-send-failed',
      previewLink: !isProd ? link : null,
    }
  }
}

function validatePayload(payload) {
  if (!payload) return { ok: false, error: 'invalid-payload' }
  if (!isSafeBase64(payload.cipher) || !isSafeBase64(payload.iv)) {
    return { ok: false, error: 'invalid-crypto' }
  }
  const kind = payload.kind === 'file' ? 'file' : 'text'
  const requiresPassphrase = Boolean(payload.requiresPassphrase)
  if (requiresPassphrase && !isSafeBase64(payload.salt)) {
    return { ok: false, error: 'missing-salt' }
  }
  const expiresAtTs = Number(payload.expiresAtTs)
  if (!Number.isFinite(expiresAtTs)) {
    return { ok: false, error: 'invalid-dates' }
  }
  const now = Date.now()
  if (expiresAtTs <= now || expiresAtTs - now > maxTtlMs) {
    return { ok: false, error: 'invalid-expiry' }
  }
  const viewsLeft = Math.min(maxViews, Math.max(1, Number(payload.viewsLeft)))
  if (kind === 'file') {
    if (
      typeof payload.filename !== 'string' ||
      payload.filename.length < 1 ||
      payload.filename.length > 200
    ) {
      return { ok: false, error: 'invalid-filename' }
    }
    const size = Number(payload.size)
    if (!Number.isFinite(size) || size <= 0 || size > maxFileBytes) {
      return { ok: false, error: 'invalid-file-size' }
    }
    if (typeof payload.mime !== 'string' || payload.mime.length > 120) {
      return { ok: false, error: 'invalid-mime' }
    }
  }

  return {
    ok: true,
    value: {
      kind,
      filename: kind === 'file' ? payload.filename : undefined,
      mime: kind === 'file' ? payload.mime : undefined,
      size: kind === 'file' ? Number(payload.size) : undefined,
      label: normalizeLabel(payload.label),
      createdAtTs: now,
      expiresAtTs,
      viewsLeft,
      cipher: payload.cipher,
      iv: payload.iv,
      salt: requiresPassphrase ? payload.salt : undefined,
      requiresPassphrase,
    },
  }
}

function parseCookies(header) {
  const cookies = {}
  if (!header) return cookies
  header.split(';').forEach((cookie) => {
    const [name, ...rest] = cookie.trim().split('=')
    if (!name) return
    cookies[name] = decodeURIComponent(rest.join('=') || '')
  })
  return cookies
}

function signSessionId(sessionId) {
  return crypto.createHmac('sha256', sessionSecret).update(sessionId).digest('hex')
}

function verifySessionCookie(value) {
  if (!value) return null
  const [id, signature] = value.split('.')
  if (!id || !signature) return null
  const expected = signSessionId(id)
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null
  }
  return id
}

function setSessionCookie(res, sessionId) {
  const value = `${sessionId}.${signSessionId(sessionId)}`
  res.cookie('nsid', value, {
    httpOnly: true,
    sameSite: 'lax',
    secure: cookieSecure,
    maxAge: 1000 * 60 * 60 * 24 * 30,
    path: '/',
  })
}

async function ensureSession(req, res, next) {
  try {
    await dbReady
    await purgeExpiredPushes()
    const cookies = parseCookies(req.headers.cookie)
    const sessionId = verifySessionCookie(cookies.nsid)
    const now = Date.now()

    let session = null
    if (sessionId) {
      const existing = await pool.query(
        'SELECT * FROM sessions WHERE id = $1 LIMIT 1',
        [sessionId],
      )
      session = mapSession(existing.rows[0])
    }

    if (!session) {
      const anonId = crypto.randomUUID()
      session = {
        id: crypto.randomUUID(),
        ownerType: 'anon',
        ownerId: anonId,
        createdAtTs: now,
        lastSeenTs: now,
      }
      await pool.query(
        'INSERT INTO sessions (id, owner_type, owner_id, created_at_ts, last_seen_ts) VALUES ($1, $2, $3, $4, $5)',
        [session.id, session.ownerType, session.ownerId, now, now],
      )
      setSessionCookie(res, session.id)
    } else {
      await pool.query('UPDATE sessions SET last_seen_ts = $1 WHERE id = $2', [
        now,
        session.id,
      ])
      session.lastSeenTs = now
    }

    req.session = session
    next()
  } catch (error) {
    next(error)
  }
}

app.use('/api', (req, res, next) => {
  res.locals.secureCookies = cookieSecure
  next()
})

app.use('/api', ensureSession)

app.get('/api/session', async (req, res, next) => {
  try {
    const session = req.session
    let user = null
    if (session.ownerType === 'user') {
      const result = await pool.query(
        'SELECT * FROM users WHERE id = $1 LIMIT 1',
        [session.ownerId],
      )
      user = mapUser(result.rows[0])
    }
    return res.json(buildSessionResponse(session, user))
  } catch (error) {
    next(error)
  }
})

app.get('/api/user/settings', async (req, res, next) => {
  try {
    const session = req.session
    if (session.ownerType !== 'user') {
      return res.status(401).json({ error: 'unauthorized' })
    }
    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1 LIMIT 1',
      [session.ownerId],
    )
    const user = mapUser(result.rows[0])
    if (!user) {
      return res.status(401).json({ error: 'unauthorized' })
    }
    return res.json({
      ok: true,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl,
      preferences: mapUserPreferences(user),
    })
  } catch (error) {
    next(error)
  }
})

app.patch('/api/user/settings', authLimiter, async (req, res, next) => {
  try {
    const session = req.session
    if (session.ownerType !== 'user') {
      return res.status(401).json({ error: 'unauthorized' })
    }
    const payload =
      req.body && typeof req.body === 'object' && !Array.isArray(req.body)
        ? req.body
        : {}
    const updates = []
    const values = []

    if (Object.prototype.hasOwnProperty.call(payload, 'displayName')) {
      if (
        payload.displayName !== null &&
        typeof payload.displayName !== 'string'
      ) {
        return res.status(400).json({ error: 'invalid-display-name' })
      }
      values.push(normalizeDisplayName(payload.displayName || ''))
      updates.push(`display_name = $${values.length}`)
    }

    if (Object.prototype.hasOwnProperty.call(payload, 'avatarUrl')) {
      const normalizedAvatar = normalizeAvatarUrl(payload.avatarUrl)
      if (!normalizedAvatar.ok) {
        return res.status(400).json({ error: 'invalid-avatar-url' })
      }
      values.push(normalizedAvatar.value ?? null)
      updates.push(`avatar_url = $${values.length}`)
    }

    if (Object.prototype.hasOwnProperty.call(payload, 'preferences')) {
      const preferences = payload.preferences
      if (
        !preferences ||
        typeof preferences !== 'object' ||
        Array.isArray(preferences)
      ) {
        return res.status(400).json({ error: 'invalid-preferences' })
      }
      if (Object.prototype.hasOwnProperty.call(preferences, 'theme')) {
        const nextTheme = normalizeUiTheme(preferences.theme)
        if (!nextTheme) {
          return res.status(400).json({ error: 'invalid-theme' })
        }
        values.push(nextTheme)
        updates.push(`ui_theme = $${values.length}`)
      }
      if (Object.prototype.hasOwnProperty.call(preferences, 'density')) {
        const nextDensity = normalizeUiDensity(preferences.density)
        if (!nextDensity) {
          return res.status(400).json({ error: 'invalid-density' })
        }
        values.push(nextDensity)
        updates.push(`ui_density = $${values.length}`)
      }
      if (Object.prototype.hasOwnProperty.call(preferences, 'language')) {
        const nextLanguage = normalizeUiLanguage(preferences.language)
        if (!nextLanguage) {
          return res.status(400).json({ error: 'invalid-language' })
        }
        values.push(nextLanguage)
        updates.push(`ui_language = $${values.length}`)
      }
      if (
        Object.prototype.hasOwnProperty.call(preferences, 'emailNotifications')
      ) {
        if (typeof preferences.emailNotifications !== 'boolean') {
          return res.status(400).json({ error: 'invalid-email-notifications' })
        }
        values.push(preferences.emailNotifications)
        updates.push(`notif_email = $${values.length}`)
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'no-settings-updated' })
    }

    values.push(session.ownerId)
    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING *`
    const updateResult = await pool.query(query, values)
    const updatedUser = mapUser(updateResult.rows[0])
    if (!updatedUser) {
      return res.status(404).json({ error: 'user-not-found' })
    }
    return res.json({
      ok: true,
      displayName: updatedUser.displayName,
      avatarUrl: updatedUser.avatarUrl,
      preferences: mapUserPreferences(updatedUser),
    })
  } catch (error) {
    next(error)
  }
})

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password, fullName } = req.body || {}
  const normalizedEmail = typeof email === 'string' ? email.toLowerCase().trim() : ''
  const normalizedEmailHash = hashLookup(normalizedEmail)
  if (
    fullName !== undefined &&
    fullName !== null &&
    typeof fullName !== 'string'
  ) {
    return res.status(400).json({ error: 'invalid-full-name' })
  }
  const normalizedDisplayName = normalizeDisplayName(fullName || '')
  if (!isValidEmail(normalizedEmail)) {
    return res.status(400).json({ error: 'invalid-email' })
  }
  if (typeof password !== 'string') {
    return res.status(400).json({ error: 'invalid-password' })
  }
  const trimmed = password.trim()
  if (
    trimmed.length < minPasswordLength ||
    trimmed.length > maxPasswordLength ||
    trimmed !== password
  ) {
    return res.status(400).json({ error: 'weak-password' })
  }
  const existing = await pool.query(
    'SELECT * FROM users WHERE email_hash = $1 OR email = $2 LIMIT 1',
    [normalizedEmailHash, normalizedEmail],
  )
  const existingUser = mapUser(existing.rows[0])
  if (existingUser) {
    if (existingUser.verified) {
      return res.status(409).json({ error: 'email-taken' })
    }
    const verifyToken = crypto.randomBytes(32).toString('hex')
    const verifyTokenHash = hashToken(verifyToken)
    await pool.query(
      'UPDATE users SET verify_token_hash = $1, verify_token_expires_at = $2, display_name = COALESCE($3, display_name) WHERE id = $4',
      [
        verifyTokenHash,
        Date.now() + verifyTokenTtlMs,
        normalizedDisplayName,
        existingUser.id,
      ],
    )
    const emailDelivery = await sendVerificationEmail(
      normalizedEmail,
      verifyToken,
      getRequestBase(req),
    )
    return res.json({
      ok: true,
      email: normalizedEmail,
      authenticated: false,
      accountStatus: 'pending-verification',
      verificationEmailSent: emailDelivery.sent,
      verificationEmailReason: emailDelivery.reason,
      verificationEmailPreviewLink: emailDelivery.previewLink,
    })
  }
  const passwordHash = await hashPassword(password)
  const verifyToken = crypto.randomBytes(32).toString('hex')
  const verifyTokenHash = hashToken(verifyToken)
  const now = Date.now()
  const userId = crypto.randomUUID()
  await pool.query(
    `INSERT INTO users
      (id, email, email_hash, password_hash, created_at_ts, verified, verify_token_hash, verify_token_expires_at, mfa_enabled, mfa_secret, mfa_temp_secret, display_name)
     VALUES ($1, $2, $3, $4, $5, FALSE, $6, $7, FALSE, NULL, NULL, $8)`,
    [
      userId,
      encryptField(normalizedEmail),
      normalizedEmailHash,
      passwordHash,
      now,
      verifyTokenHash,
      now + verifyTokenTtlMs,
      normalizedDisplayName,
    ],
  )
  const sessionId = crypto.randomUUID()
  await pool.query(
    'INSERT INTO sessions (id, owner_type, owner_id, created_at_ts, last_seen_ts) VALUES ($1, $2, $3, $4, $5)',
    [sessionId, 'user', userId, now, now],
  )
  req.session = {
    id: sessionId,
    ownerType: 'user',
    ownerId: userId,
    createdAtTs: now,
    lastSeenTs: now,
  }
  setSessionCookie(res, req.session.id)
  const emailDelivery = await sendVerificationEmail(
    normalizedEmail,
    verifyToken,
    getRequestBase(req),
  )
  return res.json({
    ok: true,
    email: normalizedEmail,
    authenticated: true,
    accountStatus: 'created',
    verificationEmailSent: emailDelivery.sent,
    verificationEmailReason: emailDelivery.reason,
    verificationEmailPreviewLink: emailDelivery.previewLink,
  })
})

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password, otp } = req.body || {}
  const normalizedEmail = typeof email === 'string' ? email.toLowerCase().trim() : ''
  const normalizedEmailHash = hashLookup(normalizedEmail)
  if (!isValidEmail(normalizedEmail) || typeof password !== 'string') {
    return res.status(400).json({ error: 'invalid-credentials' })
  }
  const userResult = await pool.query(
    'SELECT * FROM users WHERE email_hash = $1 OR email = $2 LIMIT 1',
    [normalizedEmailHash, normalizedEmail],
  )
  const user = mapUser(userResult.rows[0])
  if (!user) {
    return res.status(401).json({ error: 'invalid-credentials' })
  }
  const ok = await verifyPassword(user.passwordHash, password)
  if (!ok) {
    return res.status(401).json({ error: 'invalid-credentials' })
  }
  if (!user.verified) {
    return res.status(403).json({ error: 'email-not-verified' })
  }
  if (user.mfaEnabled) {
    if (typeof otp !== 'string' || otp.length < 6) {
      return res.status(401).json({ error: 'mfa-required' })
    }
    const valid = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: otp,
      window: 1,
    })
    if (!valid) {
      return res.status(401).json({ error: 'invalid-otp' })
    }
  }
  const sessionId = crypto.randomUUID()
  const now = Date.now()
  await pool.query(
    'INSERT INTO sessions (id, owner_type, owner_id, created_at_ts, last_seen_ts) VALUES ($1, $2, $3, $4, $5)',
    [sessionId, 'user', user.id, now, now],
  )
  req.session = {
    id: sessionId,
    ownerType: 'user',
    ownerId: user.id,
    createdAtTs: now,
    lastSeenTs: now,
  }
  setSessionCookie(res, req.session.id)
  return res.json({ ok: true, email: user.email })
})

app.post('/api/auth/resend-verification', verifyLimiter, async (req, res) => {
  const { email } = req.body || {}
  const normalizedEmail = typeof email === 'string' ? email.toLowerCase().trim() : ''
  const normalizedEmailHash = hashLookup(normalizedEmail)
  if (!isValidEmail(normalizedEmail)) {
    return res.status(400).json({ error: 'invalid-email' })
  }
  const userResult = await pool.query(
    'SELECT * FROM users WHERE email_hash = $1 OR email = $2 LIMIT 1',
    [normalizedEmailHash, normalizedEmail],
  )
  const user = mapUser(userResult.rows[0])
  if (!user) {
    return res.status(200).json({
      ok: true,
      verificationEmailSent: false,
      verificationEmailReason: 'not-delivered',
      verificationEmailPreviewLink: null,
    })
  }
  if (user.verified) {
    return res.status(200).json({
      ok: true,
      verificationEmailSent: false,
      verificationEmailReason: 'not-delivered',
      verificationEmailPreviewLink: null,
    })
  }
  const verifyToken = crypto.randomBytes(32).toString('hex')
  const verifyTokenHash = hashToken(verifyToken)
  await pool.query(
    'UPDATE users SET verify_token_hash = $1, verify_token_expires_at = $2 WHERE id = $3',
    [verifyTokenHash, Date.now() + verifyTokenTtlMs, user.id],
  )
  const emailDelivery = await sendVerificationEmail(
    user.email,
    verifyToken,
    getRequestBase(req),
  )
  return res.json({
    ok: true,
    verificationEmailSent: emailDelivery.sent,
    verificationEmailReason: emailDelivery.reason,
    verificationEmailPreviewLink: emailDelivery.previewLink,
  })
})

app.get('/api/auth/verify', async (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : ''
  if (!token) {
    return res.status(400).json({ error: 'invalid-token' })
  }
  const tokenHash = hashToken(token)
  const result = await pool.query(
    'SELECT * FROM users WHERE verify_token_hash = $1 LIMIT 1',
    [tokenHash],
  )
  const user = mapUser(result.rows[0])
  if (!user) {
    return res.status(400).json({ error: 'invalid-token' })
  }
  if (user.verifyTokenExpiresAt && user.verifyTokenExpiresAt < Date.now()) {
    return res.status(400).json({ error: 'expired-token' })
  }
  await pool.query(
    'UPDATE users SET verified = TRUE, verify_token_hash = NULL, verify_token_expires_at = NULL WHERE id = $1',
    [user.id],
  )
  return res.json({ ok: true })
})

app.post('/api/mfa/setup', authLimiter, async (req, res) => {
  const session = req.session
  if (session.ownerType !== 'user') {
    return res.status(401).json({ error: 'unauthorized' })
  }
  const result = await pool.query(
    'SELECT * FROM users WHERE id = $1 LIMIT 1',
    [session.ownerId],
  )
  const user = mapUser(result.rows[0])
  if (!user) {
    return res.status(401).json({ error: 'unauthorized' })
  }
  const secret = speakeasy.generateSecret({
    name: `Nemosyne (${user.email})`,
  })
  await pool.query('UPDATE users SET mfa_temp_secret = $1 WHERE id = $2', [
    secret.base32,
    user.id,
  ])
  const qr = await qrcode.toDataURL(secret.otpauth_url)
  return res.json({ otpauthUrl: secret.otpauth_url, qr })
})

app.post('/api/mfa/enable', authLimiter, async (req, res) => {
  const { otp } = req.body || {}
  const session = req.session
  if (session.ownerType !== 'user') {
    return res.status(401).json({ error: 'unauthorized' })
  }
  const result = await pool.query(
    'SELECT * FROM users WHERE id = $1 LIMIT 1',
    [session.ownerId],
  )
  const user = mapUser(result.rows[0])
  if (!user || !user.mfaTempSecret) {
    return res.status(400).json({ error: 'no-setup' })
  }
  const valid = speakeasy.totp.verify({
    secret: user.mfaTempSecret,
    encoding: 'base32',
    token: String(otp || ''),
    window: 1,
  })
  if (!valid) {
    return res.status(400).json({ error: 'invalid-otp' })
  }
  await pool.query(
    'UPDATE users SET mfa_enabled = TRUE, mfa_secret = mfa_temp_secret, mfa_temp_secret = NULL WHERE id = $1',
    [user.id],
  )
  return res.json({ ok: true })
})

app.post('/api/mfa/disable', authLimiter, async (req, res) => {
  const { otp } = req.body || {}
  const session = req.session
  if (session.ownerType !== 'user') {
    return res.status(401).json({ error: 'unauthorized' })
  }
  const result = await pool.query(
    'SELECT * FROM users WHERE id = $1 LIMIT 1',
    [session.ownerId],
  )
  const user = mapUser(result.rows[0])
  if (!user || !user.mfaEnabled || !user.mfaSecret) {
    return res.status(400).json({ error: 'no-mfa' })
  }
  const valid = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token: String(otp || ''),
    window: 1,
  })
  if (!valid) {
    return res.status(400).json({ error: 'invalid-otp' })
  }
  await pool.query(
    'UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_temp_secret = NULL WHERE id = $1',
    [user.id],
  )
  return res.json({ ok: true })
})

app.post('/api/auth/logout', async (req, res, next) => {
  try {
    const now = Date.now()
    const anonId = crypto.randomUUID()
    const sessionId = crypto.randomUUID()
    await pool.query(
      'INSERT INTO sessions (id, owner_type, owner_id, created_at_ts, last_seen_ts) VALUES ($1, $2, $3, $4, $5)',
      [sessionId, 'anon', anonId, now, now],
    )
    req.session = {
      id: sessionId,
      ownerType: 'anon',
      ownerId: anonId,
      createdAtTs: now,
      lastSeenTs: now,
    }
    setSessionCookie(res, req.session.id)
    return res.json({ ok: true })
  } catch (error) {
    next(error)
  }
})

app.post('/api/push', createLimiter, async (req, res) => {
  const result = validatePayload(req.body)
  if (!result.ok) {
    return res.status(400).json({ error: result.error })
  }
  const session = req.session
  const id = crypto.randomUUID()
  const payload = {
    id,
    ownerType: session.ownerType,
    ownerId: session.ownerId,
    ...result.value,
  }
  try {
    await pool.query(
      `INSERT INTO pushes
        (id, owner_type, owner_id, kind, label, created_at_ts, expires_at_ts, views_left, cipher, iv, salt, requires_passphrase, filename, mime, size)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        payload.id,
        payload.ownerType,
        payload.ownerId,
        payload.kind,
        encryptField(payload.label),
        payload.createdAtTs,
        payload.expiresAtTs,
        payload.viewsLeft,
        payload.cipher,
        payload.iv,
        payload.salt ?? null,
        payload.requiresPassphrase,
        payload.filename ? encryptField(payload.filename) : null,
        payload.mime ? encryptField(payload.mime) : null,
        payload.size ?? null,
      ],
    )
    return res.status(201).json({ id })
  } catch (error) {
    console.error('Failed to insert push', error)
    return res.status(500).json({ error: 'server-error' })
  }
})

app.post('/api/push/purge', async (_req, res) => {
  await purgeExpiredPushes()
  return res.json({ purged: true })
})

app.get('/api/push', async (req, res) => {
  const session = req.session
  const now = Date.now()
  const result = await pool.query(
    `SELECT * FROM pushes
     WHERE owner_type = $1 AND owner_id = $2 AND expires_at_ts > $3 AND views_left > 0
     ORDER BY created_at_ts DESC
     LIMIT 5`,
    [session.ownerType, session.ownerId, now],
  )
  const summaries = result.rows.map(mapPush).map(getSummary)
  return res.json({ items: summaries })
})

app.get('/api/push/:id/meta', async (req, res) => {
  if (!isValidId(req.params.id)) {
    return res.status(400).json({ error: 'invalid-id' })
  }
  const now = Date.now()
  const result = await pool.query(
    `SELECT * FROM pushes WHERE id = $1 AND expires_at_ts > $2 AND views_left > 0 LIMIT 1`,
    [req.params.id, now],
  )
  const item = mapPush(result.rows[0])
  if (!item) {
    return res.status(404).json({ error: 'not-found' })
  }
  return res.json(getSummary(item))
})

app.post(
  '/api/push/:id/reveal',
  revealLimiterByIp,
  revealLimiterById,
  async (req, res) => {
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: 'invalid-id' })
    }
    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      const now = Date.now()
      const selectResult = await client.query(
        'SELECT * FROM pushes WHERE id = $1 FOR UPDATE',
        [req.params.id],
      )
      const row = selectResult.rows[0]
      const item = mapPush(row)
      if (
        !item ||
        item.expiresAtTs <= now ||
        item.viewsLeft <= 0
      ) {
        await client.query('ROLLBACK')
        return res.status(404).json({ error: 'not-found' })
      }
      const nextViews = item.viewsLeft - 1
      if (nextViews <= 0) {
        await client.query('DELETE FROM pushes WHERE id = $1', [item.id])
      } else {
        await client.query('UPDATE pushes SET views_left = $1 WHERE id = $2', [
          nextViews,
          item.id,
        ])
      }
      await client.query('COMMIT')
      return res.json({ ...item, viewsLeft: Math.max(0, nextViews) })
    } catch (error) {
      await client.query('ROLLBACK')
      console.error('Failed to reveal push', error)
      return res.status(500).json({ error: 'server-error' })
    } finally {
      client.release()
    }
  },
)

if (process.env.NODE_ENV === 'production' && process.env.VERCEL !== '1') {
  const distPath = path.join(process.cwd(), 'dist')
  app.use(express.static(distPath))
  app.get('*', (_req, res) => {
    res.sendFile(path.join(distPath, 'index.html'))
  })
}

if (process.env.VERCEL !== '1') {
  app.listen(port, '0.0.0.0', () => {
    console.log(`Password pusher server running on ${port}`)
  })

  cron.schedule('*/5 * * * *', () => {
    purgeExpiredPushes().catch((error) => {
      console.error('cron purge failed', error)
    })
  })
}

// Final error handler: hide stack in prod
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err, _req, res, _next) => {
  console.error(err)
  res.status(500).json({ error: 'server-error' })
})

export default app
