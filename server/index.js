import express from 'express'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import cron from 'node-cron'
import helmet from 'helmet'
import rateLimit, { ipKeyGenerator } from 'express-rate-limit'
import crypto from 'crypto'
import argon2 from 'argon2'
import nodemailer from 'nodemailer'
import speakeasy from 'speakeasy'
import qrcode from 'qrcode'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const dataFile = path.join(__dirname, 'data.json')

const app = express()
const port = Number(process.env.PORT || 8787)

const isProd = process.env.NODE_ENV === 'production'
const cookieSecure = process.env.COOKIE_SECURE === 'true' || isProd
const sessionSecret =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex')
const appUrl = process.env.APP_URL || `http://localhost:${port}`

const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com'
const smtpPort = Number(process.env.SMTP_PORT || 465)
const smtpUser = process.env.SMTP_USER
const smtpPass = process.env.SMTP_PASS
const smtpFrom = process.env.SMTP_FROM || smtpUser

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

app.disable('x-powered-by')
app.set('trust proxy', 1)
const enableHsts = process.env.ENABLE_HSTS === 'true'
const enableCsp = process.env.ENABLE_CSP === 'true'

app.use(
  helmet({
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

function readStore() {
  if (!fs.existsSync(dataFile)) {
    return { pushes: [], users: [], sessions: [] }
  }
  try {
    const raw = fs.readFileSync(dataFile, 'utf8')
    const data = JSON.parse(raw)
    if (Array.isArray(data)) {
      return { pushes: data, users: [], sessions: [] }
    }
    if (!data || typeof data !== 'object') {
      return { pushes: [], users: [], sessions: [] }
    }
    return {
      pushes: Array.isArray(data.pushes) ? data.pushes : [],
      users: Array.isArray(data.users) ? data.users : [],
      sessions: Array.isArray(data.sessions) ? data.sessions : [],
    }
  } catch {
    return { pushes: [], users: [], sessions: [] }
  }
}

function writeStore(store) {
  fs.writeFileSync(dataFile, JSON.stringify(store, null, 2))
}

function purgeExpired(store) {
  const now = Date.now()
  return {
    ...store,
    pushes: store.pushes.filter(
      (item) => item.expiresAtTs > now && item.viewsLeft > 0,
    ),
  }
}

function loadStore() {
  return purgeExpired(readStore())
}

function saveStore(store) {
  writeStore(store)
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

function getRequestBase(req) {
  if (process.env.APP_URL) {
    return process.env.APP_URL.replace(/\/$/, '')
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
    return appUrl.replace(/\/$/, '')
  }
  return `${proto}://${host}`.replace(/\/$/, '')
}

function buildVerifyLink(baseUrl, token) {
  return `${baseUrl}/verify?token=${encodeURIComponent(token)}`
}

async function sendVerificationEmail(email, token, baseUrl) {
  if (!mailer || !smtpFrom) return false
  const link = buildVerifyLink(baseUrl, token)
  await mailer.sendMail({
    from: smtpFrom,
    to: email,
    subject: 'Vérification de votre email',
    text: `Cliquez sur ce lien pour vérifier votre email: ${link}`,
  })
  return true
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

function ensureSession(req, res, next) {
  const cookies = parseCookies(req.headers.cookie)
  const store = loadStore()
  const sessionId = verifySessionCookie(cookies.nsid)
  const now = Date.now()

  let session = sessionId
    ? store.sessions.find((item) => item.id === sessionId)
    : null

  if (!session) {
    const anonId = crypto.randomUUID()
    session = {
      id: crypto.randomUUID(),
      ownerType: 'anon',
      ownerId: anonId,
      createdAtTs: now,
      lastSeenTs: now,
    }
    store.sessions.push(session)
    saveStore(store)
    setSessionCookie(res, session.id)
  } else {
    session.lastSeenTs = now
    saveStore(store)
  }

  req.session = session
  req.store = store
  next()
}

app.use('/api', (req, res, next) => {
  res.locals.secureCookies = cookieSecure
  next()
})

app.use('/api', ensureSession)

app.get('/api/session', (req, res) => {
  const session = req.session
  const store = req.store
  const user =
    session.ownerType === 'user'
      ? store.users.find((item) => item.id === session.ownerId)
      : null
  return res.json({
    authenticated: Boolean(user),
    email: user?.email ?? null,
    ownerType: session.ownerType,
    verified: user?.verified ?? false,
    mfaEnabled: user?.mfaEnabled ?? false,
  })
})

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password } = req.body || {}
  const normalizedEmail = typeof email === 'string' ? email.toLowerCase().trim() : ''
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
  const store = req.store
  const existing = store.users.find((item) => item.email === normalizedEmail)
  if (existing) {
    return res.status(409).json({ error: 'email-taken' })
  }
  const passwordHash = await hashPassword(password)
  const verifyToken = crypto.randomBytes(32).toString('hex')
  const verifyTokenHash = hashToken(verifyToken)
  const user = {
    id: crypto.randomUUID(),
    email: normalizedEmail,
    passwordHash,
    createdAtTs: Date.now(),
    verified: false,
    verifyTokenHash,
    verifyTokenExpiresAt: Date.now() + verifyTokenTtlMs,
    mfaEnabled: false,
    mfaSecret: null,
    mfaTempSecret: null,
  }
  store.users.push(user)
  const newSessionId = crypto.randomUUID()
  req.session.id = newSessionId
  req.session.ownerType = 'user'
  req.session.ownerId = user.id
  saveStore(store)
  setSessionCookie(res, req.session.id)
  await sendVerificationEmail(user.email, verifyToken, getRequestBase(req))
  return res.json({ ok: true, email: user.email })
})

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password, otp } = req.body || {}
  const normalizedEmail = typeof email === 'string' ? email.toLowerCase().trim() : ''
  if (!isValidEmail(normalizedEmail) || typeof password !== 'string') {
    return res.status(400).json({ error: 'invalid-credentials' })
  }
  const store = req.store
  const user = store.users.find((item) => item.email === normalizedEmail)
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
  const newSessionId = crypto.randomUUID()
  req.session.id = newSessionId
  req.session.ownerType = 'user'
  req.session.ownerId = user.id
  saveStore(store)
  setSessionCookie(res, req.session.id)
  return res.json({ ok: true, email: user.email })
})

app.post('/api/auth/resend-verification', verifyLimiter, async (req, res) => {
  const { email } = req.body || {}
  const normalizedEmail = typeof email === 'string' ? email.toLowerCase().trim() : ''
  if (!isValidEmail(normalizedEmail)) {
    return res.status(400).json({ error: 'invalid-email' })
  }
  const store = req.store
  const user = store.users.find((item) => item.email === normalizedEmail)
  if (!user) {
    return res.status(200).json({ ok: true })
  }
  if (user.verified) {
    return res.status(200).json({ ok: true })
  }
  const verifyToken = crypto.randomBytes(32).toString('hex')
  user.verifyTokenHash = hashToken(verifyToken)
  user.verifyTokenExpiresAt = Date.now() + verifyTokenTtlMs
  saveStore(store)
  await sendVerificationEmail(user.email, verifyToken, getRequestBase(req))
  return res.json({ ok: true })
})

app.get('/api/auth/verify', async (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : ''
  if (!token) {
    return res.status(400).json({ error: 'invalid-token' })
  }
  const store = req.store
  const tokenHash = hashToken(token)
  const user = store.users.find((item) => item.verifyTokenHash === tokenHash)
  if (!user) {
    return res.status(400).json({ error: 'invalid-token' })
  }
  if (user.verifyTokenExpiresAt && user.verifyTokenExpiresAt < Date.now()) {
    return res.status(400).json({ error: 'expired-token' })
  }
  user.verified = true
  user.verifyTokenHash = null
  user.verifyTokenExpiresAt = null
  saveStore(store)
  return res.json({ ok: true })
})

app.post('/api/mfa/setup', authLimiter, async (req, res) => {
  const store = req.store
  const session = req.session
  if (session.ownerType !== 'user') {
    return res.status(401).json({ error: 'unauthorized' })
  }
  const user = store.users.find((item) => item.id === session.ownerId)
  if (!user) {
    return res.status(401).json({ error: 'unauthorized' })
  }
  const secret = speakeasy.generateSecret({
    name: `Nemosyne (${user.email})`,
  })
  user.mfaTempSecret = secret.base32
  saveStore(store)
  const qr = await qrcode.toDataURL(secret.otpauth_url)
  return res.json({ otpauthUrl: secret.otpauth_url, qr })
})

app.post('/api/mfa/enable', authLimiter, async (req, res) => {
  const { otp } = req.body || {}
  const store = req.store
  const session = req.session
  if (session.ownerType !== 'user') {
    return res.status(401).json({ error: 'unauthorized' })
  }
  const user = store.users.find((item) => item.id === session.ownerId)
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
  user.mfaEnabled = true
  user.mfaSecret = user.mfaTempSecret
  user.mfaTempSecret = null
  saveStore(store)
  return res.json({ ok: true })
})

app.post('/api/mfa/disable', authLimiter, async (req, res) => {
  const { otp } = req.body || {}
  const store = req.store
  const session = req.session
  if (session.ownerType !== 'user') {
    return res.status(401).json({ error: 'unauthorized' })
  }
  const user = store.users.find((item) => item.id === session.ownerId)
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
  user.mfaEnabled = false
  user.mfaSecret = null
  saveStore(store)
  return res.json({ ok: true })
})

app.post('/api/auth/logout', (req, res) => {
  req.session.ownerType = 'anon'
  req.session.ownerId = crypto.randomUUID()
  saveStore(req.store)
  setSessionCookie(res, req.session.id)
  return res.json({ ok: true })
})

app.post('/api/push', createLimiter, (req, res) => {
  const result = validatePayload(req.body)
  if (!result.ok) {
    return res.status(400).json({ error: result.error })
  }
  const store = req.store
  const session = req.session
  const id = crypto.randomUUID()
  const payload = {
    id,
    ownerType: session.ownerType,
    ownerId: session.ownerId,
    ...result.value,
  }
  store.pushes.push(payload)
  saveStore(store)
  return res.status(201).json({ id })
})

app.post('/api/push/purge', (_req, res) => {
  const store = loadStore()
  saveStore(store)
  return res.json({ purged: true })
})

app.get('/api/push', (req, res) => {
  const store = req.store
  const session = req.session
  const summaries = store.pushes
    .filter(
      (item) =>
        item.ownerType === session.ownerType && item.ownerId === session.ownerId,
    )
    .sort((a, b) => b.createdAtTs - a.createdAtTs)
    .slice(0, 5)
    .map(getSummary)
  saveStore(store)
  return res.json({ items: summaries })
})

app.get('/api/push/:id/meta', (req, res) => {
  if (!isValidId(req.params.id)) {
    return res.status(400).json({ error: 'invalid-id' })
  }
  const store = loadStore()
  const item = store.pushes.find((entry) => entry.id === req.params.id)
  if (!item) {
    saveStore(store)
    return res.status(404).json({ error: 'not-found' })
  }
  saveStore(store)
  return res.json(getSummary(item))
})

app.post(
  '/api/push/:id/reveal',
  revealLimiterByIp,
  revealLimiterById,
  (req, res) => {
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: 'invalid-id' })
    }
    const store = loadStore()
    const index = store.pushes.findIndex((entry) => entry.id === req.params.id)
    if (index === -1) {
      saveStore(store)
      return res.status(404).json({ error: 'not-found' })
    }
    const item = store.pushes[index]
    const nextViews = item.viewsLeft - 1
    if (nextViews <= 0) {
      store.pushes.splice(index, 1)
    } else {
      store.pushes[index] = { ...item, viewsLeft: nextViews }
    }
    saveStore(store)
    return res.json({ ...item, viewsLeft: Math.max(0, nextViews) })
  },
)

if (process.env.NODE_ENV === 'production') {
  const distPath = path.join(process.cwd(), 'dist')
  app.use(express.static(distPath))
  app.get('*', (_req, res) => {
    res.sendFile(path.join(distPath, 'index.html'))
  })
}

app.listen(port, '0.0.0.0', () => {
  console.log(`Password pusher server running on ${port}`)
})

cron.schedule('*/5 * * * *', () => {
  const store = loadStore()
  saveStore(store)
})
