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
import Stripe from 'stripe'
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

let planEnabled = false

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
      mfa_temp_secret text
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
}

async function ensurePlanSupport() {
  try {
    await pool.query(`
      ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS plan text NOT NULL DEFAULT 'free';
      ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS plan_changed_at_ts bigint;
    `)
    planEnabled = true
  } catch (error) {
    planEnabled = false
    console.warn('Plan columns unavailable, falling back to starter-only mode', error)
  }
}

const dbReady = (async () => {
  if (shouldMigrate) {
    await initDb().catch((error) => {
      console.error('Failed to initialize database', error)
      throw error
    })
  }
  await ensurePlanSupport()
})()

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

const stripeSecretKey = process.env.STRIPE_SECRET_KEY
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET
const stripePricePremium = process.env.STRIPE_PRICE_PREMIUM
const stripePricePro = process.env.STRIPE_PRICE_PRO
const stripe =
  stripeSecretKey && Stripe
    ? new Stripe(stripeSecretKey, { apiVersion: '2023-10-16' })
    : null

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

// Stripe webhook (doit recevoir le corps brut)
app.post(
  '/api/billing/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    if (!stripe || !stripeWebhookSecret) {
      return res.status(503).send('stripe-unavailable')
    }
    const signature = req.headers['stripe-signature']
    let event
    try {
      event = stripe.webhooks.constructEvent(req.body, signature, stripeWebhookSecret)
    } catch (error) {
      console.error('Stripe signature failed', error.message)
      return res.status(400).send(`Webhook Error: ${error.message}`)
    }

    const applyPlan = async (meta) => {
      const userId = meta?.userId
      const plan = meta?.plan
      if (userId && plan && planCatalog[plan]) {
        await pool.query(
          'UPDATE users SET plan = $1, plan_changed_at_ts = $2 WHERE id = $3',
          [plan, Date.now(), userId],
        )
        console.log(`Stripe webhook: plan ${plan} appliqué pour user ${userId}`)
      }
    }

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object
      await applyPlan(session.metadata)
    } else if (event.type === 'invoice.payment_succeeded') {
      const invoice = event.data.object
      if (invoice.subscription && stripe) {
        const subscription = await stripe.subscriptions.retrieve(invoice.subscription)
        await applyPlan(subscription.metadata)
      }
    } else if (event.type === 'customer.subscription.updated') {
      const subscription = event.data.object
      await applyPlan(subscription.metadata)
    }

    return res.json({ received: true })
  },
)

app.use(express.json({ limit: '25mb' }))

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
const absoluteMaxFileBytes = 15 * 1024 * 1024
const maxCipherBase64Len = Math.ceil((absoluteMaxFileBytes * 4) / 3) + 8
const defaultMaxTtlMs = 7 * 24 * 60 * 60 * 1000
const defaultMaxViews = 20
const maxLabelLength = 64
const idPattern = /^[0-9a-fA-F-]{36}$/
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const minPasswordLength = 12
const maxPasswordLength = 128
const verifyTokenTtlMs = 1000 * 60 * 60

const planCatalog = {
  free: {
    id: 'free',
    label: 'Starter',
    monthlyPushLimit: 10,
    maxTtlMs: 24 * 60 * 60 * 1000, // 24h
    maxViews: 5,
    maxFileBytes: 2 * 1024 * 1024, // 2MB
    historyLimit: 5,
  },
  premium: {
    id: 'premium',
    label: 'Premium',
    monthlyPushLimit: null, // unlimited
    maxTtlMs: 3 * 24 * 60 * 60 * 1000, // 72h
    maxViews: 12,
    maxFileBytes: 8 * 1024 * 1024, // 8MB
    historyLimit: 30,
  },
  pro: {
    id: 'pro',
    label: 'Pro',
    monthlyPushLimit: null, // unlimited
    maxTtlMs: defaultMaxTtlMs, // 7 days
    maxViews: defaultMaxViews,
    maxFileBytes: absoluteMaxFileBytes, // 15MB
    historyLimit: 100,
  },
}

function getPlanLimits(planId) {
  return planCatalog[planId] ?? planCatalog.free
}

function getCurrentCycleBounds(now = Date.now()) {
  const start = new Date(now)
  start.setUTCHours(0, 0, 0, 0)
  start.setUTCDate(1)
  const next = new Date(start)
  next.setUTCMonth(next.getUTCMonth() + 1)
  return { startTs: start.getTime(), nextResetTs: next.getTime() }
}

function mapUser(row) {
  if (!row) return null
  return {
    id: row.id,
    email: row.email,
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
    plan: row.plan || 'free',
    planChangedAtTs: row.plan_changed_at_ts ? Number(row.plan_changed_at_ts) : null,
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

async function getUserById(userId) {
  const result = await pool.query('SELECT * FROM users WHERE id = $1 LIMIT 1', [
    userId,
  ])
  return mapUser(result.rows[0])
}

function mapPush(row) {
  if (!row) return null
  return {
    id: row.id,
    ownerType: row.owner_type,
    ownerId: row.owner_id,
    kind: row.kind,
    label: row.label,
    createdAtTs: Number(row.created_at_ts),
    expiresAtTs: Number(row.expires_at_ts),
    viewsLeft: row.views_left,
    cipher: row.cipher,
    iv: row.iv,
    salt: row.salt,
    requiresPassphrase: row.requires_passphrase,
    filename: row.filename,
    mime: row.mime,
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

async function getUsageForUser(userId, planId) {
  const limits = getPlanLimits(planId)
  const { startTs, nextResetTs } = getCurrentCycleBounds()
  const result = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM pushes
     WHERE owner_type = 'user' AND owner_id = $1 AND created_at_ts >= $2`,
    [userId, startTs],
  )
  const used = Number(result.rows[0]?.count || 0)
  return {
    used,
    limit: limits.monthlyPushLimit,
    nextResetTs,
  }
}

async function buildPlanResponse(user) {
  if (!user) {
    return {
      plan: 'free',
      label: planCatalog.free.label,
      monthlyPushLimit: planCatalog.free.monthlyPushLimit,
      monthlyUsed: 0,
      maxTtlMs: planCatalog.free.maxTtlMs,
      maxViews: planCatalog.free.maxViews,
      maxFileBytes: planCatalog.free.maxFileBytes,
      historyLimit: planCatalog.free.historyLimit,
      nextResetTs: getCurrentCycleBounds().nextResetTs,
      planEnabled: planEnabled,
    }
  }
  const limits = getPlanLimits(user.plan)
  const usage = await getUsageForUser(user.id, user.plan)
  return {
    plan: user.plan,
    label: limits.label,
    monthlyPushLimit: limits.monthlyPushLimit,
    monthlyUsed: usage.used,
    maxTtlMs: limits.maxTtlMs,
    maxViews: limits.maxViews,
    maxFileBytes: limits.maxFileBytes,
    historyLimit: limits.historyLimit,
    nextResetTs: usage.nextResetTs,
    planEnabled: planEnabled,
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

function validatePayload(payload, planLimits) {
  const limits = planLimits ?? planCatalog.free
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
  const maxTtlMs = limits.maxTtlMs ?? defaultMaxTtlMs
  if (expiresAtTs <= now) {
    return { ok: false, error: 'invalid-expiry' }
  }
  if (expiresAtTs - now > maxTtlMs) {
    return { ok: false, error: 'plan-expiry-limit' }
  }
  const maxViews = limits.maxViews ?? defaultMaxViews
  const requestedViews = Number(payload.viewsLeft)
  if (!Number.isFinite(requestedViews) || requestedViews < 1) {
    return { ok: false, error: 'invalid-views' }
  }
  if (requestedViews > maxViews) {
    return { ok: false, error: 'plan-views-limit' }
  }
  const viewsLeft = Math.min(maxViews, Math.max(1, requestedViews))
  if (kind === 'file') {
    if (
      typeof payload.filename !== 'string' ||
      payload.filename.length < 1 ||
      payload.filename.length > 200
    ) {
      return { ok: false, error: 'invalid-filename' }
    }
    const size = Number(payload.size)
    const maxFileBytes = limits.maxFileBytes ?? absoluteMaxFileBytes
    if (!Number.isFinite(size) || size <= 0) {
      return { ok: false, error: 'invalid-file-size' }
    }
    if (size > maxFileBytes) {
      return { ok: false, error: 'plan-file-limit' }
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
      user = await getUserById(session.ownerId)
    }
    return res.json({
      authenticated: Boolean(user),
      email: user?.email ?? null,
      ownerType: session.ownerType,
      verified: user?.verified ?? false,
      mfaEnabled: user?.mfaEnabled ?? false,
      plan: user?.plan ?? 'free',
    })
  } catch (error) {
    next(error)
  }
})

app.get('/api/plan', async (req, res, next) => {
  try {
    await dbReady
    const session = req.session
    if (session.ownerType !== 'user') {
      return res.status(401).json({ error: 'unauthorized', plan: 'free' })
    }
    const user = await getUserById(session.ownerId)
    if (!user) {
      return res.status(401).json({ error: 'unauthorized' })
    }
    const plan = await buildPlanResponse(user)
    return res.json(plan)
  } catch (error) {
    next(error)
  }
})

app.post('/api/plan/select', authLimiter, async (req, res, next) => {
  try {
    await dbReady
    const session = req.session
    if (session.ownerType !== 'user') {
      return res.status(401).json({ error: 'unauthorized' })
    }
    const requested =
      typeof req.body?.plan === 'string' ? req.body.plan.toLowerCase().trim() : ''
    if (!requested || !planCatalog[requested]) {
      return res.status(400).json({ error: 'invalid-plan' })
    }
    if (!planEnabled) {
      return res.status(503).json({ error: 'plan-storage-unavailable' })
    }
    await pool.query(
      'UPDATE users SET plan = $1, plan_changed_at_ts = $2 WHERE id = $3',
      [requested, Date.now(), session.ownerId],
    )
    const user = await getUserById(session.ownerId)
    const plan = await buildPlanResponse(user)
    return res.json(plan)
  } catch (error) {
    next(error)
  }
})

app.post('/api/billing/checkout', authLimiter, async (req, res, next) => {
  try {
    await dbReady
    if (req.session.ownerType !== 'user') {
      return res.status(401).json({ error: 'unauthorized' })
    }
    if (!stripe || !stripePricePremium || !stripePricePro) {
      return res.status(503).json({ error: 'stripe-unavailable' })
    }
    const requested =
      typeof req.body?.plan === 'string' ? req.body.plan.toLowerCase().trim() : ''
    if (!['premium', 'pro'].includes(requested)) {
      return res.status(400).json({ error: 'invalid-plan' })
    }
    const user = await getUserById(req.session.ownerId)
    const priceId = requested === 'premium' ? stripePricePremium : stripePricePro
    const successUrl =
      typeof req.body?.successUrl === 'string' && req.body.successUrl.startsWith('http')
        ? req.body.successUrl
        : `${appUrl}/?checkout=success`
    const cancelUrl =
      typeof req.body?.cancelUrl === 'string' && req.body.cancelUrl.startsWith('http')
        ? req.body.cancelUrl
        : `${appUrl}/pricing?checkout=cancel`

    const sessionStripe = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      customer_email: user?.email,
      metadata: { userId: req.session.ownerId, plan: requested },
      subscription_data: { metadata: { userId: req.session.ownerId, plan: requested } },
      success_url: successUrl,
      cancel_url: cancelUrl,
    })
    return res.json({ url: sessionStripe.url })
  } catch (error) {
    next(error)
  }
})

app.post('/api/auth/register', authLimiter, async (req, res) => {
  await dbReady
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
  const existing = await pool.query('SELECT id FROM users WHERE email = $1 LIMIT 1', [
    normalizedEmail,
  ])
  if (existing.rowCount > 0) {
    return res.status(409).json({ error: 'email-taken' })
  }
  const passwordHash = await hashPassword(password)
  const verifyToken = crypto.randomBytes(32).toString('hex')
  const verifyTokenHash = hashToken(verifyToken)
  const now = Date.now()
  const userId = crypto.randomUUID()
  const columns = [
    'id',
    'email',
    'password_hash',
    'created_at_ts',
    'verified',
    'verify_token_hash',
    'verify_token_expires_at',
    'mfa_enabled',
    'mfa_secret',
    'mfa_temp_secret',
  ]
  const values = [
    userId,
    normalizedEmail,
    passwordHash,
    now,
    false,
    verifyTokenHash,
    now + verifyTokenTtlMs,
    false,
    null,
    null,
  ]
  if (planEnabled) {
    columns.push('plan', 'plan_changed_at_ts')
    values.push('free', now)
  }
  const placeholders = columns.map((_, index) => `$${index + 1}`)
  await pool.query(
    `INSERT INTO users (${columns.join(', ')}) VALUES (${placeholders.join(', ')})`,
    values,
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
  await sendVerificationEmail(normalizedEmail, verifyToken, getRequestBase(req))
  return res.json({ ok: true, email: normalizedEmail })
})

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password, otp } = req.body || {}
  const normalizedEmail = typeof email === 'string' ? email.toLowerCase().trim() : ''
  if (!isValidEmail(normalizedEmail) || typeof password !== 'string') {
    return res.status(400).json({ error: 'invalid-credentials' })
  }
  const userResult = await pool.query(
    'SELECT * FROM users WHERE email = $1 LIMIT 1',
    [normalizedEmail],
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
  if (!isValidEmail(normalizedEmail)) {
    return res.status(400).json({ error: 'invalid-email' })
  }
  const userResult = await pool.query(
    'SELECT * FROM users WHERE email = $1 LIMIT 1',
    [normalizedEmail],
  )
  const user = mapUser(userResult.rows[0])
  if (!user) {
    return res.status(200).json({ ok: true })
  }
  if (user.verified) {
    return res.status(200).json({ ok: true })
  }
  const verifyToken = crypto.randomBytes(32).toString('hex')
  const verifyTokenHash = hashToken(verifyToken)
  await pool.query(
    'UPDATE users SET verify_token_hash = $1, verify_token_expires_at = $2 WHERE id = $3',
    [verifyTokenHash, Date.now() + verifyTokenTtlMs, user.id],
  )
  await sendVerificationEmail(user.email, verifyToken, getRequestBase(req))
  return res.json({ ok: true })
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
  await dbReady
  const session = req.session
  const user = session.ownerType === 'user' ? await getUserById(session.ownerId) : null
  const planLimits = user ? getPlanLimits(user.plan) : planCatalog.free
  const usage = user ? await getUsageForUser(user.id, user.plan) : null
  if (user && planLimits.monthlyPushLimit && usage.used >= planLimits.monthlyPushLimit) {
    return res.status(403).json({
      error: 'quota-exceeded',
      monthlyUsed: usage.used,
      monthlyLimit: planLimits.monthlyPushLimit,
      nextResetTs: usage.nextResetTs,
    })
  }
  const result = validatePayload(req.body, planLimits)
  if (!result.ok) {
    return res.status(400).json({ error: result.error })
  }
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
        payload.label,
        payload.createdAtTs,
        payload.expiresAtTs,
        payload.viewsLeft,
        payload.cipher,
        payload.iv,
        payload.salt ?? null,
        payload.requiresPassphrase,
        payload.filename ?? null,
        payload.mime ?? null,
        payload.size ?? null,
      ],
    )
    return res.status(201).json({
      id,
      monthlyUsed: usage ? usage.used + 1 : null,
      monthlyLimit: planLimits.monthlyPushLimit,
      plan: user?.plan ?? 'free',
    })
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
  let historyLimit = 5
  if (session.ownerType === 'user') {
    const user = await getUserById(session.ownerId)
    historyLimit = getPlanLimits(user?.plan).historyLimit ?? 5
  }
  const result = await pool.query(
    `SELECT * FROM pushes
     WHERE owner_type = $1 AND owner_id = $2 AND expires_at_ts > $3 AND views_left > 0
     ORDER BY created_at_ts DESC
     LIMIT $4`,
    [session.ownerType, session.ownerId, now, historyLimit],
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
