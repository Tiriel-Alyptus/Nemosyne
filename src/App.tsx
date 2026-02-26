import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import type { AuthChangeEvent, Session, User } from '@supabase/supabase-js'
import logo from './assets/logo.svg'
import VaultPage from './vault/VaultPage'
import { supabase } from './lib/supabaseClient'

type PushMeta = {
  id: string
  label: string
  createdAtTs: number
  expiresAtTs: number
  viewsLeft: number
  requiresPassphrase: boolean
}

type StoredPush = PushMeta & {
  kind: 'text' | 'file'
  cipher: string
  iv: string
  salt?: string
  filename?: string
  mime?: string
  size?: number
}

type NewPush = Omit<StoredPush, 'id'>

type PushSummary = PushMeta & {
  createdAtText: string
  expiresAtText: string
  isExpired: boolean
}

type PlanId = 'free' | 'premium' | 'pro'

type PlanInfo = {
  plan: PlanId
  label: string
  monthlyPushLimit: number | null
  monthlyUsed: number
  maxTtlMs: number
  maxViews: number
  maxFileBytes: number
  historyLimit: number
  nextResetTs: number
  planEnabled: boolean
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

const presets = [
  { label: '15 minutes', minutes: 15 },
  { label: '1 heure', minutes: 60 },
  { label: '24 heures', minutes: 60 * 24 },
  { label: '72 heures', minutes: 60 * 24 * 3, minPlan: 'premium' as PlanId },
  { label: '7 jours', minutes: 60 * 24 * 7, minPlan: 'pro' as PlanId },
]

const planOrder: Record<PlanId, number> = { free: 0, premium: 1, pro: 2 }

function nextResetTimestamp() {
  const d = new Date()
  d.setUTCDate(1)
  d.setUTCHours(0, 0, 0, 0)
  d.setUTCMonth(d.getUTCMonth() + 1)
  return d.getTime()
}

const defaultPlan: PlanInfo = {
  plan: 'free',
  label: 'Starter',
  monthlyPushLimit: 10,
  monthlyUsed: 0,
  maxTtlMs: 24 * 60 * 60 * 1000,
  maxViews: 5,
  maxFileBytes: 2 * 1024 * 1024,
  historyLimit: 5,
  nextResetTs: nextResetTimestamp(),
  planEnabled: true,
}

type PlanPricing = {
  price: string
  subtitle: string
  tagline: string
  features: string[]
  badge?: string
  badgeTone?: 'primary' | 'accent'
}

const planPricing: Record<PlanId, PlanPricing> = {
  free: {
    price: '0 €',
    subtitle: 'Compte gratuit requis',
    tagline: 'Idéal pour tester et usage perso ponctuel.',
    features: ['10 pushes / mois', 'Expiration 24h', 'Push de mots de passe gratuits'],
  },
  premium: {
    price: '19 € / mois',
    subtitle: 'Premium (solo) — aligné sur eu.pwpush.com',
    tagline: 'Le plus populaire pour les freelancers et petites équipes.',
    badge: 'Le plus populaire',
    badgeTone: 'primary',
    features: [
      'Push illimités',
      'Expiration jusqu’à 72h',
      'Fichiers chiffrés jusqu’à 8 MB',
      'Journalisation et API',
    ],
  },
  pro: {
    price: '29 € / mois',
    subtitle: 'Pro (équipes) — aligné sur eu.pwpush.com',
    tagline: 'Recommandé pour les organisations exigeantes.',
    badge: 'Recommandé',
    badgeTone: 'accent',
    features: [
      'Push illimités + 7 jours',
      'Jusqu’à 20 vues, historique étendu',
      'Audit avancé, blocage IP / MFA',
      'Gestionnaire de mots de passe & support prioritaire',
    ],
  },
}

function generateLabel() {
  const adjectives = [
    'Brise',
    'Quartz',
    'Serein',
    'Opale',
    'Nimbus',
    'Saumon',
    'Neon',
    'Ivory',
    'Cobalt',
    'Oasis',
    'Prisme',
    'Sienna',
  ]
  const nouns = [
    'Atlas',
    'Lynx',
    'Nova',
    'Echo',
    'Vertex',
    'Lagune',
    'Velours',
    'Comète',
    'Spline',
    'Delta',
    'Fjord',
    'Granite',
  ]
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)]
  const noun = nouns[Math.floor(Math.random() * nouns.length)]
  const suffix = Math.floor(100 + Math.random() * 900)
  return `${adj} ${noun} ${suffix}`
}
const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined)
  ?.trim()
  .replace(/\/$/, '')

function buildApiUrl(path: string) {
  if (/^https?:\/\//i.test(path)) return path
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  if (!apiBaseUrl) return normalizedPath
  return `${apiBaseUrl}${normalizedPath}`
}

function formatBytes(value: number) {
  if (!Number.isFinite(value)) return '0 B'
  if (value < 1024) return `${value} B`
  const kb = value / 1024
  if (kb < 1024) return `${kb.toFixed(1)} KB`
  const mb = kb / 1024
  return `${mb.toFixed(2)} MB`
}

function formatTime(ts: number) {
  return new Date(ts).toLocaleString('fr-FR', {
    hour: '2-digit',
    minute: '2-digit',
    day: '2-digit',
    month: 'short',
  })
}

function formatResetDate(ts: number) {
  return new Date(ts).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short' })
}

function buildLink(id: string, key?: string) {
  if (typeof window === 'undefined') return `https://local.push/${id}`
  if (!key) return `${window.location.origin}/push/${id}`
  return `${window.location.origin}/push/${id}#k=${encodeURIComponent(key)}`
}

function arrayBufferToBase64(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
}

function base64ToArrayBuffer(value: string): ArrayBuffer {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

async function apiRequest<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(buildApiUrl(path), {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    ...options,
  })
  if (!response.ok) {
    try {
      const body = (await response.json()) as { error?: string }
      if (body?.error) {
        throw new Error(`api-${response.status}:${body.error}`)
      }
    } catch {
      // ignore json parse
    }
    throw new Error(`api-${response.status}`)
  }
  return (await response.json()) as T
}

async function deriveKey(passphrase: string, salt: ArrayBuffer) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 150000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function encryptSecret(secret: string, passphrase: string) {
  const data = encoder.encode(secret)
  return encryptBytes(data.buffer, passphrase)
}

async function encryptBytes(buffer: ArrayBuffer, passphrase: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  if (passphrase.trim()) {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveKey(passphrase, salt.buffer)
    const cipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      buffer,
    )
    return {
      cipher: arrayBufferToBase64(cipher),
      iv: arrayBufferToBase64(iv.buffer),
      salt: arrayBufferToBase64(salt.buffer),
      requiresPassphrase: true,
    }
  }

  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )
  const rawKey = await crypto.subtle.exportKey('raw', key)
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    buffer,
  )
  return {
    cipher: arrayBufferToBase64(cipher),
    iv: arrayBufferToBase64(iv.buffer),
    key: arrayBufferToBase64(rawKey),
    requiresPassphrase: false,
  }
}

async function decryptSecret(payload: StoredPush, passphrase: string, inlineKey?: string) {
  const plainBuffer = await decryptBytes(payload, passphrase, inlineKey)
  return decoder.decode(plainBuffer)
}

async function decryptBytes(payload: StoredPush, passphrase: string, inlineKey?: string) {
  const iv = new Uint8Array(base64ToArrayBuffer(payload.iv))
  let key: CryptoKey

  if (payload.requiresPassphrase) {
    if (!payload.salt) throw new Error('missing-salt')
    key = await deriveKey(passphrase, base64ToArrayBuffer(payload.salt))
  } else {
    if (!inlineKey) throw new Error('missing-key')
    key = await crypto.subtle.importKey(
      'raw',
      base64ToArrayBuffer(inlineKey),
      'AES-GCM',
      false,
      ['decrypt'],
    )
  }

  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    base64ToArrayBuffer(payload.cipher),
  )

  return plainBuffer
}

function toSummary(item: PushMeta): PushSummary {
  return {
    ...item,
    createdAtText: formatTime(item.createdAtTs),
    expiresAtText: formatTime(item.expiresAtTs),
    isExpired: Date.now() > item.expiresAtTs,
  }
}

function Home() {
  const location = useLocation()
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window === 'undefined') return 'light'
    const stored = window.localStorage.getItem('theme')
    if (stored === 'light' || stored === 'dark') return stored
    return 'light' // interface blanche par défaut
  })
  const [auth, setAuth] = useState<{
    authenticated: boolean
    email: string | null
    ownerType: 'anon' | 'user'
    verified?: boolean
    mfaEnabled?: boolean
    plan?: PlanId
  }>({ authenticated: false, email: null, ownerType: 'anon', plan: 'free' })
  const [plan, setPlan] = useState<PlanInfo>(defaultPlan)
  const [supabaseUser, setSupabaseUser] = useState<User | null>(null)
  const [mfaFactors, setMfaFactors] = useState<any[]>([])
  const [mfaEnroll, setMfaEnroll] = useState<{ factorId: string; qr: string; uri?: string } | null>(
    null,
  )
  const [mfaChallenge, setMfaChallenge] = useState<{
    factorId: string
    challengeId: string
  } | null>(null)
  const [authTab, setAuthTab] = useState<'login' | 'signup' | 'reset' | 'mfa'>('login')
  const [authBanner, setAuthBanner] = useState<{
    tone: 'success' | 'error' | 'info'
    text: string
  } | null>(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [authLoading, setAuthLoading] = useState(false)
  const [showAuth, setShowAuth] = useState(false)
  const [showUpgrade, setShowUpgrade] = useState(false)
  const [paywallReason, setPaywallReason] = useState<string | null>(null)
  const [planLoading, setPlanLoading] = useState(false)
  const [secret, setSecret] = useState('')
  const [mode, setMode] = useState<'text' | 'file'>('text')
  const [file, setFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState('')
  const [label, setLabel] = useState<string>(() => generateLabel())
  const [views, setViews] = useState(3)
  const [expiry, setExpiry] = useState(presets[2].minutes)
  const [passphrase, setPassphrase] = useState('')
  const [generatedPassword, setGeneratedPassword] = useState('')
  const [passwordLength, setPasswordLength] = useState(20)
  const [useUpper, setUseUpper] = useState(true)
  const [useLower, setUseLower] = useState(true)
  const [useNumbers, setUseNumbers] = useState(true)
  const [useSymbols, setUseSymbols] = useState(true)
  const [link, setLink] = useState('')
  const [status, setStatus] = useState<
    'idle' | 'ready' | 'copied' | 'error' | 'working' | 'autocopied'
  >('idle')
  const [history, setHistory] = useState<PushSummary[]>([])
  const [toast, setToast] = useState<{
    message: string
    kind: 'success' | 'error' | 'info'
  } | null>(null)

  const showToast = (message: string, kind: 'success' | 'error' | 'info' = 'info') => {
    setToast({ message, kind })
    window.setTimeout(() => {
      setToast((current) => (current?.message === message ? null : current))
    }, 2200)
  }

  const expiryLimitMinutes = useMemo(
    () => Math.floor(plan.maxTtlMs / (60 * 1000)),
    [plan.maxTtlMs],
  )
  const paywallQuotaReached =
    plan.monthlyPushLimit !== null && plan.monthlyUsed >= plan.monthlyPushLimit

  useEffect(() => {
    if (expiry > expiryLimitMinutes) {
      setExpiry(expiryLimitMinutes)
    }
  }, [expiry, expiryLimitMinutes])

  const expiresAt = useMemo(() => {
    const date = new Date()
    date.setMinutes(date.getMinutes() + expiry)
    return date.getTime()
  }, [expiry])
  const expiresAtLabel = useMemo(() => formatTime(expiresAt), [expiresAt])

  const triggerUpgrade = (reason: string) => {
    setPaywallReason(reason)
    setShowUpgrade(true)
  }

  const fetchPlanInfo = useCallback(
    async (sessionOverride?: {
      authenticated: boolean
      plan?: PlanId
    }) => {
      const targetSession = sessionOverride
      if (!targetSession || !targetSession.authenticated) {
        setPlan(defaultPlan)
        return
      }
      try {
        const planData = await apiRequest<PlanInfo>('/api/plan')
        setPlan(planData)
      } catch {
        setPlan(defaultPlan)
      }
    },
    [],
  )

  const syncSupabaseSession = useCallback(
    async (session?: Session | null) => {
      const token =
        session?.access_token ??
        (await supabase.auth.getSession()).data.session?.access_token
      if (!token) return
      try {
        const result = await apiRequest<{
          ok: boolean
          email: string
          verified: boolean
          plan?: PlanInfo
        }>('/api/auth/supabase-sync', {
          method: 'POST',
          body: JSON.stringify({ accessToken: token }),
        })
        setAuth((current) => ({
          authenticated: true,
          email: result.email,
          ownerType: 'user',
          verified: result.verified,
          mfaEnabled: current.mfaEnabled,
          plan: result.plan?.plan ?? current.plan ?? 'free',
        }))
        if (result.plan) {
          setPlan(result.plan)
        }
      } catch (error) {
        console.warn('Impossible de synchroniser la session Supabase', error)
      }
    },
    [],
  )

  const refreshMfaFactors = useCallback(async () => {
    try {
      const session = await supabase.auth.getSession()
      if (!session.data.session) {
        return false
      }
      const { data, error } = await supabase.auth.mfa.listFactors()
      if (error || !data) return false
      const factors = data.all ?? []
      setMfaFactors(factors)
      const hasVerifiedTotp = factors.some(
        (factor) => factor.factor_type === 'totp' && factor.status === 'verified',
      )
      setAuth((current) => ({ ...current, mfaEnabled: hasVerifiedTotp }))
      return hasVerifiedTotp
    } catch (error) {
      console.warn('Liste MFA Supabase impossible', error)
      return false
    }
  }, [])

  const friendlyAuthError = (message?: string) => {
    if (!message) return 'Action impossible.'
    if (message.includes('Invalid login credentials')) return 'Identifiants invalides.'
    if (message.includes('Email rate limit exceeded')) return 'Trop de tentatives, patiente 30s.'
    if (message.includes('Email not confirmed')) return 'VÃ©rifie ton email avant de te connecter.'
    return message
  }

  const handleSelectPlan = async (nextPlan: PlanId) => {
    if (nextPlan === 'free') {
      setPlan(defaultPlan)
      setShowUpgrade(false)
      return
    }
    if (!auth.authenticated) {
      setShowAuth(true)
      triggerUpgrade('Connexion requise pour choisir un plan')
      return
    }
    setPlanLoading(true)
    try {
      if (nextPlan === 'premium' || nextPlan === 'pro') {
        const origin = typeof window !== 'undefined' ? window.location.origin : ''
        const successUrl = `${origin}/?checkout=success`
        const cancelUrl = `${origin}/pricing?checkout=cancel`
        const checkout = await apiRequest<{ url: string }>('/api/billing/checkout', {
          method: 'POST',
          body: JSON.stringify({ plan: nextPlan, successUrl, cancelUrl }),
        })
        if (!checkout.url) {
          throw new Error('stripe-unavailable')
        }
        window.location.href = checkout.url
        return
      }
      const result = await apiRequest<PlanInfo>('/api/plan/select', {
        method: 'POST',
        body: JSON.stringify({ plan: nextPlan }),
      })
      setPlan(result)
      setShowUpgrade(false)
      showToast('Plan mis \u00e0 jour.', 'success')
    } catch (error) {
      const msg = error instanceof Error ? error.message : `${error}`
      if (msg.includes('plan-storage-unavailable')) {
        showToast('Mise \u00e0 niveau impossible (migration DB requise).', 'error')
      } else if (msg.includes('api-401')) {
        setShowAuth(true)
        triggerUpgrade('Connecte-toi ou cr\u00e9e un compte pour souscrire.')
      } else if (msg.includes('stripe-unavailable') || msg.includes('no-checkout-url')) {
        showToast('Stripe non configur\u00e9 (cl\u00e9/price manquants ?)', 'error')
      } else {
        showToast('Impossible de changer de plan.', 'error')
      }
    } finally {
      setPlanLoading(false)
    }
  }

  useEffect(() => {
    const hydrate = async () => {
      try {
        const session = await apiRequest<{
          authenticated: boolean
          email: string | null
          ownerType: 'anon' | 'user'
          verified: boolean
          mfaEnabled: boolean
          plan: PlanId
        }>('/api/session')
        setAuth(session)
        await fetchPlanInfo(session)
        await apiRequest('/api/push/purge', { method: 'POST' })
        const data = await apiRequest<{ items: PushMeta[] }>('/api/push')
        setHistory(data.items.map(toSummary))
      } catch {
        setPlan(defaultPlan)
        setHistory([])
      }
    }
    hydrate()
  }, [fetchPlanInfo])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    window.localStorage.setItem('theme', theme)
  }, [theme])

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const checkout = params.get('checkout')
    if (checkout === 'success') {
      showToast('Paiement confirmé, mise à jour du plan…', 'success')
      fetchPlanInfo()
      setShowUpgrade(false)
    } else if (checkout === 'cancel') {
      showToast('Paiement annulé.', 'info')
    }
    if (checkout) {
      window.history.replaceState({}, '', location.pathname)
    }
  }, [location.search, fetchPlanInfo])

  const refreshHistory = useCallback(async () => {
    try {
      const session = await apiRequest<{
        authenticated: boolean
        email: string | null
        ownerType: 'anon' | 'user'
        verified: boolean
        mfaEnabled: boolean
        plan: PlanId
      }>('/api/session')
      setAuth(session)
      await fetchPlanInfo(session)
      const data = await apiRequest<{ items: PushMeta[] }>('/api/push')
      setHistory(data.items.map(toSummary))
    } catch {
      setPlan(defaultPlan)
      setHistory([])
    }
  }, [fetchPlanInfo])

  useEffect(() => {
    const bootstrapSupabase = async () => {
      const { data } = await supabase.auth.getSession()
      setSupabaseUser(data.session?.user ?? null)
      if (data.session?.access_token) {
        await syncSupabaseSession(data.session)
        await refreshMfaFactors()
        await refreshHistory()
      }
    }
    bootstrapSupabase()
    const { data: listener } = supabase.auth.onAuthStateChange(
      async (_event: AuthChangeEvent, session) => {
        setSupabaseUser(session?.user ?? null)
        if (session?.access_token) {
          await syncSupabaseSession(session)
          await refreshMfaFactors()
          await refreshHistory()
          setShowAuth(false)
        } else {
          setAuth({ authenticated: false, email: null, ownerType: 'anon', plan: 'free' })
          setPlan(defaultPlan)
          setSupabaseUser(null)
        }
      },
    )
    return () => {
      listener.subscription.unsubscribe()
    }
  }, [refreshHistory, refreshMfaFactors, syncSupabaseSession])

  useEffect(() => {
    if (supabaseUser) {
      const verifiedFromSupabase = Boolean(
        (supabaseUser as any)?.email_confirmed_at || (supabaseUser as any)?.confirmed_at,
      )
      setAuth((current) => ({
        authenticated: true,
        email: supabaseUser.email ?? current.email ?? null,
        ownerType: 'user',
        verified: verifiedFromSupabase || current.verified,
        mfaEnabled: current.mfaEnabled,
        plan: current.plan ?? 'free',
      }))
    }
  }, [supabaseUser])

  const handleLogin = async () => {
    setAuthLoading(true)
    setAuthBanner(null)
    setMfaChallenge(null)
    const normalizedEmail = email.trim().toLowerCase()
    if (!normalizedEmail || !normalizedEmail.includes('@')) {
      setAuthBanner({ tone: 'error', text: 'Email invalide.' })
      setAuthLoading(false)
      return
    }
    if (password.length < 12) {
      setAuthBanner({ tone: 'error', text: 'Mot de passe trop court (12 caractères mini).' })
      setAuthLoading(false)
      return
    }
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email: normalizedEmail,
        password,
      })
      if (error) {
        setAuthBanner({ tone: 'error', text: friendlyAuthError(error.message) })
        return
      }
      const { data: aalData } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel()
      if (aalData?.nextLevel === 'aal2') {
        const factors = await supabase.auth.mfa.listFactors()
        const totpFactor = factors.data?.all?.find(
          (factor) => factor.factor_type === 'totp' && factor.status === 'verified',
        )
        if (totpFactor) {
          const challenge = await supabase.auth.mfa.challenge({ factorId: totpFactor.id })
          if (challenge.error || !challenge.data?.id) {
            setAuthBanner({ tone: 'error', text: 'Impossible de créer le challenge MFA.' })
          } else {
            setMfaChallenge({ factorId: totpFactor.id, challengeId: challenge.data.id })
            setAuthTab('mfa')
            setAuthBanner({ tone: 'info', text: 'Entre ton code MFA pour terminer.' })
            return
          }
        }
      }
      setAuthBanner({ tone: 'success', text: 'Connexion OK, synchronisation en cours…' })
      await syncSupabaseSession(data.session)
      await refreshMfaFactors()
      await refreshHistory()
      setShowAuth(false)
    } catch (error) {
      setAuthBanner({ tone: 'error', text: friendlyAuthError((error as Error)?.message) })
    } finally {
      setAuthLoading(false)
    }
  }

  const handleRegister = async () => {
    setAuthLoading(true)
    setAuthBanner(null)
    const normalizedEmail = email.trim().toLowerCase()
    if (!normalizedEmail || !normalizedEmail.includes('@')) {
      setAuthBanner({ tone: 'error', text: 'Email invalide.' })
      setAuthLoading(false)
      return
    }
    if (password.length < 12) {
      setAuthBanner({ tone: 'error', text: 'Mot de passe trop court (12 caractères mini).' })
      setAuthLoading(false)
      return
    }
    try {
      const redirectTo =
        typeof window !== 'undefined' ? `${window.location.origin}/verify` : undefined
      const { error } = await supabase.auth.signUp({
        email: normalizedEmail,
        password,
        options: { emailRedirectTo: redirectTo },
      })
      if (error) {
        setAuthBanner({ tone: 'error', text: friendlyAuthError(error.message) })
      } else {
        setAuthBanner({
          tone: 'success',
          text: 'Compte créé. Vérifie ta boîte mail pour activer ton compte.',
        })
        setAuthTab('login')
      }
    } catch (error) {
      setAuthBanner({ tone: 'error', text: friendlyAuthError((error as Error)?.message) })
    } finally {
      setAuthLoading(false)
    }
  }

  const handleResetPassword = async () => {
    setAuthLoading(true)
    setAuthBanner(null)
    const normalizedEmail = email.trim().toLowerCase()
    if (!normalizedEmail || !normalizedEmail.includes('@')) {
      setAuthBanner({ tone: 'error', text: 'Email invalide.' })
      setAuthLoading(false)
      return
    }
    try {
      const redirectTo =
        typeof window !== 'undefined'
          ? `${window.location.origin}/verify?type=recovery`
          : undefined
      const { error } = await supabase.auth.resetPasswordForEmail(normalizedEmail, {
        redirectTo,
      })
      if (error) {
        setAuthBanner({ tone: 'error', text: friendlyAuthError(error.message) })
      } else {
        setAuthBanner({
          tone: 'success',
          text: 'Email de réinitialisation envoyé. Vérifie ta boîte.',
        })
        setAuthTab('login')
      }
    } catch (error) {
      setAuthBanner({ tone: 'error', text: friendlyAuthError((error as Error)?.message) })
    } finally {
      setAuthLoading(false)
    }
  }

  const handleResendVerification = async () => {
    setAuthLoading(true)
    setAuthBanner(null)
    const normalizedEmail = email.trim().toLowerCase()
    if (!normalizedEmail || !normalizedEmail.includes('@')) {
      setAuthBanner({ tone: 'error', text: 'Email invalide.' })
      setAuthLoading(false)
      return
    }
    const { error } = await supabase.auth.resend({
      type: 'signup',
      email: normalizedEmail,
    })
    setAuthBanner(
      error
        ? { tone: 'error', text: friendlyAuthError(error.message) }
        : { tone: 'success', text: 'Email de vérification renvoyé.' },
    )
    setAuthLoading(false)
  }

  const handleVerifyMfaChallenge = async () => {
    if (!mfaChallenge) return
    setAuthLoading(true)
    setAuthBanner(null)
    const result = await supabase.auth.mfa.verify({
      factorId: mfaChallenge.factorId,
      challengeId: mfaChallenge.challengeId,
      code: otp,
    })
    if (result.error) {
      setAuthBanner({ tone: 'error', text: 'Code MFA invalide.' })
      setAuthLoading(false)
      return
    }
    setAuthBanner({ tone: 'success', text: 'MFA validé.' })
    setOtp('')
    setMfaChallenge(null)
    await refreshMfaFactors()
    const latestSession = (await supabase.auth.getSession()).data.session
    await syncSupabaseSession(latestSession)
    await refreshHistory()
    setShowAuth(false)
    setAuthTab('login')
    setAuthLoading(false)
  }

  const handleStartMfaEnroll = async () => {
    setAuthLoading(true)
    setAuthBanner(null)
    const { data, error } = await supabase.auth.mfa.enroll({
      factorType: 'totp',
      friendlyName: 'Authenticator',
    })
    if (error || !data?.id || !data?.totp?.qr_code) {
      setAuthBanner({ tone: 'error', text: 'Impossible de préparer le MFA.' })
    } else {
      setMfaEnroll({ factorId: data.id, qr: data.totp.qr_code, uri: data.totp.uri })
      setAuthTab('mfa')
      setAuthBanner({
        tone: 'info',
        text: 'Scanne le QR Code puis saisis le code à 6 chiffres.',
      })
    }
    setAuthLoading(false)
  }

  const handleConfirmMfaEnroll = async () => {
    if (!mfaEnroll) return
    setAuthLoading(true)
    setAuthBanner(null)
    const challenge = await supabase.auth.mfa.challenge({ factorId: mfaEnroll.factorId })
    if (challenge.error || !challenge.data?.id) {
      setAuthBanner({ tone: 'error', text: 'Challenge MFA introuvable.' })
      setAuthLoading(false)
      return
    }
    const verification = await supabase.auth.mfa.verify({
      factorId: mfaEnroll.factorId,
      challengeId: challenge.data.id,
      code: otp,
    })
    if (verification.error) {
      setAuthBanner({ tone: 'error', text: 'Code MFA invalide.' })
      setAuthLoading(false)
      return
    }
    setAuthBanner({ tone: 'success', text: 'MFA activé sur ton compte.' })
    setOtp('')
    setMfaEnroll(null)
    await refreshMfaFactors()
    const latestSession = (await supabase.auth.getSession()).data.session
    await syncSupabaseSession(latestSession)
    setAuthLoading(false)
  }

  const handleDisableMfa = async () => {
    const activeFactor = mfaFactors.find(
      (factor) => factor.factor_type === 'totp' && factor.status === 'verified',
    )
    if (!activeFactor) {
      setAuthBanner({ tone: 'info', text: 'Aucun MFA actif.' })
      return
    }
    setAuthLoading(true)
    const { error } = await supabase.auth.mfa.unenroll({ factorId: activeFactor.id })
    if (error) {
      setAuthBanner({ tone: 'error', text: 'Impossible de désactiver le MFA.' })
    } else {
      setAuthBanner({ tone: 'success', text: 'MFA désactivé.' })
      await refreshMfaFactors()
      await syncSupabaseSession()
    }
    setAuthLoading(false)
  }

  const handleLogout = async (fromSupabase = false) => {
    setAuthLoading(true)
    setAuthBanner(null)
    try {
      if (!fromSupabase) {
        await supabase.auth.signOut()
      }
      await apiRequest('/api/auth/logout', { method: 'POST' })
    } catch {
      // ignore
    } finally {
      setAuth({
        authenticated: false,
        email: null,
        ownerType: 'anon',
        plan: 'free',
        verified: false,
        mfaEnabled: false,
      })
      setPlan(defaultPlan)
      setSupabaseUser(null)
      setHistory([])
      setShowAuth(false)
      setMfaEnroll(null)
      setMfaChallenge(null)
      setOtp('')
      setAuthLoading(false)
    }
  }

  const handleGenerate = async () => {
    if (typeof window !== 'undefined' && (!window.isSecureContext || !crypto?.subtle)) {
      setStatus('error')
      showToast('Le chiffrement nécessite HTTPS ou localhost.', 'error')
      return
    }
    if (paywallQuotaReached) {
      setStatus('error')
      triggerUpgrade('Quota mensuel atteint : passe en Premium ou Pro.')
      return
    }
    if (mode === 'text' && !secret.trim()) {
      setStatus('error')
      showToast('Message requis.', 'error')
      return
    }
    if (mode === 'file' && !file) {
      setStatus('error')
      showToast('Sélectionnez un fichier.', 'error')
      return
    }
    if (mode === 'file' && file && file.size > plan.maxFileBytes) {
      setStatus('error')
      triggerUpgrade(
        `Tailles supérieures à ${formatBytes(plan.maxFileBytes)} réservées aux plans supérieurs.`,
      )
      return
    }
    const selectedExpiryMs = expiry * 60 * 1000
    if (selectedExpiryMs > plan.maxTtlMs) {
      setStatus('error')
      triggerUpgrade('Durées au-delà de ta limite plan (jusqu’à 7 jours en Pro).')
      return
    }
    if (views > plan.maxViews) {
      setStatus('error')
      triggerUpgrade(`Maximum ${plan.maxViews} vues sur ton plan actuel.`)
      return
    }

    setStatus('working')
    const now = Date.now()

    try {
      let encrypted: Awaited<ReturnType<typeof encryptSecret>>
      let item: NewPush

      if (mode === 'file' && file) {
        const buffer = await file.arrayBuffer()
        encrypted = await encryptBytes(buffer, passphrase)
        item = {
          kind: 'file',
          filename: file.name,
          mime: file.type || 'application/octet-stream',
          size: file.size,
          label: label.trim() || file.name || generateLabel(),
          createdAtTs: now,
          expiresAtTs: expiresAt,
          viewsLeft: Math.max(1, Math.min(plan.maxViews, views)),
          cipher: encrypted.cipher,
          iv: encrypted.iv,
          salt: encrypted.salt,
          requiresPassphrase: encrypted.requiresPassphrase,
        }
      } else {
        encrypted = await encryptSecret(secret, passphrase)
        item = {
          kind: 'text',
          label: label.trim() || generateLabel(),
          createdAtTs: now,
          expiresAtTs: expiresAt,
          viewsLeft: Math.max(1, Math.min(plan.maxViews, views)),
          cipher: encrypted.cipher,
          iv: encrypted.iv,
          salt: encrypted.salt,
          requiresPassphrase: encrypted.requiresPassphrase,
        }
      }

      const result = await apiRequest<{
        id: string
        monthlyUsed?: number
        monthlyLimit?: number | null
        plan?: PlanId
      }>('/api/push', {
        method: 'POST',
        body: JSON.stringify(item),
      })
      const nextLink = buildLink(result.id, encrypted.key)
      if (typeof result.monthlyUsed === 'number') {
        setPlan((current) => ({
          ...current,
          monthlyUsed: result.monthlyUsed ?? current.monthlyUsed,
          monthlyPushLimit:
            typeof result.monthlyLimit === 'number' ? result.monthlyLimit : current.monthlyPushLimit,
          plan: (result.plan as PlanId) || current.plan,
        }))
      }
      setLabel(generateLabel())
      setLink(nextLink)
      if (nextLink) {
        try {
          await navigator.clipboard.writeText(nextLink)
          setStatus('autocopied')
          setTimeout(() => setStatus('ready'), 1500)
          showToast('Lien généré et copié.', 'success')
        } catch {
          setStatus('ready')
          showToast('Lien généré.', 'success')
        }
      } else {
        setStatus('ready')
        showToast('Lien généré.', 'success')
      }
      await refreshHistory()
    } catch (error) {
      setStatus('error')
      if (error instanceof Error && error.message.includes('quota-exceeded')) {
        triggerUpgrade('Quota atteint : upgrade conseillé.')
      } else if (error instanceof Error && error.message.includes('plan-expiry-limit')) {
        triggerUpgrade('Durées prolongées réservées aux offres supérieures.')
      } else if (error instanceof Error && error.message.includes('plan-file-limit')) {
        triggerUpgrade('Fichier trop volumineux pour ce plan.')
      } else if (error instanceof Error && error.message.includes('plan-views-limit')) {
        triggerUpgrade('Nombre de vues trop élevé pour ce plan.')
      } else if (error instanceof Error && error.message.includes('auth-required')) {
        setShowAuth(true)
        triggerUpgrade('Connecte-toi pour envoyer des pushes gratuits.')
      } else {
        showToast('Erreur de génération.', 'error')
      }
    }
  }

  const handleCopy = async () => {
    if (!link) return
    try {
      await navigator.clipboard.writeText(link)
      setStatus('copied')
      setTimeout(() => setStatus('ready'), 1500)
      showToast('Lien copié.', 'success')
    } catch {
      setStatus('ready')
      showToast('Impossible de copier.', 'error')
    }
  }

  const generatePassword = (customLength?: number) => {
    const lower = 'abcdefghijklmnopqrstuvwxyz'
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    const numbers = '0123456789'
    const symbols = '!@#$%^&*()-_=+[]{};:,.<>?'
    let pool = ''
    if (useLower) pool += lower
    if (useUpper) pool += upper
    if (useNumbers) pool += numbers
    if (useSymbols) pool += symbols
    if (!pool) return
    const length = customLength ?? passwordLength
    if (!length) return
    const values = new Uint32Array(length)
    crypto.getRandomValues(values)
    let result = ''
    for (let i = 0; i < values.length; i += 1) {
      result += pool[values[i] % pool.length]
    }
    setGeneratedPassword(result)
  }

  const handleCopyGenerated = async () => {
    if (!generatedPassword) return
    try {
      await navigator.clipboard.writeText(generatedPassword)
      showToast('Mot de passe copié.', 'success')
    } catch {
      showToast('Impossible de copier.', 'error')
    }
  }

  useEffect(() => {
    generatePassword()
  }, [passwordLength, useUpper, useLower, useNumbers, useSymbols])

  const resetComposer = () => {
    setSecret('')
    setFile(null)
    setFileError('')
    setPassphrase('')
    setViews(Math.min(plan.maxViews, 3))
    setExpiry(Math.min(expiryLimitMinutes, presets[2].minutes))
    setLink('')
    setStatus('idle')
    setMode('text')
    setLabel(generateLabel())
  }

  return (
    <div className="mx-auto flex w-full max-w-[1080px] flex-col gap-8 pb-14 px-4 sm:px-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <img src={logo} alt="Nemosyne logo" className="h-9 w-9" />
          <div className="leading-tight">
            <p className="text-2xl font-semibold tracking-tight">Nemosyne</p>
            <p className="text-xs text-[var(--ink-soft)]">Liens sécurisés, auto-destruits.</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}
            className="rounded-full border border-[var(--line)] px-3 py-1 text-xs text-[var(--ink-soft)]"
            aria-label="Basculer le thème"
          >
            {theme === 'light' ? 'Mode sombre' : 'Mode clair'}
          </button>
          <span className="rounded-full border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-1 text-xs text-[var(--ink-soft)]">
            Plan {plan.label}{' '}
            {plan.monthlyPushLimit === null
              ? '(illimité)'
              : `${plan.monthlyUsed}/${plan.monthlyPushLimit}`}
          </span>
          <button
            type="button"
            onClick={() => setShowAuth(true)}
            className="rounded-full border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-white transition hover:opacity-90"
          >
            Compte / Upgrade
          </button>
        </div>
      </header>



      {showAuth ? (
        <div className="fixed inset-0 z-50 bg-black/55 px-3 py-6 sm:px-6 sm:py-10">
          <div className="mx-auto grid w-full max-w-5xl gap-0 rounded-3xl border border-[var(--line)] bg-[var(--surface)] shadow-2xl md:grid-cols-[1.05fr,1fr]">
            <div className="flex flex-col gap-4 border-b border-[var(--line)] px-6 py-5 md:border-b-0 md:border-r">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.22em] text-[var(--ink-soft)]">
                    Espace compte
                  </p>
                  <p className="text-xl font-semibold text-[var(--ink)]">
                    {auth.authenticated ? auth.email : 'Créer ou rejoindre'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowAuth(false)}
                  className="rounded-full border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-1 text-sm text-[var(--ink-soft)] hover:text-[var(--ink)]"
                  aria-label="Fermer"
                >
                  ✕
                </button>
              </div>
              <div className="flex flex-wrap gap-2 text-[11px]">
                <span className="rounded-full border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-1 uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                  Plan {plan.label}
                </span>
                <span
                  className={`rounded-full border px-3 py-1 uppercase tracking-[0.2em] ${
                    auth.verified
                      ? 'border-emerald-500/60 bg-emerald-500/10 text-emerald-200'
                      : 'border-amber-500/60 bg-amber-500/10 text-amber-100'
                  }`}
                >
                  {auth.verified ? 'Email vérifié' : 'Email à vérifier'}
                </span>
                <span
                  className={`rounded-full border px-3 py-1 uppercase tracking-[0.2em] ${
                    auth.mfaEnabled
                      ? 'border-emerald-500/60 bg-emerald-500/10 text-emerald-200'
                      : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)]'
                  }`}
                >
                  {auth.mfaEnabled ? 'MFA TOTP actif' : 'MFA non configuré'}
                </span>
              </div>
              <div className="rounded-2xl bg-[var(--surface-muted)] px-4 py-3 text-sm text-[var(--ink-soft)]">
                <p className="font-semibold text-[var(--ink)]">Flux Supabase Auth</p>
                <ul className="mt-2 flex flex-col gap-2 text-[13px]">
                  <li>• Emails de vérification et magic links gérés par Supabase.</li>
                  <li>• Reset mot de passe avec redirection locale (/verify).</li>
                  <li>• MFA TOTP compatible Authenticator / 1Password.</li>
                  <li>• Session backend synchronisée pour quotas et historique.</li>
                </ul>
              </div>
              <div className="rounded-2xl border border-[var(--line)] px-4 py-3 text-sm text-[var(--ink-soft)]">
                <p className="font-semibold text-[var(--ink)]">État</p>
                <p className="mt-2">
                  Connexion : {auth.authenticated ? 'connecté' : 'invité'} · Plan {plan.label}.
                </p>
                <p className="mt-1">
                  Quota : {plan.monthlyPushLimit === null ? 'illimité' : `${plan.monthlyUsed}/${plan.monthlyPushLimit} pushes / mois`}.
                </p>
                <p className="mt-1">
                  Sécurité : {auth.verified ? 'email validé' : 'email à confirmer'} · {auth.mfaEnabled ? 'MFA actif' : 'MFA désactivé'}.
                </p>
              </div>
              {auth.authenticated ? (
                <button
                  type="button"
                  onClick={() => handleLogout()}
                  className="w-fit rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)] hover:border-[var(--primary)]"
                >
                  Se déconnecter
                </button>
              ) : null}
            </div>
            <div className="flex flex-col gap-4 px-6 py-5">
              <div className="flex flex-wrap gap-2 text-[11px] font-semibold uppercase tracking-[0.2em]">
                <button
                  type="button"
                  onClick={() => setAuthTab('login')}
                  className={`rounded-full px-3 py-1 ${
                    authTab === 'login'
                      ? 'bg-[var(--primary)] text-white'
                      : 'border border-[var(--line)] text-[var(--ink-soft)]'
                  }`}
                >
                  Connexion
                </button>
                <button
                  type="button"
                  onClick={() => setAuthTab('signup')}
                  className={`rounded-full px-3 py-1 ${
                    authTab === 'signup'
                      ? 'bg-[var(--primary)] text-white'
                      : 'border border-[var(--line)] text-[var(--ink-soft)]'
                  }`}
                >
                  Créer un compte
                </button>
                <button
                  type="button"
                  onClick={() => setAuthTab('reset')}
                  className={`rounded-full px-3 py-1 ${
                    authTab === 'reset'
                      ? 'bg-[var(--primary)] text-white'
                      : 'border border-[var(--line)] text-[var(--ink-soft)]'
                  }`}
                >
                  Réinitialiser
                </button>
                <button
                  type="button"
                  onClick={() => setAuthTab('mfa')}
                  className={`rounded-full px-3 py-1 ${
                    authTab === 'mfa'
                      ? 'bg-[var(--primary)] text-white'
                      : 'border border-[var(--line)] text-[var(--ink-soft)]'
                  }`}
                >
                  MFA
                </button>
              </div>

              {authBanner ? (
                <div
                  className={`rounded-xl border px-4 py-3 text-sm ${
                    authBanner.tone === 'success'
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-100'
                      : authBanner.tone === 'error'
                        ? 'border-red-500/40 bg-red-500/10 text-red-100'
                        : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)]'
                  }`}
                >
                  {authBanner.text}
                </div>
              ) : null}

              {authTab === 'login' ? (
                <div className="flex flex-col gap-3">
                  <input
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="Email"
                    className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  />
                  <input
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="Mot de passe (>=12 caractères)"
                    className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  />
                  {mfaChallenge ? (
                    <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-3">
                      <p className="text-xs text-[var(--ink-soft)]">MFA requis pour finaliser la connexion.</p>
                      <input
                        value={otp}
                        onChange={(event) => setOtp(event.target.value)}
                        placeholder="Code MFA (6 chiffres)"
                        className="mt-2 rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                      />
                      <button
                        type="button"
                        onClick={handleVerifyMfaChallenge}
                        disabled={authLoading}
                        className="mt-2 rounded-md border border-[var(--primary)] bg-[var(--primary)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-white"
                      >
                        Valider le MFA
                      </button>
                    </div>
                  ) : null}
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={handleLogin}
                      disabled={authLoading}
                      className="rounded-md border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
                    >
                      Se connecter
                    </button>
                    <button
                      type="button"
                      onClick={() => setAuthTab('reset')}
                      className="rounded-md border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                    >
                      Mot de passe oublié
                    </button>
                  </div>
                  <p className="text-[12px] text-[var(--ink-soft)]">
                    Pas encore de compte ?{' '}
                    <button
                      type="button"
                      className="text-[var(--primary)] underline"
                      onClick={() => setAuthTab('signup')}
                    >
                      Créer un compte
                    </button>
                  </p>
                </div>
              ) : null}

              {authTab === 'signup' ? (
                <div className="flex flex-col gap-3">
                  <input
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="Email professionnel"
                    className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  />
                  <input
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="Mot de passe (>=12 caractères)"
                    className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  />
                  <button
                    type="button"
                    onClick={handleRegister}
                    disabled={authLoading}
                    className="rounded-md border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
                  >
                    Créer mon compte
                  </button>
                  <button
                    type="button"
                    onClick={handleResendVerification}
                    disabled={authLoading}
                    className="w-fit text-[12px] uppercase tracking-[0.18em] text-[var(--ink-soft)]"
                  >
                    Renvoyer l'email de vérification
                  </button>
                </div>
              ) : null}

              {authTab === 'reset' ? (
                <div className="flex flex-col gap-3">
                  <input
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="Email"
                    className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  />
                  <button
                    type="button"
                    onClick={handleResetPassword}
                    disabled={authLoading}
                    className="rounded-md border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
                  >
                    Envoyer le lien de réinitialisation
                  </button>
                  <p className="text-[12px] text-[var(--ink-soft)]">
                    Le lien Supabase redirige vers /verify pour saisir un nouveau mot de passe.
                  </p>
                </div>
              ) : null}

              {authTab === 'mfa' ? (
                <div className="flex flex-col gap-3">
                  {!auth.authenticated ? (
                    <p className="text-sm text-[var(--ink-soft)]">
                      Connecte-toi d'abord pour configurer le MFA.
                    </p>
                  ) : mfaEnroll ? (
                    <div className="flex flex-col gap-3 rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3">
                      <p className="text-sm text-[var(--ink-soft)]">Scanne puis saisis le code TOTP.</p>
                      <img src={mfaEnroll.qr} alt="QR MFA" className="h-40 w-40 rounded-lg bg-white p-2" />
                      <input
                        value={otp}
                        onChange={(event) => setOtp(event.target.value)}
                        placeholder="Code TOTP"
                        className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                      />
                      <button
                        type="button"
                        onClick={handleConfirmMfaEnroll}
                        disabled={authLoading}
                        className="w-fit rounded-md border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
                      >
                        Valider le MFA
                      </button>
                    </div>
                  ) : (
                    <>
                      <p className="text-sm text-[var(--ink-soft)]">
                        {auth.mfaEnabled
                          ? 'MFA actif. Tu peux le désactiver ou ré-initialiser.'
                          : 'Renforce l’authentification avec un code TOTP.'}
                      </p>
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={handleStartMfaEnroll}
                          disabled={authLoading}
                          className="rounded-md border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
                        >
                          Activer MFA TOTP
                        </button>
                        {auth.mfaEnabled ? (
                          <button
                            type="button"
                            onClick={handleDisableMfa}
                            disabled={authLoading}
                            className="rounded-md border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                          >
                            Désactiver le MFA
                          </button>
                        ) : null}
                      </div>
                    </>
                  )}
                </div>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}

      {showUpgrade ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4">
          <div className="card-elev w-full max-w-4xl rounded-2xl border border-[var(--line)]">
            <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-3">
              <div>
                <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Upgrade</p>
                <p className="text-sm text-[var(--ink)]">
                  {paywallReason ?? 'Plus de temps, plus de vues, fichiers plus lourds.'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowUpgrade(false)}
                className="text-sm text-[var(--ink-soft)]"
                aria-label="Fermer le paywall"
              >
                ✕
              </button>
            </div>
            <div className="grid gap-4 px-5 py-4 md:grid-cols-2">
              {(['premium', 'pro'] as PlanId[]).map((pid) => (
                <div
                  key={pid}
                  className="rounded-2xl border border-[var(--line)] bg-[var(--surface)] px-4 py-4 shadow-sm"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                        {pid === 'premium' ? 'Premium' : 'Pro'}
                      </p>
                      <p className="text-2xl font-semibold text-[var(--ink)]">
                        {planPricing[pid].price}
                      </p>
                      <p className="text-xs text-[var(--ink-soft)]">{planPricing[pid].subtitle}</p>
                    </div>
                    {plan.plan === pid ? (
                      <span className="rounded-full bg-[var(--primary-weak)] px-3 py-1 text-[10px] uppercase tracking-[0.2em] text-[var(--ink)]">
                        Actuel
                      </span>
                    ) : null}
                  </div>
                  <ul className="mt-3 flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
                    {planPricing[pid].features.map((feat) => (
                      <li key={feat}>• {feat}</li>
                    ))}
                    {pid === 'pro' ? <li>• Audit complet et support prioritaire</li> : null}
                  </ul>
                  <button
                    type="button"
                    onClick={() => handleSelectPlan(pid)}
                    disabled={planLoading || plan.plan === pid}
                    className={`mt-4 w-full rounded-full border px-4 py-2 text-xs uppercase tracking-[0.2em] ${
                      plan.plan === pid
                        ? 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)]'
                        : 'border-[var(--primary)] bg-[var(--primary)] text-white hover:opacity-90'
                    }`}
                  >
                    {plan.plan === pid ? 'Plan en cours' : `Choisir ${pid === 'premium' ? 'Premium' : 'Pro'}`}
                  </button>
                </div>
              ))}
            </div>
            <p className="px-5 pb-5 text-xs text-[var(--ink-soft)]">
              Aligné sur eu.pwpush.com : Premium 19 € / mois, Pro 29 € / mois. Les pushes de mots de passe restent gratuits une fois connecté.
            </p>
          </div>
        </div>
      ) : null}

      

      
      <section className="flex flex-wrap items-center gap-3 rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)]/70 px-4 py-3 text-sm text-[var(--ink-soft)]">
        <span className="rounded-full border border-[var(--line)] bg-[var(--surface)] px-3 py-1 text-[10px] uppercase tracking-[0.18em] text-[var(--ink)]">
          Plan {plan.label}
        </span>
        <span>Chiffré dans votre navigateur. Lien supprimé après expiration ou vues.</span>
        <span className="text-[11px] text-[var(--ink-soft)]">Reset {formatResetDate(plan.nextResetTs)}</span>
      </section>

      <section
        id="composer"
        className="relative overflow-hidden rounded-3xl border border-[var(--line)] bg-[var(--surface)]/95 shadow-[var(--shadow-strong)] backdrop-blur"
      >
        {paywallQuotaReached ? (
          <div className="absolute inset-0 z-20 flex flex-col items-center justify-center gap-3 bg-[var(--surface)]/92 backdrop-blur">
            <p className="text-sm font-semibold text-[var(--ink)]">Quota atteint sur ce plan.</p>
            <p className="text-xs text-[var(--ink-soft)]">Passe en Premium/Pro pour continuer.</p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => handleSelectPlan('premium')}
                className="pill border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
              >
                Premium
              </button>
              <button
                type="button"
                onClick={() => handleSelectPlan('pro')}
                className="pill border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
              >
                Pro
              </button>
            </div>
          </div>
        ) : null}

        <div className="flex items-center justify-between border-b border-[var(--line)] px-6 py-4">
          <div>
            <p className="text-[11px] uppercase tracking-[0.25em] text-[var(--ink-soft)]">Envoyer un secret</p>
            <p className="text-sm text-[var(--ink-soft)]">Copie, lien, suppression automatique.</p>
          </div>
          <span className="pill border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-1 text-xs text-[var(--ink-soft)]">
            {status === 'working'
              ? 'Chiffrement…'
              : status === 'copied'
                ? 'Copié'
                : link
                  ? 'Prêt'
                  : 'En attente'}
          </span>
        </div>

        <div className="flex flex-col gap-5 p-6">
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between text-xs text-[var(--ink-soft)]">
              <span>Collez votre secret</span>
              <span className="rounded-full border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-1 text-[10px]">{label}</span>
            </div>
            <textarea
              id="memo-area"
              rows={5}
              value={secret}
              disabled={mode === 'file'}
              onChange={(event) => {
                setSecret(event.target.value)
                setStatus('idle')
              }}
              placeholder="Texte, mot de passe, note..."
              className="w-full resize-none rounded-xl border border-[var(--line)] bg-[var(--field)] px-4 py-3 text-sm text-[var(--ink)] outline-none focus:border-[var(--primary)] disabled:cursor-not-allowed disabled:opacity-60"
            />
            {fileError ? <p className="text-xs text-[var(--primary)]">{fileError}</p> : null}
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => {
                setMode('text')
                setFile(null)
                setFileError('')
              }}
              className={`rounded-full border px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] transition ${
                mode === 'text'
                  ? 'border-[var(--primary)] bg-[var(--primary)] text-white'
                  : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)] hover:border-[var(--primary)]'
              }`}
            >
              Mode texte
            </button>
            <label className="flex cursor-pointer items-center gap-2 rounded-full border border-dashed border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)] hover:border-[var(--primary)]">
              <input
                type="file"
                className="hidden"
                onChange={(event) => {
                  const selected = event.target.files?.[0]
                  if (!selected) return
                  const maxBytes = plan.maxFileBytes
                  if (selected.size > maxBytes) {
                    setFile(null)
                    setFileError(`Fichier trop volumineux (max ${formatBytes(maxBytes)}).`)
                    setMode('file')
                    return
                  }
                  setFile(selected)
                  setFileError('')
                  setMode('file')
                }}
              />
              <span>{file ? file.name : 'Ajouter un fichier'}</span>
              <span className="text-[10px] text-[var(--ink-soft)]">
                {file ? formatBytes(file.size) : `Max ${formatBytes(plan.maxFileBytes)}`}
              </span>
            </label>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="flex flex-col gap-2">
              <label className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Expiration</label>
              <select
                value={expiry}
                onChange={(event) => {
                  const next = Number(event.target.value)
                  const preset = presets.find((p) => p.minutes === next)
                  const locked = preset?.minPlan && planOrder[plan.plan] < planOrder[preset.minPlan]
                  if (locked) {
                    triggerUpgrade(
                      `Durée ${preset?.label ?? ''} disponible en ${preset?.minPlan === 'pro' ? 'Pro' : 'Premium'}.`,
                    )
                    return
                  }
                  setExpiry(next)
                }}
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)] outline-none focus:border-[var(--primary)]"
              >
                {presets.map((preset) => {
                  const locked = preset.minPlan && planOrder[plan.plan] < planOrder[preset.minPlan]
                  return (
                    <option key={preset.label} value={preset.minutes} disabled={locked}>
                      {preset.label}
                      {locked ? ` ? ${preset.minPlan?.toUpperCase()}` : ''}
                    </option>
                  )
                })}
              </select>
              <p className="text-xs text-[var(--ink-soft)]">
                Sera supprimé le {expiresAtLabel}.
                {planOrder[plan.plan] < planOrder.pro ? ' Jusqu’à 7 jours en Pro.' : ''}
              </p>
            </div>
            <div className="flex flex-col gap-2">
              <label className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Vues max</label>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  max={plan.maxViews}
                  value={views}
                  onChange={(event) => {
                    const next = Number(event.target.value)
                    setViews(Math.min(plan.maxViews, Math.max(1, next)))
                  }}
                  className="w-24 rounded-lg border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)] outline-none focus:border-[var(--primary)]"
                />
                <span className="text-xs text-[var(--ink-soft)]">Max {plan.maxViews} sur ce plan.</span>
                {plan.maxViews < 20 ? (
                  <button
                    type="button"
                    onClick={() => triggerUpgrade('Jusqu’à 20 vues en Pro')}
                    className="flex items-center gap-1 rounded-full border border-[var(--line)] px-3 py-1 text-[10px] uppercase tracking-[0.18em] text-[var(--ink-soft)] hover:border-[var(--primary)]"
                  >
                    ?? Pro
                  </button>
                ) : null}
              </div>
            </div>
          </div>

          <details className="rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3 text-sm text-[var(--ink-soft)]">
            <summary className="cursor-pointer text-xs uppercase tracking-[0.2em] text-[var(--ink)]">Options avancées</summary>
            <div className="mt-3 flex flex-col gap-2">
              <label className="text-xs text-[var(--ink-soft)]">Passphrase (optionnel)</label>
              <input
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                className="rounded-lg border border-[var(--line)] bg-[var(--field)] px-4 py-2 text-sm text-[var(--ink)] outline-none focus:border-[var(--primary)]"
                placeholder="Ajoutez un mot de passe pour ce lien"
                type="password"
              />
              <p className="text-xs text-[var(--ink-soft)]">Nous ne voyons jamais votre passphrase.</p>
            </div>
          </details>

          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={handleGenerate}
                className="rounded-md bg-[var(--primary)] px-6 py-2 text-sm font-semibold text-white transition hover:opacity-90"
              >
                {status === 'working' ? 'Chiffrement…' : 'Générer le lien sécurisé'}
              </button>
              <span className="text-xs text-[var(--ink-soft)]">Expire {expiresAtLabel} • {views} vues max</span>
            </div>
            <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3 text-sm">
              {link ? (
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div className="flex flex-col gap-1">
                    <span className="break-all text-[var(--ink)]">{link}</span>
                    <span className="text-xs text-[var(--ink-soft)]">Chiffré côté navigateur.</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={handleCopy}
                      className="rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                    >
                      Copier
                    </button>
                    <button
                      type="button"
                      onClick={resetComposer}
                      className="rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)] hover:border-[var(--primary)]"
                    >
                      Nouveau secret
                    </button>
                  </div>
                </div>
              ) : (
                <span className="text-[var(--ink-soft)]">Le lien apparaît ici après génération.</span>
              )}
            </div>
          </div>
        </div>
      </section>

      <details className="rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3">
        <summary className="cursor-pointer text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">Historique récent</summary>
        <div className="mt-3 flex items-center justify-between">
          <p className="text-sm text-[var(--ink-soft)]">Derniers liens accessibles depuis cet appareil.</p>
          <button
            type="button"
            onClick={refreshHistory}
            className="rounded-full border border-[var(--line)] px-3 py-1 text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)] hover:border-[var(--primary)]"
          >
            Rafraîchir
          </button>
        </div>
        <div className="mt-3 flex flex-col gap-2">
          {history.length === 0 ? (
            <div className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-4 py-2 text-sm text-[var(--ink-soft)]">
              Aucun secret encore.
            </div>
          ) : (
            history.map((item) => (
              <Link
                key={item.id}
                to={`/push/${item.id}`}
                className="rounded-lg border border-[var(--line)] bg-[var(--surface)] px-4 py-3 transition hover:border-[var(--primary)]"
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-[var(--ink)]">{item.label}</p>
                    <p className="text-xs text-[var(--ink-soft)]">
                      Expire {item.expiresAtText} • {item.viewsLeft} vues restantes
                    </p>
                  </div>
                  <span className="pill border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-1 text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                    {item.requiresPassphrase ? 'Passphrase' : 'Clé URL'}
                  </span>
                </div>
              </Link>
            ))
          )}
        </div>
      </details>

      <details className="rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3">
        <summary className="cursor-pointer text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">Outils (générateur de mot de passe)</summary>
        <div className="mt-3 rounded-2xl border border-[var(--line)] bg-[var(--field-muted)] px-3 py-3">
          <div className="flex flex-col gap-3">
            <input
              value={generatedPassword}
              readOnly
              className="w-full rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
              placeholder="Génère et copie en 1 clic"
            />
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2 text-xs text-[var(--ink-soft)]">
                <span>Longueur</span>
                <input
                  type="range"
                  min={12}
                  max={48}
                  value={passwordLength}
                  onChange={(event) => {
                    const next = Number(event.target.value)
                    setPasswordLength(next)
                    generatePassword(next)
                  }}
                />
                <span className="min-w-[2ch] text-right">{passwordLength}</span>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => generatePassword()}
                  className="pill border border-[var(--primary)] bg-[var(--primary)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-white transition hover:opacity-90"
                >
                  Générer
                </button>
                <button
                  type="button"
                  onClick={handleCopyGenerated}
                  className="pill border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)] hover:border-[var(--primary)]"
                >
                  Copier
                </button>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 text-xs text-[var(--ink-soft)]">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={useUpper}
                  onChange={(event) => setUseUpper(event.target.checked)}
                />
                Majuscules
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={useLower}
                  onChange={(event) => setUseLower(event.target.checked)}
                />
                Minuscules
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={useNumbers}
                  onChange={(event) => setUseNumbers(event.target.checked)}
                />
                Chiffres
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={useSymbols}
                  onChange={(event) => setUseSymbols(event.target.checked)}
                />
                Symboles
              </label>
            </div>
          </div>
        </div>
      </details>

      {toast ? (
        <div className="fixed bottom-6 right-6 z-50">
          <div
            className={`rounded-full border px-4 py-2 text-xs uppercase tracking-[0.2em] shadow-lg ${
              toast.kind === 'success'
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                : toast.kind === 'error'
                  ? 'border-red-500/30 bg-red-500/10 text-red-200'
                  : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)]'
            }`}
          >
            {toast.message}
          </div>
        </div>
      ) : null}
    </div>
  )
}

function PushView() {
  const { id } = useParams()
  const location = useLocation()
  const navigate = useNavigate()
  const [item, setItem] = useState<PushSummary | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [secret, setSecret] = useState('')
  const [fileUrl, setFileUrl] = useState<string | null>(null)
  const [fileName, setFileName] = useState<string | null>(null)
  const [fileMime, setFileMime] = useState<string | null>(null)
  const [inlineKey, setInlineKey] = useState<string | null>(null)
  const [status, setStatus] = useState<
    'loading' | 'ready' | 'revealed' | 'error' | 'expired' | 'missing' | 'consumed'
  >('loading')
  const [toast, setToast] = useState<{
    message: string
    kind: 'success' | 'error' | 'info'
  } | null>(null)

  const showToast = (message: string, kind: 'success' | 'error' | 'info' = 'info') => {
    setToast({ message, kind })
    window.setTimeout(() => {
      setToast((current) => (current?.message === message ? null : current))
    }, 2200)
  }

  useEffect(() => {
    if (!id) {
      setStatus('missing')
      return
    }
    const keyFragment = new URLSearchParams(location.hash.replace('#', '')).get('k')
    setInlineKey(keyFragment ? decodeURIComponent(keyFragment) : null)
    const loadMeta = async () => {
      try {
        const meta = await apiRequest<PushMeta>(`/api/push/${id}/meta`)
        const summary = toSummary(meta)
        setItem(summary)
        setStatus('ready')
      } catch (error) {
        if (error instanceof Error && error.message.includes('api-404')) {
          setStatus('missing')
          return
        }
        setStatus('error')
      }
    }
    loadMeta()
  }, [id, location.hash])

  useEffect(() => {
    return () => {
      if (fileUrl) {
        URL.revokeObjectURL(fileUrl)
      }
    }
  }, [fileUrl])

  const handleReveal = async () => {
    if (!item || !id) return
    if (status === 'revealed' || status === 'consumed') {
      showToast('Secret déjà révélé dans cet onglet.', 'info')
      return
    }
    if (typeof window !== 'undefined' && (!window.isSecureContext || !crypto?.subtle)) {
      setStatus('error')
      showToast('Le chiffrement nécessite HTTPS ou localhost.', 'error')
      return
    }
    if (item.requiresPassphrase && !passphrase.trim()) {
      setStatus('error')
      showToast('Passphrase requise.', 'error')
      return
    }
    if (!item.requiresPassphrase && !inlineKey) {
      setStatus('error')
      showToast('Clé URL manquante.', 'error')
      return
    }
    try {
      const stored = await apiRequest<StoredPush>(`/api/push/${id}/reveal`, {
        method: 'POST',
      })
      const summary = toSummary(stored)
      if (summary.isExpired) {
        setItem(summary)
        setStatus('expired')
        return
      }
      if (fileUrl) {
        URL.revokeObjectURL(fileUrl)
      }
      if (stored.kind === 'file') {
        const buffer = await decryptBytes(stored, passphrase, inlineKey ?? undefined)
        const blob = new Blob([buffer], { type: stored.mime || 'application/octet-stream' })
        const url = URL.createObjectURL(blob)
        setFileUrl(url)
        setFileName(stored.filename || 'memo')
        setFileMime(stored.mime || null)
        setSecret('')
      } else {
        const plain = await decryptSecret(stored, passphrase, inlineKey ?? undefined)
        setSecret(plain)
        setFileUrl(null)
        setFileName(null)
        setFileMime(null)
      }
      setItem(summary)
      setStatus(summary.viewsLeft <= 0 ? 'consumed' : 'revealed')
      showToast('Secret déchiffré.', 'success')
    } catch (error) {
      if (error instanceof Error && error.message.includes('api-404')) {
        setStatus('missing')
        return
      }
      setStatus('error')
      showToast("Impossible de déchiffrer.", 'error')
    }
  }

  const handleCopySecret = async () => {
    if (!secret) return
    try {
      await navigator.clipboard.writeText(secret)
      showToast('Secret copié.', 'success')
    } catch {
      showToast('Impossible de copier.', 'error')
    }
  }

  return (
    <div className="mx-auto flex w-full max-w-[1200px] flex-col gap-6 px-4 sm:px-6">
      <header className="flex flex-col gap-3">
        <button
          type="button"
          onClick={() => navigate('/')}
          className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
        >
          ← Retour
        </button>
        <h1 className="text-3xl font-semibold">Votre message est enregistré.</h1>
        <p className="max-w-2xl text-sm text-[var(--ink-soft)]">
          Le message s’autodétruira après lecture ou à expiration.
        </p>
      </header>

      <section className="card-elev rounded-2xl border border-[var(--line)]">
        <div className="rounded-t-2xl bg-[var(--primary)] px-4 py-3 text-center text-sm font-semibold text-white">
          Votre message est enregistré.
        </div>
        <div className="flex flex-col gap-5 p-6">
        {status === 'missing' ?(
          <div className="flex flex-col gap-3">
            <p className="text-sm text-[var(--ink-soft)]">Secret introuvable.</p>
            <Link to="/" className="text-sm text-[var(--primary)]">
              Revenir à l’accueil
            </Link>
          </div>
        ) : null}

        {status === 'expired' ?(
          <div className="flex flex-col gap-3">
            <p className="text-sm text-[var(--ink-soft)]">
              Ce secret a expiré et a été supprimé.
            </p>
            <Link to="/" className="text-sm text-[var(--primary)]">
              Créer un nouveau push
            </Link>
          </div>
        ) : null}

        {status === 'error' && !item ?(
          <div className="flex flex-col gap-3">
            <p className="text-sm text-[var(--ink-soft)]">
              Une erreur est survenue. Réessayez plus tard.
            </p>
            <Link to="/" className="text-sm text-[var(--primary)]">
              Retour à l’accueil
            </Link>
          </div>
        ) : null}

        {status !== 'missing' && status !== 'expired' && item ?(
          <div className="flex flex-col gap-6">
            <div>
              <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                {item.label}
              </p>
              <p className="mt-2 text-sm text-[var(--ink-soft)]">
                Expire {item.expiresAtText} • {item.viewsLeft} vues restantes
              </p>
            </div>

            {!item.requiresPassphrase && !inlineKey ?(
              <div className="rounded-lg border border-[var(--primary)] bg-[var(--primary)]/10 px-4 py-3 text-sm text-[var(--ink)]">
                La clé du lien est absente. Vérifiez que l’URL contient bien
                <span className="font-semibold"> #k=...</span>.
              </div>
            ) : null}

            {item.requiresPassphrase ?(
              <div className="flex flex-col gap-2">
                <label className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                  Passphrase
                </label>
                <input
                  type="password"
                  value={passphrase}
                  onChange={(event) => setPassphrase(event.target.value)}
                  className="rounded-lg border border-[var(--line)] bg-[var(--field)] px-4 py-2 text-sm text-[var(--ink)] outline-none focus:border-[var(--primary)]"
                  placeholder="Entrez la passphrase"
                />
              </div>
            ) : null}

            <div className="flex flex-col gap-3 md:flex-row md:items-center">
              <button
                type="button"
                onClick={handleReveal}
                disabled={status === 'revealed' || status === 'consumed'}
                className={`rounded-md px-6 py-2 text-sm font-semibold transition ${
                  status === 'revealed' || status === 'consumed'
                    ? 'cursor-not-allowed bg-[var(--line)] text-[var(--ink-soft)]'
                    : 'bg-[var(--primary)] text-white hover:opacity-90'
                }`}
              >
                {status === 'revealed' || status === 'consumed'
                  ? 'Déjà révélé'
                  : 'Révéler le secret'}
              </button>
              {status === 'error' ?(
                <p className="text-sm text-[var(--primary)]">
                  Impossible de déchiffrer. Vérifiez la passphrase ou la clé du lien.
                </p>
              ) : null}
            </div>

            {status === 'revealed' || status === 'consumed' ?(
              <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3">
                <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                  Secret
                </p>
                {fileUrl ?(
                  <div className="mt-2 flex flex-col gap-2 text-sm text-[var(--ink)]">
                    <span>{fileName}</span>
                    <a
                      href={fileUrl}
                      download={fileName || 'memo'}
                      className="w-fit rounded-md border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                    >
                      Télécharger
                    </a>
                    {fileMime ?(
                      <span className="text-xs text-[var(--ink-soft)]">{fileMime}</span>
                    ) : null}
                  </div>
                ) : (
                  <pre className="mt-2 whitespace-pre-wrap text-sm text-[var(--ink)]">
                    {secret}
                  </pre>
                )}
                <div className="mt-3 flex flex-wrap gap-3">
                  <button
                    type="button"
                    onClick={handleCopySecret}
                    className="rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                  >
                    Copier
                  </button>
                  {status === 'consumed' ?(
                    <span className="rounded-full bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white">
                      Dernière vue, supprimé
                    </span>
                  ) : null}
                </div>
                {item.requiresPassphrase ?(
                  <p className="mt-3 text-xs text-[var(--ink-soft)]">
                    Ce secret a été protégé par passphrase.
                  </p>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : null}
        </div>
      </section>

      {toast ? (
        <div className="fixed bottom-6 right-6 z-50">
          <div
            className={`rounded-full border px-4 py-2 text-xs uppercase tracking-[0.2em] shadow-lg ${
              toast.kind === 'success'
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                : toast.kind === 'error'
                  ? 'border-red-500/30 bg-red-500/10 text-red-200'
                  : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)]'
            }`}
          >
            {toast.message}
          </div>
        </div>
      ) : null}
    </div>
  )
}

function NotFound() {
  return (
    <div className="mx-auto flex w-full max-w-[1100px] flex-col gap-4 px-4 sm:px-6">
      <h1 className="text-3xl font-semibold">Page introuvable</h1>
      <Link to="/" className="text-sm text-[var(--primary)]">
        Retour à l’accueil
      </Link>
    </div>
  )
}



function VerifyEmail() {
  const location = useLocation()
  const navigate = useNavigate()
  const [status, setStatus] = useState<'loading' | 'ok' | 'error' | 'reset'>('loading')
  const [message, setMessage] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [updating, setUpdating] = useState(false)

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const code = params.get('code')
    const type = params.get('type')
    const legacyToken = params.get('token')
    const verify = async () => {
      if (code) {
        const { data, error } = await supabase.auth.exchangeCodeForSession(code)
        if (error) {
          setStatus('error')
          setMessage('Lien invalide ou expiré.')
          return
        }
        const session = data.session
        if (session?.access_token) {
          try {
            await apiRequest('/api/auth/supabase-sync', {
              method: 'POST',
              body: JSON.stringify({ accessToken: session.access_token }),
            })
          } catch {
            // ignore sync errors
          }
        }
        if (type === 'recovery') {
          setStatus('reset')
          setMessage('Choisis un nouveau mot de passe pour finaliser la récupération.')
          return
        }
        setStatus('ok')
        setMessage('Email vérifié. Tu es connecté.')
        return
      }
      if (legacyToken) {
        try {
          await apiRequest(`/api/auth/verify?token=${encodeURIComponent(legacyToken)}`)
          setStatus('ok')
          setMessage('Email vérifié.')
        } catch {
          setStatus('error')
          setMessage('Lien invalide ou expiré.')
        }
        return
      }
      setStatus('error')
      setMessage('Lien invalide.')
    }
    verify()
  }, [location.search])

  const handlePasswordUpdate = async () => {
    if (newPassword.trim().length < 12) {
      setMessage('Mot de passe trop court (12 caractères mini).')
      return
    }
    setUpdating(true)
    const { error } = await supabase.auth.updateUser({ password: newPassword.trim() })
    if (error) {
      setMessage('Impossible de mettre à jour le mot de passe.')
      setUpdating(false)
      return
    }
    const session = (await supabase.auth.getSession()).data.session
    if (session?.access_token) {
      try {
        await apiRequest('/api/auth/supabase-sync', {
          method: 'POST',
          body: JSON.stringify({ accessToken: session.access_token }),
        })
      } catch {
        // ignore
      }
    }
    setStatus('ok')
    setMessage('Mot de passe mis à jour et session active.')
    setUpdating(false)
  }

  return (
    <div className="mx-auto flex w-full max-w-[1100px] flex-col gap-4 px-4 sm:px-6">
      <h1 className="text-3xl font-semibold">Validation & récupération</h1>
      {status === 'loading' ? (
        <p className="text-sm text-[var(--ink-soft)]">Vérification en cours…</p>
      ) : null}
      {status === 'ok' ? (
        <p className="text-sm text-[var(--ink-soft)]">{message || 'Email vérifié.'}</p>
      ) : null}
      {status === 'error' ? (
        <p className="text-sm text-[var(--ink-soft)]">{message || 'Lien invalide ou expiré.'}</p>
      ) : null}
      {status === 'reset' ? (
        <div className="flex flex-col gap-3 rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-4">
          <p className="text-sm text-[var(--ink-soft)]">
            Définis un nouveau mot de passe (Supabase Auth).
          </p>
          <input
            type="password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            placeholder="Nouveau mot de passe (>=12 caractères)"
            className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
          />
          <button
            type="button"
            onClick={handlePasswordUpdate}
            disabled={updating}
            className="w-fit rounded-md border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
          >
            Mettre à jour le mot de passe
          </button>
          {message ? <p className="text-xs text-[var(--ink-soft)]">{message}</p> : null}
        </div>
      ) : null}
      <button
        type="button"
        onClick={() => navigate('/')}
        className="w-fit text-sm text-[var(--primary)]"
      >
        Retour à l’accueil
      </button>
    </div>
  )
}

function LegalPage({
  title,
  children,
}: {
  title: string
  children: React.ReactNode
}) {
  return (
    <div className="mx-auto flex w-full max-w-[1200px] flex-col gap-4 px-4 sm:px-6">
      <h1 className="text-3xl font-semibold">{title}</h1>
      <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] px-6 py-5 text-sm text-[var(--ink-soft)]">
        {children}
      </div>
    </div>
  )
}

function PrivacyPolicy() {
  return (
    <LegalPage title="Politique de confidentialité">
      <p>
        Nous collectons uniquement les données nécessaires au fonctionnement du
        service (sessions, paramètres de sécurité, authentification).
      </p>
      <p className="mt-3">
        Les contenus sont chiffrés côté client avant stockage. Nous ne conservons
        pas de clé de déchiffrement.
      </p>
      <p className="mt-3">
        Vos données sont supprimées à l’expiration ou après épuisement des vues.
      </p>
      <p className="mt-3">
        Vous pouvez demander la suppression de votre compte à tout moment.
      </p>
    </LegalPage>
  )
}

function TermsOfUse() {
  return (
    <LegalPage title="Conditions d'utilisation">
      <p>
        En utilisant Nemosyne, vous acceptez de ne pas partager de contenus
        illégaux, malveillants ou non autorisés.
      </p>
      <p className="mt-3">
        Le service est fourni « tel quel ». Nous nous engageons à sécuriser les
        données et à limiter l’accès aux secrets via un lien unique.
      </p>
      <p className="mt-3">
        Nous nous réservons le droit de suspendre un compte en cas d’abus.
      </p>
    </LegalPage>
  )
}

function CookiePolicy() {
  return (
    <LegalPage title="Politique de cookies">
      <p>
        Nous utilisons uniquement des cookies strictement nécessaires pour
        maintenir votre session et protéger l’accès au service.
      </p>
      <p className="mt-3">
        Aucun cookie publicitaire ni de tracking tiers n’est utilisé.
      </p>
      <p className="mt-3">
        Vous pouvez à tout moment refuser les cookies non essentiels. Le refus
        n’impacte pas l’accès au service, mais certaines fonctionnalités
        (préférences d’interface) peuvent être limitées.
      </p>
    </LegalPage>
  )
}

function FeaturesPage() {
  return (
    <LegalPage title="Caractéristiques">
      <p>Chiffrement côté client (AES-GCM) avant stockage.</p>
      <p className="mt-3">Liens secrets à usage limité avec expiration.</p>
      <p className="mt-3">
        Partage de fichiers chiffrés : 2 MB (Gratuit), 8 MB (Premium), 15 MB (Pro).
      </p>
      <p className="mt-3">MFA TOTP, vérification email et sessions sécurisées.</p>
      <p className="mt-3">Historique des pushes et tableau de bord.</p>
    </LegalPage>
  )
}

function PricingPage() {
  const plans = [
    {
      id: 'free',
      name: 'Gratuit',
      price: '0 €',
      subtitle: 'Compte requis, pushes gratuits',
      accent: false,
      cta: 'Créer un compte',
      features: [
        'Push de mots de passe gratuits (10 / mois)',
        'Expiration jusqu’à 24h',
        'Fichiers chiffrés jusqu’à 2 MB',
        'Historique 5 éléments',
      ],
    },
    {
      id: 'premium',
      name: 'Premium',
      price: '19 € / mois',
      subtitle: 'Aligné sur eu.pwpush.com (individuel)',
      accent: true,
      cta: 'Choisir Premium',
      features: [
        'Push illimités',
        'Expiration jusqu’à 72h',
        'Fichiers 8 MB + API & branding léger',
        'Logs d’accès et notifications',
      ],
    },
    {
      id: 'pro',
      name: 'Pro',
      price: '29 € / mois',
      subtitle: 'Équipes / audit avancé',
      accent: false,
      cta: 'Passer en Pro',
      features: [
        'Tout Premium + expiration 7 jours',
        'Jusqu’à 20 vues par push',
        'Audit complet, blocage IP, MFA',
        'Gestionnaire de mots de passe natif intégré',
      ],
    },
  ]

  return (
    <div className="mx-auto flex w-full max-w-[1300px] flex-col gap-6 px-4 sm:px-6">
      <h1 className="text-3xl font-semibold">Tarifs</h1>
      <p className="text-sm text-[var(--ink-soft)]">
        Grille alignée sur <span className="font-semibold">eu.pwpush.com/pricing</span> : les
        pushs de mots de passe restent gratuits avec compte.
      </p>
      <div className="grid gap-5 md:grid-cols-3">
        {plans.map((planItem) => (
          <div
            key={planItem.id}
            className={`card-elev px-5 py-6 ${planItem.accent ? 'border border-[var(--primary)]' : ''}`}
          >
            <p
              className={`text-xs uppercase tracking-[0.2em] ${planItem.accent ? 'text-[var(--primary)]' : 'text-[var(--ink-soft)]'}`}
            >
              {planItem.name}
            </p>
            <p className="mt-2 text-2xl font-semibold">{planItem.price}</p>
            <p className="text-xs text-[var(--ink-soft)]">{planItem.subtitle}</p>
            <ul className="mt-4 flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
              {planItem.features.map((feat) => (
                <li key={feat}>{feat}</li>
              ))}
            </ul>
            <button
              className={`mt-5 w-full rounded-full px-4 py-2 text-xs uppercase tracking-[0.2em] ${
                planItem.accent
                  ? 'border border-[var(--primary)] bg-[var(--primary)] text-white'
                  : 'border border-[var(--line)] text-[var(--ink-soft)]'
              }`}
            >
              {planItem.cta}
            </button>
          </div>
        ))}
      </div>
      <p className="text-xs text-[var(--ink-soft)]">
        Premium pour particuliers (19 € / mois) et Pro pour équipes (29 € / mois) – mêmes paliers que eu.pwpush.com.
      </p>
    </div>
  )
}

function ApiDocsPage() {
  return (
    <LegalPage title="Documentation API">
      <p>Créer un push (auth requis): POST /api/push</p>
      <p className="mt-3">Récupérer les métadonnées: GET /api/push/:id/meta</p>
      <p className="mt-3">Révéler un secret: POST /api/push/:id/reveal</p>
      <p className="mt-3">Session: GET /api/session</p>
      <p className="mt-3">Plan & quotas: GET /api/plan</p>
      <p className="mt-3">Changer de plan (Premium/Pro): POST /api/plan/select</p>
      <p className="mt-3">Authentification: /api/auth/*</p>
    </LegalPage>
  )
}

function WhatsNewPage() {
  return (
    <LegalPage title="Quoi de neuf">
      <p>Jan 2026: chiffrement fichiers, MFA TOTP et vérif email.</p>
      <p className="mt-3">Déc 2025: thèmes clair/sombre et générateur de mots de passe.</p>
      <p className="mt-3">Nov 2025: backend sécurisé et purge automatique.</p>
    </LegalPage>
  )
}

function PasswordGeneratorPage() {
  return (
    <LegalPage title="Générateur de mot de passe">
      <p>Générez des mots de passe forts, avec longueur et options.</p>
      <p className="mt-3">Astuce: utilisez 16+ caractères et des symboles.</p>
    </LegalPage>
  )
}

function KeyGeneratorPage() {
  return (
    <LegalPage title="Générateur de clé">
      <p>Générez une clé secrète pour partager un mémo chiffré.</p>
      <p className="mt-3">Conservez cette clé hors de tout canal public.</p>
    </LegalPage>
  )
}

function BestPracticesPage() {
  return (
    <LegalPage title="Bonnes pratiques">
      <p>Ne partagez jamais la clé dans le même canal que le lien.</p>
      <p className="mt-3">Activez MFA pour le compte administrateur.</p>
      <p className="mt-3">Utilisez une passphrase unique par push.</p>
    </LegalPage>
  )
}

function FaqPage() {
  return (
    <LegalPage title="FAQ">
      <p>Q: Puis-je récupérer un secret expiré ?</p>
      <p className="mt-2">R: Non, la suppression est définitive.</p>
      <p className="mt-3">Q: Où est stockée la clé ?</p>
      <p className="mt-2">R: Dans l’URL après #k= (côté client).</p>
    </LegalPage>
  )
}

function App() {
  const [cookieChoice, setCookieChoice] = useState<'accepted' | 'refused' | null>(
    () => {
      if (typeof window === 'undefined') return null
      const stored = window.localStorage.getItem('cookie-consent')
      return stored === 'accepted' || stored === 'refused' ? stored : null
    },
  )

  const handleCookieChoice = (value: 'accepted' | 'refused') => {
    setCookieChoice(value)
    window.localStorage.setItem('cookie-consent', value)
  }

  return (
    <div className="min-h-screen px-6 pb-14 pt-8 text-[var(--ink)] md:px-12">
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/push/:id" element={<PushView />} />
        <Route path="/verify" element={<VerifyEmail />} />
        <Route path="/features" element={<FeaturesPage />} />
        <Route path="/pricing" element={<PricingPage />} />
        <Route path="/api" element={<ApiDocsPage />} />
        <Route path="/whats-new" element={<WhatsNewPage />} />
        <Route path="/tools/passwords" element={<PasswordGeneratorPage />} />
        <Route path="/tools/keys" element={<KeyGeneratorPage />} />
        <Route path="/vault" element={<VaultPage />} />
        <Route path="/best-practices" element={<BestPracticesPage />} />
        <Route path="/faq" element={<FaqPage />} />
        <Route path="/privacy" element={<PrivacyPolicy />} />
        <Route path="/terms" element={<TermsOfUse />} />
        <Route path="/cookies" element={<CookiePolicy />} />
        <Route path="*" element={<NotFound />} />
      </Routes>

      <footer className="mt-16 rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] px-6 py-8">
        <div className="grid gap-8 md:grid-cols-5">
          <div className="md:col-span-2">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-full bg-[var(--primary)]" />
              <div>
                <p className="text-lg font-semibold">Nemosyne.</p>
                <p className="text-xs text-[var(--ink-soft)]">
                  Liens sécurisés et autodéstructeurs pour le partage de données sensibles.
                </p>
              </div>
            </div>
            <div className="mt-4 flex items-center gap-2 text-xs text-[var(--ink-soft)]">
              <span className="rounded-full border border-[var(--line)] px-3 py-1">
                GitHub
              </span>
              <span className="rounded-full border border-[var(--line)] px-3 py-1">
                Documentation
              </span>
              <span className="rounded-full border border-[var(--line)] px-3 py-1">
                Contact
              </span>
            </div>
          </div>

          <div className="text-xs">
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.2em] text-[var(--ink-soft)]">
              Produit
            </p>
            <ul className="flex flex-col gap-2 text-[var(--ink-soft)]">
              <li>
                <Link to="/features" className="hover:text-[var(--ink)]">
                  Caractéristiques
                </Link>
              </li>
              <li>
                <Link to="/pricing" className="hover:text-[var(--ink)]">
                  Tarifs
                </Link>
              </li>
              <li>
                <Link to="/api" className="hover:text-[var(--ink)]">
                  Documentation API
                </Link>
              </li>
              <li>
                <Link to="/whats-new" className="hover:text-[var(--ink)]">
                  Quoi de neuf
                </Link>
              </li>
            </ul>
          </div>

          <div className="text-xs">
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.2em] text-[var(--ink-soft)]">
              Outils
            </p>
            <ul className="flex flex-col gap-2 text-[var(--ink-soft)]">
              <li>
                <Link to="/tools/passwords" className="hover:text-[var(--ink)]">
                  Générateur de mot de passe
                </Link>
              </li>
              <li>
                <Link to="/tools/keys" className="hover:text-[var(--ink)]">
                  Générateur de clé
                </Link>
              </li>
              <li>
                <Link to="/best-practices" className="hover:text-[var(--ink)]">
                  Bonnes pratiques
                </Link>
              </li>
              <li>
                <Link to="/faq" className="hover:text-[var(--ink)]">
                  FAQ
                </Link>
              </li>
            </ul>
          </div>

          <div className="text-xs">
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.2em] text-[var(--ink-soft)]">
              Juridique
            </p>
            <ul className="flex flex-col gap-2 text-[var(--ink-soft)]">
              <li>
                <Link to="/privacy" className="hover:text-[var(--ink)]">
                  Politique de confidentialité
                </Link>
              </li>
              <li>
                <Link to="/terms" className="hover:text-[var(--ink)]">
                  Conditions d'utilisation
                </Link>
              </li>
              <li>
                <Link to="/cookies" className="hover:text-[var(--ink)]">
                  Politique de cookies
                </Link>
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-8 flex flex-col gap-3 border-t border-[var(--line)] pt-6 text-xs text-[var(--ink-soft)] md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <span className="rounded-md border border-[var(--line)] px-3 py-2">
              Région de données (UE)
            </span>
            <span>© 2026 Nemosyne. Tous droits réservés.</span>
          </div>
          <div className="flex items-center gap-3">
            <span>GitHub</span>
            <span>Docker</span>
          </div>
        </div>
      </footer>

      <div className="mt-6 rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-5 py-4 text-xs text-[var(--ink-soft)]">
        Politique de cookies : nous utilisons des cookies strictement nécessaires pour
        maintenir votre session et sécuriser l’accès. Aucun cookie publicitaire.
        <span className="ml-2">
          <Link to="/cookies" className="text-[var(--primary)]">
            En savoir plus
          </Link>
        </span>
      </div>

      {cookieChoice === null ? (
        <div className="fixed bottom-5 left-1/2 z-50 w-[min(90vw,760px)] -translate-x-1/2 rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] px-5 py-4 shadow-lg">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <p className="text-sm text-[var(--ink-soft)]">
              Nous utilisons des cookies strictement nécessaires pour sécuriser votre
              session et améliorer l’expérience. Vous pouvez accepter ou refuser.
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleCookieChoice('refused')}
                className="rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
              >
                Refuser
              </button>
              <button
                type="button"
                onClick={() => handleCookieChoice('accepted')}
                className="rounded-full border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
              >
                Accepter
              </button>
            </div>
          </div>
          <div className="mt-2 text-xs text-[var(--ink-soft)]">
            <Link to="/cookies" className="text-[var(--primary)]">
              Consulter la politique de cookies
            </Link>
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default App


