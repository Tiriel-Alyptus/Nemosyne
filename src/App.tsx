import { useEffect, useMemo, useState } from 'react'
import { Link, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import logo from './assets/logo.svg'

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

const encoder = new TextEncoder()
const decoder = new TextDecoder()

const presets = [
  { label: '15 minutes', minutes: 15 },
  { label: '1 heure', minutes: 60 },
  { label: '24 heures', minutes: 60 * 24 },
  { label: '7 jours', minutes: 60 * 24 * 7 },
]
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
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window === 'undefined') return 'light'
    const stored = window.localStorage.getItem('theme')
    if (stored === 'light' || stored === 'dark') return stored
    return window.matchMedia('(prefers-color-scheme: dark)').matches ?'dark' : 'light'
  })
  const [auth, setAuth] = useState<{
    authenticated: boolean
    email: string | null
    ownerType: 'anon' | 'user'
    verified?: boolean
    mfaEnabled?: boolean
  }>({ authenticated: false, email: null, ownerType: 'anon' })
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [authError, setAuthError] = useState('')
  const [authLoading, setAuthLoading] = useState(false)
  const [showAuth, setShowAuth] = useState(false)
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaSetup, setMfaSetup] = useState(false)
  const [mfaQr, setMfaQr] = useState<string | null>(null)
  const [secret, setSecret] = useState('')
  const [mode, setMode] = useState<'text' | 'file'>('text')
  const [file, setFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState('')
  const [label] = useState('Accès base staging')
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

  const expiresAt = useMemo(() => {
    const date = new Date()
    date.setMinutes(date.getMinutes() + expiry)
    return date.getTime()
  }, [expiry])
  const expiresAtLabel = useMemo(() => formatTime(expiresAt), [expiresAt])

  const focusComposer = () => {
    const editor = document.getElementById('memo-area') as HTMLTextAreaElement | null
    if (editor) editor.focus()
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
        }>('/api/session')
        setAuth(session)
        await apiRequest('/api/push/purge', { method: 'POST' })
        const data = await apiRequest<{ items: PushMeta[] }>('/api/push')
        setHistory(data.items.map(toSummary))
      } catch {
        setHistory([])
      }
    }
    hydrate()
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    window.localStorage.setItem('theme', theme)
  }, [theme])

  const refreshHistory = async () => {
    try {
      const session = await apiRequest<{
        authenticated: boolean
        email: string | null
        ownerType: 'anon' | 'user'
        verified: boolean
        mfaEnabled: boolean
      }>('/api/session')
      setAuth(session)
      const data = await apiRequest<{ items: PushMeta[] }>('/api/push')
      setHistory(data.items.map(toSummary))
    } catch {
      setHistory([])
    }
  }

  const handleLogin = async () => {
    setAuthLoading(true)
    setAuthError('')
    setMfaRequired(false)
    if (!email.trim() || !email.includes('@')) {
      setAuthError('Email invalide.')
      setAuthLoading(false)
      return
    }
    if (password.length < 12) {
      setAuthError('Mot de passe trop court (12 caractères minimum).')
      setAuthLoading(false)
      return
    }
    try {
      const result = await apiRequest<{ ok: boolean; email: string }>(
        '/api/auth/login',
        {
          method: 'POST',
          body: JSON.stringify({ email, password, otp: otp || undefined }),
        },
      )
      setAuth({ authenticated: true, email: result.email, ownerType: 'user' })
      setPassword('')
      setOtp('')
      await refreshHistory()
    } catch (error) {
      if (error instanceof Error && error.message.includes('mfa-required')) {
        setMfaRequired(true)
        setAuthError('Code MFA requis.')
      } else if (error instanceof Error && error.message.includes('invalid-otp')) {
        setMfaRequired(true)
        setAuthError('Code MFA invalide.')
      } else if (error instanceof Error && error.message.includes('email-not-verified')) {
        setAuthError('Email non vérifié.')
      } else {
        setAuthError('Identifiants invalides.')
      }
    } finally {
      setAuthLoading(false)
    }
  }

  const handleRegister = async () => {
    setAuthLoading(true)
    setAuthError('')
    setMfaRequired(false)
    if (!email.trim() || !email.includes('@')) {
      setAuthError('Email invalide.')
      setAuthLoading(false)
      return
    }
    if (password.length < 12) {
      setAuthError('Mot de passe trop court (12 caractères minimum).')
      setAuthLoading(false)
      return
    }
    try {
      const result = await apiRequest<{ ok: boolean; email: string }>(
        '/api/auth/register',
        {
          method: 'POST',
          body: JSON.stringify({ email, password }),
        },
      )
      setAuth({ authenticated: true, email: result.email, ownerType: 'user' })
      setPassword('')
      await refreshHistory()
    } catch (error) {
      if (error instanceof Error && error.message.includes('api-409')) {
        setAuthError('Email déjà utilisé.')
      } else if (error instanceof Error && error.message.includes('api-400')) {
        setAuthError('Email ou mot de passe invalide.')
      } else {
        setAuthError('Impossible de créer le compte.')
      }
    } finally {
      setAuthLoading(false)
    }
  }

  const handleLogout = async () => {
    setAuthLoading(true)
    setAuthError('')
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' })
      setAuth({ authenticated: false, email: null, ownerType: 'anon' })
      await refreshHistory()
    } catch {
      setAuthError('Déconnexion impossible.')
    } finally {
      setAuthLoading(false)
    }
  }

  const handleResendVerification = async () => {
    setAuthLoading(true)
    setAuthError('')
    try {
      await apiRequest('/api/auth/resend-verification', {
        method: 'POST',
        body: JSON.stringify({ email }),
      })
      setAuthError('Email de vérification envoyé.')
    } catch {
      setAuthError('Impossible d’envoyer la vérification.')
    } finally {
      setAuthLoading(false)
    }
  }

  const handleMfaSetup = async () => {
    setAuthLoading(true)
    setAuthError('')
    try {
      const result = await apiRequest<{ otpauthUrl: string; qr: string }>(
        '/api/mfa/setup',
        { method: 'POST' },
      )
      setMfaQr(result.qr)
      setMfaSetup(true)
    } catch {
      setAuthError('Impossible de configurer le MFA.')
    } finally {
      setAuthLoading(false)
    }
  }

  const handleMfaEnable = async () => {
    setAuthLoading(true)
    setAuthError('')
    try {
      await apiRequest('/api/mfa/enable', {
        method: 'POST',
        body: JSON.stringify({ otp }),
      })
      setOtp('')
      setMfaSetup(false)
      setMfaQr(null)
      await refreshHistory()
    } catch {
      setAuthError('Code MFA invalide.')
    } finally {
      setAuthLoading(false)
    }
  }


  const handleGenerate = async () => {
    if (typeof window !== 'undefined' && (!window.isSecureContext || !crypto?.subtle)) {
      setStatus('error')
      showToast('Le chiffrement nécessite HTTPS ou localhost.', 'error')
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
          label: label.trim() || file.name || 'Fichier',
          createdAtTs: now,
          expiresAtTs: expiresAt,
          viewsLeft: Math.max(1, Math.min(20, views)),
          cipher: encrypted.cipher,
          iv: encrypted.iv,
          salt: encrypted.salt,
          requiresPassphrase: encrypted.requiresPassphrase,
        }
      } else {
        encrypted = await encryptSecret(secret, passphrase)
        item = {
          kind: 'text',
          label: label.trim() || 'Secret sans titre',
          createdAtTs: now,
          expiresAtTs: expiresAt,
          viewsLeft: Math.max(1, Math.min(20, views)),
          cipher: encrypted.cipher,
          iv: encrypted.iv,
          salt: encrypted.salt,
          requiresPassphrase: encrypted.requiresPassphrase,
        }
      }

      const result = await apiRequest<{ id: string }>('/api/push', {
        method: 'POST',
        body: JSON.stringify(item),
      })
      const nextLink = buildLink(result.id, encrypted.key)
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
    } catch {
      setStatus('error')
      showToast('Erreur de génération.', 'error')
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

  const generatePassword = () => {
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
    const values = new Uint32Array(passwordLength)
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

  return (
    <div className="mx-auto flex min-h-[80vh] w-full max-w-6xl flex-col gap-8">
      <header className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-3">
          <img src={logo} alt="Nemosyne logo" className="h-10 w-10" />
          <span className="text-3xl font-semibold tracking-tight">Nemosyne.</span>
          <span className="pill bg-[var(--primary-weak)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--primary)]">
            Secure Memo
          </span>
        </div>

        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-end lg:gap-4 lg:flex-nowrap">
          <div className="flex items-center gap-3 lg:justify-end">
            <div className="flex items-center gap-1 rounded-full bg-[var(--surface-muted)] p-1">
              <button
                type="button"
                onClick={() => setTheme('dark')}
                className={`h-5 w-5 rounded-full border ${
                  theme === 'dark'
                    ?'border-[var(--primary)] bg-[var(--primary)]'
                    : 'border-[var(--line)] bg-[var(--surface)]'
                }`}
                aria-label="Mode sombre"
              />
              <button
                type="button"
                onClick={() => setTheme('light')}
                className={`h-5 w-5 rounded-full border ${
                  theme === 'light'
                    ?'border-[var(--primary)] bg-[var(--primary)]'
                    : 'border-[var(--line)] bg-[var(--surface)]'
                }`}
                aria-label="Mode clair"
              />
            </div>
            <div className="flex items-center gap-2 text-xs text-[var(--ink-soft)]">
              <span className="rounded bg-[var(--surface-muted)] px-2 py-1">FR</span>
              <span className="rounded bg-[var(--surface-muted)] px-2 py-1">EN</span>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowAuth(true)}
            className="pill border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)] transition hover:border-[var(--primary)]"
          >
            Accès Gestionnaire de mot de passe
          </button>
        </div>
      </header>

      {showAuth ?(
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
          <div className="card-elev w-full max-w-md rounded-2xl border border-[var(--line)]">
            <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-3">
              <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                Accès à la gestion de mot de passe
              </p>
              <button
                type="button"
                onClick={() => setShowAuth(false)}
                className="text-sm text-[var(--ink-soft)]"
                aria-label="Fermer"
              >
                ✕
              </button>
            </div>
            <div className="flex flex-col gap-3 px-5 py-4">
              {auth.authenticated ?(
                <div className="flex flex-col gap-2">
                  <p className="text-sm text-[var(--ink)]">
                    Connecté: <span className="font-semibold">{auth.email}</span>
                  </p>
                  {!auth.verified ?(
                    <div className="rounded-md border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-2 text-xs text-[var(--ink-soft)]">
                      Email non vérifié. Vérifiez votre boîte mail.
                    </div>
                  ) : null}
                  {auth.verified && !auth.mfaEnabled ?(
                    <button
                      type="button"
                      onClick={handleMfaSetup}
                      disabled={authLoading}
                      className="w-fit rounded-md border border-[var(--primary)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--primary)]"
                    >
                      Activer le MFA
                    </button>
                  ) : null}
                  {mfaSetup && mfaQr ?(
                    <div className="rounded-md border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-3 text-xs text-[var(--ink-soft)]">
                      <p className="mb-2">Scannez le QR code avec Google Authenticator.</p>
                      <img src={mfaQr} alt="QR MFA" className="h-40 w-40" />
                      <input
                        value={otp}
                        onChange={(event) => setOtp(event.target.value)}
                        placeholder="Code MFA"
                        className="mt-3 w-full rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                      />
                      <button
                        type="button"
                        onClick={handleMfaEnable}
                        disabled={authLoading}
                        className="mt-2 w-fit rounded-md border border-[var(--primary)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--primary)]"
                      >
                        Confirmer le MFA
                      </button>
                    </div>
                  ) : null}
                  <button
                    type="button"
                    onClick={handleLogout}
                    disabled={authLoading}
                    className="w-fit rounded-md border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                  >
                    Se déconnecter
                  </button>
                </div>
              ) : (
                <>
                  <p className="text-[11px] text-[var(--ink-soft)]">
                    Mode invité (historique uniquement sur cet appareil).
                  </p>
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
                    placeholder="Mot de passe"
                    className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  />
                  {mfaRequired ?(
                    <input
                      value={otp}
                      onChange={(event) => setOtp(event.target.value)}
                      placeholder="Code MFA (6 chiffres)"
                      className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                    />
                  ) : null}
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={handleLogin}
                      disabled={authLoading}
                      className="rounded-md border border-[var(--primary)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--primary)]"
                    >
                      Se connecter
                    </button>
                    <button
                      type="button"
                      onClick={handleRegister}
                      disabled={authLoading}
                      className="rounded-md border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                    >
                      Créer un compte
                    </button>
                  </div>
                  {authError ?(
                    <p className="text-xs text-[var(--primary)]">{authError}</p>
                  ) : null}
                  <button
                    type="button"
                    onClick={handleResendVerification}
                    disabled={authLoading}
                    className="w-fit text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                  >
                    Renvoyer l’email de vérification
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      ) : null}

      <main className="grid items-center gap-10 lg:grid-cols-[1fr_1.2fr]">
        <section className="flex flex-col gap-5">
          <h1 className="text-4xl font-semibold uppercase tracking-tight md:text-5xl">
            Crée ton Mémo chiffré
          </h1>
          <p className="max-w-md text-sm text-[var(--ink-soft)]">
            En cliquant sur le bouton, vous obtenez un lien vers le Mémo. Le Mémo est
            stocké de manière chiffrée. Après autodéstruction, il ne peut être récupéré.
          </p>
          <div className="grid gap-3 text-sm text-[var(--ink-soft)]">
            <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3">
              Le contenu est crypté avant le stockage et n'est disponible que pour ceux
              disposant du lien secret.
            </div>
            <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3">
              Une fois expiré, tous les contenus et fichiers de la publication sont supprimés
              immédiatement et entièrement.
            </div>
            <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3">
              Toutes les activités liées à votre push sont enregistrées et accessibles dans
              votre tableau de bord.
            </div>
          </div>
          <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3">
            <div className="flex items-center justify-between">
              <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                Générateur de mot de passe
              </p>
              <button
                type="button"
                onClick={generatePassword}
                className="pill border border-[var(--line)] bg-[var(--primary-weak)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--primary)]"
              >
                Générer
              </button>
            </div>
            <div className="mt-3 flex flex-col gap-3">
              <input
                value={generatedPassword}
                readOnly
                className="rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                placeholder="Mot de passe généré"
              />
              <div className="flex items-center gap-3">
                <label className="text-xs text-[var(--ink-soft)]">Longueur</label>
                <input
                  type="range"
                  min={12}
                  max={48}
                  value={passwordLength}
                  onChange={(event) => setPasswordLength(Number(event.target.value))}
                  className="flex-1"
                />
                <span className="text-xs text-[var(--ink-soft)]">{passwordLength}</span>
                <button
                  type="button"
                  onClick={handleCopyGenerated}
                  className="pill border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                >
                  Copier
                </button>
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
        </section>

        <section className="card-elev rounded-2xl border border-[var(--line)]">
          <div className="rounded-t-2xl bg-[var(--primary)] px-4 py-3 text-center text-sm font-semibold text-white">
            Envoie un Mémo.
          </div>
          <div className="flex flex-col gap-4 p-6">
            <div className="grid gap-4 md:grid-cols-2">
              <button
                type="button"
                onClick={() => {
                  setMode('text')
                  setFile(null)
                  setFileError('')
                }}
                className={`rounded-lg border px-4 py-6 text-sm font-semibold transition ${
                  mode === 'text'
                    ?'border-[var(--primary)] bg-[var(--primary)] text-white'
                    : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)]'
                }`}
              >
                Écrire un message
              </button>
              <label
                className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-4 py-6 text-center text-xs transition ${
                  mode === 'file'
                    ?'border-[var(--primary)] bg-[var(--primary-weak)] text-[var(--primary)]'
                    : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)]'
                }`}
              >
                <input
                  type="file"
                  className="hidden"
                  onChange={(event) => {
                    const selected = event.target.files?.[0]
                    if (!selected) return
                    const maxBytes = 5 * 1024 * 1024
                    if (selected.size > maxBytes) {
                      setFile(null)
                      setFileError('Fichier trop volumineux (max 5 MB).')
                      setMode('file')
                      return
                    }
                    setFile(selected)
                    setFileError('')
                    setMode('file')
                  }}
                />
                {file ?(
                  <>
                    <span className="font-semibold text-[var(--primary)]">
                      {file.name}
                    </span>
                    <span className="mt-1 text-[10px] text-[var(--ink-soft)]">
                      {formatBytes(file.size)}
                    </span>
                  </>
                ) : (
                  <>
                    Importer un fichier
                    <span className="mt-1 text-[10px] text-[var(--ink-soft)]">
                      Taille maximale : 5 MB
                    </span>
                  </>
                )}
              </label>
            </div>

            <div className="flex flex-col gap-2">
              <label className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                Message chiffré
              </label>
              <textarea
                rows={4}
                value={secret}
                disabled={mode === 'file'}
                onChange={(event) => {
                  setSecret(event.target.value)
                  setStatus('idle')
                }}
                placeholder="Tapez votre message..."
                className="w-full resize-none rounded-lg border border-[var(--line)] bg-[var(--field)] px-4 py-3 text-sm text-[var(--ink)] outline-none focus:border-[var(--primary)] disabled:cursor-not-allowed disabled:opacity-60"
              />
              {fileError ?(
                <p className="text-xs text-[var(--primary)]">{fileError}</p>
              ) : null}
            </div>

            <div className="grid gap-3 md:grid-cols-3">
              <div className="flex flex-col gap-2 md:col-span-2">
                <label className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                  Date d'expiration
                </label>
                <div className="flex flex-wrap gap-2">
                  {presets.map((preset) => (
                    <button
                      key={preset.label}
                      type="button"
                      onClick={() => setExpiry(preset.minutes)}
                      className={`rounded-md border px-3 py-2 text-xs uppercase tracking-[0.2em] transition ${
                        expiry === preset.minutes
                          ?'border-[var(--primary)] bg-[var(--primary)] text-white'
                          : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)] hover:border-[var(--primary)]'
                      }`}
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex flex-col gap-2">
                <label className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                  Vues max
                </label>
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={views}
                  onChange={(event) => setViews(Number(event.target.value))}
                  className="rounded-lg border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)] outline-none focus:border-[var(--primary)]"
                />
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <label className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                Passphrase (optionnelle)
              </label>
              <input
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                className="rounded-lg border border-[var(--line)] bg-[var(--field)] px-4 py-2 text-sm text-[var(--ink)] outline-none focus:border-[var(--primary)]"
                placeholder="Ex: mot doux"
                type="password"
              />
            </div>

            <button
              type="button"
              onClick={handleGenerate}
              className="mx-auto rounded-md border border-[var(--primary)] bg-[var(--primary-weak)] px-6 py-2 text-sm font-semibold text-[var(--primary)] transition hover:bg-[var(--primary)] hover:text-white"
            >
              {status === 'working' ?'Chiffrement…' : 'Créer un Mémo'}
            </button>

            {status === 'error' ?(
              <p className="text-sm text-[var(--primary)]">
                Vérifiez le secret ou réessayez.
              </p>
            ) : null}

            <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3 text-sm">
              {link ? (
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <span className="break-all text-[var(--ink)]">{link}</span>
                  <button
                    type="button"
                    onClick={handleCopy}
                    className="w-fit rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                  >
                    {status === 'copied' ? 'Copié' : 'Copier'}
                  </button>
                </div>
              ) : (
                <span className="text-[var(--ink-soft)]">
                  Le lien apparaîtra ici après génération.
                </span>
              )}
            </div>
            {status === 'autocopied' ?(
              <span className="text-xs text-[var(--primary)]">
                Lien copié automatiquement.
              </span>
            ) : null}
          </div>
        </section>
      </main>

      <section className="card rounded-2xl px-5 py-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.2em] text-[var(--ink-soft)]">
          Derniers pushes
        </h3>
        <div className="mt-3 flex flex-col gap-2">
          {history.length === 0 ?(
            <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-2 text-sm text-[var(--ink-soft)]">
              Aucun push pour le moment.
            </div>
          ) : (
            history.map((item) => (
              <Link
                key={item.id}
                to={`/push/${item.id}`}
                className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-2 text-sm text-[var(--ink)]"
              >
                <span>{item.label} • {item.viewsLeft} vues</span>
                {!item.requiresPassphrase ?(
                  <span className="ml-2 text-xs text-[var(--ink-soft)]">
                    (clé URL requise)
                  </span>
                ) : null}
              </Link>
            ))
          )}
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
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-6">
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
                className="rounded-md bg-[var(--primary)] px-6 py-2 text-sm font-semibold text-white transition hover:opacity-90"
              >
                Révéler le secret
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
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
      <h1 className="text-3xl font-semibold">Page introuvable</h1>
      <Link to="/" className="text-sm text-[var(--primary)]">
        Retour à l’accueil
      </Link>
    </div>
  )
}

function VerifyEmail() {
  const location = useLocation()
  const [status, setStatus] = useState<'loading' | 'ok' | 'error'>('loading')

  useEffect(() => {
    const token = new URLSearchParams(location.search).get('token')
    if (!token) {
      setStatus('error')
      return
    }
    const verify = async () => {
      try {
        await apiRequest(`/api/auth/verify?token=${encodeURIComponent(token)}`)
        setStatus('ok')
      } catch {
        setStatus('error')
      }
    }
    verify()
  }, [location.search])

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
      <h1 className="text-3xl font-semibold">Vérification email</h1>
      {status === 'loading' ?(
        <p className="text-sm text-[var(--ink-soft)]">Vérification en cours…</p>
      ) : null}
      {status === 'ok' ?(
        <p className="text-sm text-[var(--ink-soft)]">
          Email vérifié. Vous pouvez vous connecter.
        </p>
      ) : null}
      {status === 'error' ?(
        <p className="text-sm text-[var(--ink-soft)]">
          Lien invalide ou expiré.
        </p>
      ) : null}
      <Link to="/" className="text-sm text-[var(--primary)]">
        Retour à l’accueil
      </Link>
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
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-4">
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
      <p className="mt-3">Partage de fichiers chiffrés jusqu’à 5 MB.</p>
      <p className="mt-3">MFA TOTP, vérification email et sessions sécurisées.</p>
      <p className="mt-3">Historique des pushes et tableau de bord.</p>
    </LegalPage>
  )
}

function PricingPage() {
  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <h1 className="text-3xl font-semibold">Tarifs</h1>
      <p className="text-sm text-[var(--ink-soft)]">
        Des plans simples pour sécuriser et partager vos secrets.
      </p>
      <div className="grid gap-5 md:grid-cols-3">
        <div className="card-elev px-5 py-6">
          <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">Starter</p>
          <p className="mt-2 text-2xl font-semibold">0 €</p>
          <p className="text-xs text-[var(--ink-soft)]">Pour essayer</p>
          <ul className="mt-4 flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
            <li>Jusqu’à 10 pushes / mois</li>
            <li>Expiration max 24h</li>
            <li>1 utilisateur</li>
          </ul>
          <button className="mt-5 w-full rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
            Commencer
          </button>
        </div>
        <div className="card-elev px-5 py-6 border border-[var(--primary)]">
          <p className="text-xs uppercase tracking-[0.2em] text-[var(--primary)]">Pro</p>
          <p className="mt-2 text-2xl font-semibold">9 € / mois</p>
          <p className="text-xs text-[var(--ink-soft)]">Idéal pour les indépendants</p>
          <ul className="mt-4 flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
            <li>Pushes illimités</li>
            <li>Expiration jusqu’à 7 jours</li>
            <li>Historique complet</li>
            <li>MFA & audit d’accès</li>
          </ul>
          <button className="mt-5 w-full rounded-full border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white">
            Choisir Pro
          </button>
        </div>
        <div className="card-elev px-5 py-6">
          <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">Business</p>
          <p className="mt-2 text-2xl font-semibold">25 € / mois</p>
          <p className="text-xs text-[var(--ink-soft)]">Équipes et PME</p>
          <ul className="mt-4 flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
            <li>Tout Pro</li>
            <li>Jusqu’à 20 utilisateurs</li>
            <li>Rôles & permissions</li>
            <li>Support prioritaire</li>
          </ul>
          <button className="mt-5 w-full rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
            Contacter
          </button>
        </div>
      </div>
    </div>
  )
}

function ApiDocsPage() {
  return (
    <LegalPage title="Documentation API">
      <p>Créer un push: POST /api/push</p>
      <p className="mt-3">Récupérer les métadonnées: GET /api/push/:id/meta</p>
      <p className="mt-3">Révéler un secret: POST /api/push/:id/reveal</p>
      <p className="mt-3">Session: GET /api/session</p>
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
