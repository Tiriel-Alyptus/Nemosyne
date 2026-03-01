import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { Link, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import logo from './assets/logo.svg'
import Header from './components/layout/Header'
import { broadcastAuthEvent, onAuthEvent } from './lib/sessionSync'

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

type AuthStatus =
  | 'anonymous'
  | 'checking'
  | 'pending_email_verification'
  | 'authenticated'

type UserPreferences = {
  theme: 'light' | 'dark'
  density: 'comfortable' | 'compact'
  language: 'fr' | 'en'
  emailNotifications: boolean
}

type SessionSnapshot = {
  authenticated: boolean
  email: string | null
  ownerType: 'anon' | 'user'
  verified: boolean
  mfaEnabled: boolean
  user: {
    id: string
    email: string
    displayName: string | null
    avatarUrl: string | null
    preferences: Partial<UserPreferences> | null
  } | null
}

type AuthState = {
  status: AuthStatus
  authenticated: boolean
  email: string | null
  ownerType: 'anon' | 'user'
  verified: boolean
  mfaEnabled: boolean
  userId: string | null
  displayName: string | null
  avatarUrl: string | null
  preferences: UserPreferences
}

type AuthContextValue = {
  auth: AuthState
  refreshAuth: () => Promise<AuthState>
  signalAuthChange: (reason: string) => void
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

const presets = [
  { label: '15 minutes', minutes: 15 },
  { label: '1 heure', minutes: 60 },
  { label: '24 heures', minutes: 60 * 24 },
  { label: '7 jours', minutes: 60 * 24 * 7 },
]
const quickDurationPresets = [
  { label: '1 h', minutes: 60 },
  { label: '1 j', minutes: 60 * 24 },
  { label: '7 j', minutes: 60 * 24 * 7 },
]
const quickViewPresets = [1, 5, 10]
const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined)
  ?.trim()
  .replace(/\/$/, '')
const defaultUserPreferences: UserPreferences = {
  theme: 'light',
  density: 'comfortable',
  language: 'fr',
  emailNotifications: true,
}
const baseAnonymousAuth: AuthState = {
  status: 'anonymous',
  authenticated: false,
  email: null,
  ownerType: 'anon',
  verified: false,
  mfaEnabled: false,
  userId: null,
  displayName: null,
  avatarUrl: null,
  preferences: defaultUserPreferences,
}
const AuthContext = createContext<AuthContextValue | null>(null)

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

function formatDuration(minutes: number) {
  if (minutes < 60) return `${minutes} min`
  if (minutes % (60 * 24) === 0) {
    const days = minutes / (60 * 24)
    return days === 1 ? '1 jour' : `${days} jours`
  }
  if (minutes % 60 === 0) {
    const hours = minutes / 60
    return hours === 1 ? '1 heure' : `${hours} heures`
  }
  const hours = Math.floor(minutes / 60)
  const remainder = minutes % 60
  return `${hours} h ${remainder} min`
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

function toAuthStatus(snapshot: SessionSnapshot): AuthStatus {
  if (!snapshot.authenticated || snapshot.ownerType !== 'user') {
    return 'anonymous'
  }
  if (!snapshot.verified) {
    return 'pending_email_verification'
  }
  return 'authenticated'
}

function toAuthState(snapshot: SessionSnapshot): AuthState {
  const userPreferences = snapshot.user?.preferences || {}
  return {
    status: toAuthStatus(snapshot),
    authenticated: snapshot.authenticated,
    email: snapshot.email || null,
    ownerType: snapshot.ownerType,
    verified: snapshot.verified,
    mfaEnabled: snapshot.mfaEnabled,
    userId: snapshot.user?.id || null,
    displayName: snapshot.user?.displayName || null,
    avatarUrl: snapshot.user?.avatarUrl || null,
    preferences: {
      theme: userPreferences.theme === 'dark' ? 'dark' : 'light',
      density:
        userPreferences.density === 'compact'
          ? 'compact'
          : defaultUserPreferences.density,
      language: userPreferences.language === 'en' ? 'en' : 'fr',
      emailNotifications:
        typeof userPreferences.emailNotifications === 'boolean'
          ? userPreferences.emailNotifications
          : defaultUserPreferences.emailNotifications,
    },
  }
}

function getInitials(value: string | null | undefined) {
  if (!value) return 'U'
  const parts = value
    .trim()
    .split(/\s+/)
    .filter(Boolean)
  if (parts.length === 0) return 'U'
  const first = parts[0]?.[0] || ''
  const second = parts.length > 1 ? parts[1]?.[0] || '' : ''
  const fallback = value.includes('@') ? value[0] || 'U' : ''
  return `${first}${second || fallback}`.toUpperCase().slice(0, 2)
}

function AuthProvider({ children }: { children: React.ReactNode }) {
  const [auth, setAuth] = useState<AuthState>({ ...baseAnonymousAuth, status: 'checking' })

  const refreshAuth = useCallback(async () => {
    try {
      const session = await apiRequest<SessionSnapshot>('/api/session')
      const next = toAuthState(session)
      setAuth(next)
      return next
    } catch {
      setAuth(baseAnonymousAuth)
      return baseAnonymousAuth
    }
  }, [])

  const refreshAuthFromExternalEvent = useCallback(async () => {
    setAuth((current) =>
      current.status === 'checking'
        ? current
        : {
            ...current,
            status: 'checking',
          },
    )
    return refreshAuth()
  }, [refreshAuth])

  const signalAuthChange = useCallback((reason: string) => {
    broadcastAuthEvent(reason)
  }, [])

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refreshAuth()
    }, 0)
    return () => window.clearTimeout(timer)
  }, [refreshAuth])

  useEffect(() => {
    if (typeof window === 'undefined') return

    const unsubscribe = onAuthEvent(() => {
      void refreshAuthFromExternalEvent()
    })

    const onFocus = () => {
      void refreshAuth()
    }
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void refreshAuth()
      }
    }

    window.addEventListener('focus', onFocus)
    document.addEventListener('visibilitychange', onVisibilityChange)

    return () => {
      unsubscribe()
      window.removeEventListener('focus', onFocus)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [refreshAuth, refreshAuthFromExternalEvent])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const pollIntervalMs =
      auth.status === 'pending_email_verification'
        ? 7000
        : auth.status === 'authenticated'
          ? 15000
          : 30000
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void refreshAuth()
      }
    }, pollIntervalMs)
    return () => window.clearInterval(timer)
  }, [auth.status, refreshAuth])

  return (
    <AuthContext.Provider
      value={{
        auth,
        refreshAuth,
        signalAuthChange,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

function useAuthStore() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuthStore must be used within AuthProvider')
  }
  return context
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
  const { auth, refreshAuth, signalAuthChange } = useAuthStore()
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window === 'undefined') return 'light'
    const stored = window.localStorage.getItem('theme')
    if (stored === 'light' || stored === 'dark') return stored
    return 'light' // interface blanche par defaut
  })
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [authError, setAuthError] = useState('')
  const [authLoading, setAuthLoading] = useState(false)
  const [showAuth, setShowAuth] = useState(false)
  const [authMode, setAuthMode] = useState<'signin' | 'signup'>(() => {
    if (typeof window === 'undefined') return 'signup'
    const stored = window.localStorage.getItem('auth-mode')
    return stored === 'signin' || stored === 'signup' ? stored : 'signup'
  })
  const [fullName, setFullName] = useState('')
  const [rememberMe, setRememberMe] = useState(() => {
    if (typeof window === 'undefined') return true
    const stored = window.localStorage.getItem('auth-remember')
    return stored !== '0'
  })
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaSetup, setMfaSetup] = useState(false)
  const [mfaQr, setMfaQr] = useState<string | null>(null)
  const [secret, setSecret] = useState('')
  const [mode, setMode] = useState<'text' | 'file' | 'url'>('text')
  const [file, setFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState('')
  const [label] = useState('Acces base staging')
  const [views, setViews] = useState(3)
  const [expiry, setExpiry] = useState(presets[2].minutes)
  const [passphrase, setPassphrase] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
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
  const [historySearch, setHistorySearch] = useState('')
  const [toast, setToast] = useState<{
    message: string
    kind: 'success' | 'error' | 'info'
  } | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [settingsError, setSettingsError] = useState('')
  const [settingsName, setSettingsName] = useState('')
  const [settingsAvatarUrl, setSettingsAvatarUrl] = useState('')
  const [settingsTheme, setSettingsTheme] = useState<'light' | 'dark'>('light')
  const [settingsDensity, setSettingsDensity] = useState<'comfortable' | 'compact'>(
    'comfortable',
  )
  const [settingsLanguage, setSettingsLanguage] = useState<'fr' | 'en'>('fr')
  const [settingsEmailNotifications, setSettingsEmailNotifications] = useState(true)
  const [mobileSettingsOpen, setMobileSettingsOpen] = useState(false)
  const [isExpiryCustom, setIsExpiryCustom] = useState(
    !quickDurationPresets.some((preset) => preset.minutes === presets[2].minutes),
  )
  const [isViewsCustom, setIsViewsCustom] = useState(!quickViewPresets.includes(3))
  const [avatarLoadError, setAvatarLoadError] = useState(false)
  const copyLinkButtonRef = useRef<HTMLButtonElement | null>(null)

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
  const durationLabel = useMemo(() => formatDuration(expiry), [expiry])
  const viewsLabel = useMemo(() => (views > 1 ? `${views} vues` : '1 vue'), [views])
  const isFileMode = mode === 'file'
  const textareaPlaceholder = mode === 'url'
    ? "Entrez l'URL sensible a publier..."
    : "Entrez le mot de passe, le texte ou l'URL a publier..."
  const statusLabel = status === 'working'
    ? 'Chiffrement...'
    : status === 'ready' || status === 'autocopied'
      ? 'Lien pret'
      : status === 'copied'
        ? 'Copie'
        : status === 'error'
          ? 'A verifier'
          : 'En attente'
  const mainCtaLabel = status === 'working' ? 'Creation en cours...' : 'Creer le lien securise'
  const isGenerating = status === 'working'
  const hasSecretInput = mode === 'file' ? Boolean(file) : Boolean(secret.trim())
  const isGenerateDisabled = isGenerating || !hasSecretInput
  const userDisplayName = auth.displayName || auth.email || 'Utilisateur'
  const userInitials = getInitials(userDisplayName)
  const userAvatarUrl = avatarLoadError ? null : auth.avatarUrl
  const pendingEmailVerification = auth.status === 'pending_email_verification'
  const filteredHistory = useMemo(() => {
    const query = historySearch.trim().toLowerCase()
    if (!query) return history
    return history.filter((item) => {
      return (
        item.label.toLowerCase().includes(query) ||
        item.id.toLowerCase().includes(query)
      )
    })
  }, [history, historySearch])

  const focusComposer = () => {
    const editor = document.getElementById('memo-area') as HTMLTextAreaElement | null
    if (editor) editor.focus()
  }

  useEffect(() => {
    const hydrate = async () => {
      try {
        await apiRequest('/api/push/purge', { method: 'POST' })
        const data = await apiRequest<{ items: PushMeta[] }>('/api/push')
        setHistory(data.items.map(toSummary))
      } catch {
        setHistory([])
      }
    }
    void hydrate()
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    window.localStorage.setItem('theme', theme)
  }, [theme])

  useEffect(() => {
    document.documentElement.dataset.density = auth.preferences.density
    document.documentElement.lang = auth.preferences.language
  }, [auth.preferences.density, auth.preferences.language])

  useEffect(() => {
    if (auth.authenticated) {
      const nextTheme = auth.preferences.theme
      setTheme((current) => (current === nextTheme ? current : nextTheme))
    }
  }, [auth.authenticated, auth.preferences.theme])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const rememberedEmail = window.localStorage.getItem('auth-email')
    if (rememberedEmail) {
      setEmail(rememberedEmail)
    }
  }, [])

  useEffect(() => {
    if (typeof window === 'undefined') return
    window.localStorage.setItem('auth-mode', authMode)
  }, [authMode])

  useEffect(() => {
    setAvatarLoadError(false)
  }, [auth.avatarUrl])

  useEffect(() => {
    if (!showSettings) return
    setSettingsError('')
    setSettingsName(auth.displayName || '')
    setSettingsAvatarUrl(auth.avatarUrl || '')
    setSettingsTheme(auth.preferences.theme)
    setSettingsDensity(auth.preferences.density)
    setSettingsLanguage(auth.preferences.language)
    setSettingsEmailNotifications(auth.preferences.emailNotifications)
  }, [
    auth.avatarUrl,
    auth.displayName,
    auth.preferences.density,
    auth.preferences.emailNotifications,
    auth.preferences.language,
    auth.preferences.theme,
    showSettings,
  ])

  useEffect(() => {
    if (!link) return
    if (status !== 'ready' && status !== 'autocopied') return
    const timer = window.setTimeout(() => {
      copyLinkButtonRef.current?.focus()
    }, 0)
    return () => window.clearTimeout(timer)
  }, [link, status])

  const refreshHistory = async () => {
    try {
      const data = await apiRequest<{ items: PushMeta[] }>('/api/push')
      setHistory(data.items.map(toSummary))
    } catch {
      setHistory([])
    }
  }

  const persistRememberedAuth = (nextEmail: string) => {
    if (typeof window === 'undefined') return
    window.localStorage.setItem('auth-mode', authMode)
    window.localStorage.setItem('auth-remember', rememberMe ? '1' : '0')
    if (rememberMe) {
      window.localStorage.setItem('auth-email', nextEmail)
    } else {
      window.localStorage.removeItem('auth-email')
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
      setAuthError('Mot de passe trop court (12 caracteres minimum).')
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
      persistRememberedAuth(result.email)
      setPassword('')
      setOtp('')
      setAuthError('')
      setShowAuth(false)
      await refreshAuth()
      signalAuthChange('auth-login')
      await refreshHistory()
    } catch (error) {
      if (error instanceof Error && error.message.includes('mfa-required')) {
        setMfaRequired(true)
        setAuthError('Code MFA requis.')
      } else if (error instanceof Error && error.message.includes('invalid-otp')) {
        setMfaRequired(true)
        setAuthError('Code MFA invalide.')
      } else if (error instanceof Error && error.message.includes('email-not-verified')) {
        setAuthError('Email non verifie.')
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
      setAuthError('Mot de passe trop court (12 caracteres minimum).')
      setAuthLoading(false)
      return
    }
    try {
      const result = await apiRequest<{
        ok: boolean
        email: string
        authenticated: boolean
        accountStatus: 'created' | 'pending-verification'
        verificationEmailSent: boolean
        verificationEmailReason: string | null
        verificationEmailPreviewLink: string | null
      }>(
        '/api/auth/register',
        {
          method: 'POST',
          body: JSON.stringify({ email, password, fullName }),
        },
      )
      const isAuthenticated = Boolean(result.authenticated)
      if (isAuthenticated) {
        persistRememberedAuth(result.email)
      }
      setPassword('')
      const devHint = result.verificationEmailPreviewLink
        ? ` Lien dev: ${result.verificationEmailPreviewLink}`
        : ''
      if (result.accountStatus === 'pending-verification') {
        if (result.verificationEmailSent) {
          setAuthError('Compte deja cree mais non verifie. Nouvel email de verification envoye.')
          showToast('Compte non verifie: email de verification renvoye.', 'info')
        } else {
          setAuthError(
            `Compte deja cree mais non verifie. Email non envoye (raison: ${result.verificationEmailReason || 'inconnue'}).${devHint}`,
          )
          showToast('Compte non verifie mais service email indisponible.', 'error')
        }
      } else if (result.verificationEmailSent) {
        setAuthError('Compte cree. Email de verification envoye.')
        showToast('Email de verification envoye.', 'success')
        setShowAuth(false)
      } else {
        setAuthError(
          `Compte cree, mais l'email de verification n'a pas pu etre envoye (raison: ${result.verificationEmailReason || 'inconnue'}).${devHint}`,
        )
        showToast('Service email non disponible. Verifiez la configuration SMTP.', 'error')
      }
      await refreshAuth()
      if (isAuthenticated) {
        signalAuthChange('auth-register')
      }
      await refreshHistory()
    } catch (error) {
      if (error instanceof Error && error.message.includes('api-409')) {
        setAuthError('Email deja utilise.')
      } else if (error instanceof Error && error.message.includes('api-400')) {
        setAuthError('Email ou mot de passe invalide.')
      } else {
        setAuthError('Impossible de creer le compte.')
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
      await refreshAuth()
      signalAuthChange('auth-logout')
      await refreshHistory()
    } catch {
      setAuthError('Deconnexion impossible.')
    } finally {
      setAuthLoading(false)
    }
  }

  const handleResendVerification = async () => {
    setAuthLoading(true)
    setAuthError('')
    try {
      const targetEmail = (auth.email || email).trim()
      if (!targetEmail) {
        setAuthError('Email manquant pour le renvoi.')
        setAuthLoading(false)
        return
      }
      const result = await apiRequest<{
        ok: boolean
        verificationEmailSent: boolean
        verificationEmailReason: string | null
        verificationEmailPreviewLink: string | null
      }>('/api/auth/resend-verification', {
        method: 'POST',
        body: JSON.stringify({ email: targetEmail }),
      })
      if (result.verificationEmailSent) {
        setAuthError('Email de verification envoye.')
        showToast('Email de verification envoye.', 'success')
      } else {
        const reason = result.verificationEmailReason || 'inconnue'
        const devHint = result.verificationEmailPreviewLink
          ? ` Lien dev: ${result.verificationEmailPreviewLink}`
          : ''
        if (reason === 'not-delivered') {
          setAuthError('Si un compte non verifie existe pour cet email, un nouveau lien a ete envoye.')
          showToast('Demande prise en compte.', 'info')
        } else {
          setAuthError(`Email non envoye (raison: ${reason}).${devHint}`)
          showToast('Email non envoye. Verifiez la configuration SMTP.', 'error')
        }
      }
    } catch {
      setAuthError("Impossible d'envoyer la verification.")
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
      await refreshAuth()
      signalAuthChange('mfa-enabled')
      await refreshHistory()
    } catch {
      setAuthError('Code MFA invalide.')
    } finally {
      setAuthLoading(false)
    }
  }

  const handleSaveSettings = async () => {
    if (!auth.authenticated) return
    setSettingsSaving(true)
    setSettingsError('')
    try {
      await apiRequest('/api/user/settings', {
        method: 'PATCH',
        body: JSON.stringify({
          displayName: settingsName,
          avatarUrl: settingsAvatarUrl,
          preferences: {
            theme: settingsTheme,
            density: settingsDensity,
            language: settingsLanguage,
            emailNotifications: settingsEmailNotifications,
          },
        }),
      })
      setTheme(settingsTheme)
      await refreshAuth()
      signalAuthChange('user-settings-updated')
      setShowSettings(false)
      showToast('Parametres enregistres.', 'success')
    } catch {
      setSettingsError('Impossible deenregistrer les parametres.')
    } finally {
      setSettingsSaving(false)
    }
  }

  const openAuthModal = (modeValue: 'signin' | 'signup') => {
    setAuthMode(modeValue)
    setAuthError('')
    setMfaRequired(false)
    setOtp('')
    setShowAuth(true)
  }

  const openSecurityPanel = () => {
    setAuthError('')
    setMfaRequired(false)
    setOtp('')
    setShowAuth(true)
  }

  const resetComposer = () => {
    setMode('text')
    setSecret('')
    setFile(null)
    setFileError('')
    setPassphrase('')
    setExpiry(presets[2].minutes)
    setViews(3)
    setIsExpiryCustom(!quickDurationPresets.some((preset) => preset.minutes === presets[2].minutes))
    setIsViewsCustom(!quickViewPresets.includes(3))
    setShowAdvanced(false)
    setMobileSettingsOpen(false)
    setLink('')
    setStatus('idle')
    if (typeof window !== 'undefined') {
      window.requestAnimationFrame(() => {
        focusComposer()
      })
    }
  }


  const handleGenerate = async () => {
    if (typeof window !== 'undefined' && (!window.isSecureContext || !crypto?.subtle)) {
      setStatus('error')
      showToast('Le chiffrement necessite HTTPS ou localhost.', 'error')
      return
    }
    if (mode !== 'file' && !secret.trim()) {
      setStatus('error')
      showToast('Message requis.', 'error')
      return
    }
    if (mode === 'file' && !file) {
      setStatus('error')
      showToast('Selectionnez un fichier.', 'error')
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
          showToast('Lien genere et copie.', 'success')
        } catch {
          setStatus('ready')
          showToast('Lien genere.', 'success')
        }
      } else {
        setStatus('ready')
        showToast('Lien genere.', 'success')
      }
      await refreshHistory()
    } catch {
      setStatus('error')
      showToast('Erreur de generation.', 'error')
    }
  }

  const handleCopy = async () => {
    if (!link) return
    try {
      await navigator.clipboard.writeText(link)
      setStatus('copied')
      setTimeout(() => setStatus('ready'), 1500)
      showToast('Lien copie.', 'success')
    } catch {
      setStatus('ready')
      showToast('Impossible de copier.', 'error')
    }
  }

  const handleCopyPreparedMessage = async () => {
    if (!link) return
    const text = `Voici votre lien Nemosyne : ${link}\nExpire dans ${durationLabel} ou apres ${viewsLabel} (au premier atteint).`
    try {
      await navigator.clipboard.writeText(text)
      showToast('Message pret copie.', 'success')
    } catch {
      showToast('Impossible de copier le message.', 'error')
    }
  }

  const generatePassword = useCallback((customLength?: number) => {
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
  }, [passwordLength, useLower, useNumbers, useSymbols, useUpper])

  const handleCopyGenerated = async () => {
    if (!generatedPassword) return
    try {
      await navigator.clipboard.writeText(generatedPassword)
      showToast('Mot de passe copie.', 'success')
    } catch {
      showToast('Impossible de copier.', 'error')
    }
  }

  useEffect(() => {
    generatePassword()
  }, [generatePassword])
  return (
    <div className="flex w-full flex-col gap-10 pb-28 lg:pb-14">
      <Header
        logoSrc={logo}
        theme={theme}
        onThemeChange={setTheme}
        isAuthenticated={auth.authenticated}
        authLoading={authLoading}
        userDisplayName={userDisplayName}
        userInitials={userInitials}
        avatarUrl={userAvatarUrl}
        onAvatarError={() => setAvatarLoadError(true)}
        onOpenSettings={() => setShowSettings(true)}
        onOpenSecurity={openSecurityPanel}
        onOpenAuth={openAuthModal}
        onLogout={handleLogout}
        hasBillingRoute
      />
      {pendingEmailVerification ? (
        <div className="rounded-2xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-[var(--ink)]">
          Email en attente de verification. Ouvrez votre boete mail puis cliquez sur le
          lien de validation. Cette page se mettra a jour automatiquement.
        </div>
      ) : null}


      {showAuth ?(
        <div className="fixed inset-0 z-50 overflow-y-auto bg-[var(--bg-2)]/95 text-[var(--ink)] backdrop-blur-sm">
          <div className="mx-auto flex min-h-screen w-full max-w-6xl flex-col px-5 py-8 md:px-10">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <img src={logo} alt="Logo Nemosyne" className="h-9 w-9" />
                <div className="leading-tight">
                  <p className="text-xl font-semibold tracking-tight">Nemosyne</p>
                  <p className="text-[11px] uppercase tracking-[0.22em] text-[var(--ink-soft)]">
                    Partage securise
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowAuth(false)}
                className="rounded-full border border-[var(--line)] px-4 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)] transition hover:bg-[var(--surface-muted)]"
                aria-label="Fermer"
              >
                Fermer
              </button>
            </div>

            <div className="mx-auto mt-8 w-full max-w-xl">
              <div className="rounded-xl border border-[var(--line)] bg-[var(--surface)] px-6 py-7 shadow-[var(--shadow)] md:px-10 md:py-10">
                {auth.authenticated ?(
                  <div className="flex flex-col gap-4">
                    <div className="text-center">
                      <h2 className="text-4xl font-medium">Mon compte</h2>
                      <p className="mt-2 text-sm text-[var(--ink-soft)]">
                        Connecte avec <span className="font-semibold text-[var(--ink)]">{auth.email}</span>
                      </p>
                    </div>

                    {!auth.verified ?(
                      <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3 text-sm text-[var(--ink)]">
                        Email non verifie. Verifiez votre boete de reception.
                        <button
                          type="button"
                          onClick={handleResendVerification}
                          disabled={authLoading}
                          className="mt-3 block text-sm font-semibold text-[var(--primary)] underline disabled:opacity-50"
                        >
                          Renvoyer leemail de verification
                        </button>
                      </div>
                    ) : null}

                    {auth.verified && !auth.mfaEnabled ?(
                      <button
                        type="button"
                        onClick={handleMfaSetup}
                        disabled={authLoading}
                        className="w-full rounded-md border border-[var(--primary)] px-4 py-3 text-sm font-semibold text-[var(--primary)]"
                      >
                        Activer le MFA
                      </button>
                    ) : null}

                    {mfaSetup && mfaQr ?(
                      <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-4 text-sm text-[var(--ink-soft)]">
                        <p className="mb-3">Scannez le QR code avec votre application TOTP.</p>
                        <img src={mfaQr} alt="QR MFA" className="mx-auto h-40 w-40" />
                        <input
                          value={otp}
                          onChange={(event) => setOtp(event.target.value)}
                          placeholder="Code MFA"
                          className="mt-3 w-full border-0 border-b border-[var(--line)] bg-transparent px-0 py-2 text-base text-[var(--ink)] focus:border-[var(--primary)]"
                        />
                        <button
                          type="button"
                          onClick={handleMfaEnable}
                          disabled={authLoading}
                          className="mt-4 w-full rounded-md border border-[var(--primary)] bg-[var(--primary)] px-4 py-3 text-sm font-semibold text-white transition hover:opacity-90"
                        >
                          Confirmer le MFA
                        </button>
                      </div>
                    ) : null}

                    <button
                      type="button"
                      onClick={handleLogout}
                      disabled={authLoading}
                      className="w-full rounded-md border border-[var(--line)] px-4 py-3 text-sm font-semibold text-[var(--ink-soft)]"
                    >
                      Se deconnecter
                    </button>
                  </div>
                ) : (
                  <>
                    <div className="text-center">
                      <h2 className="text-5xl font-light tracking-tight">
                        {authMode === 'signup' ? "S'inscrire" : 'Se connecter'}
                      </h2>
                      <p className="mt-2 text-xl text-[var(--ink-soft)]">
                        {authMode === 'signup'
                          ? 'Creer votre espace securise'
                          : 'Connectez-vous pour continuer'}
                      </p>
                    </div>

                    <div className="mt-8 flex flex-col gap-7">
                      {authMode === 'signup' ?(
                        <div className="flex flex-col gap-2">
                          <label className="text-[15px] text-[var(--ink-soft)]">Nom</label>
                          <input
                            value={fullName}
                            onChange={(event) => setFullName(event.target.value)}
                            placeholder="Votre nom"
                            className="border-0 border-b border-[var(--line)] bg-transparent px-0 pb-2 pt-1 text-lg text-[var(--ink)] focus:border-[var(--primary)]"
                          />
                        </div>
                      ) : null}

                      <div className="flex flex-col gap-2">
                        <label className="text-[15px] text-[var(--ink-soft)]">Email</label>
                        <input
                          value={email}
                          onChange={(event) => setEmail(event.target.value)}
                          placeholder="votre@email.com"
                          className="border-0 border-b border-[var(--line)] bg-transparent px-0 pb-2 pt-1 text-lg text-[var(--ink)] focus:border-[var(--primary)]"
                        />
                      </div>

                      <div className="flex flex-col gap-2">
                        <label className="text-[15px] text-[var(--ink-soft)]">Mot de passe</label>
                        <input
                          type="password"
                          value={password}
                          onChange={(event) => setPassword(event.target.value)}
                          placeholder="Mot de passe"
                          className="border-0 border-b border-[var(--line)] bg-transparent px-0 pb-2 pt-1 text-lg text-[var(--ink)] focus:border-[var(--primary)]"
                        />
                      </div>

                      {authMode === 'signin' && mfaRequired ?(
                        <div className="flex flex-col gap-2">
                          <label className="text-[15px] text-[var(--ink-soft)]">Code MFA</label>
                          <input
                            value={otp}
                            onChange={(event) => setOtp(event.target.value)}
                            placeholder="6 chiffres"
                            className="border-0 border-b border-[var(--line)] bg-transparent px-0 pb-2 pt-1 text-lg text-[var(--ink)] focus:border-[var(--primary)]"
                          />
                        </div>
                      ) : null}

                      <button
                        type="button"
                        onClick={() => {
                          if (authMode === 'signup') {
                            handleRegister()
                            return
                          }
                          handleLogin()
                        }}
                        disabled={authLoading}
                        className="mt-2 w-full rounded-md border border-[var(--primary)] bg-[var(--primary)] px-4 py-3 text-xl font-semibold text-white shadow-[var(--shadow)] transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {authLoading
                          ? 'Chargement...'
                          : authMode === 'signup'
                            ? "S'inscrire"
                            : 'Se connecter'}
                      </button>

                      <label className="flex items-center gap-3 text-lg text-[var(--ink)]">
                        <input
                          type="checkbox"
                          checked={rememberMe}
                          onChange={(event) => setRememberMe(event.target.checked)}
                          className="h-4 w-4 rounded border-[var(--line)] accent-[var(--primary)]"
                        />
                        Se souvenir de moi
                      </label>

                      {authError ?(
                        <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                          {authError}
                        </p>
                      ) : null}

                      {authMode === 'signup' ?(
                        <button
                          type="button"
                          onClick={handleResendVerification}
                          disabled={authLoading}
                          className="w-fit text-sm text-[var(--primary)] underline"
                        >
                          Renvoyer leemail de verification
                        </button>
                      ) : null}

                      <div className="mt-1 flex items-center gap-4">
                        <span className="h-px flex-1 bg-[var(--line)]" />
                        <span className="text-sm font-semibold uppercase tracking-[0.1em] text-[var(--ink-soft)]">
                          Acces rapide
                        </span>
                        <span className="h-px flex-1 bg-[var(--line)]" />
                      </div>

                      <div className="grid grid-cols-3 gap-3">
                        <button
                          type="button"
                          onClick={() => showToast('Connexion Google bientet disponible.')}
                          className="rounded-md border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-2 text-sm font-semibold text-[var(--primary)] transition hover:border-[var(--primary)]"
                        >
                          Google
                        </button>
                        <button
                          type="button"
                          onClick={() => showToast('Connexion LinkedIn bientet disponible.')}
                          className="rounded-md border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-2 text-sm font-semibold text-[var(--primary)] transition hover:border-[var(--primary)]"
                        >
                          Linkedin
                        </button>
                        <button
                          type="button"
                          onClick={() => showToast('SSO bientet disponible.')}
                          className="rounded-md border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-2 text-sm font-semibold text-[var(--primary)] transition hover:border-[var(--primary)]"
                        >
                          SSO
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>

              {!auth.authenticated ?(
                <p className="mt-6 text-center text-lg text-[var(--ink-soft)]">
                  {authMode === 'signup'
                    ? 'Vous avez deja un compte ? '
                    : "Besoin d'un compte ? "}
                  <button
                    type="button"
                    onClick={() => {
                      const nextMode = authMode === 'signup' ? 'signin' : 'signup'
                      setAuthMode(nextMode)
                      setAuthError('')
                      setMfaRequired(false)
                      setOtp('')
                    }}
                    className="font-semibold text-[var(--primary)] underline"
                  >
                    {authMode === 'signup' ? 'Se connecter' : "S'inscrire"}
                  </button>
                </p>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}

      {showSettings ? (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-[var(--bg-2)]/90 backdrop-blur-sm">
          <div className="mx-auto flex min-h-screen w-full max-w-3xl items-center px-4 py-10">
            <div className="w-full rounded-3xl border border-[var(--line)] bg-[var(--surface)] p-6 shadow-[var(--shadow-strong)]">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                    Parametres utilisateur
                  </p>
                  <h2 className="mt-1 text-2xl font-semibold">Experience utilisateur</h2>
                </div>
                <button
                  type="button"
                  onClick={() => setShowSettings(false)}
                  className="rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                >
                  Fermer
                </button>
              </div>

              <div className="mt-6 grid gap-4">
                <label className="flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
                  Nom affiche
                  <input
                    value={settingsName}
                    onChange={(event) => setSettingsName(event.target.value)}
                    placeholder="Votre nom"
                    className="rounded-xl border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  />
                </label>

                <label className="flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
                  Avatar (URL)
                  <input
                    value={settingsAvatarUrl}
                    onChange={(event) => setSettingsAvatarUrl(event.target.value)}
                    placeholder="https://..."
                    className="rounded-xl border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  />
                  <button
                    type="button"
                    onClick={() => setSettingsAvatarUrl('')}
                    className="w-fit rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                  >
                    Supprimer leavatar
                  </button>
                </label>

                <div className="grid gap-3 md:grid-cols-3">
                  <label className="flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
                    Theme
                    <select
                      value={settingsTheme}
                      onChange={(event) => setSettingsTheme(event.target.value as 'light' | 'dark')}
                      className="rounded-xl border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                    >
                      <option value="light">Clair</option>
                      <option value="dark">Sombre</option>
                    </select>
                  </label>

                  <label className="flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
                    Densite
                    <select
                      value={settingsDensity}
                      onChange={(event) =>
                        setSettingsDensity(event.target.value as 'comfortable' | 'compact')
                      }
                      className="rounded-xl border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                    >
                      <option value="comfortable">Confortable</option>
                      <option value="compact">Compacte</option>
                    </select>
                  </label>

                  <label className="flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
                    Langue
                    <select
                      value={settingsLanguage}
                      onChange={(event) => setSettingsLanguage(event.target.value as 'fr' | 'en')}
                      className="rounded-xl border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                    >
                      <option value="fr">Franeais</option>
                      <option value="en">Anglais</option>
                    </select>
                  </label>
                </div>

                <label className="flex items-center gap-2 text-sm text-[var(--ink)]">
                  <input
                    type="checkbox"
                    checked={settingsEmailNotifications}
                    onChange={(event) => setSettingsEmailNotifications(event.target.checked)}
                    className="h-4 w-4 rounded border-[var(--line)]"
                  />
                  Recevoir les notifications email
                </label>

                {settingsError ? (
                  <p className="rounded-xl border border-red-400/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
                    {settingsError}
                  </p>
                ) : null}

                <div className="flex flex-wrap items-center justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowSettings(false)}
                    className="pill border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                  >
                    Annuler
                  </button>
                  <button
                    type="button"
                    onClick={handleSaveSettings}
                    disabled={settingsSaving}
                    className="pill border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white disabled:opacity-60"
                  >
                    {settingsSaving ? 'Enregistrement...' : 'Enregistrer'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      
      <section className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px] lg:items-start">
        <section
          id="composer"
          className="relative overflow-hidden rounded-3xl border border-[var(--line)] bg-[var(--surface)]/95 shadow-[var(--shadow-strong)] backdrop-blur"
        >
          <div className="flex flex-col gap-2 border-b border-[var(--line)] px-5 py-5 md:px-6">
            <p className="text-[11px] uppercase tracking-[0.25em] text-[var(--ink-soft)]">
              Nouveau lien
            </p>
            <h1 className="text-3xl font-semibold leading-tight md:text-4xl">
              Publier un secret en moins de 10 secondes
            </h1>
            <p className="max-w-2xl text-sm text-[var(--ink-soft)]">
              Collez votre secret, reglez l'expiration, puis creez le lien securise.
            </p>
          </div>

          <div className="flex flex-col gap-6 p-5 md:p-6">
            <div className="grid gap-2 sm:grid-cols-3">
              <button
                type="button"
                onClick={() => {
                  setMode('text')
                  setFile(null)
                  setFileError('')
                  focusComposer()
                }}
                className={`rounded-xl border px-4 py-3 text-sm font-semibold transition ${
                  mode === 'text'
                    ?'border-[var(--primary)] bg-[var(--primary)] text-white'
                    : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)] hover:border-[var(--primary)]'
                }`}
              >
                Mots de passe et texte
              </button>
              <button
                type="button"
                onClick={() => setMode('file')}
                className={`rounded-xl border px-4 py-3 text-sm font-semibold transition ${
                  mode === 'file'
                    ?'border-[var(--primary)] bg-[var(--primary)] text-white'
                    : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)] hover:border-[var(--primary)]'
                }`}
              >
                Fichiers
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode('url')
                  setFile(null)
                  setFileError('')
                  focusComposer()
                }}
                className={`rounded-xl border px-4 py-3 text-sm font-semibold transition ${
                  mode === 'url'
                    ?'border-[var(--primary)] bg-[var(--primary)] text-white'
                    : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)] hover:border-[var(--primary)]'
                }`}
              >
                URLs
              </button>
            </div>

            {isFileMode ? (
              <div className="flex flex-col gap-3 rounded-2xl border border-[var(--line)] bg-[var(--field-muted)] px-4 py-4">
                <label className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                  Fichier
                </label>
                <label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed border-[var(--line)] bg-[var(--surface)] px-5 py-6 text-center text-sm text-[var(--ink-soft)] transition hover:border-[var(--primary)]">
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
                        return
                      }
                      setFile(selected)
                      setFileError('')
                    }}
                  />
                  {file ? (
                    <>
                      <span className="text-base font-semibold text-[var(--ink)]">{file.name}</span>
                      <span className="mt-1 text-xs">{formatBytes(file.size)}</span>
                      <span className="mt-2 rounded-full border border-[var(--line)] px-3 py-1 text-[11px] uppercase tracking-[0.2em]">
                        Remplacer le fichier
                      </span>
                    </>
                  ) : (
                    <>
                      Deposer ou choisir un fichier
                      <span className="mt-2 text-xs">Taille maximum: 5 MB</span>
                    </>
                  )}
                </label>
                {fileError ? <p className="text-xs text-[var(--primary)]">{fileError}</p> : null}
              </div>
            ) : (
              <div className="flex flex-col gap-3 rounded-2xl border border-[var(--line)] bg-[var(--field-muted)] px-4 py-4">
                <label className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                  {mode === 'url' ? 'URL sensible' : 'Secret / texte'}
                </label>
                <textarea
                  id="memo-area"
                  rows={10}
                  value={secret}
                  onChange={(event) => {
                    setSecret(event.target.value)
                    setStatus('idle')
                  }}
                  placeholder={textareaPlaceholder}
                  className="w-full resize-y rounded-xl border border-[var(--line)] bg-[var(--field)] px-4 py-4 text-sm text-[var(--ink)]"
                />
              </div>
            )}

            <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3">
              <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Astuce</p>
              <p className="mt-1 text-sm text-[var(--ink-soft)]">
                Ne mettez ici que le secret, gardez le contexte dans un autre canal.
              </p>
            </div>

          </div>
        </section>
        <aside className="flex flex-col gap-4">
          <button
            type="button"
            onClick={() => setMobileSettingsOpen((current) => !current)}
            className="card flex items-center justify-between rounded-2xl px-4 py-3 text-left lg:hidden"
          >
            <span className="text-sm font-semibold text-[var(--ink)]">Parametres du lien</span>
            <span className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
              {mobileSettingsOpen ? 'Masquer' : 'Afficher'}
            </span>
          </button>

          <div className={`${mobileSettingsOpen ? 'flex' : 'hidden'} flex-col gap-4 lg:flex`}>
            <div className="card rounded-2xl px-4 py-4">
              <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Parametres du lien</p>
              <h2 className="mt-1 text-sm font-semibold text-[var(--ink)]">
                Expiration et acces
              </h2>

              <div className="mt-4 flex flex-col gap-4">
                <div className="flex flex-col gap-3">
                  <div className="flex items-center justify-between gap-2">
                    <label className="text-sm font-semibold text-[var(--ink)]">Expiration (duree)</label>
                    <span className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                      {isExpiryCustom ? 'Personnalise' : 'Preset'}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {quickDurationPresets.map((preset) => (
                      <button
                        key={preset.label}
                        type="button"
                        onClick={() => {
                          setExpiry(preset.minutes)
                          setIsExpiryCustom(false)
                        }}
                        className={`rounded-full border px-3 py-1.5 text-xs uppercase tracking-[0.2em] transition ${
                          !isExpiryCustom && expiry === preset.minutes
                            ? 'border-[var(--primary)] bg-[var(--primary)] text-white'
                            : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)] hover:border-[var(--primary)]'
                        }`}
                      >
                        {preset.label}
                      </button>
                    ))}
                  </div>
                  <div className="flex items-center gap-3">
                    <input
                      type="range"
                      min={15}
                      max={10080}
                      step={15}
                      value={expiry}
                      onChange={(event) => {
                        setExpiry(Number(event.target.value))
                        setIsExpiryCustom(true)
                      }}
                      className="w-full accent-[var(--primary)]"
                    />
                    <span className="min-w-[72px] text-right text-sm font-semibold text-[var(--ink)]">
                      {durationLabel}
                    </span>
                  </div>
                </div>

                <div className="flex flex-col gap-3">
                  <div className="flex items-center justify-between gap-2">
                    <label className="text-sm font-semibold text-[var(--ink)]">Expiration (vues)</label>
                    <span className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                      {isViewsCustom ? 'Personnalise' : 'Preset'}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {quickViewPresets.map((preset) => (
                      <button
                        key={preset}
                        type="button"
                        onClick={() => {
                          setViews(preset)
                          setIsViewsCustom(false)
                        }}
                        className={`rounded-full border px-3 py-1.5 text-xs uppercase tracking-[0.2em] transition ${
                          !isViewsCustom && views === preset
                            ? 'border-[var(--primary)] bg-[var(--primary)] text-white'
                            : 'border-[var(--line)] bg-[var(--surface-muted)] text-[var(--ink-soft)] hover:border-[var(--primary)]'
                        }`}
                      >
                        {preset} {preset > 1 ? 'vues' : 'vue'}
                      </button>
                    ))}
                  </div>
                  <div className="flex items-center gap-3">
                    <input
                      type="range"
                      min={1}
                      max={20}
                      step={1}
                      value={views}
                      onChange={(event) => {
                        setViews(Number(event.target.value))
                        setIsViewsCustom(true)
                      }}
                      className="w-full accent-[var(--primary)]"
                    />
                    <input
                      type="number"
                      min={1}
                      max={20}
                      value={views}
                      onChange={(event) => {
                        const next = Number(event.target.value)
                        if (!Number.isFinite(next)) return
                        setViews(Math.max(1, Math.min(20, Math.round(next))))
                        setIsViewsCustom(true)
                      }}
                      className="w-16 rounded-lg border border-[var(--line)] bg-[var(--field)] px-2 py-1.5 text-sm text-[var(--ink)]"
                    />
                  </div>
                </div>

                <p className="text-xs text-[var(--ink-soft)]">
                  (La premiere condition atteinte supprime le memo)
                </p>
              </div>
            </div>

            <div className="card rounded-2xl px-4 py-4">
              <button
                type="button"
                onClick={() => setShowAdvanced((current) => !current)}
                className="flex w-full items-center justify-between text-left"
              >
                <span className="text-sm font-semibold text-[var(--ink)]">Options supplementaires</span>
                <span className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                  {showAdvanced ? 'Masquer' : 'Afficher'}
                </span>
              </button>
              {showAdvanced ? (
                <div className="mt-3 border-t border-[var(--line)] pt-3">
                  <div className="flex flex-col gap-2">
                    <label className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                      Securite (optionnel)
                    </label>
                    <input
                      value={passphrase}
                      onChange={(event) => setPassphrase(event.target.value)}
                      className="rounded-xl border border-[var(--line)] bg-[var(--field)] px-4 py-3 text-sm text-[var(--ink)]"
                      placeholder="Exiger une passphrase pour ouvrir"
                      type="password"
                    />
                    <p className="text-xs text-[var(--ink-soft)]">
                      Cette passphrase sera demandee au destinataire avant le dechiffrement.
                    </p>
                  </div>
                </div>
              ) : null}
            </div>
          </div>

          <div className="card-elev rounded-2xl px-4 py-4 lg:sticky lg:top-6">
            <div className="mb-3 flex items-center justify-between gap-3">
              <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Publication</p>
              <span className="rounded-full border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-1 text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                {statusLabel}
              </span>
            </div>
            <p className="mb-3 text-xs text-[var(--ink-soft)]">
              Expire dans {durationLabel} ou apres {viewsLabel} (au premier atteint).
            </p>
            <button
              type="button"
              onClick={handleGenerate}
              disabled={isGenerateDisabled}
              className="hidden w-full rounded-xl border border-[var(--primary)] bg-[var(--primary)] px-4 py-3 text-sm font-semibold text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60 lg:block"
            >
              {mainCtaLabel}
            </button>
            {status === 'error' ? (
              <p className="mt-2 text-xs text-[var(--primary)]">Verifiez les champs puis reessayez.</p>
            ) : null}

            <div className="mt-3 rounded-xl border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-3">
              <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Resultat</p>
              {link ? (
                <div className="mt-2 flex flex-col gap-3">
                  <input
                    value={link}
                    readOnly
                    aria-label="Lien genere"
                    className="w-full rounded-lg border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  />
                  <div className="flex flex-wrap gap-2">
                    <button
                      ref={copyLinkButtonRef}
                      type="button"
                      onClick={handleCopy}
                      className="rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                    >
                      Copier
                    </button>
                    <button
                      type="button"
                      onClick={handleCopyPreparedMessage}
                      className="rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                    >
                      Copier le message pret
                    </button>
                    <button
                      type="button"
                      onClick={resetComposer}
                      className="rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                    >
                      Creer un nouveau
                    </button>
                  </div>
                </div>
              ) : (
                <p className="mt-2 text-xs text-[var(--ink-soft)]">
                  Le lien apparaitra ici apres generation.
                </p>
              )}
            </div>

            <p className="mt-3 text-xs text-[var(--ink-soft)]">
              Expire le {expiresAtLabel}. Maximum {viewsLabel}.
            </p>
          </div>
        </aside>
      </section>

      <div className="fixed inset-x-0 bottom-0 z-40 border-t border-[var(--line)] bg-[var(--surface)]/95 px-4 py-3 backdrop-blur lg:hidden">
        <div className="mx-auto w-full max-w-6xl">
          <button
            type="button"
            onClick={handleGenerate}
            disabled={isGenerateDisabled}
            className="w-full rounded-xl border border-[var(--primary)] bg-[var(--primary)] px-4 py-3 text-sm font-semibold text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {mainCtaLabel}
          </button>
        </div>
      </div>
      <section id="history" className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="card rounded-2xl px-5 py-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-[11px] uppercase tracking-[0.25em] text-[var(--ink-soft)]">
                Historique
              </p>
              <p className="text-base font-semibold text-[var(--ink)]">Derniers memos</p>
            </div>
            <button
              type="button"
              onClick={refreshHistory}
              className="rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)] hover:border-[var(--primary)]"
            >
              Rafraichir
            </button>
          </div>
          <div className="mt-3">
            <input
              value={historySearch}
              onChange={(event) => setHistorySearch(event.target.value)}
              placeholder="Rechercher un lien ou un identifiant"
              className="w-full rounded-lg border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
            />
          </div>
          <div className="mt-3 flex flex-col gap-2">
            {filteredHistory.length === 0 ? (
              <div className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-2 text-sm text-[var(--ink-soft)]">
                {historySearch.trim()
                  ? 'Aucun resultat pour cette recherche.'
                  : "Rien pour l'instant."}
              </div>
            ) : (
              filteredHistory.map((item) => {
                const isExpired = item.isExpired || item.viewsLeft <= 0
                return (
                  <Link
                    key={item.id}
                    to={`/push/${item.id}`}
                    className="rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-3 transition hover:border-[var(--primary)]"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-[var(--ink)]">{item.label}</p>
                        <p className="text-xs text-[var(--ink-soft)]">
                          {isExpired ? 'Expire' : 'Actif'} - {Math.max(0, item.viewsLeft)} vues restantes
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`pill border px-3 py-1 text-[11px] uppercase tracking-[0.2em] ${
                          isExpired
                            ? 'border-red-500/40 bg-red-500/10 text-red-300'
                            : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                        }`}>
                          {isExpired ? 'Expire' : 'Actif'}
                        </span>
                        <span className="pill border border-[var(--line)] bg-[var(--surface)] px-3 py-1 text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                          {item.requiresPassphrase ? 'Passphrase' : 'Cle URL'}
                        </span>
                      </div>
                    </div>
                  </Link>
                )
              })
            )}
          </div>
        </div>

        <div className="card rounded-2xl px-5 py-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[11px] uppercase tracking-[0.25em] text-[var(--ink-soft)]">
                Mot de passe
              </p>
              <p className="text-base font-semibold text-[var(--ink)]">Generateur express</p>
            </div>
          </div>

          <div className="mt-4">
            <div className="rounded-2xl border border-[var(--line)] bg-[var(--field-muted)] px-3 py-3">
              <div className="flex flex-col gap-3">
                <input
                  value={generatedPassword}
                  readOnly
                  className="w-full rounded-md border border-[var(--line)] bg-[var(--field)] px-3 py-2 text-sm text-[var(--ink)]"
                  placeholder="Genere et copie en 1 clic"
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
                      Generer
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
          </div>
        </div>
      </section>


      {toast ? (
        <div className="fixed bottom-24 right-4 z-50 sm:right-6 lg:bottom-6">
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
  const inlineKey = useMemo(() => {
    const keyFragment = new URLSearchParams(location.hash.replace('#', '')).get('k')
    return keyFragment ? decodeURIComponent(keyFragment) : null
  }, [location.hash])
  const [status, setStatus] = useState<
    'loading' | 'ready' | 'revealed' | 'error' | 'expired' | 'missing' | 'consumed'
  >(() => (id ? 'loading' : 'missing'))
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
      return
    }
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
  }, [id])

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
      showToast('Le chiffrement necessite HTTPS ou localhost.', 'error')
      return
    }
    if (item.requiresPassphrase && !passphrase.trim()) {
      setStatus('error')
      showToast('Passphrase requise.', 'error')
      return
    }
    if (!item.requiresPassphrase && !inlineKey) {
      setStatus('error')
      showToast('Cle URL manquante.', 'error')
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
      showToast('Secret dechiffre.', 'success')
    } catch (error) {
      if (error instanceof Error && error.message.includes('api-404')) {
        setStatus('missing')
        return
      }
      setStatus('error')
      showToast("Impossible de dechiffrer.", 'error')
    }
  }

  const handleCopySecret = async () => {
    if (!secret) return
    try {
      await navigator.clipboard.writeText(secret)
      showToast('Secret copie.', 'success')
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
        >← Retour
        </button>
        <h1 className="text-3xl font-semibold">Votre message est enregistre.</h1>
        <p className="max-w-2xl text-sm text-[var(--ink-soft)]">
          Le message s'autodetruira apres lecture ou a expiration.
        </p>
      </header>

      <section className="card-elev rounded-2xl border border-[var(--line)]">
        <div className="rounded-t-2xl bg-[var(--primary)] px-4 py-3 text-center text-sm font-semibold text-white">
          Votre message est enregistre.
        </div>
        <div className="flex flex-col gap-5 p-6">
        {status === 'missing' ?(
          <div className="flex flex-col gap-3">
            <p className="text-sm text-[var(--ink-soft)]">Secret introuvable.</p>
            <Link to="/" className="text-sm text-[var(--primary)]">
              Revenir a l'accueil
            </Link>
          </div>
        ) : null}

        {status === 'expired' ?(
          <div className="flex flex-col gap-3">
            <p className="text-sm text-[var(--ink-soft)]">
              Ce secret a expire et a ete supprime.
            </p>
            <Link to="/" className="text-sm text-[var(--primary)]">
              Creer un nouveau push
            </Link>
          </div>
        ) : null}

        {status === 'error' && !item ?(
          <div className="flex flex-col gap-3">
            <p className="text-sm text-[var(--ink-soft)]">
              Une erreur est survenue. Reessayez plus tard.
            </p>
            <Link to="/" className="text-sm text-[var(--primary)]">
              Retour a l'accueil
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
                Expire {item.expiresAtText} - {item.viewsLeft} vues restantes
              </p>
            </div>

            {!item.requiresPassphrase && !inlineKey ?(
              <div className="rounded-lg border border-[var(--primary)] bg-[var(--primary)]/10 px-4 py-3 text-sm text-[var(--ink)]">
                La cle du lien est absente. Verifiez que l'URL contient bien
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
                Reveler le secret
              </button>
              {status === 'error' ?(
                <p className="text-sm text-[var(--primary)]">
                  Impossible de dechiffrer. Verifiez la passphrase ou la cle du lien.
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
                      Telecharger
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
                      Derniere vue, supprime
                    </span>
                  ) : null}
                </div>
                {item.requiresPassphrase ?(
                  <p className="mt-3 text-xs text-[var(--ink-soft)]">
                    Ce secret a ete protege par passphrase.
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
        Retour a l'accueil
      </Link>
    </div>
  )
}

function VerifyEmail() {
  const location = useLocation()
  const { auth, refreshAuth, signalAuthChange } = useAuthStore()
  const token = useMemo(() => new URLSearchParams(location.search).get('token'), [location.search])
  const [status, setStatus] = useState<'loading' | 'ok' | 'error'>(() => (token ? 'loading' : 'error'))
  const effectiveStatus = token ? status : 'error'

  useEffect(() => {
    if (!token) {
      return
    }
    const verify = async () => {
      try {
        await apiRequest(`/api/auth/verify?token=${encodeURIComponent(token)}`)
        await refreshAuth()
        signalAuthChange('email-verified')
        setStatus('ok')
      } catch {
        setStatus('error')
      }
    }
    void verify()
  }, [token, refreshAuth, signalAuthChange])

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
      <h1 className="text-3xl font-semibold">Verification email</h1>
      {effectiveStatus === 'loading' ?(
        <p className="text-sm text-[var(--ink-soft)]">Verification en cours</p>
      ) : null}
      {effectiveStatus === 'ok' ?(
        <p className="text-sm text-[var(--ink-soft)]">
          {auth.status === 'checking'
            ? 'Verification de session en cours...'
            : auth.status === 'authenticated'
            ? 'Email verifie. Vous Etes connecte.'
            : auth.status === 'pending_email_verification'
              ? 'Email verifie. Synchronisation de session en cours...'
              : 'Email verifie. Vous pouvez vous connecter.'}
        </p>
      ) : null}
      {effectiveStatus === 'error' ?(
        <p className="text-sm text-[var(--ink-soft)]">
          Lien invalide ou expire.
        </p>
      ) : null}
      <Link to="/" className="text-sm text-[var(--primary)]">
        Retour a l'accueil
      </Link>
    </div>
  )
}

function LegalPage({
  title,
  subtitle,
  updatedAt,
  children,
}: {
  title: string
  subtitle: string
  updatedAt: string
  children: React.ReactNode
}) {
  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6">
      <header className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] px-6 py-6">
        <p className="text-[11px] uppercase tracking-[0.25em] text-[var(--ink-soft)]">
          Centre de ressources
        </p>
        <h1 className="mt-2 text-3xl font-semibold">{title}</h1>
        {subtitle ? (
          <p className="mt-3 max-w-3xl text-sm text-[var(--ink-soft)]">{subtitle}</p>
        ) : null}
        {updatedAt ? (
          <p className="mt-3 text-xs text-[var(--ink-soft)]">Derniere mise a jour: {updatedAt}</p>
        ) : null}
      </header>
      <div className="grid gap-4">
        {children}
      </div>
    </div>
  )
}

function DocSection({
  title,
  children,
}: {
  title: string
  children: React.ReactNode
}) {
  return (
    <section className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] px-6 py-5">
      <h2 className="text-xl font-semibold">{title}</h2>
      <div className="mt-3 text-sm leading-relaxed text-[var(--ink-soft)]">
        {children}
      </div>
    </section>
  )
}

function PrivacyPolicy() {
  return (
    <LegalPage
      title="Politique de confidentialite"
      subtitle="Transparence sur les donnees traitees, les finalites et vos droits."
      updatedAt="28 fevrier 2026"
    >
      <DocSection title="1. Donnees traitees">
        <p>
          Nous limitons les donnees au strict necessaire: adresse email (si compte),
          empreinte de mot de passe, metadonnees de publication (dates, vues restantes,
          type de contenu), journaux de securite et informations de session.
        </p>
        <p className="mt-3">
          Le contenu des secrets est chiffre cote client avant envoi. Nous ne stockons
          pas la cle de dechiffrement presente dans le fragment d'URL.
        </p>
      </DocSection>

      <DocSection title="2. Finalites du traitement">
        <ul className="list-disc pl-5">
          <li>Fournir le service de creation, partage et expiration des liens.</li>
          <li>Securiser l'acces (authentification, MFA, protection contre les abus).</li>
          <li>Assurer leintegrite operationnelle et le support utilisateur.</li>
          <li>Respecter les obligations legales et de conformite.</li>
        </ul>
      </DocSection>

      <DocSection title="3. Durees de conservation">
        <ul className="list-disc pl-5">
          <li>Secrets: supprimes a expiration ou a epuisement des vues.</li>
          <li>Comptes: conserves tant que le compte est actif.</li>
          <li>Logs techniques de securite: conservation limitee et rotative.</li>
        </ul>
      </DocSection>

      <DocSection title="4. Securite et sous-traitance">
        <p>
          Les donnees transitent via HTTPS. Les acces deadministration sont restreints
          et journalises. Les prestataires deinfrastructure Eventuels sont selectionnes
          pour leurs garanties de securite et de conformite.
        </p>
      </DocSection>

      <DocSection title="5. Vos droits">
        <p>
          Selon la reglementation applicable (notamment RGPD), vous pouvez demander:
          acces, rectification, effacement, limitation, opposition et portabilite.
        </p>
        <p className="mt-3">
          Pour exercer vos droits ou signaler un incident, contactez le support via le
          canal indique dans la page de contact.
        </p>
      </DocSection>
    </LegalPage>
  )
}

function TermsOfUse() {
  return (
    <LegalPage
      title="Conditions d'utilisation"
      subtitle="Regles deusage du service, responsabilites et limitations."
      updatedAt="28 fevrier 2026"
    >
      <DocSection title="1. Objet du service">
        <p>
          Nemosyne permet de partager des donnees sensibles via des liens chiffres et
          auto-destructibles. Le service est destine a des usages professionnels ou
          personnels legitimes.
        </p>
      </DocSection>

      <DocSection title="2. Usage autorise">
        <ul className="list-disc pl-5">
          <li>Vous vous engagez a ne pas publier de contenu illicite ou malveillant.</li>
          <li>Vous Etes responsable des secrets partages et des destinataires choisis.</li>
          <li>Vous devez proteger vos identifiants et activer MFA quand disponible.</li>
        </ul>
      </DocSection>

      <DocSection title="3. Disponibilite et limites">
        <p>
          Le service est fourni tel quel, avec un objectif de haute disponibilite.
          Des interruptions temporaires peuvent survenir pour maintenance, securite ou
          Evenement hors de notre contrele.
        </p>
      </DocSection>

      <DocSection title="4. Suspension et resiliation">
        <p>
          Nous pouvons limiter ou suspendre l'acces en cas d'abus, de tentative
          deintrusion, de fraude ou de non-respect des presentes conditions.
        </p>
      </DocSection>

      <DocSection title="5. Responsabilite">
        <p>
          Nemosyne met en Euvre des mesures de securite raisonnables mais ne peut pas
          garantir leabsence absolue de risque sur Internet. Vous devez completer ces
          mesures par vos propres politiques internes.
        </p>
      </DocSection>

      <DocSection title="6. Droit applicable">
        <p>
          Les presentes conditions sont regies par le droit applicable au siege
          deexploitation du service, sous reserve des dispositions imperatives locales.
        </p>
      </DocSection>
    </LegalPage>
  )
}

function CookiePolicy() {
  return (
    <LegalPage
      title="Politique de cookies"
      subtitle="Informations sur les cookies et stockages locaux utilises par Nemosyne."
      updatedAt="28 fevrier 2026"
    >
      <DocSection title="1. Principes">
        <p>
          Nous privilegions une politique minimale: cookies strictement necessaires a
          la securite et au fonctionnement de la session. Aucun cookie publicitaire.
        </p>
      </DocSection>

      <DocSection title="2. Types de traceurs utilises">
        <ul className="list-disc pl-5">
          <li>Session de connexion securisee.</li>
          <li>Preferences utilisateur (consentement cookies, theme d'interface).</li>
          <li>Mecanismes anti-abus et protection deacces.</li>
        </ul>
      </DocSection>

      <DocSection title="3. Durees et contrele">
        <p>
          Les durees de conservation varient selon la finalite (session, preference,
          securite). Vous pouvez gerer ces preferences via la banniere de consentement
          et les reglages de votre navigateur.
        </p>
      </DocSection>

      <DocSection title="4. Desactivation">
        <p>
          La desactivation de certains traceurs peut limiter des fonctions non
          essentielles (memorisation d'interface) mais n'empeche pas l'usage de base.
        </p>
      </DocSection>
    </LegalPage>
  )
}

function FeaturesPage() {
  return (
    <LegalPage
      title="Caracteristiques"
      subtitle="Tout ce queil faut pour publier des donnees sensibles avec un minimum de friction."
      updatedAt="28 fevrier 2026"
    >
      <div className="grid gap-4 md:grid-cols-2">
        <DocSection title="Chiffrement cote client">
          <p>
            Les contenus sont chiffres dans le navigateur avant envoi. Le serveur ne
            voit queun payload chiffre et des metadonnees minimales.
          </p>
        </DocSection>
        <DocSection title="Liens a duree de vie controlee">
          <p>
            Double expiration configurable: par duree et par nombre de vues, avec
            suppression automatique a la premiere condition atteinte.
          </p>
        </DocSection>
        <DocSection title="Modes de publication">
          <p>
            Publication de texte, mots de passe, URL sensibles et fichiers (jusqu'a
            5 MB). Leinterface est optimisee pour un envoi en quelques secondes.
          </p>
        </DocSection>
        <DocSection title="Protection renforcee">
          <p>
            Passphrase optionnelle cote destinataire + cle de lien. Authentification
            compte avec MFA TOTP et verification email.
          </p>
        </DocSection>
        <DocSection title="Traeabilite operationnelle">
          <p>
            Historique des publications, statut deexpiration et visibilite sur les
            acces restants pour faciliter l'audit interne.
          </p>
        </DocSection>
        <DocSection title="Conception orientee sobriete">
          <p>
            Interface centree sur leaction principale: publier, partager, expirer.
            Peu d'etapes, faible charge cognitive, conversion rapide.
          </p>
        </DocSection>
      </div>
    </LegalPage>
  )
}

function PricingPage() {
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <h1 className="text-3xl font-semibold">Tarifs</h1>
      <p className="max-w-3xl text-sm text-[var(--ink-soft)]">
        Des plans coneus pour un deploiement progressif: essai rapide, montee en
        charge individuelle, puis collaboration Equipe.
      </p>

      <div className="grid gap-5 md:grid-cols-3">
        <div className="card-elev px-5 py-6">
          <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">Starter</p>
          <p className="mt-2 text-2xl font-semibold">0 EUR</p>
          <p className="text-xs text-[var(--ink-soft)]">Pour tester le service</p>
          <ul className="mt-4 flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
            <li>Jusqu'a 10 pushes / mois</li>
            <li>Expiration max 24h</li>
            <li>1 utilisateur</li>
            <li>Support communautaire</li>
          </ul>
          <button className="mt-5 w-full rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
            Commencer
          </button>
        </div>
        <div className="card-elev px-5 py-6 border border-[var(--primary)]">
          <p className="text-xs uppercase tracking-[0.2em] text-[var(--primary)]">Pro</p>
          <p className="mt-2 text-2xl font-semibold">9 EUR / mois</p>
          <p className="text-xs text-[var(--ink-soft)]">Ideal pour independants et petites Equipes</p>
          <ul className="mt-4 flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
            <li>Pushes illimites</li>
            <li>Expiration jusqu'a 7 jours</li>
            <li>Historique complet</li>
            <li>MFA & audit deacces</li>
            <li>Support prioritaire standard</li>
          </ul>
          <button className="mt-5 w-full rounded-full border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white">
            Choisir Pro
          </button>
        </div>
        <div className="card-elev px-5 py-6">
          <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">Business</p>
          <p className="mt-2 text-2xl font-semibold">25 EUR / mois</p>
          <p className="text-xs text-[var(--ink-soft)]">Equipes et PME</p>
          <ul className="mt-4 flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
            <li>Tout Pro</li>
            <li>Jusqu'a 20 utilisateurs</li>
            <li>Reles & permissions</li>
            <li>Support prioritaire</li>
            <li>Accompagnement onboarding</li>
          </ul>
          <button className="mt-5 w-full rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
            Contacter
          </button>
        </div>
      </div>

      <section className="grid gap-4 md:grid-cols-2">
        <DocSection title="Ce qui est inclus dans tous les plans">
          <ul className="list-disc pl-5">
            <li>Chiffrement cote client.</li>
            <li>Liens auto-destructibles.</li>
            <li>Expiration par duree et vues.</li>
            <li>Interface FR, usage mobile et desktop.</li>
          </ul>
        </DocSection>
        <DocSection title="Questions frequentes sur la facturation">
          <ul className="list-disc pl-5">
            <li>Changement de plan possible ? tout moment.</li>
            <li>Les tarifs sont indiques hors taxes locales Eventuelles.</li>
            <li>Le plan Business peut etre personnalise sur demande.</li>
          </ul>
        </DocSection>
      </section>
    </div>
  )
}

function ApiDocsPage() {
  return (
    <LegalPage
      title="Documentation API"
      subtitle="Reference HTTP pour integrer Nemosyne dans vos workflows internes."
      updatedAt="28 fevrier 2026"
    >
      <DocSection title="Base et format">
        <ul className="list-disc pl-5">
          <li>Base: <code>/api</code></li>
          <li>Format: JSON UTF-8</li>
          <li>Authentification: session cookie selon endpoint</li>
          <li>Codes deerreur: HTTP standard + message JSON {`{ error }`}</li>
        </ul>
      </DocSection>

      <DocSection title="Endpoints principaux">
        <ul className="list-disc pl-5">
          <li><code>POST /api/push</code> creer une publication chiffree</li>
          <li><code>GET /api/push</code> lister les publications de leutilisateur</li>
          <li><code>POST /api/push/purge</code> purger les Elements expires</li>
          <li><code>GET /api/push/:id/meta</code> metadonnees deune publication</li>
          <li><code>POST /api/push/:id/reveal</code> consommer/reveler un secret</li>
          <li><code>GET /api/session</code> Etat de session</li>
          <li><code>/api/auth/*</code> login, register, verify, logout</li>
          <li><code>/api/mfa/*</code> setup/enable MFA TOTP</li>
        </ul>
      </DocSection>

      <DocSection title="Exemple: creation deun push">
        <pre className="overflow-x-auto rounded-xl border border-[var(--line)] bg-[var(--surface-muted)] p-3 text-xs text-[var(--ink)]">
{`POST /api/push
Content-Type: application/json

{
  "kind": "text",
  "label": "Acces VPN temporaire",
  "createdAtTs": 1772304000000,
  "expiresAtTs": 1772390400000,
  "viewsLeft": 3,
  "cipher": "base64...",
  "iv": "base64...",
  "salt": "base64...",
  "requiresPassphrase": true
}`}
        </pre>
      </DocSection>

      <DocSection title="Exemple: reponse de creation">
        <pre className="overflow-x-auto rounded-xl border border-[var(--line)] bg-[var(--surface-muted)] p-3 text-xs text-[var(--ink)]">
{`HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "f2e7c9ab..."
}`}
        </pre>
      </DocSection>

      <DocSection title="Bonnes pratiques deintegration">
        <ul className="list-disc pl-5">
          <li>Ne jamais journaliser la cle de dechiffrement cote client.</li>
          <li>Envoyer le lien et la passphrase via deux canaux differents.</li>
          <li>Gerer explicitement les erreurs deexpiration et de vues Epuisees.</li>
        </ul>
      </DocSection>
    </LegalPage>
  )
}

function WhatsNewPage() {
  return (
    <LegalPage
      title="Quoi de neuf"
      subtitle="Journal de versions produit et ameliorations recentes."
      updatedAt="28 fevrier 2026"
    >
      <DocSection title="Fevrier 2026">
        <ul className="list-disc pl-5">
          <li>Refonte UX du flow de publication avec CTA toujours visible.</li>
          <li>Hierarchie simplifiee et options avancees en progressive disclosure.</li>
          <li>Pages annexes enrichies pour une publication publique.</li>
        </ul>
      </DocSection>
      <DocSection title="Janvier 2026">
        <ul className="list-disc pl-5">
          <li>Chiffrement des fichiers jusqu'a 5 MB.</li>
          <li>Activation MFA TOTP et verification email.</li>
          <li>Amelioration du suivi dehistorique des publications.</li>
        </ul>
      </DocSection>
      <DocSection title="Decembre 2025">
        <ul className="list-disc pl-5">
          <li>Themes clair/sombre.</li>
          <li>Generateur de mots de passe integre.</li>
          <li>Stabilisation des composants UI et accessibilite.</li>
        </ul>
      </DocSection>
      <DocSection title="Novembre 2025">
        <ul className="list-disc pl-5">
          <li>Backend securise avec purge automatique.</li>
          <li>Premiere version des liens a expiration et vues limitees.</li>
        </ul>
      </DocSection>
    </LegalPage>
  )
}

function PasswordGeneratorPage() {
  return (
    <LegalPage
      title="Generateur de mot de passe"
      subtitle="Guide pratique pour creer des mots de passe robustes et utilisables."
      updatedAt="28 fevrier 2026"
    >
      <DocSection title="Configuration recommandee">
        <ul className="list-disc pl-5">
          <li>Longueur minimum: 16 caracteres (idealement 20+).</li>
          <li>Activer majuscules, minuscules, chiffres et symboles.</li>
          <li>Generer un mot de passe unique par service.</li>
        </ul>
      </DocSection>

      <DocSection title="Procedure operationnelle">
        <ol className="list-decimal pl-5">
          <li>Choisir la longueur adaptee au niveau de risque.</li>
          <li>Generer puis copier immediatement dans un coffre-fort.</li>
          <li>Ne jamais partager le mot de passe en clair dans un chat.</li>
          <li>Utiliser un lien Nemosyne si un partage temporaire est necessaire.</li>
        </ol>
      </DocSection>

      <DocSection title="Checklist avant mise en production">
        <ul className="list-disc pl-5">
          <li>Rotation documentee des secrets critiques.</li>
          <li>Politique de compromission et revocation testee.</li>
          <li>MFA active sur les comptes deadministration.</li>
        </ul>
      </DocSection>
    </LegalPage>
  )
}

function KeyGeneratorPage() {
  return (
    <LegalPage
      title="Generateur de cle"
      subtitle="Bonnes pratiques pour manipuler la cle de dechiffrement en securite."
      updatedAt="28 fevrier 2026"
    >
      <DocSection title="Rappel de fonctionnement">
        <p>
          Dans Nemosyne, la cle peut etre incluse dans le fragment d'URL (
          <code>#k=...</code>). Ce fragment est traite cote client et n'est pas envoye
          au serveur lors de la requete HTTP.
        </p>
      </DocSection>

      <DocSection title="Partage securise en 3 Etapes">
        <ol className="list-decimal pl-5">
          <li>Envoyer le lien Nemosyne via un canal principal.</li>
          <li>Transmettre la passphrase ou leinstruction deacces via un second canal.</li>
          <li>Valider la lecture puis laisser le secret expirer automatiquement.</li>
        </ol>
      </DocSection>

      <DocSection title="A eviter absolument">
        <ul className="list-disc pl-5">
          <li>Copier la cle dans des tickets ou logs partages.</li>
          <li>Reutiliser la meme cle/passphrase sur plusieurs envois.</li>
          <li>Conserver les liens sensibles dans des espaces publics.</li>
        </ul>
      </DocSection>
    </LegalPage>
  )
}

function BestPracticesPage() {
  return (
    <LegalPage
      title="Bonnes pratiques"
      subtitle="Recommandations operationnelles pour un usage securise en Equipe."
      updatedAt="28 fevrier 2026"
    >
      <DocSection title="Avant envoi">
        <ul className="list-disc pl-5">
          <li>Limiter le secret au strict minimum necessaire.</li>
          <li>Choisir une expiration courte adaptee au besoin.</li>
          <li>Configurer un nombre de vues realiste (1 a 5 le plus souvent).</li>
        </ul>
      </DocSection>

      <DocSection title="Pendant le partage">
        <ul className="list-disc pl-5">
          <li>Separer lien et passphrase sur deux canaux distincts.</li>
          <li>Eviter les transferts automatiques non chiffres.</li>
          <li>Privilegier les destinataires nominativement identifies.</li>
        </ul>
      </DocSection>

      <DocSection title="Apres consultation">
        <ul className="list-disc pl-5">
          <li>Verifier dans lehistorique la consommation du secret.</li>
          <li>Revoquer et regenerer en cas de doute.</li>
          <li>Documenter les incidents dans votre registre interne.</li>
        </ul>
      </DocSection>

      <DocSection title="Hygiene securite de leorganisation">
        <ul className="list-disc pl-5">
          <li>MFA obligatoire pour les comptes a privileges.</li>
          <li>Gestionnaire de secrets recommande pour les Elements persistants.</li>
          <li>Formation reguliere des Equipes aux risques de fuite de donnees.</li>
        </ul>
      </DocSection>
    </LegalPage>
  )
}

function FaqPage() {
  return (
    <LegalPage
      title="FAQ"
      subtitle="Reponses aux questions les plus frequentes avant deploiement public."
      updatedAt="28 fevrier 2026"
    >
      <DocSection title="Puis-je recuperer un secret expire ?">
        <p>
          Non. La suppression a expiration ou apres la derniere vue est definitive.
        </p>
      </DocSection>

      <DocSection title="Ou est stockee la cle de dechiffrement ?">
        <p>
          Elle est portee cote client dans le fragment d'URL (<code>#k=</code>) ou
          derivee depuis une passphrase. Elle n'est pas conservee en clair cote serveur.
        </p>
      </DocSection>

      <DocSection title="Que se passe-t-il si le mauvais destinataire ouvre le lien ?">
        <p>
          La vue est consommee. Utilisez de preference une passphrase pour ajouter une
          barriere, et un nombre de vues faible pour limiter leexposition.
        </p>
      </DocSection>

      <DocSection title="Puis-je partager des fichiers volumineux ?">
        <p>
          La taille maximale actuelle est de 5 MB par fichier. Au-dele, privilegiez un
          stockage dedie et partagez uniquement un token ou mot de passe via Nemosyne.
        </p>
      </DocSection>

      <DocSection title="Nemosyne est-il adapte a la production ?">
        <p>
          Oui, a condition de respecter les bonnes pratiques: HTTPS strict, MFA active,
          politique deexpiration courte, supervision des acces et revue reguliere des
          incidents de securite.
        </p>
      </DocSection>

      <DocSection title="Comment integrer Nemosyne dans un workflow interne ?">
        <p>
          Utilisez les endpoints API documentes, automatisez la creation de push,
          transmettez les passphrases via un canal separe et journalisez les operations
          critiques cote SI.
        </p>
      </DocSection>
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
    <AuthProvider>
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
                  Liens securises et autodestructeurs pour le partage de donnees sensibles.
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
                  Caracteristiques
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
                  Generateur de mot de passe
                </Link>
              </li>
              <li>
                <Link to="/tools/keys" className="hover:text-[var(--ink)]">
                  Generateur de cle
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
                  Politique de confidentialite
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
              Region de donnees (UE)
            </span>
            <span>Â© 2026 Nemosyne. Tous droits reserves.</span>
          </div>
          <div className="flex items-center gap-3">
            <span>GitHub</span>
            <span>Docker</span>
          </div>
        </div>
      </footer>

      <div className="mt-6 rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-5 py-4 text-xs text-[var(--ink-soft)]">
        Politique de cookies : nous utilisons des cookies strictement necessaires pour
        maintenir votre session et securiser l'acces. Aucun cookie publicitaire.
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
                Nous utilisons des cookies strictement necessaires pour securiser votre
                session et ameliorer l'experience. Vous pouvez accepter ou refuser.
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
    </AuthProvider>
  )
}

export default App





