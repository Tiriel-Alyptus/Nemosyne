import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

type VaultScope = 'perso' | 'team' | 'travel'
type VaultItemType =
  | 'login'
  | 'note'
  | 'card'
  | 'identity'
  | 'ssh'
  | 'wifi'
  | 'api'
  | 'server'
  | 'passkey'

type Vault = {
  id: string
  name: string
  color: string
  scope: VaultScope
  defaultShare: 'private' | 'team'
  memberCount?: number
}

type VaultItem = {
  id: string
  vaultId: string
  type: VaultItemType
  title: string
  subtitle?: string
  url?: string
  username?: string
  password?: string
  note?: string
  tags: string[]
  favorite?: boolean
  travelSafe?: boolean
  totpSecret?: string
  passkeyOrigin?: string
  card?: { holder: string; last4: string; expMonth: number; expYear: number; network: string }
  identity?: { email?: string; phone?: string; address?: string }
  ssh?: { fingerprint?: string; host?: string }
  wifi?: { ssid?: string; protocol?: string }
  api?: { tokenPreview?: string; rotationIntervalDays?: number }
  history?: { timestamp: number; summary: string }[]
  createdAt: number
  updatedAt: number
  status?: {
    weak?: boolean
    reused?: boolean
    breached?: boolean
    expiresAt?: number
  }
}

type VaultData = {
  vaults: Vault[]
  items: VaultItem[]
  travelMode?: boolean
}

type VaultBlob = { version: 1; cipher: string; iv: string; salt: string }

const VAULT_STORAGE_KEY = 'nemosyne-native-vault-v1'
const encoder = new TextEncoder()
const decoder = new TextDecoder()

function arrayBufferToBase64(buffer: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
}

function base64ToArrayBuffer(value: string): ArrayBuffer {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

async function deriveKey(password: string, salt: ArrayBuffer) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 240_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function encryptVault(data: VaultData, password: string): Promise<VaultBlob> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveKey(password, salt.buffer)
  const payload = encoder.encode(JSON.stringify(data))
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, payload)
  return {
    version: 1,
    cipher: arrayBufferToBase64(cipher),
    iv: arrayBufferToBase64(iv.buffer),
    salt: arrayBufferToBase64(salt.buffer),
  }
}

async function decryptVault(blob: VaultBlob, password: string): Promise<VaultData> {
  const salt = base64ToArrayBuffer(blob.salt)
  const iv = new Uint8Array(base64ToArrayBuffer(blob.iv))
  const key = await deriveKey(password, salt)
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    base64ToArrayBuffer(blob.cipher),
  )
  return JSON.parse(decoder.decode(plain)) as VaultData
}

function formatDate(ts: number) {
  return new Date(ts).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short' })
}

function base32ToBytes(secret: string) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const cleaned = secret.replace(/=+$/, '').toUpperCase()
  const bytes: number[] = []
  let bits = 0
  let value = 0
  for (let i = 0; i < cleaned.length; i += 1) {
    const idx = alphabet.indexOf(cleaned[i])
    if (idx === -1) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return new Uint8Array(bytes)
}

async function generateTotp(secret: string, step = 30, digits = 6) {
  const counter = Math.floor(Date.now() / 1000 / step)
  const msg = new ArrayBuffer(8)
  const view = new DataView(msg)
  view.setUint32(4, counter, false)
  const keyBytes = base32ToBytes(secret)
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, [
    'sign',
  ])
  const signature = await crypto.subtle.sign('HMAC', key, msg)
  const hmac = new Uint8Array(signature)
  const offset = hmac[hmac.length - 1] & 0xf
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  const hotp = code % 10 ** digits
  return hotp.toString().padStart(digits, '0')
}

const demoData: VaultData = {
  travelMode: false,
  vaults: [
    { id: 'vault-personal', name: 'Personnel', color: '#1d4ed8', scope: 'perso', defaultShare: 'private' },
    { id: 'vault-team', name: 'Équipe SecOps', color: '#9333ea', scope: 'team', defaultShare: 'team', memberCount: 8 },
    { id: 'vault-travel', name: 'Voyage / frontière', color: '#10b981', scope: 'travel', defaultShare: 'private' },
  ],
  items: [
    {
      id: 'item-login-1',
      vaultId: 'vault-personal',
      type: 'login',
      title: 'Banque Nova',
      subtitle: 'Compte courant',
      url: 'https://bank.nova/login',
      username: 'lea.dupont',
      password: 'M0ntreAl!2026',
      tags: ['finance', '2FA'],
      favorite: true,
      totpSecret: 'JBSWY3DPEHPK3PXP',
      travelSafe: false,
      createdAt: Date.now() - 1000 * 60 * 60 * 24 * 140,
      updatedAt: Date.now() - 1000 * 60 * 60 * 12,
      history: [
        { timestamp: Date.now() - 1000 * 60 * 60 * 72, summary: 'Rotation automatique du mot de passe' },
      ],
      status: { weak: false, reused: false },
    },
    {
      id: 'item-login-2',
      vaultId: 'vault-team',
      type: 'login',
      title: 'Console AWS',
      subtitle: 'Compte admin restreint',
      url: 'https://signin.aws.amazon.com',
      username: 'secops+nemosyne',
      password: 'aws-!Admin-2026',
      tags: ['cloud', 'prod'],
      favorite: true,
      totpSecret: 'JBSWY3DPEHPK3PXQ',
      travelSafe: true,
      createdAt: Date.now() - 1000 * 60 * 60 * 24 * 32,
      updatedAt: Date.now() - 1000 * 60 * 30,
      api: { tokenPreview: 'AKIA...MJ3', rotationIntervalDays: 30 },
      status: { reused: false },
    },
    {
      id: 'item-card-1',
      vaultId: 'vault-personal',
      type: 'card',
      title: 'Visa Infinite',
      subtitle: 'Carte perso',
      tags: ['finance', 'paiement'],
      card: { holder: 'Léa Dupont', last4: '8219', expMonth: 11, expYear: 2027, network: 'Visa' },
      travelSafe: true,
      createdAt: Date.now() - 1000 * 60 * 60 * 24 * 260,
      updatedAt: Date.now() - 1000 * 60 * 60 * 20,
      status: { expiresAt: new Date().setMonth(new Date().getMonth() + 6) },
    },
    {
      id: 'item-ssh-1',
      vaultId: 'vault-team',
      type: 'ssh',
      title: 'Clé SSH - bastion prod',
      subtitle: 'rsa4096',
      ssh: { fingerprint: 'SHA256:qYQv...bHk', host: 'bastion.prod.nemo' },
      tags: ['ssh', 'prod'],
      travelSafe: false,
      createdAt: Date.now() - 1000 * 60 * 60 * 24 * 15,
      updatedAt: Date.now() - 1000 * 60 * 15,
      status: { reused: false },
    },
    {
      id: 'item-wifi-1',
      vaultId: 'vault-travel',
      type: 'wifi',
      title: 'Airbnb Lisbonne',
      subtitle: 'Séjour mars',
      wifi: { ssid: 'MareAlta-5G', protocol: 'WPA3' },
      password: 'Lisbonne#2026!',
      tags: ['wifi', 'voyage'],
      travelSafe: true,
      favorite: true,
      createdAt: Date.now() - 1000 * 60 * 60 * 24 * 5,
      updatedAt: Date.now() - 1000 * 60 * 5,
      status: { weak: false },
    },
    {
      id: 'item-note-1',
      vaultId: 'vault-personal',
      type: 'note',
      title: 'Notes biométrie',
      note: 'Empreintes enregistrées: MacBook, iPhone. Passkeys activées sur GitHub et Figma.',
      tags: ['sécurité', 'passkey'],
      travelSafe: true,
      createdAt: Date.now() - 1000 * 60 * 60 * 24 * 40,
      updatedAt: Date.now() - 1000 * 60 * 60 * 30,
    },
    {
      id: 'item-passkey-1',
      vaultId: 'vault-team',
      type: 'passkey',
      title: 'Passkey FIDO',
      subtitle: 'GitHub SSO',
      passkeyOrigin: 'https://github.com',
      tags: ['passkey', 'dev'],
      travelSafe: true,
      createdAt: Date.now() - 1000 * 60 * 60 * 24 * 3,
      updatedAt: Date.now() - 1000 * 60 * 10,
    },
  ],
}

function passwordScore(value?: string) {
  if (!value) return 'faible'
  let score = 0
  if (value.length >= 16) score += 1
  if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score += 1
  if (/\d/.test(value)) score += 1
  if (/[^A-Za-z0-9]/.test(value)) score += 1
  if (value.length >= 24) score += 1
  if (score >= 4) return 'fort'
  if (score >= 3) return 'bon'
  return 'faible'
}

function mask(value?: string) {
  if (!value) return '••••••••'
  if (value.length <= 4) return '••••'
  return `${'•'.repeat(Math.min(12, value.length - 4))}${value.slice(-4)}`
}

function Pill({ children, tone = 'default' }: { children: string; tone?: 'default' | 'ok' | 'warn' }) {
  const colors =
    tone === 'ok'
      ? 'bg-emerald-500/15 text-emerald-700 border-emerald-500/30'
      : tone === 'warn'
        ? 'bg-amber-500/15 text-amber-700 border-amber-500/30'
        : 'bg-[var(--surface-muted)] text-[var(--ink-soft)] border-[var(--line)]'
  return (
    <span className={`pill border px-3 py-1 text-[11px] uppercase tracking-[0.22em] ${colors}`}>
      {children}
    </span>
  )
}

function VaultChip({ vault }: { vault: Vault }) {
  return (
    <span
      className="pill border px-2 py-[6px] text-[11px] uppercase tracking-[0.2em]"
      style={{ borderColor: vault.color, color: vault.color }}
    >
      {vault.name}
    </span>
  )
}

function ItemRow({
  item,
  active,
  onSelect,
}: {
  item: VaultItem
  active: boolean
  onSelect: () => void
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`flex w-full flex-col gap-1 rounded-xl border px-3 py-3 text-left transition ${
        active
          ? 'border-[var(--primary)] bg-[var(--primary-weak)] shadow-md'
          : 'border-[var(--line)] bg-[var(--surface)] hover:border-[var(--primary)]'
      }`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold">{item.title}</span>
          {item.favorite ? <span className="text-xs text-amber-500">★</span> : null}
        </div>
        <span className="text-[11px] uppercase tracking-[0.22em] text-[var(--ink-soft)]">
          {item.type}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--ink-soft)]">
        {item.subtitle ? <span>{item.subtitle}</span> : null}
        {item.url ? <span className="text-[var(--primary)]">{item.url.replace(/^https?:\/\//, '')}</span> : null}
        {item.tags.map((tag) => (
          <span key={tag} className="rounded-full bg-[var(--surface-muted)] px-2 py-[2px]">
            {tag}
          </span>
        ))}
      </div>
    </button>
  )
}

function Generator({
  value,
  onGenerate,
  onUse,
}: {
  value: string
  onGenerate: () => void
  onUse: () => void
}) {
  return (
    <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] p-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold">Générateur rapide</p>
        <button
          type="button"
          onClick={onGenerate}
          className="rounded-full border border-[var(--line)] px-3 py-1 text-[11px] uppercase tracking-[0.2em]"
        >
          Régénérer
        </button>
      </div>
      <p className="mt-2 rounded-lg bg-[var(--surface-muted)] px-3 py-2 font-mono text-sm">{value}</p>
      <div className="mt-2 flex gap-2">
        <button
          type="button"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value)
            } catch {
              /* ignore */
            }
          }}
          className="rounded-full border border-[var(--line)] px-3 py-1 text-xs text-[var(--ink-soft)]"
        >
          Copier
        </button>
        <button
          type="button"
          onClick={onUse}
          className="rounded-full border border-[var(--primary)] bg-[var(--primary)] px-3 py-1 text-xs text-white"
        >
          Utiliser sur la fiche
        </button>
      </div>
    </div>
  )
}

function DetailField({
  label,
  value,
  masked,
  monospace,
}: {
  label: string
  value?: string
  masked?: boolean
  monospace?: boolean
}) {
  if (!value) return null
  return (
    <div>
      <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">{label}</p>
      <div className="mt-1 flex items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-2">
        <span className={monospace ? 'font-mono text-sm' : 'text-sm'}>{masked ? mask(value) : value}</span>
        <button
          type="button"
          onClick={async () => navigator.clipboard.writeText(value)}
          className="text-xs text-[var(--primary)]"
        >
          Copier
        </button>
      </div>
    </div>
  )
}

function WatchBadge({
  label,
  value,
  tone,
}: {
  label: string
  value: number
  tone: 'ok' | 'warn'
}) {
  const palette =
    tone === 'ok'
      ? 'bg-emerald-500/15 text-emerald-700 border-emerald-500/30'
      : 'bg-amber-500/15 text-amber-700 border-amber-500/30'
  return (
    <div className={`flex flex-col rounded-xl border px-3 py-2 ${palette}`}>
      <span className="text-sm font-semibold">{value}</span>
      <span className="text-[11px] uppercase tracking-[0.2em]">{label}</span>
    </div>
  )
}

function VaultPage() {
  const [blob, setBlob] = useState<VaultBlob | null>(null)
  const [data, setData] = useState<VaultData | null>(null)
  const [unlockKey, setUnlockKey] = useState<string>('')
  const [unlockError, setUnlockError] = useState('')
  const [passwordInput, setPasswordInput] = useState('')
  const [selectedVaultId, setSelectedVaultId] = useState<string>('vault-personal')
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null)
  const [filterType, setFilterType] = useState<VaultItemType | 'all'>('all')
  const [favoritesOnly, setFavoritesOnly] = useState(false)
  const [search, setSearch] = useState('')
  const [showEditor, setShowEditor] = useState(false)
  const [draft, setDraft] = useState<Partial<VaultItem>>({})
  const [generated, setGenerated] = useState('')
  const [totp, setTotp] = useState<string | null>(null)

  useEffect(() => {
    try {
      const stored = localStorage.getItem(VAULT_STORAGE_KEY)
      if (stored) {
        const parsed = JSON.parse(stored) as VaultBlob
        setBlob(parsed)
      }
    } catch {
      setBlob(null)
    }
  }, [])

  useEffect(() => {
    const length = 22
    const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+='
    let result = ''
    const bytes = crypto.getRandomValues(new Uint8Array(length))
    for (let i = 0; i < length; i += 1) {
      result += alphabet[bytes[i] % alphabet.length]
    }
    setGenerated(result)
  }, [])

  useEffect(() => {
    if (!data || !unlockKey) return
    encryptVault(data, unlockKey).then((nextBlob) => {
      localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(nextBlob))
      setBlob(nextBlob)
    })
  }, [data, unlockKey])

  const selectedItem = useMemo(
    () => data?.items.find((it) => it.id === selectedItemId) ?? null,
    [data, selectedItemId],
  )

  useEffect(() => {
    let timer: number | undefined
    if (selectedItem?.totpSecret) {
      const tick = async () => {
        const code = await generateTotp(selectedItem.totpSecret!)
        setTotp(code)
      }
      tick()
      timer = window.setInterval(tick, 1000)
    } else {
      setTotp(null)
    }
    return () => {
      if (timer) window.clearInterval(timer)
    }
  }, [selectedItem?.totpSecret])

  const watch = useMemo(() => {
    const items = data?.items ?? []
    const weak = items.filter((it) => passwordScore(it.password) === 'faible')
    const reusedPasswords = new Map<string, number>()
    items.forEach((it) => {
      if (it.password) reusedPasswords.set(it.password, (reusedPasswords.get(it.password) || 0) + 1)
    })
    const reused = items.filter((it) => it.password && (reusedPasswords.get(it.password) ?? 0) > 1)
    const expiring = items.filter(
      (it) => it.status?.expiresAt && it.status.expiresAt < Date.now() + 1000 * 60 * 60 * 24 * 45,
    )
    const safeForTravel = items.filter((it) => it.travelSafe).length
    return { weak, reused, expiring, total: items.length, safeForTravel }
  }, [data?.items])

  const filteredItems = useMemo(() => {
    if (!data) return []
    return data.items
      .filter((it) => (selectedVaultId === 'all' ? true : it.vaultId === selectedVaultId))
      .filter((it) => (favoritesOnly ? it.favorite : true))
      .filter((it) => (filterType === 'all' ? true : it.type === filterType))
      .filter((it) => (data.travelMode ? it.travelSafe : true))
      .filter((it) => {
        if (!search.trim()) return true
        const haystack = `${it.title} ${it.subtitle ?? ''} ${it.username ?? ''} ${it.tags.join(' ')}`.toLowerCase()
        return haystack.includes(search.toLowerCase())
      })
      .sort((a, b) => b.updatedAt - a.updatedAt)
  }, [data, favoritesOnly, filterType, search, selectedVaultId])

  const handleUnlock = async (mode: 'existing' | 'new') => {
    setUnlockError('')
    if (!passwordInput.trim()) {
      setUnlockError('Saisis un mot de passe maître.')
      return
    }
    try {
      if (mode === 'existing' && blob) {
        const decrypted = await decryptVault(blob, passwordInput)
        setData(decrypted)
        setUnlockKey(passwordInput)
        setSelectedVaultId(decrypted.vaults[0]?.id ?? 'all')
        setSelectedItemId(decrypted.items[0]?.id ?? null)
      } else {
        const firstData = demoData
        const nextBlob = await encryptVault(firstData, passwordInput)
        localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(nextBlob))
        setBlob(nextBlob)
        setData(firstData)
        setUnlockKey(passwordInput)
        setSelectedVaultId(firstData.vaults[0].id)
        setSelectedItemId(firstData.items[0]?.id ?? null)
      }
    } catch (error) {
      console.error(error)
      setUnlockError('Impossible de déverrouiller. Mot de passe maître incorrect ?')
    }
  }

  const handleSaveItem = (isEdit = false) => {
    if (!data) return
    const now = Date.now()
    const base: VaultItem = {
      id: isEdit && draft.id ? draft.id : crypto.randomUUID(),
      vaultId: draft.vaultId || selectedVaultId || data.vaults[0].id,
      type: (draft.type as VaultItemType) || 'login',
      title: draft.title || 'Entrée sans titre',
      subtitle: draft.subtitle,
      url: draft.url,
      username: draft.username,
      password: draft.password,
      note: draft.note,
      tags: draft.tags ?? [],
      favorite: draft.favorite ?? false,
      travelSafe: draft.travelSafe ?? true,
      totpSecret: draft.totpSecret,
      passkeyOrigin: draft.passkeyOrigin,
      card: draft.card,
      identity: draft.identity,
      ssh: draft.ssh,
      wifi: draft.wifi,
      api: draft.api,
      history: draft.history ?? [{ timestamp: now, summary: 'Création' }],
      createdAt: draft.createdAt ?? now,
      updatedAt: now,
      status: draft.status,
    }
    const nextItems = isEdit
      ? data.items.map((it) => (it.id === base.id ? base : it))
      : [base, ...data.items]
    setData({ ...data, items: nextItems })
    setSelectedItemId(base.id)
    setShowEditor(false)
    setDraft({})
  }

  const handleDelete = (id: string) => {
    if (!data) return
    const remaining = data.items.filter((it) => it.id !== id)
    setData({ ...data, items: remaining })
    setSelectedItemId(remaining[0]?.id ?? null)
  }

  const handleRegenerate = () => {
    const length = 24
    const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}'
    let result = ''
    const bytes = crypto.getRandomValues(new Uint8Array(length))
    for (let i = 0; i < length; i += 1) {
      result += alphabet[bytes[i] % alphabet.length]
    }
    setGenerated(result)
  }

  const locked = !data

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-8 pb-12">
      <header className="flex flex-col gap-3 pt-4">
        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
          <Link to="/" className="text-[var(--primary)]">
            ← Retour
          </Link>
          <span className="h-px w-10 bg-[var(--line)]" />
          <span>Coffre-fort natif</span>
        </div>
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-3xl font-semibold">Coffre-fort Nemosyne</h1>
            <p className="text-sm text-[var(--ink-soft)]">
              Multi-vaults, recherche instantanée, TOTP, passkeys, mode voyage. Interface inspirée des
              meilleurs coffres, mais 100% native et chiffrée client.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Pill tone="ok">Chiffrement AES-GCM 256</Pill>
            <Pill tone={data?.travelMode ? 'warn' : 'default'}>
              {data?.travelMode ? 'Mode voyage actif' : 'Mode complet'}
            </Pill>
          </div>
        </div>
      </header>

      {locked ? (
        <div className="grid gap-4 md:grid-cols-2">
          <div className="card-elev rounded-2xl border border-[var(--line)] p-6">
            <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">Déverrouiller</p>
            <h2 className="mt-1 text-xl font-semibold">Coffre natif</h2>
            <p className="text-sm text-[var(--ink-soft)]">
              Mot de passe maître local uniquement. Les données sont chiffrées côté client et stockées dans
              ton navigateur. Aucune dépendance externe.
            </p>
            <div className="mt-4 flex flex-col gap-2">
              <label className="text-xs text-[var(--ink-soft)]">Mot de passe maître</label>
              <input
                type="password"
                value={passwordInput}
                onChange={(e) => setPasswordInput(e.target.value)}
                className="rounded-xl border border-[var(--line)] px-3 py-2"
                placeholder="••••••••••••••"
              />
            </div>
            {unlockError ? <p className="mt-2 text-sm text-red-500">{unlockError}</p> : null}
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => handleUnlock(blob ? 'existing' : 'new')}
                className="rounded-full border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
              >
                {blob ? 'Déverrouiller' : 'Créer et déverrouiller'}
              </button>
              <button
                type="button"
                onClick={() => handleUnlock('new')}
                className="rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
              >
                Repartir de la démo coffre natif
              </button>
            </div>
          </div>

          <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] p-6">
            <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">Fonctions natives</p>
            <ul className="mt-3 flex list-disc flex-col gap-2 pl-4 text-sm text-[var(--ink-soft)]">
              <li>Multi-vaults (perso, équipe, voyage) avec tags et favoris.</li>
              <li>Types complets : connexions, cartes, identités, notes, Wi‑Fi, SSH, API, passkeys.</li>
              <li>Watchtower: mots de passe faibles/recyclés, cartes expirantes, périmètre voyage.</li>
              <li>TOTP live, générateur intégré, historique et rotation rapide.</li>
            </ul>
            <div className="mt-4 flex gap-2">
              <Pill>Interface 3 panneaux</Pill>
              <Pill>Mode voyage</Pill>
              <Pill>Audit instantané</Pill>
            </div>
          </div>
        </div>
      ) : null}

      {!locked && data ? (
        <div className="grid gap-4 lg:grid-cols-[250px_minmax(320px,1fr)_minmax(320px,1fr)]">
          <aside className="flex flex-col gap-3">
            <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] p-4">
              <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Vaults</p>
              <div className="mt-2 flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedVaultId('all')}
                  className={`flex items-center justify-between rounded-xl border px-3 py-2 text-sm ${
                    selectedVaultId === 'all'
                      ? 'border-[var(--primary)] bg-[var(--primary-weak)]'
                      : 'border-[var(--line)] bg-[var(--surface)]'
                  }`}
                >
                  <span>Tous les coffres</span>
                  <span className="text-xs text-[var(--ink-soft)]">{data.items.length}</span>
                </button>
                {data.vaults.map((vault) => (
                  <button
                    key={vault.id}
                    type="button"
                    onClick={() => setSelectedVaultId(vault.id)}
                    className={`flex items-center justify-between rounded-xl border px-3 py-2 text-sm transition ${
                      selectedVaultId === vault.id
                        ? 'border-[var(--primary)] bg-[var(--primary-weak)]'
                        : 'border-[var(--line)] bg-[var(--surface)] hover:border-[var(--primary)]'
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: vault.color }} />
                      {vault.name}
                    </span>
                    <span className="text-xs text-[var(--ink-soft)]">
                      {data.items.filter((it) => it.vaultId === vault.id).length}
                    </span>
                  </button>
                ))}
              </div>

              <div className="mt-4 flex items-center justify-between rounded-xl border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-2">
                <div>
                  <p className="text-xs font-semibold">Mode voyage</p>
                  <p className="text-[11px] text-[var(--ink-soft)]">Masque les items non marqués "safe".</p>
                </div>
                <label className="relative inline-flex cursor-pointer items-center">
                  <input
                    type="checkbox"
                    className="peer sr-only"
                    checked={data.travelMode ?? false}
                    onChange={() => setData({ ...data, travelMode: !data.travelMode })}
                  />
                  <div className="peer h-5 w-10 rounded-full bg-gray-300 after:absolute after:left-0.5 after:top-0.5 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition peer-checked:bg-[var(--primary)] peer-checked:after:translate-x-5" />
                </label>
              </div>
            </div>

            <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] p-4">
              <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Watchtower</p>
              <div className="mt-3 grid grid-cols-2 gap-2">
                <WatchBadge label="Faibles" value={watch.weak.length} tone={watch.weak.length ? 'warn' : 'ok'} />
                <WatchBadge label="Recyclés" value={watch.reused.length} tone={watch.reused.length ? 'warn' : 'ok'} />
                <WatchBadge label="Expire <45j" value={watch.expiring.length} tone={watch.expiring.length ? 'warn' : 'ok'} />
                <WatchBadge label="Safe voyage" value={watch.safeForTravel} tone="ok" />
              </div>
            </div>
          </aside>

          <section className="flex flex-col gap-3">
            <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] p-4">
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    type="search"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Recherche rapide (titre, tag, login)"
                    className="w-full rounded-xl border border-[var(--line)] px-3 py-2 text-sm md:w-72"
                  />
                  <select
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value as VaultItemType | 'all')}
                    className="rounded-xl border border-[var(--line)] px-3 py-2 text-sm"
                  >
                    <option value="all">Tous les types</option>
                    <option value="login">Connexions</option>
                    <option value="card">Cartes</option>
                    <option value="identity">Identités</option>
                    <option value="note">Notes sécurisées</option>
                    <option value="wifi">Wi‑Fi</option>
                    <option value="ssh">SSH</option>
                    <option value="api">API / tokens</option>
                    <option value="passkey">Passkeys</option>
                  </select>
                  <label className="flex cursor-pointer items-center gap-2 text-xs text-[var(--ink-soft)]">
                    <input
                      type="checkbox"
                      checked={favoritesOnly}
                      onChange={() => setFavoritesOnly(!favoritesOnly)}
                    />
                    Favoris uniquement
                  </label>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setDraft({ vaultId: selectedVaultId === 'all' ? data.vaults[0].id : selectedVaultId })
                      setShowEditor(true)
                    }}
                    className="rounded-full border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
                  >
                    Nouvel item
                  </button>
                  <button
                    type="button"
                    onClick={handleRegenerate}
                    className="rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                  >
                    Générer
                  </button>
                </div>
              </div>
            </div>

            {showEditor ? (
              <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] p-4">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-semibold">Éditeur rapide</p>
                  <button
                    type="button"
                    onClick={() => setShowEditor(false)}
                    className="text-sm text-[var(--ink-soft)]"
                  >
                    ✕
                  </button>
                </div>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  <div className="flex flex-col gap-2">
                    <label className="text-xs text-[var(--ink-soft)]">Titre</label>
                    <input
                      type="text"
                      value={draft.title ?? ''}
                      onChange={(e) => setDraft({ ...draft, title: e.target.value })}
                      className="rounded-xl border border-[var(--line)] px-3 py-2"
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-xs text-[var(--ink-soft)]">Type</label>
                    <select
                      value={(draft.type as VaultItemType) ?? 'login'}
                      onChange={(e) => setDraft({ ...draft, type: e.target.value as VaultItemType })}
                      className="rounded-xl border border-[var(--line)] px-3 py-2"
                    >
                      <option value="login">Connexion</option>
                      <option value="card">Carte</option>
                      <option value="identity">Identité</option>
                      <option value="note">Note sécurisée</option>
                      <option value="wifi">Wi‑Fi</option>
                      <option value="ssh">SSH</option>
                      <option value="api">API / token</option>
                      <option value="passkey">Passkey</option>
                    </select>
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-xs text-[var(--ink-soft)]">URL / domaine</label>
                    <input
                      type="text"
                      value={draft.url ?? ''}
                      onChange={(e) => setDraft({ ...draft, url: e.target.value })}
                      className="rounded-xl border border-[var(--line)] px-3 py-2"
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-xs text-[var(--ink-soft)]">Identifiant</label>
                    <input
                      type="text"
                      value={draft.username ?? ''}
                      onChange={(e) => setDraft({ ...draft, username: e.target.value })}
                      className="rounded-xl border border-[var(--line)] px-3 py-2"
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-xs text-[var(--ink-soft)]">Mot de passe</label>
                    <input
                      type="text"
                      value={draft.password ?? ''}
                      onChange={(e) => setDraft({ ...draft, password: e.target.value })}
                      className="rounded-xl border border-[var(--line)] px-3 py-2"
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-xs text-[var(--ink-soft)]">Tags (séparés par des virgules)</label>
                    <input
                      type="text"
                      value={draft.tags?.join(', ') ?? ''}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          tags: e.target.value
                            .split(',')
                            .map((tag) => tag.trim())
                            .filter(Boolean),
                        })
                      }
                      className="rounded-xl border border-[var(--line)] px-3 py-2"
                    />
                  </div>
                  <div className="flex flex-col gap-2 md:col-span-2">
                    <label className="text-xs text-[var(--ink-soft)]">Note / détails</label>
                    <textarea
                      value={draft.note ?? ''}
                      onChange={(e) => setDraft({ ...draft, note: e.target.value })}
                      className="min-h-[90px] rounded-xl border border-[var(--line)] px-3 py-2"
                    />
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-3">
                  <label className="flex items-center gap-2 text-xs text-[var(--ink-soft)]">
                    <input
                      type="checkbox"
                      checked={draft.favorite ?? false}
                      onChange={() => setDraft({ ...draft, favorite: !draft.favorite })}
                    />
                    Marquer favori
                  </label>
                  <label className="flex items-center gap-2 text-xs text-[var(--ink-soft)]">
                    <input
                      type="checkbox"
                      checked={draft.travelSafe ?? true}
                      onChange={() => setDraft({ ...draft, travelSafe: !(draft.travelSafe ?? true) })}
                    />
                    Autoriser en mode voyage
                  </label>
                  <label className="flex items-center gap-2 text-xs text-[var(--ink-soft)]">
                    <input
                      type="checkbox"
                      checked={Boolean(draft.totpSecret)}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          totpSecret: e.target.checked ? draft.totpSecret ?? 'JBSWY3DPEHPK3PXP' : undefined,
                        })
                      }
                    />
                    Ajouter un TOTP
                  </label>
                </div>
                {draft.totpSecret ? (
                  <div className="mt-2 flex flex-col gap-2 md:w-1/2">
                    <label className="text-xs text-[var(--ink-soft)]">Secret TOTP (Base32)</label>
                    <input
                      type="text"
                      value={draft.totpSecret}
                      onChange={(e) => setDraft({ ...draft, totpSecret: e.target.value })}
                      className="rounded-xl border border-[var(--line)] px-3 py-2"
                    />
                  </div>
                ) : null}
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => handleSaveItem(Boolean(draft.id))}
                    className="rounded-full border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white"
                  >
                    {draft.id ? 'Mettre à jour' : 'Enregistrer'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setDraft({})
                      setShowEditor(false)
                    }}
                    className="rounded-full border border-[var(--line)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]"
                  >
                    Annuler
                  </button>
                </div>
              </div>
            ) : null}

            <div className="grid gap-3">
              {filteredItems.map((item) => (
                <ItemRow
                  key={item.id}
                  item={item}
                  active={item.id === selectedItemId}
                  onSelect={() => setSelectedItemId(item.id)}
                />
              ))}
              {!filteredItems.length ? (
                <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-6 text-sm text-[var(--ink-soft)]">
                  Aucun élément ne correspond. Ajoute un item ou enlève un filtre.
                </div>
              ) : null}
            </div>
          </section>

          <section className="flex flex-col gap-3">
            <div className="rounded-2xl border border-[var(--line)] bg-[var(--surface-elev)] p-4">
              {selectedItem ? (
                <div className="flex flex-col gap-3">
                  <div className="flex items-start justify-between">
                    <div className="flex flex-col gap-1">
                      <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">
                        {selectedItem.type}
                      </p>
                      <h3 className="text-xl font-semibold">{selectedItem.title}</h3>
                      {selectedItem.subtitle ? (
                        <p className="text-sm text-[var(--ink-soft)]">{selectedItem.subtitle}</p>
                      ) : null}
                      <div className="flex flex-wrap gap-2">
                        <VaultChip
                          vault={
                            data.vaults.find((v) => v.id === selectedItem.vaultId) ?? {
                              id: 'x',
                              name: 'Inconnu',
                              color: '#0f172a',
                              scope: 'perso',
                              defaultShare: 'private',
                            }
                          }
                        />
                        {selectedItem.tags.map((tag) => (
                          <span
                            key={tag}
                            className="rounded-full bg-[var(--surface-muted)] px-2 py-[2px] text-xs text-[var(--ink-soft)]"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          setDraft(selectedItem)
                          setShowEditor(true)
                        }}
                        className="rounded-full border border-[var(--line)] px-3 py-1 text-xs uppercase tracking-[0.2em]"
                      >
                        Modifier
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDelete(selectedItem.id)}
                        className="rounded-full border border-red-200 bg-red-50 px-3 py-1 text-xs uppercase tracking-[0.2em] text-red-600"
                      >
                        Supprimer
                      </button>
                    </div>
                  </div>

                  <div className="grid gap-3 md:grid-cols-2">
                    <DetailField label="Identifiant" value={selectedItem.username} />
                    <DetailField label="URL" value={selectedItem.url} />
                    <DetailField label="Mot de passe" value={selectedItem.password} masked monospace />
                    {selectedItem.totpSecret ? (
                      <div>
                        <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">TOTP</p>
                        <div className="mt-1 flex items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-2 font-mono text-lg">
                          <span>{totp ?? '••••••'}</span>
                          <span className="text-xs text-[var(--ink-soft)]">
                            {30 - Math.floor((Date.now() / 1000) % 30)}s
                          </span>
                        </div>
                      </div>
                    ) : null}
                  </div>

                  {selectedItem.card ? (
                    <div className="rounded-xl border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-2 text-sm">
                      <p className="text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)]">Carte</p>
                      <p>{selectedItem.card.holder}</p>
                      <p>
                        {selectedItem.card.network} •••• {selectedItem.card.last4} · exp {selectedItem.card.expMonth}/
                        {selectedItem.card.expYear}
                      </p>
                    </div>
                  ) : null}

                  {selectedItem.note ? (
                    <div className="rounded-xl border border-[var(--line)] bg-[var(--surface-muted)] px-3 py-3 text-sm text-[var(--ink-soft)]">
                      {selectedItem.note}
                    </div>
                  ) : null}

                  {selectedItem.history ? (
                    <div className="rounded-xl border border-[var(--line)] bg-[var(--surface)] px-3 py-3">
                      <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--ink-soft)]">Historique</p>
                      <ul className="mt-2 flex flex-col gap-2 text-sm text-[var(--ink-soft)]">
                        {selectedItem.history.map((entry) => (
                          <li key={entry.timestamp} className="flex items-center justify-between">
                            <span>{entry.summary}</span>
                            <span className="text-xs">{formatDate(entry.timestamp)}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="text-sm text-[var(--ink-soft)]">Sélectionne un item pour afficher ses détails.</div>
              )}
            </div>

            <Generator
              value={generated}
              onGenerate={handleRegenerate}
              onUse={() => {
                if (!selectedItem || !data) {
                  setDraft({ ...draft, password: generated })
                  return
                }
                const updated = data.items.map((it) =>
                  it.id === selectedItem.id ? { ...it, password: generated, updatedAt: Date.now() } : it,
                )
                setData({ ...data, items: updated })
              }}
            />
          </section>
        </div>
      ) : null}
    </div>
  )
}

export default VaultPage
