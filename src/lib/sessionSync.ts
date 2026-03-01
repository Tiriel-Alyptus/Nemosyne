export type AuthEvent = {
  id: string
  type: string
  payload?: unknown
  ts: number
}

const AUTH_CHANNEL_NAME = 'auth'
const AUTH_STORAGE_KEY = 'auth_event'

function isAuthEvent(value: unknown): value is AuthEvent {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<AuthEvent>
  return (
    typeof candidate.id === 'string' &&
    typeof candidate.type === 'string' &&
    typeof candidate.ts === 'number'
  )
}

function buildAuthEvent(type: string, payload?: unknown): AuthEvent {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    type,
    payload,
    ts: Date.now(),
  }
}

export function broadcastAuthEvent(type: string, payload?: unknown) {
  if (typeof window === 'undefined') return

  const event = buildAuthEvent(type, payload)

  if ('BroadcastChannel' in window) {
    try {
      const channel = new BroadcastChannel(AUTH_CHANNEL_NAME)
      channel.postMessage(event)
      channel.close()
    } catch {
      // Ignore transport errors.
    }
  }

  try {
    window.localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(event))
    // Triggering storage event is enough; key does not need to persist.
    window.localStorage.removeItem(AUTH_STORAGE_KEY)
  } catch {
    // Ignore storage errors (private mode, quota, etc.).
  }
}

export function onAuthEvent(callback: (event: AuthEvent) => void) {
  if (typeof window === 'undefined') {
    return () => undefined
  }

  let channel: BroadcastChannel | null = null
  const seen = new Set<string>()

  const dispatch = (value: unknown) => {
    if (!isAuthEvent(value)) return
    if (seen.has(value.id)) return
    seen.add(value.id)
    if (seen.size > 20) {
      const first = seen.values().next().value
      if (first) seen.delete(first)
    }
    callback(value)
  }

  if ('BroadcastChannel' in window) {
    try {
      channel = new BroadcastChannel(AUTH_CHANNEL_NAME)
      channel.onmessage = (event) => {
        dispatch(event.data)
      }
    } catch {
      channel = null
    }
  }

  const onStorage = (event: StorageEvent) => {
    if (event.key !== AUTH_STORAGE_KEY || !event.newValue) return
    try {
      const parsed = JSON.parse(event.newValue) as unknown
      dispatch(parsed)
    } catch {
      // Ignore malformed payload.
    }
  }

  window.addEventListener('storage', onStorage)

  return () => {
    window.removeEventListener('storage', onStorage)
    if (channel) {
      channel.close()
    }
  }
}