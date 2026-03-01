import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import UserAvatar from '../ui/UserAvatar'

type HeaderProps = {
  logoSrc: string
  theme: 'light' | 'dark'
  onThemeChange: (theme: 'light' | 'dark') => void
  isAuthenticated: boolean
  authLoading: boolean
  userDisplayName: string
  userInitials: string
  avatarUrl: string | null
  onAvatarError?: () => void
  onOpenSettings: () => void
  onOpenSecurity: () => void
  onOpenAuth: (mode: 'signin' | 'signup') => void
  onLogout: () => void
  hasBillingRoute?: boolean
}

function Header({
  logoSrc,
  theme,
  onThemeChange,
  isAuthenticated,
  authLoading,
  userDisplayName,
  userInitials,
  avatarUrl,
  onAvatarError,
  onOpenSettings,
  onOpenSecurity,
  onOpenAuth,
  onLogout,
  hasBillingRoute = false,
}: HeaderProps) {
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement | null>(null)
  const menuButtonRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    if (!isMenuOpen) return

    const onPointerDown = (event: MouseEvent) => {
      const target = event.target as Node
      const insideMenu = Boolean(menuRef.current?.contains(target))
      const insideTrigger = Boolean(menuButtonRef.current?.contains(target))
      if (!insideMenu && !insideTrigger) {
        setIsMenuOpen(false)
      }
    }

    const onEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsMenuOpen(false)
      }
    }

    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onEscape)

    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onEscape)
    }
  }, [isMenuOpen])

  return (
    <header className="overflow-hidden rounded-3xl border border-[var(--line)] bg-[var(--surface)]/95 shadow-[var(--shadow)] backdrop-blur">
      <div className="flex flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center lg:justify-between lg:px-6">
        <div className="flex items-center gap-3">
          <img src={logoSrc} alt="Logo Nemosyne" className="h-10 w-10" />
          <div className="flex flex-col leading-tight">
            <span className="text-2xl font-semibold tracking-tight">Nemosyne</span>
            <span className="text-[11px] uppercase tracking-[0.28em] text-[var(--ink-soft)]">
              Liens sensibles et auto-destructibles
            </span>
          </div>
        </div>

        <nav className="hidden items-center gap-1 lg:flex">
          <a
            href="#history"
            className="rounded-full px-3 py-2 text-sm text-[var(--ink-soft)] transition hover:bg-[var(--surface-muted)] hover:text-[var(--ink)]"
          >
            Publications
          </a>
          <a
            href="#composer"
            className="rounded-full px-3 py-2 text-sm text-[var(--ink-soft)] transition hover:bg-[var(--surface-muted)] hover:text-[var(--ink)]"
          >
            Demandes
          </a>
          <Link
            to="/features"
            className="rounded-full px-3 py-2 text-sm text-[var(--ink-soft)] transition hover:bg-[var(--surface-muted)] hover:text-[var(--ink)]"
          >
            Caracteristiques
          </Link>
          <Link
            to="/whats-new"
            className="inline-flex items-center gap-2 rounded-full px-3 py-2 text-sm text-[var(--ink-soft)] transition hover:bg-[var(--surface-muted)] hover:text-[var(--ink)]"
          >
            Quoi de neuf
            <span className="h-2 w-2 rounded-full bg-red-500" />
          </Link>
        </nav>

        <div className="flex flex-wrap items-center gap-2 lg:gap-3">
          <div className="flex items-center gap-1 rounded-full border border-[var(--line)] bg-[var(--surface-muted)] p-1">
            <button
              type="button"
              onClick={() => onThemeChange('dark')}
              className={`h-6 w-6 rounded-full border ${
                theme === 'dark'
                  ? 'border-[var(--primary)] bg-[var(--primary)]'
                  : 'border-[var(--line)] bg-[var(--surface)]'
              }`}
              aria-label="Activer le mode sombre"
              aria-pressed={theme === 'dark'}
            />
            <button
              type="button"
              onClick={() => onThemeChange('light')}
              className={`h-6 w-6 rounded-full border ${
                theme === 'light'
                  ? 'border-[var(--primary)] bg-[var(--primary)]'
                  : 'border-[var(--line)] bg-[var(--surface)]'
              }`}
              aria-label="Activer le mode clair"
              aria-pressed={theme === 'light'}
            />
          </div>

          {isAuthenticated ? (
            <div className="relative flex items-center gap-2">
              <button
                type="button"
                onClick={onOpenSettings}
                className="rounded-full border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-2 text-sm font-semibold text-[var(--ink)] transition hover:border-[var(--primary)]"
              >
                {userDisplayName}
              </button>

              <button
                ref={menuButtonRef}
                type="button"
                onClick={() => setIsMenuOpen((current) => !current)}
                className="inline-flex items-center gap-2 rounded-full border border-[var(--line)] bg-[var(--surface-muted)] px-2 py-1.5"
                aria-haspopup="menu"
                aria-expanded={isMenuOpen}
                aria-label="Ouvrir le menu profil"
              >
                <UserAvatar
                  avatarUrl={avatarUrl}
                  label={userDisplayName}
                  initials={userInitials}
                  onImageError={onAvatarError}
                />
                <svg
                  aria-hidden="true"
                  viewBox="0 0 20 20"
                  className="h-4 w-4 text-[var(--ink-soft)]"
                >
                  <path
                    fill="currentColor"
                    d="M5.23 7.21a.75.75 0 0 1 1.06.02L10 11.17l3.71-3.94a.75.75 0 1 1 1.08 1.04l-4.25 4.5a.75.75 0 0 1-1.08 0l-4.25-4.5a.75.75 0 0 1 .02-1.06Z"
                  />
                </svg>
              </button>

              {isMenuOpen ? (
                <div
                  ref={menuRef}
                  className="absolute right-0 top-[calc(100%+8px)] z-30 w-60 rounded-2xl border border-[var(--line)] bg-[var(--surface)] p-2 shadow-[var(--shadow)]"
                  role="menu"
                >
                  <button
                    type="button"
                    onClick={() => {
                      setIsMenuOpen(false)
                      onOpenSettings()
                    }}
                    className="w-full rounded-xl px-3 py-2 text-left text-sm text-[var(--ink)] transition hover:bg-[var(--surface-muted)]"
                    role="menuitem"
                  >
                    Parametres
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setIsMenuOpen(false)
                      onOpenSecurity()
                    }}
                    className="w-full rounded-xl px-3 py-2 text-left text-sm text-[var(--ink)] transition hover:bg-[var(--surface-muted)]"
                    role="menuitem"
                  >
                    Securite
                  </button>
                  {hasBillingRoute ? (
                    <Link
                      to="/pricing"
                      onClick={() => setIsMenuOpen(false)}
                      className="block w-full rounded-xl px-3 py-2 text-left text-sm text-[var(--ink)] transition hover:bg-[var(--surface-muted)]"
                      role="menuitem"
                    >
                      Facturation
                    </Link>
                  ) : null}
                  <button
                    type="button"
                    onClick={() => {
                      setIsMenuOpen(false)
                      onLogout()
                    }}
                    disabled={authLoading}
                    className="mt-1 w-full rounded-xl border border-[var(--line)] px-3 py-2 text-left text-sm text-[var(--ink-soft)] transition hover:border-[var(--primary)] disabled:opacity-60"
                    role="menuitem"
                  >
                    Deconnexion
                  </button>
                </div>
              ) : null}
            </div>
          ) : (
            <>
              <button
                type="button"
                onClick={() => onOpenAuth('signin')}
                className="pill border border-[var(--line)] bg-[var(--surface-muted)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-[var(--ink-soft)] transition hover:border-[var(--primary)]"
              >
                Se connecter
              </button>
              <button
                type="button"
                onClick={() => onOpenAuth('signup')}
                className="pill border border-[var(--primary)] bg-[var(--primary)] px-4 py-2 text-xs uppercase tracking-[0.2em] text-white transition hover:opacity-90"
              >
                S'inscrire
              </button>
            </>
          )}
        </div>
      </div>
    </header>
  )
}

export default Header
