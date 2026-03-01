type UserAvatarProps = {
  avatarUrl: string | null
  label: string
  initials: string
  onImageError?: () => void
}

export function UserAvatar({ avatarUrl, label, initials, onImageError }: UserAvatarProps) {
  return (
    <span className="inline-flex h-9 w-9 items-center justify-center overflow-hidden rounded-full bg-[var(--primary)] text-xs font-semibold uppercase text-white">
      {avatarUrl ? (
        <img
          src={avatarUrl}
          alt={label}
          className="h-full w-full object-cover"
          onError={onImageError}
        />
      ) : (
        initials
      )}
    </span>
  )
}

export default UserAvatar