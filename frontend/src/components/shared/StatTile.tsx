import { cn } from '@/lib/utils'
import { ACCENT, type Accent } from './statTileStyles'

interface StatTileProps {
  icon?: React.ReactNode
  label: string
  value: React.ReactNode
  sub?: React.ReactNode
  accent?: Accent
  glow?: boolean
  className?: string
}

/** Compact metric tile with an accent-colored value and optional glow. */
export default function StatTile({ icon, label, value, sub, accent = 'gray', glow = false, className }: StatTileProps) {
  const a = ACCENT[accent]
  return (
    <div className={cn(
      'relative rounded-xl border border-white/8 bg-[#12121e]/80 px-3.5 py-3 ring-1 ring-inset',
      a.ring, glow && a.glow, className,
    )}>
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-500">
        {icon && <span className={a.text}>{icon}</span>}
        <span>{label}</span>
      </div>
      <div className={cn('mt-1 text-2xl font-bold tabular-nums leading-none', a.text)}>{value}</div>
      {sub && <div className="mt-1 text-[10px] text-gray-600 truncate">{sub}</div>}
    </div>
  )
}
