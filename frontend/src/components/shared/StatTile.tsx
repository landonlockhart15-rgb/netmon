import { cn } from '@/lib/utils'

export type Accent = 'emerald' | 'red' | 'amber' | 'cyan' | 'purple' | 'blue' | 'indigo' | 'gray'

/** Shared accent palette for the command-center surfaces. */
export const ACCENT: Record<Accent, {
  text: string; chipBg: string; ring: string; glow: string; dot: string; bar: string
}> = {
  emerald: { text: 'text-emerald-400', chipBg: 'bg-emerald-500/10', ring: 'ring-emerald-500/30', glow: 'shadow-[0_0_24px_-6px_rgba(16,185,129,0.55)]', dot: 'bg-emerald-400', bar: 'bg-emerald-500' },
  red:     { text: 'text-red-400',     chipBg: 'bg-red-500/10',     ring: 'ring-red-500/30',     glow: 'shadow-[0_0_24px_-6px_rgba(239,68,68,0.6)]',   dot: 'bg-red-400',     bar: 'bg-red-500' },
  amber:   { text: 'text-amber-400',   chipBg: 'bg-amber-500/10',   ring: 'ring-amber-500/30',   glow: 'shadow-[0_0_24px_-6px_rgba(245,158,11,0.55)]', dot: 'bg-amber-400',   bar: 'bg-amber-500' },
  cyan:    { text: 'text-cyan-400',    chipBg: 'bg-cyan-500/10',    ring: 'ring-cyan-500/30',    glow: 'shadow-[0_0_24px_-6px_rgba(34,211,238,0.5)]',  dot: 'bg-cyan-400',    bar: 'bg-cyan-500' },
  purple:  { text: 'text-purple-400',  chipBg: 'bg-purple-500/10',  ring: 'ring-purple-500/30',  glow: 'shadow-[0_0_24px_-6px_rgba(168,85,247,0.5)]',  dot: 'bg-purple-400',  bar: 'bg-purple-500' },
  blue:    { text: 'text-blue-400',    chipBg: 'bg-blue-500/10',    ring: 'ring-blue-500/30',    glow: 'shadow-[0_0_24px_-6px_rgba(59,130,246,0.5)]',  dot: 'bg-blue-400',    bar: 'bg-blue-500' },
  indigo:  { text: 'text-indigo-400',  chipBg: 'bg-indigo-500/10',  ring: 'ring-indigo-500/30',  glow: 'shadow-[0_0_24px_-6px_rgba(99,102,241,0.5)]',  dot: 'bg-indigo-400',  bar: 'bg-indigo-500' },
  gray:    { text: 'text-gray-400',    chipBg: 'bg-white/5',        ring: 'ring-white/10',       glow: '',                                             dot: 'bg-gray-500',    bar: 'bg-gray-500' },
}

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
