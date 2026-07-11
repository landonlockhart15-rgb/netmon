import { cn } from '@/lib/utils'
import { ACCENT, type Accent } from './statTileStyles'

// Conic-sweep + border colors per accent. Kept as literal strings so Tailwind's
// scanner picks the border classes up (never build class names at runtime).
const SWEEP: Record<Accent, string> = {
  emerald: 'rgba(16,185,129,0.5)', red: 'rgba(239,68,68,0.55)', amber: 'rgba(245,158,11,0.5)',
  cyan: 'rgba(34,211,238,0.45)', purple: 'rgba(168,85,247,0.5)', blue: 'rgba(59,130,246,0.5)',
  indigo: 'rgba(99,102,241,0.5)', gray: 'rgba(148,163,184,0.4)',
}
const BORDER: Record<Accent, string> = {
  emerald: 'border-emerald-500/40', red: 'border-red-500/50', amber: 'border-amber-500/40',
  cyan: 'border-cyan-500/30', purple: 'border-purple-500/40', blue: 'border-blue-500/40',
  indigo: 'border-indigo-500/40', gray: 'border-white/15',
}

interface PageHeroProps {
  icon: React.ElementType
  eyebrow: string
  title: string
  subtitle?: string
  accent?: Accent
  /** Show expanding sonar rings around the emblem (use for "live"/active states). */
  pulse?: boolean
  /** Grid of <StatTile> metrics shown on the right. */
  tiles?: React.ReactNode
  /** Action buttons rendered under the tiles (right-aligned). */
  actions?: React.ReactNode
  /** Extra content under the title — status badges, hints, etc. */
  children?: React.ReactNode
}

/**
 * Shared command-center hero used across every section page. Animated radar
 * emblem + title on the left, optional metric tiles and actions on the right.
 */
export default function PageHero({
  icon: Icon, eyebrow, title, subtitle, accent = 'cyan', pulse = false, tiles, actions, children,
}: PageHeroProps) {
  const a = ACCENT[accent]
  const border = BORDER[accent]
  return (
    <div className={cn('relative overflow-hidden rounded-2xl border bg-[#0d0d18]', border, a.glow)}>
      <div className="absolute inset-0 nm-grid-bg opacity-50" />
      <div className="absolute inset-0 bg-gradient-to-br from-transparent to-black/40" />
      <div className="relative flex flex-col lg:flex-row lg:items-center gap-5 p-5 md:p-6">
        {/* Emblem + identity */}
        <div className="flex items-center gap-5 min-w-0">
          <div className="relative h-20 w-20 flex-shrink-0">
            {pulse && <span className={cn('absolute inset-0 rounded-full border nm-pulse-ring', border)} />}
            <span className="absolute inset-1 rounded-full nm-sweep"
              style={{ background: `conic-gradient(from 0deg, transparent 0deg, ${SWEEP[accent]} 60deg, transparent 120deg)` }} />
            <div className={cn('absolute inset-3 grid place-items-center rounded-full border bg-[#0a0a14]', border)}>
              <Icon size={26} className={cn(a.text, pulse && 'nm-breathe')} />
            </div>
          </div>
          <div className="min-w-0">
            <div className={cn('flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.2em]', a.text)}>
              <span className={cn('h-2 w-2 rounded-full nm-blip', a.dot, a.text)} />
              <span className="truncate">{eyebrow}</span>
            </div>
            <h1 className="mt-1 text-2xl md:text-3xl font-bold text-white tracking-tight">{title}</h1>
            {subtitle && <p className="mt-1 text-sm text-gray-400 max-w-md">{subtitle}</p>}
            {children && <div className="mt-2">{children}</div>}
          </div>
        </div>

        {/* Metrics + actions */}
        {(tiles || actions) && (
          <div className="lg:ml-auto w-full lg:w-auto">
            {tiles && <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">{tiles}</div>}
            {actions && <div className={cn('flex flex-wrap justify-end gap-2', tiles && 'mt-3')}>{actions}</div>}
          </div>
        )}
      </div>
    </div>
  )
}
