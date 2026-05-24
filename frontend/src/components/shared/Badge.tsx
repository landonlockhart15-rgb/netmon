import { cn } from '@/lib/utils'

type Variant = 'ok' | 'warn' | 'error' | 'info' | 'muted' | 'purple'

const VARIANTS: Record<Variant, string> = {
  ok:     'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  warn:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  error:  'bg-red-500/15 text-red-400 border-red-500/30',
  info:   'bg-blue-500/15 text-blue-400 border-blue-500/30',
  muted:  'bg-white/5 text-gray-400 border-white/10',
  purple: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
}

export function severityVariant(s: string): Variant {
  const l = s?.toLowerCase()
  if (l === 'critical' || l === 'high' || l === 'error') return 'error'
  if (l === 'medium' || l === 'warning' || l === 'warn') return 'warn'
  if (l === 'low' || l === 'info') return 'info'
  if (l === 'ok' || l === 'clean') return 'ok'
  return 'muted'
}

interface BadgeProps {
  variant?: Variant
  children: React.ReactNode
  className?: string
}

export default function Badge({ variant = 'muted', children, className }: BadgeProps) {
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border', VARIANTS[variant], className)}>
      {children}
    </span>
  )
}
