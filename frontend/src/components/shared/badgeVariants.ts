export type Variant = 'ok' | 'warn' | 'error' | 'info' | 'muted' | 'purple'

export const BADGE_VARIANTS: Record<Variant, string> = {
  ok: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  warn: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  error: 'bg-red-500/15 text-red-400 border-red-500/30',
  info: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  muted: 'bg-white/5 text-gray-400 border-white/10',
  purple: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
}

export function severityVariant(s: string): Variant {
  const level = s?.toLowerCase()
  if (level === 'critical' || level === 'high' || level === 'error') return 'error'
  if (level === 'medium' || level === 'warning' || level === 'warn') return 'warn'
  if (level === 'low' || level === 'info') return 'info'
  if (level === 'ok' || level === 'clean') return 'ok'
  return 'muted'
}
