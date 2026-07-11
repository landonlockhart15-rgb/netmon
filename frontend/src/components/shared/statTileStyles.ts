export type Accent = 'emerald' | 'red' | 'amber' | 'cyan' | 'purple' | 'blue' | 'indigo' | 'gray'

export const ACCENT: Record<Accent, {
  text: string; chipBg: string; ring: string; glow: string; dot: string; bar: string
}> = {
  emerald: { text: 'text-emerald-400', chipBg: 'bg-emerald-500/10', ring: 'ring-emerald-500/30', glow: 'shadow-[0_0_24px_-6px_rgba(16,185,129,0.55)]', dot: 'bg-emerald-400', bar: 'bg-emerald-500' },
  red:     { text: 'text-red-400',     chipBg: 'bg-red-500/10',     ring: 'ring-red-500/30',     glow: 'shadow-[0_0_24px_-6px_rgba(239,68,68,0.6)]',   dot: 'bg-red-400',     bar: 'bg-red-500' },
  amber:   { text: 'text-amber-400',   chipBg: 'bg-amber-500/10',   ring: 'ring-amber-500/30',   glow: 'shadow-[0_0_24px_-6px_rgba(245,158,11,0.55)]', dot: 'bg-amber-400',   bar: 'bg-amber-500' },
  cyan:    { text: 'text-cyan-400',    chipBg: 'bg-cyan-500/10',    ring: 'ring-cyan-500/30',     glow: 'shadow-[0_0_24px_-6px_rgba(34,211,238,0.5)]',  dot: 'bg-cyan-400',    bar: 'bg-cyan-500' },
  purple:  { text: 'text-purple-400',  chipBg: 'bg-purple-500/10',  ring: 'ring-purple-500/30',   glow: 'shadow-[0_0_24px_-6px_rgba(168,85,247,0.5)]',  dot: 'bg-purple-400',  bar: 'bg-purple-500' },
  blue:    { text: 'text-blue-400',    chipBg: 'bg-blue-500/10',    ring: 'ring-blue-500/30',     glow: 'shadow-[0_0_24px_-6px_rgba(59,130,246,0.5)]',  dot: 'bg-blue-400',    bar: 'bg-blue-500' },
  indigo:  { text: 'text-indigo-400',  chipBg: 'bg-indigo-500/10',  ring: 'ring-indigo-500/30',   glow: 'shadow-[0_0_24px_-6px_rgba(99,102,241,0.5)]',  dot: 'bg-indigo-400',  bar: 'bg-indigo-500' },
  gray:    { text: 'text-gray-400',    chipBg: 'bg-white/5',        ring: 'ring-white/10',         glow: '',                                             dot: 'bg-gray-500',    bar: 'bg-gray-500' },
}
