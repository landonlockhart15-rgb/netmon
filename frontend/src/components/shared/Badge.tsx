import { cn } from '@/lib/utils'
import { BADGE_VARIANTS, type Variant } from './badgeVariants'

interface BadgeProps {
  variant?: Variant
  children: React.ReactNode
  className?: string
}

export default function Badge({ variant = 'muted', children, className }: BadgeProps) {
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border', BADGE_VARIANTS[variant], className)}>
      {children}
    </span>
  )
}
