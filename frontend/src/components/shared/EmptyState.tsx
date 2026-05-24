import { cn } from '@/lib/utils'

interface EmptyStateProps {
  icon?: string
  text: string
  hint?: string
  className?: string
}

export default function EmptyState({ icon = '◎', text, hint, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-12 text-center', className)}>
      <span className="text-3xl mb-3 opacity-30">{icon}</span>
      <p className="text-sm text-gray-400">{text}</p>
      {hint && <p className="text-xs text-gray-600 mt-1">{hint}</p>}
    </div>
  )
}
