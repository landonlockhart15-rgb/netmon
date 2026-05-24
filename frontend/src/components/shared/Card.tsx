import { cn } from '@/lib/utils'

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string
  badge?: string
  action?: React.ReactNode
}

export default function Card({ title, badge, action, className, children, ...props }: CardProps) {
  return (
    <div
      className={cn('rounded-xl border border-white/8 bg-[#12121e] overflow-hidden', className)}
      {...props}
    >
      {(title || action) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-white/5">
          <div className="flex items-center gap-2">
            {title && <h2 className="text-sm font-semibold text-white/90">{title}</h2>}
            {badge && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-600/20 text-purple-300 font-medium">
                {badge}
              </span>
            )}
          </div>
          {action && <div className="flex items-center gap-2">{action}</div>}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  )
}
