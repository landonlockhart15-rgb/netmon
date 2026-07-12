import { ShieldAlert, WifiOff } from 'lucide-react'
import { useGuestMode } from '@/lib/useGuestMode'
import { cn } from '@/lib/utils'

export const GuestModeBanner = () => {
  const { state } = useGuestMode()

  if (!state?.guest_mode) {
    return null
  }

  const suppressedCount = state.suppressed.length
  const suppressedLabel = suppressedCount === 1 ? 'feature suppressed' : 'features suppressed'

  return (
    <div
      className={cn(
        'mx-4 mt-4 flex items-center justify-between gap-3 rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-amber-100 shadow-lg shadow-amber-950/10',
      )}
    >
      <div className="flex min-w-0 items-center gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 text-amber-300">
          <ShieldAlert className="h-5 w-5" />
        </div>

        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-medium text-amber-100">
            <WifiOff className="h-4 w-4 shrink-0 text-orange-300" />
            <span>Guest Mode active — active scanning suppressed on this untrusted network</span>
          </div>
        </div>
      </div>

      <div className="shrink-0 rounded-full border border-amber-500/20 bg-orange-500/10 px-2.5 py-1 text-xs font-medium text-orange-200">
        {suppressedCount} {suppressedLabel}
      </div>
    </div>
  )
}
