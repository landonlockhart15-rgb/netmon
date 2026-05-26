import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { CheckCheck, Bell, BellRing, Inbox } from 'lucide-react'
import { getAlerts, readAlert, readAllAlerts } from '@/lib/api'
import { formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge, { severityVariant } from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile from '@/components/shared/StatTile'

// API shape: { unread_count: number, alerts: RawAlert[] }
interface RawAlert {
  id: number
  created_at: string
  alert_type: string
  message: string
  read: boolean
  device_id: number | null
}

export default function Alerts() {
  const qc = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: getAlerts,
    refetchInterval: 30_000,
  })

  const readMutation = useMutation({
    mutationFn: (id: number) => readAlert(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })

  const readAllMutation = useMutation({
    mutationFn: readAllAlerts,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })

  // API returns { unread_count, alerts: [] } — handle both shapes
  const raw = data as any
  const list: RawAlert[] = Array.isArray(raw) ? raw : (raw?.alerts ?? [])
  const unread: number = raw?.unread_count ?? list.filter((a: RawAlert) => !a.read).length

  return (
    <div className="space-y-4">
      <PageHero
        icon={unread > 0 ? BellRing : Bell}
        accent={unread > 0 ? 'amber' : 'emerald'}
        pulse={unread > 0}
        eyebrow={unread > 0 ? `${unread} need attention` : 'All caught up'}
        title="Alerts"
        subtitle="New devices, anomalies, and threats surface here the moment they're detected."
        tiles={
          <>
            <StatTile icon={<BellRing size={11} />} label="Unread" accent={unread > 0 ? 'amber' : 'gray'} glow value={unread} sub="need review" />
            <StatTile icon={<Inbox size={11} />} label="Total" accent="blue" value={list.length} sub="in history" />
          </>
        }
      />

      <Card
        title="Alerts"
        badge={unread > 0 ? `${unread} UNREAD` : undefined}
        action={
          unread > 0 ? (
            <Btn variant="ghost" size="sm" loading={readAllMutation.isPending} onClick={() => readAllMutation.mutate()}>
              <CheckCheck size={13} /> Mark All Read
            </Btn>
          ) : undefined
        }
      >
        {isLoading ? (
          <SkeletonRows />
        ) : list.length === 0 ? (
          <EmptyState icon="◎" text="No alerts" hint="Alerts appear here when anomalies or threats are detected." />
        ) : (
          <div className="space-y-2">
            {list.map(a => (
              <AlertRow key={a.id} alert={a} onRead={() => readMutation.mutate(a.id)} />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

function AlertRow({ alert: a, onRead }: { alert: RawAlert; onRead: () => void }) {
  // alert_type maps to severity
  const variant = severityVariant(a.alert_type)
  return (
    <div className={cn(
      'rounded-lg border p-3 transition-all',
      a.read ? 'border-white/5 bg-white/[0.02] opacity-60' : 'border-white/10 bg-[#1a1a2e]'
    )}>
      <div className="flex items-start gap-3">
        <Bell size={14} className={cn('mt-0.5 flex-shrink-0', a.read ? 'text-gray-600' : 'text-yellow-400')} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <Badge variant={variant}>{a.alert_type}</Badge>
            <span className="text-sm text-gray-200 font-medium truncate">{a.message}</span>
          </div>
          <div className="flex items-center gap-3 mt-1 text-[10px] text-gray-600">
            {a.device_id && <span className="font-mono">device #{a.device_id}</span>}
            <span>{formatRelativeTime(a.created_at)}</span>
          </div>
        </div>
        {!a.read && (
          <button onClick={onRead} className="text-xs text-gray-600 hover:text-gray-300 transition-colors flex-shrink-0 mt-0.5">
            Dismiss
          </button>
        )}
      </div>
    </div>
  )
}

function SkeletonRows() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="rounded-lg border border-white/5 p-3 animate-pulse">
          <div className="flex gap-3">
            <div className="w-4 h-4 bg-white/5 rounded" />
            <div className="flex-1 space-y-2">
              <div className="h-4 bg-white/5 rounded w-48" />
              <div className="h-3 bg-white/5 rounded w-full" />
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
