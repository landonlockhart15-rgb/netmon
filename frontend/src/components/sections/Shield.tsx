import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, ShieldCheck, Trash2, RotateCcw } from 'lucide-react'
import {
  getShield, getAutonomousActions, dismissShieldEvent, dismissAllShield,
  clearDNSLogs, revertAction,
} from '@/lib/api'
import { formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge, { severityVariant } from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'

type ActionStatus = 'active' | 'reverted' | 'all'

// API shape for /api/shield
interface ShieldEvent {
  id: number
  level: string       // API uses 'level' not 'severity'
  summary: string     // API uses 'summary' not 'title'
  detail: Record<string, unknown> | null
  device_ip: string | null
  created_at: string
  category: string
}

interface FirewallBlock {
  name: string
  ip: string
  direction?: string
  created_at?: string
}

interface ShieldResponse {
  threat_level: string
  stats: Record<string, number>
  layers: unknown[]
  events: ShieldEvent[]
  dns_events: ShieldEvent[]
  blocks: FirewallBlock[]
}

export default function Shield() {
  const qc = useQueryClient()
  const [actionStatus, setActionStatus] = useState<ActionStatus>('active')

  const { data: shield } = useQuery({
    queryKey: ['shield'],
    queryFn: getShield,
    refetchInterval: 15_000,
  })

  const { data: actionsRaw } = useQuery({
    queryKey: ['autonomous-actions', actionStatus],
    queryFn: () => getAutonomousActions(actionStatus),
    refetchInterval: 30_000,
  })

  const dismissAllMutation = useMutation({
    mutationFn: dismissAllShield,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['shield'] }),
  })

  const clearDNSMutation = useMutation({
    mutationFn: clearDNSLogs,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['shield'] }),
  })

  const revertMutation = useMutation({
    mutationFn: (id: number) => revertAction(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['autonomous-actions'] }),
  })

  const s = shield as ShieldResponse | undefined
  const events = s?.events ?? []
  const blocks = s?.blocks ?? []
  const dnsEvents = s?.dns_events ?? []
  // API returns { entries: [...], count, status } not a flat array
  const actionsRawAny = actionsRaw as any
  const actions: any[] = Array.isArray(actionsRawAny) ? actionsRawAny : (actionsRawAny?.entries ?? [])

  return (
    <div className="space-y-4">
      {/* Threat level banner */}
      {s?.threat_level && s.threat_level !== 'secure' && (
        <div className={cn(
          'rounded-lg border p-3 flex items-center gap-2 text-sm',
          s.threat_level === 'critical' ? 'border-red-500/30 bg-red-500/5 text-red-300' : 'border-yellow-500/30 bg-yellow-500/5 text-yellow-300'
        )}>
          <ShieldAlert size={16} />
          Threat level: <strong className="capitalize">{s.threat_level}</strong>
        </div>
      )}

      {/* Threat events */}
      <Card
        title="Threat Events"
        badge={events.length > 0 ? `${events.length}` : undefined}
        action={
          events.length > 0 ? (
            <Btn variant="ghost" size="sm" loading={dismissAllMutation.isPending} onClick={() => dismissAllMutation.mutate()}>
              <ShieldCheck size={13} /> Dismiss All
            </Btn>
          ) : undefined
        }
      >
        {events.length === 0 ? (
          <EmptyState icon="◎" text="No active threats" hint="Shield is monitoring your network." />
        ) : (
          <div className="space-y-2">
            {events.map(e => (
              <div key={e.id} className="rounded-lg border border-white/10 bg-[#1a1a2e] p-3">
                <div className="flex items-start gap-2">
                  <ShieldAlert size={14} className="text-red-400 mt-0.5 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <Badge variant={severityVariant(e.level)}>{e.level}</Badge>
                      <span className="text-sm text-gray-200">{e.summary}</span>
                    </div>
                    <div className="flex gap-3 mt-1 text-[10px] text-gray-600">
                      {e.device_ip && <span className="font-mono">{e.device_ip}</span>}
                      <span>{e.category}</span>
                      <span>{formatRelativeTime(e.created_at)}</span>
                    </div>
                  </div>
                  <button
                    onClick={() => dismissShieldEvent(e.id).then(() => qc.invalidateQueries({ queryKey: ['shield'] }))}
                    className="text-xs text-gray-600 hover:text-gray-300 transition-colors flex-shrink-0"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Active firewall blocks */}
      <Card title="Active Firewall Blocks" badge={blocks.length ? String(blocks.length) : undefined}>
        {blocks.length === 0 ? (
          <EmptyState icon="◎" text="No active firewall blocks" />
        ) : (
          <div className="overflow-x-auto -mx-4 -mb-4">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-gray-600 border-b border-white/5">
                  <th className="px-4 py-2">Rule Name</th>
                  <th className="px-4 py-2">IP</th>
                  <th className="px-4 py-2">Direction</th>
                </tr>
              </thead>
              <tbody>
                {blocks.map((r, i) => (
                  <tr key={i} className="border-b border-white/5">
                    <td className="px-4 py-2 font-mono text-gray-300 text-[10px]">{r.name}</td>
                    <td className="px-4 py-2 font-mono text-red-400">{r.ip}</td>
                    <td className="px-4 py-2 text-gray-400">{r.direction ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Autonomous actions */}
      <Card
        title="Autonomous Actions"
        action={
          <div className="flex rounded-md overflow-hidden border border-white/10 text-xs">
            {(['active', 'reverted', 'all'] as ActionStatus[]).map(st => (
              <button key={st} onClick={() => setActionStatus(st)}
                className={cn('px-3 py-1 capitalize transition-colors',
                  actionStatus === st ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-200')}>
                {st}
              </button>
            ))}
          </div>
        }
      >
        {(actions as any[]).length === 0 ? (
          <EmptyState icon="◎" text="No autonomous actions" />
        ) : (
          <div className="space-y-2">
            {(actions as any[]).map(a => (
              <div key={a.id} className={cn(
                'rounded-lg border p-3 text-xs',
                a.reverted_at ? 'border-white/5 opacity-60' : 'border-orange-500/20 bg-orange-500/5'
              )}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-gray-200">{a.summary}</p>
                    <div className="flex gap-3 mt-1 text-[10px] text-gray-600">
                      <span>{a.actor}</span>
                      <span>{formatRelativeTime(a.created_at)}</span>
                      {a.reverted_at && <span className="text-emerald-600">reverted {formatRelativeTime(a.reverted_at)}</span>}
                    </div>
                  </div>
                  {!a.reverted_at && a.revert && (
                    <Btn variant="ghost" size="sm" onClick={() => revertMutation.mutate(a.id)}>
                      <RotateCcw size={12} /> Undo
                    </Btn>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* DNS blocks */}
      <Card
        title="DNS Blocked Events"
        badge={dnsEvents.length ? String(dnsEvents.length) : undefined}
        action={
          dnsEvents.length > 0 ? (
            <Btn variant="danger" size="sm" loading={clearDNSMutation.isPending} onClick={() => clearDNSMutation.mutate()}>
              <Trash2 size={12} /> Clear
            </Btn>
          ) : undefined
        }
      >
        {dnsEvents.length === 0 ? (
          <EmptyState icon="◎" text="No DNS blocks logged" />
        ) : (
          <div className="space-y-1">
            {dnsEvents.slice(0, 20).map((e, i) => (
              <div key={i} className="flex items-center justify-between py-1.5 border-b border-white/5 last:border-0 text-xs">
                <span className="font-mono text-red-400 truncate">{e.summary}</span>
                <span className="text-gray-600 flex-shrink-0 ml-2">{formatRelativeTime(e.created_at)}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
