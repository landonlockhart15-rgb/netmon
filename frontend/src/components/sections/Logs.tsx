import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, BrainCircuit, Filter } from 'lucide-react'
import { getLogs, getLogFacets, clearLogs, runHistorySynthesis } from '@/lib/api'
import { formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import EmptyState from '@/components/shared/EmptyState'

// API shape: { total, offset, limit, entries: LogEntry[] }
interface LogEntry {
  id: number
  created_at: string
  level: string
  category: string
  event: string
  summary: string
  detail: string | null
  device_ip: string | null
  actor: string
  reversible: boolean
  reverted_at: string | null
}

// Facets shape: { events: [{event, count}], actors: [{actor, count}], categories: [{category, count}] }
interface Facets {
  events?: { event: string; count: number }[]
  actors?: { actor: string; count: number }[]
  categories?: { category: string; count: number }[]
}

export default function Logs() {
  const qc = useQueryClient()
  const [eventFilter, setEventFilter] = useState('')
  const [actorFilter, setActorFilter] = useState('')
  const [search, setSearch] = useState('')
  const [showFilters, setShowFilters] = useState(false)
  const [synthResult, setSynthResult] = useState<string | null>(null)

  const params: Record<string, string> = { limit: '100' }
  if (eventFilter) params.event = eventFilter
  if (actorFilter) params.actor = actorFilter
  if (search) params.search = search

  const { data: logsData, isLoading } = useQuery({
    queryKey: ['logs', params],
    queryFn: () => getLogs(params),
    refetchInterval: 30_000,
  })

  const { data: facetsData } = useQuery({
    queryKey: ['log-facets'],
    queryFn: getLogFacets,
    staleTime: 60_000,
  })

  const clearMutation = useMutation({
    mutationFn: clearLogs,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['logs'] }),
  })

  const synthMutation = useMutation({
    mutationFn: () => runHistorySynthesis(7),
    onSuccess: (data: any) => setSynthResult(data?.summary ?? JSON.stringify(data)),
  })

  // API returns { total, entries: [] } — handle both shapes
  const raw = logsData as any
  const logs: LogEntry[] = Array.isArray(raw) ? raw : (raw?.entries ?? [])
  const total: number = raw?.total ?? logs.length

  const facets = facetsData as Facets | undefined

  return (
    <div className="space-y-4">
      {/* AI synthesis */}
      <Card
        title="AI History Synthesis"
        action={
          <Btn variant="ghost" size="sm" loading={synthMutation.isPending} onClick={() => synthMutation.mutate()}>
            <BrainCircuit size={13} /> Analyze Last 7 Days
          </Btn>
        }
      >
        {synthResult ? (
          <p className="text-xs text-gray-300 leading-relaxed">{synthResult}</p>
        ) : (
          <EmptyState icon="◎" text="Click Analyze to generate an AI summary of recent activity." />
        )}
      </Card>

      {/* Log list */}
      <Card
        title="Activity Logs"
        badge={total ? String(total) : undefined}
        action={
          <div className="flex items-center gap-2">
            <Btn variant="ghost" size="sm" onClick={() => setShowFilters(v => !v)}>
              <Filter size={13} /> Filter
            </Btn>
            <Btn variant="danger" size="sm" loading={clearMutation.isPending} onClick={() => clearMutation.mutate()}>
              <Trash2 size={12} /> Clear
            </Btn>
          </div>
        }
      >
        {showFilters && (
          <div className="flex flex-wrap gap-2 mb-4 pb-4 border-b border-white/5">
            <input
              placeholder="Search…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
            />
            <select
              value={eventFilter}
              onChange={e => setEventFilter(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:border-purple-500"
            >
              <option value="">All events</option>
              {facets?.events?.map(f => (
                <option key={f.event} value={f.event}>{f.event} ({f.count})</option>
              ))}
            </select>
            <select
              value={actorFilter}
              onChange={e => setActorFilter(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:border-purple-500"
            >
              <option value="">All actors</option>
              {facets?.actors?.map(a => (
                <option key={a.actor} value={a.actor}>{a.actor} ({a.count})</option>
              ))}
            </select>
          </div>
        )}

        {isLoading ? (
          <SkeletonRows />
        ) : logs.length === 0 ? (
          <EmptyState icon="◎" text="No logs found" />
        ) : (
          <div className="-mx-4 -mb-4">
            {logs.map(log => (
              <LogRow key={log.id} log={log} />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

function LogRow({ log }: { log: LogEntry }) {
  const actorColors: Record<string, string> = {
    system: 'text-blue-400',
    user: 'text-emerald-400',
    ai_auto: 'text-purple-400',
    anomaly_auto: 'text-orange-400',
    ntfy_command: 'text-yellow-400',
  }
  return (
    <div className="flex items-start gap-3 px-4 py-2.5 border-b border-white/5 hover:bg-white/[0.02] text-xs">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={cn('font-medium', actorColors[log.actor] ?? 'text-gray-400')}>{log.actor}</span>
          <span className="text-gray-500">{log.event}</span>
          {log.device_ip && <span className="font-mono text-blue-400">{log.device_ip}</span>}
        </div>
        <p className="text-gray-300 mt-0.5 truncate">{log.summary}</p>
      </div>
      <span className="text-gray-600 flex-shrink-0 mt-0.5">{formatRelativeTime(log.created_at)}</span>
    </div>
  )
}

function SkeletonRows() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="flex gap-3 py-2 animate-pulse">
          <div className="h-4 bg-white/5 rounded w-20" />
          <div className="h-4 bg-white/5 rounded flex-1" />
          <div className="h-4 bg-white/5 rounded w-16" />
        </div>
      ))}
    </div>
  )
}
