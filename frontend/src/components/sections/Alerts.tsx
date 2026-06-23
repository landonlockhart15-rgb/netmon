import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { CheckCheck, Bell, BellRing, Inbox, Search, Trash2, MonitorSmartphone, Eraser, BrainCircuit, Loader2 } from 'lucide-react'
import { getAlerts, readAlert, readAllAlerts, deleteAlert, clearReadAlerts, explainAlert, getContextualInsight } from '@/lib/api'
import { formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge, { type Variant } from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile from '@/components/shared/StatTile'
import DeviceModal from '@/components/shared/DeviceModal'
import Markdown from '@/components/shared/Markdown'

// API shape: { unread_count: number, alerts: RawAlert[] }
interface RawAlert {
  id: number
  created_at: string
  alert_type: string
  message: string
  read: boolean
  device_id: number | null
}

const PAGE_SIZE = 25

// alert_type → badge color + friendly label
const TYPE_VARIANT: Record<string, Variant> = {
  threat: 'error',
  anomaly: 'warn',
  new_device: 'info',
  manual: 'purple',
}
function typeVariant(t: string): Variant {
  return TYPE_VARIANT[t] ?? 'muted'
}
function typeLabel(t: string): string {
  return t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

export default function Alerts() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all') // 'all' | 'unread' | <alert_type>
  const [visible, setVisible] = useState(PAGE_SIZE)
  const [selectedDevice, setSelectedDevice] = useState<number | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: getAlerts,
    refetchInterval: 30_000,
  })

  const invalidate = () => qc.invalidateQueries({ queryKey: ['alerts'] })
  const readMutation = useMutation({ mutationFn: (id: number) => readAlert(id), onSuccess: invalidate })
  const readAllMutation = useMutation({ mutationFn: readAllAlerts, onSuccess: invalidate })
  const deleteMutation = useMutation({ mutationFn: (id: number) => deleteAlert(id), onSuccess: invalidate })
  const clearReadMutation = useMutation({ mutationFn: clearReadAlerts, onSuccess: invalidate })

  // API returns { unread_count, alerts: [] } — tolerate a bare array too
  const raw = data as any
  const list: RawAlert[] = Array.isArray(raw) ? raw : (raw?.alerts ?? [])
  const unread = raw?.unread_count ?? list.filter(a => !a.read).length
  const readCount = list.length - (raw?.unread_count ?? list.filter(a => !a.read).length)

  // Counts per filter chip, computed once over the full list
  const typeCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const a of list) m[a.alert_type] = (m[a.alert_type] ?? 0) + 1
    return m
  }, [list])
  const types = useMemo(() => Object.keys(typeCounts).sort(), [typeCounts])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return list.filter(a => {
      if (typeFilter === 'unread' && a.read) return false
      if (typeFilter !== 'all' && typeFilter !== 'unread' && a.alert_type !== typeFilter) return false
      if (q && !a.message.toLowerCase().includes(q) && !a.alert_type.toLowerCase().includes(q)) return false
      return true
    })
  }, [list, search, typeFilter])

  const shown = filtered.slice(0, visible)

  function pick(next: string) {
    setTypeFilter(next)
    setVisible(PAGE_SIZE)
  }

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
        actions={
          <>
            {unread > 0 && (
              <Btn variant="secondary" size="sm" loading={readAllMutation.isPending} onClick={() => readAllMutation.mutate()}>
                <CheckCheck size={13} /> Mark All Read
              </Btn>
            )}
            {readCount > 0 && (
              <Btn variant="ghost" size="sm" loading={clearReadMutation.isPending}
                onClick={() => { if (confirm(`Delete ${readCount} read alert${readCount !== 1 ? 's' : ''}? This can't be undone.`)) clearReadMutation.mutate() }}>
                <Eraser size={13} /> Clear Read
              </Btn>
            )}
          </>
        }
      />

      {/* Controls */}
      <div className="space-y-3">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" />
          <input
            type="text"
            placeholder="Search alerts…"
            value={search}
            onChange={e => { setSearch(e.target.value); setVisible(PAGE_SIZE) }}
            className="w-full bg-white/5 border border-white/10 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Chip label="All" count={list.length} active={typeFilter === 'all'} onClick={() => pick('all')} />
          <Chip label="Unread" count={unread} active={typeFilter === 'unread'} onClick={() => pick('unread')} accent />
          {types.map(t => (
            <Chip key={t} label={typeLabel(t)} count={typeCounts[t]} active={typeFilter === t} onClick={() => pick(t)} />
          ))}
        </div>
      </div>

      <Card
        title="Alerts"
        badge={filtered.length ? String(filtered.length) : undefined}
      >
        {isLoading ? (
          <SkeletonRows />
        ) : list.length === 0 ? (
          <EmptyState icon="◎" text="No alerts" hint="Alerts appear here when anomalies or threats are detected." />
        ) : filtered.length === 0 ? (
          <EmptyState icon="○" text="No matches" hint="Try a different search or filter." />
        ) : (
          <div className="space-y-2">
            {shown.map(a => (
              <AlertRow
                key={a.id}
                alert={a}
                onRead={() => readMutation.mutate(a.id)}
                onDelete={() => deleteMutation.mutate(a.id)}
                onView={a.device_id ? () => setSelectedDevice(a.device_id!) : undefined}
              />
            ))}
            {filtered.length > shown.length && (
              <button
                onClick={() => setVisible(v => v + PAGE_SIZE)}
                className="w-full py-2 text-xs text-gray-500 hover:text-gray-300 border border-white/5 hover:border-white/10 rounded-lg transition-colors"
              >
                Show {Math.min(PAGE_SIZE, filtered.length - shown.length)} more · {filtered.length - shown.length} hidden
              </button>
            )}
          </div>
        )}
      </Card>

      {selectedDevice !== null && (
        <DeviceModal deviceId={selectedDevice} onClose={() => setSelectedDevice(null)} />
      )}
    </div>
  )
}

function Chip({ label, count, active, onClick, accent }: {
  label: string; count: number; active: boolean; onClick: () => void; accent?: boolean
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'px-2.5 py-1 rounded-full text-xs font-medium border transition-colors flex items-center gap-1.5',
        active
          ? 'bg-purple-600 border-purple-500 text-white'
          : accent && count > 0
            ? 'border-amber-500/30 text-amber-400 hover:bg-amber-500/10'
            : 'border-white/10 text-gray-400 hover:text-gray-200 hover:border-white/20'
      )}
    >
      {label}
      <span className={cn('text-[10px] tabular-nums', active ? 'text-white/70' : 'text-gray-600')}>{count}</span>
    </button>
  )
}

function AlertRow({ alert: a, onRead, onDelete, onView }: {
  alert: RawAlert; onRead: () => void; onDelete: () => void; onView?: () => void
}) {
  const [explanation, setExplanation] = useState<string | null>(null)
  const [explaining, setExplaining] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [insight, setInsight] = useState<string | null>(null)
  const [insightLoading, setInsightLoading] = useState(false)
  const [insightError, setInsightError] = useState<string | null>(null)

  const handleExplain = async () => {
    if (explanation) {
      setExplanation(null)
      return
    }
    setExplaining(true)
    setError(null)
    try {
      const res = await explainAlert(a.id)
      setExplanation(res.explanation)
    } catch (e: any) {
      setError(e.message || 'Failed to generate explanation')
    } finally {
      setExplaining(false)
    }
  }

  const handleInsight = async () => {
    if (insight) {
      setInsight(null)
      return
    }
    setInsightLoading(true)
    setInsightError(null)
    try {
      const res = await getContextualInsight(a.message, `type: ${a.alert_type}, device_id: ${a.device_id || 'none'}`)
      setInsight(res.explanation)
    } catch (e: any) {
      setInsightError(e.message || 'Failed to generate insight')
    } finally {
      setInsightLoading(false)
    }
  }

  return (
    <div className={cn(
      'rounded-lg border p-3 transition-all',
      a.read ? 'border-white/5 bg-white/[0.02] opacity-70' : 'border-white/10 bg-[#1a1a2e]'
    )}>
      <div className="flex items-start gap-3">
        <Bell size={14} className={cn('mt-0.5 flex-shrink-0', a.read ? 'text-gray-600' : 'text-yellow-400')} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <Badge variant={typeVariant(a.alert_type)}>{typeLabel(a.alert_type)}</Badge>
            <span className="text-sm text-gray-200 font-medium">{a.message}</span>
          </div>
          <div className="flex items-center gap-3 mt-1 text-[10px] text-gray-600">
            {a.device_id && <span className="font-mono">device #{a.device_id}</span>}
            <span>{formatRelativeTime(a.created_at)}</span>
          </div>
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          <button
            onClick={handleInsight}
            title="Contextual Insight"
            disabled={insightLoading}
            className={cn(
              'p-1.5 rounded transition-colors',
              insight
                ? 'text-purple-400 bg-purple-500/10 hover:text-purple-300'
                : 'text-gray-500 hover:text-purple-400 hover:bg-white/5'
            )}
          >
            {insightLoading ? <Loader2 size={14} className="animate-spin" /> : <BrainCircuit size={14} />}
          </button>
          <button
            onClick={handleExplain}
            title="Explain with AI (Detail)"
            disabled={explaining}
            className={cn(
              'p-1.5 rounded transition-colors',
              explanation
                ? 'text-purple-400 bg-purple-500/10 hover:text-purple-300'
                : 'text-gray-500 hover:text-purple-400 hover:bg-white/5'
            )}
          >
            {explaining ? <Loader2 size={14} className="animate-spin" /> : <BrainCircuit size={14} className="opacity-60" />}
          </button>
          {onView && (
            <button onClick={onView} title="View device"
              className="p-1.5 rounded text-gray-500 hover:text-cyan-400 hover:bg-white/5 transition-colors">
              <MonitorSmartphone size={14} />
            </button>
          )}
          {!a.read && (
            <button onClick={onRead} title="Mark read"
              className="p-1.5 rounded text-gray-500 hover:text-emerald-400 hover:bg-white/5 transition-colors">
              <CheckCheck size={14} />
            </button>
          )}
          <button onClick={onDelete} title="Delete"
            className="p-1.5 rounded text-gray-500 hover:text-red-400 hover:bg-white/5 transition-colors">
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {(explaining || explanation || error || insightLoading || insight || insightError) && (
        <div className="mt-3 pt-3 border-t border-white/5 text-xs space-y-2">
          {explaining && (
            <div className="flex items-center gap-2 text-purple-400 animate-pulse font-medium py-1">
              <BrainCircuit size={12} className="animate-pulse" />
              <span>AI is generating detailed explanation…</span>
            </div>
          )}
          {insightLoading && (
            <div className="flex items-center gap-2 text-purple-400 animate-pulse font-medium py-1">
              <BrainCircuit size={12} className="animate-pulse" />
              <span>AI is generating contextual insight…</span>
            </div>
          )}
          {error && (
            <div className="text-red-400 font-medium py-1">
              Error: {error}
            </div>
          )}
          {insightError && (
            <div className="text-red-400 font-medium py-1">
              Error: {insightError}
            </div>
          )}
          {insight && (
            <div className="prose prose-invert max-w-none font-normal leading-relaxed text-gray-300 bg-purple-950/10 rounded-lg p-3 border border-purple-500/10 shadow-inner">
              <Markdown text={insight} />
            </div>
          )}
          {explanation && (
            <div className="prose prose-invert max-w-none font-normal leading-relaxed text-gray-300 bg-purple-950/10 rounded-lg p-3 border border-purple-500/10 shadow-inner">
              <Markdown text={explanation} />
            </div>
          )}
        </div>
      )}
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
