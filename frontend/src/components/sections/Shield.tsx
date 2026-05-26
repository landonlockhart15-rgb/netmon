import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield as ShieldIcon, ShieldCheck, ShieldAlert, Siren,
  Radar, Activity, Waves, Globe, Moon, Network, BrainCircuit, ScrollText, Bell,
  Trash2, RotateCcw, Lock, MonitorSmartphone, Clock, Ban,
} from 'lucide-react'
import {
  getShield, getAutonomousActions, dismissShieldEvent, dismissAllShield,
  clearDNSLogs, revertAction,
} from '@/lib/api'
import { formatRelativeTime, cn } from '@/lib/utils'
import Btn from '@/components/shared/Btn'
import Badge, { severityVariant } from '@/components/shared/Badge'
import StatTile, { ACCENT, type Accent } from '@/components/shared/StatTile'

type ActionStatus = 'active' | 'reverted' | 'all'
type Tab = 'threats' | 'blocks' | 'actions' | 'dns'

// API shape for /api/shield
interface ShieldEvent {
  id: number
  level: string
  summary: string
  detail: Record<string, unknown> | null
  device_ip: string | null
  created_at: string
  category: string
}
interface ProtectionLayer {
  id: string
  name: string
  description: string
  enabled: boolean
  setting_key: string | null
  last_event: string | null
  stat: string
}
interface FirewallBlock { name: string; ip: string; direction?: string; created_at?: string }
interface ShieldStats {
  devices: number; uptime_pct: number; blocks: number
  threats_24h: number; scans: number; dns_blocked_total: number
}
interface ShieldResponse {
  threat_level: string
  stats: ShieldStats
  layers: ProtectionLayer[]
  events: ShieldEvent[]
  dns_events: ShieldEvent[]
  blocks: FirewallBlock[]
}

// ── Threat-level theming ──────────────────────────────────────────────────────
const LEVEL: Record<string, {
  accent: Accent; Icon: typeof ShieldIcon; headline: string; sub: string
  border: string; text: string; sweep: string; chip: string
}> = {
  secure: {
    accent: 'emerald', Icon: ShieldCheck,
    headline: 'All Systems Protected', sub: 'No active threats — defenses are watching the network.',
    border: 'border-emerald-500/40', text: 'text-emerald-400',
    sweep: 'rgba(16,185,129,0.5)', chip: 'bg-emerald-500/10',
  },
  warning: {
    accent: 'amber', Icon: ShieldAlert,
    headline: 'Defenses Engaged', sub: 'Investigating anomalies — review the activity feed below.',
    border: 'border-amber-500/40', text: 'text-amber-400',
    sweep: 'rgba(245,158,11,0.5)', chip: 'bg-amber-500/10',
  },
  critical: {
    accent: 'red', Icon: Siren,
    headline: 'Active Threats Detected', sub: 'Immediate attention recommended.',
    border: 'border-red-500/50', text: 'text-red-400',
    sweep: 'rgba(239,68,68,0.55)', chip: 'bg-red-500/10',
  },
}

// ── Per-layer icon + accent ───────────────────────────────────────────────────
const LAYER_META: Record<string, { Icon: typeof ShieldIcon; accent: Accent }> = {
  auto_scan:     { Icon: Radar,        accent: 'cyan' },
  health:        { Icon: Activity,     accent: 'emerald' },
  anomaly:       { Icon: Waves,        accent: 'purple' },
  threat_intel:  { Icon: Globe,        accent: 'blue' },
  nighttime:     { Icon: Moon,         accent: 'indigo' },
  traffic:       { Icon: Network,      accent: 'cyan' },
  ai:            { Icon: BrainCircuit, accent: 'purple' },
  auto_report:   { Icon: ScrollText,   accent: 'blue' },
  notifications: { Icon: Bell,         accent: 'amber' },
}

export default function Shield() {
  const qc = useQueryClient()
  const [actionStatus, setActionStatus] = useState<ActionStatus>('active')
  const [tab, setTab] = useState<Tab>('threats')

  const { data: shield } = useQuery({
    queryKey: ['shield'], queryFn: getShield, refetchInterval: 15_000,
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
  const level = s?.threat_level ?? 'secure'
  const layers = s?.layers ?? []
  const events = s?.events ?? []
  const blocks = s?.blocks ?? []
  const dnsEvents = s?.dns_events ?? []
  const stats = s?.stats
  const actionsRawAny = actionsRaw as any
  const actions: any[] = Array.isArray(actionsRawAny) ? actionsRawAny : (actionsRawAny?.entries ?? [])

  const activeLayers = layers.filter(l => l.enabled).length

  const counts: Record<Tab, number> = {
    threats: events.length,
    blocks: blocks.length,
    actions: actions.length,
    dns: dnsEvents.length,
  }

  return (
    <div className="space-y-5">
      <CommandHero level={level} stats={stats} activeLayers={activeLayers} totalLayers={layers.length} />

      {/* ── Defense grid — the protection layers ───────────────────────────── */}
      <section>
        <SectionLabel icon={<Lock size={12} />} title="Active Defenses"
          right={<span className="text-[11px] text-gray-500">{activeLayers} of {layers.length} engaged</span>} />
        {layers.length === 0 ? (
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="h-28 rounded-xl border border-white/5 bg-[#12121e] animate-pulse" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-3">
            {layers.map(l => <DefenseCard key={l.id} layer={l} />)}
          </div>
        )}
      </section>

      {/* ── Activity feed — bounded so it never dominates ──────────────────── */}
      <section>
        <SectionLabel icon={<Activity size={12} />} title="Defensive Activity" />
        <div className="rounded-xl border border-white/8 bg-[#12121e] overflow-hidden">
          {/* Tabs */}
          <div className="flex items-center justify-between border-b border-white/5 px-2">
            <div className="flex">
              {(['threats', 'blocks', 'actions', 'dns'] as Tab[]).map(t => (
                <button key={t} onClick={() => setTab(t)}
                  className={cn(
                    'relative px-3 py-2.5 text-xs font-medium capitalize transition-colors',
                    tab === t ? 'text-white' : 'text-gray-500 hover:text-gray-300',
                  )}>
                  {t === 'dns' ? 'DNS' : t}
                  {counts[t] > 0 && (
                    <span className={cn('ml-1.5 rounded px-1 py-0.5 text-[9px] font-semibold',
                      t === 'threats' && counts[t] > 0 ? 'bg-red-500/15 text-red-400' : 'bg-white/8 text-gray-400')}>
                      {counts[t]}
                    </span>
                  )}
                  {tab === t && <span className="absolute inset-x-2 bottom-0 h-0.5 rounded-full bg-purple-500" />}
                </button>
              ))}
            </div>
            <div className="pr-1">
              {tab === 'threats' && events.length > 0 && (
                <Btn variant="ghost" size="sm" loading={dismissAllMutation.isPending} onClick={() => dismissAllMutation.mutate()}>
                  <ShieldCheck size={13} /> Dismiss All
                </Btn>
              )}
              {tab === 'dns' && dnsEvents.length > 0 && (
                <Btn variant="ghost" size="sm" loading={clearDNSMutation.isPending} onClick={() => clearDNSMutation.mutate()}>
                  <Trash2 size={12} /> Clear
                </Btn>
              )}
            </div>
          </div>

          {/* Tab body — bounded height keeps logs from taking over the page */}
          <div className="max-h-[26rem] overflow-y-auto p-3">
            {tab === 'threats' && (
              events.length === 0
                ? <FeedEmpty text="No active threats" hint="Confirmed threats and warnings show up here." />
                : <div className="space-y-2">{events.map(e => (
                    <ThreatRow key={e.id} e={e}
                      onDismiss={() => dismissShieldEvent(e.id).then(() => qc.invalidateQueries({ queryKey: ['shield'] }))} />
                  ))}</div>
            )}

            {tab === 'blocks' && (
              blocks.length === 0
                ? <FeedEmpty text="No active firewall blocks" hint="Auto-blocked threats and manual blocks appear here." />
                : <div className="space-y-1.5">{blocks.map((r, i) => (
                    <div key={i} className="flex items-center gap-3 rounded-lg border border-white/5 bg-[#0f0f1a] px-3 py-2 text-xs">
                      <Ban size={13} className="text-red-400 flex-shrink-0" />
                      <span className="font-mono text-red-400">{r.ip}</span>
                      <span className="text-gray-500 truncate flex-1">{r.name}</span>
                      <span className="text-gray-600 flex-shrink-0">{r.direction ?? '—'}</span>
                    </div>
                  ))}</div>
            )}

            {tab === 'actions' && (
              <div className="space-y-2">
                <div className="flex rounded-md overflow-hidden border border-white/10 text-xs w-fit">
                  {(['active', 'reverted', 'all'] as ActionStatus[]).map(st => (
                    <button key={st} onClick={() => setActionStatus(st)}
                      className={cn('px-3 py-1 capitalize transition-colors',
                        actionStatus === st ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-200')}>
                      {st}
                    </button>
                  ))}
                </div>
                {actions.length === 0
                  ? <FeedEmpty text="No autonomous actions" hint="Actions taken automatically by the shield are logged here." />
                  : actions.map(a => (
                    <div key={a.id} className={cn('rounded-lg border p-3 text-xs',
                      a.reverted_at ? 'border-white/5 opacity-60' : 'border-orange-500/20 bg-orange-500/5')}>
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

            {tab === 'dns' && (
              dnsEvents.length === 0
                ? <FeedEmpty text="No DNS blocks logged" hint="Blocked ad / tracker domains appear here." />
                : <div className="space-y-0.5">{dnsEvents.slice(0, 60).map((e, i) => (
                    <div key={i} className="flex items-center justify-between py-1.5 border-b border-white/5 last:border-0 text-xs">
                      <span className="font-mono text-red-400 truncate">{e.summary}</span>
                      <span className="text-gray-600 flex-shrink-0 ml-2">{formatRelativeTime(e.created_at)}</span>
                    </div>
                  ))}</div>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}

// ── Command hero ──────────────────────────────────────────────────────────────
function CommandHero({ level, stats, activeLayers, totalLayers }: {
  level: string; stats?: ShieldStats; activeLayers: number; totalLayers: number
}) {
  const t = LEVEL[level] ?? LEVEL.secure
  const a = ACCENT[t.accent]
  const Emblem = t.Icon
  return (
    <div className={cn('relative overflow-hidden rounded-2xl border bg-[#0d0d18]', t.border, a.glow)}>
      {/* animated backdrop */}
      <div className="absolute inset-0 nm-grid-bg opacity-60" />
      <div className="absolute inset-0 bg-gradient-to-br from-transparent via-transparent to-black/40" />

      <div className="relative flex flex-col lg:flex-row lg:items-center gap-6 p-5 md:p-6">
        {/* Emblem */}
        <div className="flex items-center gap-5">
          <div className="relative h-24 w-24 flex-shrink-0">
            <span className={cn('absolute inset-0 rounded-full border', t.border, 'nm-pulse-ring')} />
            <span className={cn('absolute inset-0 rounded-full border', t.border, 'nm-pulse-ring nm-pulse-ring-2')} />
            <span className="absolute inset-1 rounded-full nm-sweep"
              style={{ background: `conic-gradient(from 0deg, transparent 0deg, ${t.sweep} 60deg, transparent 120deg)` }} />
            <div className={cn('absolute inset-3 grid place-items-center rounded-full border bg-[#0a0a14]', t.border)}>
              <Emblem size={34} className={cn(t.text, 'nm-breathe')} />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className={cn('h-2 w-2 rounded-full nm-blip', a.dot, t.text)} />
              <span className={cn('text-[11px] font-semibold uppercase tracking-[0.2em]', t.text)}>
                {level === 'secure' ? 'Secure' : level === 'warning' ? 'Elevated' : 'Critical'}
              </span>
            </div>
            <h1 className="mt-1 text-2xl md:text-3xl font-bold text-white tracking-tight">{t.headline}</h1>
            <p className="mt-1 text-sm text-gray-400 max-w-md">{t.sub}</p>
          </div>
        </div>

        {/* Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 lg:ml-auto lg:max-w-xl w-full">
          <StatTile icon={<Lock size={11} />} label="Defenses" accent={t.accent} glow
            value={<span>{activeLayers}<span className="text-base text-gray-500">/{totalLayers}</span></span>}
            sub="engaged" />
          <StatTile icon={<Activity size={11} />} label="Uptime" accent="emerald"
            value={`${stats?.uptime_pct ?? 0}%`} sub="last 200 checks" />
          <StatTile icon={<Siren size={11} />} label="Threats 24h" accent={stats && stats.threats_24h > 0 ? 'red' : 'gray'}
            value={stats?.threats_24h ?? 0} sub="confirmed" />
          <StatTile icon={<Ban size={11} />} label="Firewall" accent={stats && stats.blocks > 0 ? 'amber' : 'gray'}
            value={stats?.blocks ?? 0} sub="active blocks" />
          <StatTile icon={<Globe size={11} />} label="DNS Blocked" accent="blue"
            value={(stats?.dns_blocked_total ?? 0).toLocaleString()} sub="domains" />
          <StatTile icon={<MonitorSmartphone size={11} />} label="Devices" accent="cyan"
            value={stats?.devices ?? 0} sub="on network" />
        </div>
      </div>
    </div>
  )
}

// ── Defense layer card ──────────────────────────────────────────────────────
function DefenseCard({ layer }: { layer: ProtectionLayer }) {
  const meta = LAYER_META[layer.id] ?? { Icon: ShieldIcon, accent: 'gray' as Accent }
  const a = ACCENT[meta.accent]
  const Icon = meta.Icon
  const on = layer.enabled
  return (
    <div title={layer.description}
      className={cn(
        'group relative overflow-hidden rounded-xl border p-3.5 transition-all duration-200',
        on ? cn('border-white/10 bg-[#13131f] ring-1 ring-inset hover:-translate-y-0.5 hover:bg-[#16162499]', a.ring)
           : 'border-white/5 bg-[#0e0e18] opacity-55',
      )}>
      {on && <span className={cn('nm-scanline', a.text)} />}
      <div className="relative flex items-start justify-between">
        <div className={cn('grid h-9 w-9 place-items-center rounded-lg', a.chipBg, on ? a.text : 'text-gray-600')}>
          <Icon size={18} />
        </div>
        <span className={cn('flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider',
          on ? cn(a.chipBg, a.text) : 'bg-white/5 text-gray-500')}>
          <span className={cn('h-1.5 w-1.5 rounded-full', on ? cn(a.dot, a.text, 'nm-blip') : 'bg-gray-600')} />
          {on ? 'Active' : 'Off'}
        </span>
      </div>
      <h3 className="relative mt-2.5 text-sm font-semibold text-white/90">{layer.name}</h3>
      <p className="relative mt-1 text-[11px] font-mono text-gray-500 leading-snug line-clamp-2 min-h-[2rem]">{layer.stat}</p>
      <div className="relative mt-1 flex items-center gap-1 text-[10px] text-gray-600">
        <Clock size={9} />
        {layer.last_event ? formatRelativeTime(layer.last_event) : 'no recent events'}
      </div>
    </div>
  )
}

// ── Small helpers ─────────────────────────────────────────────────────────────
function SectionLabel({ icon, title, right }: { icon: React.ReactNode; title: string; right?: React.ReactNode }) {
  return (
    <div className="mb-2.5 flex items-center justify-between">
      <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-400">
        <span className="text-gray-500">{icon}</span>{title}
      </div>
      {right}
    </div>
  )
}

function FeedEmpty({ text, hint }: { text: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-10 text-center">
      <ShieldCheck size={28} className="text-emerald-500/40 mb-2" />
      <p className="text-sm text-gray-400">{text}</p>
      {hint && <p className="mt-1 text-xs text-gray-600">{hint}</p>}
    </div>
  )
}

function ThreatRow({ e, onDismiss }: { e: ShieldEvent; onDismiss: () => void }) {
  return (
    <div className="rounded-lg border border-white/10 bg-[#0f0f1a] p-3">
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
        <button onClick={onDismiss}
          className="text-xs text-gray-600 hover:text-gray-300 transition-colors flex-shrink-0">
          Dismiss
        </button>
      </div>
    </div>
  )
}
