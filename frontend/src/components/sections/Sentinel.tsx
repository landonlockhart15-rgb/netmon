import { useState, useMemo } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Power, ShieldCheck, ExternalLink, RefreshCw } from 'lucide-react'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile from '@/components/shared/StatTile'

const CP_PORT = 8091
const CP_TOKEN_KEY = 'netmon_cp_token'

function cpUrl() {
  const host = typeof window !== 'undefined' ? window.location.hostname : 'localhost'
  return `http://${host}:${CP_PORT}`
}

async function cpFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem(CP_TOKEN_KEY) ?? ''
  const res = await fetch(cpUrl() + path, {
    ...opts,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...opts.headers,
    },
  })
  if (!res.ok) throw new Error(`CP ${res.status}`)
  return res.json()
}

// Bounding box: 600 x 410, center (300, 205)
const cx = 300
const cy = 205
const R = 162
const shieldR = 36
const viewW = 600
const viewH = 410

type HealthState = 'healthy' | 'degraded' | 'down' | 'unknown'
interface SentinelService {
  id?: string
  name?: string
  health_state?: string
  tier?: string
  monitor_only?: boolean
  reason?: string
  probe?: { ok?: boolean; latency_ms?: number | null }
}
interface SentinelData {
  state?: { disabled?: boolean; services?: SentinelService[] }
  heartbeat?: { status?: string; heartbeat_at?: string }
}
interface ServiceCounts { healthy: number; degraded: number; down: number; unknown: number }

export default function Sentinel() {
  const [token, setToken] = useState(localStorage.getItem(CP_TOKEN_KEY) ?? '')
  const [editToken, setEditToken] = useState(false)

  const { data, error, isLoading, refetch, isFetching } = useQuery<SentinelData>({
    queryKey: ['sentinel-state', token],
    queryFn: () => cpFetch('/sentinel/state'),
    refetchInterval: 5000,
    retry: false,
    enabled: !!token,
  })

  const sentinelDisabled = data?.heartbeat?.status === 'disabled' || data?.state?.disabled === true

  const sentinelPowerMutation = useMutation({
    mutationFn: () => cpFetch(
      sentinelDisabled ? '/maintenance/sentinel/enable' : '/maintenance/sentinel/disable',
      {
        method: 'POST',
        body: sentinelDisabled ? undefined : JSON.stringify({ reason: 'disabled from NetMon Sentinel tab' }),
      }
    ),
    onSuccess: () => setTimeout(() => refetch(), 1200),
  })

  const bulkPowerMutation = useMutation({
    mutationFn: (action: 'pause' | 'resume') => cpFetch(
      action === 'pause' ? '/maintenance/pause-all' : '/maintenance/resume-all',
      {
        method: 'POST',
        body: action === 'pause' ? JSON.stringify({ reason: 'bulk action from NetMon Sentinel tab' }) : undefined,
      }
    ),
    onSuccess: () => setTimeout(() => refetch(), 1800),
  })

  const saveToken = () => {
    localStorage.setItem(CP_TOKEN_KEY, token)
    setEditToken(false)
    refetch()
  }

  const services = useMemo(() => data?.state?.services ?? [], [data?.state?.services])
  const heartbeat = data?.heartbeat ?? {}

  const counts = useMemo(() => {
    return services.reduce(
      (acc, s) => {
        const k: HealthState = s.health_state === 'healthy' || s.health_state === 'degraded' || s.health_state === 'down'
          ? s.health_state
          : 'unknown'
        acc[k] = (acc[k] || 0) + 1
        return acc
      },
      { healthy: 0, degraded: 0, down: 0, unknown: 0 } as ServiceCounts
    )
  }, [services])

  const protectedSvcs = useMemo(() => {
    return services.filter(s => String(s.id || s.name || '').toLowerCase() !== 'sentinel')
  }, [services])

  const N = protectedSvcs.length || 1

  const nodes = useMemo(() => {
    return protectedSvcs.map((s, i) => {
      const ang = -Math.PI / 2 + (i * (2 * Math.PI)) / N
      const ux = Math.cos(ang)
      const uy = Math.sin(ang)
      const st =
        s.health_state === 'healthy' || s.health_state === 'degraded' || s.health_state === 'down'
          ? s.health_state
          : 'unknown'
      const lat = s.probe && s.probe.ok && s.probe.latency_ms != null ? s.probe.latency_ms + 'ms' : ''
      const sub = [s.tier || '', lat].filter(Boolean).join(' · ')
      const monitor = s.monitor_only ? ' (monitor-only)' : ''
      return {
        id: s.id || s.name,
        name: s.name || s.id,
        state: st,
        sub,
        nodeX: cx + R * ux,
        nodeY: cy + R * uy,
        x2: cx + (R - 24) * ux,
        y2: cy + (R - 24) * uy,
        tooltip: `${s.name || s.id} — ${st}${monitor}\n${s.reason || ''}${lat ? '\nlatency ' + lat : ''}`,
      }
    })
  }, [protectedSvcs, N])

  const centerSub = `${counts.healthy || 0}/${services.length} ok`
  const shieldPath = `M ${cx - 34} ${cy - 32} L ${cx + 34} ${cy - 32} L ${cx + 34} ${cy + 4} Q ${cx + 34} ${cy + 34} ${cx} ${cy + 44} Q ${cx - 34} ${cy + 34} ${cx - 34} ${cy + 4} Z`

  const heartbeatTime = heartbeat.heartbeat_at
    ? new Date(heartbeat.heartbeat_at).toLocaleString()
    : 'unknown'

  const hasAuthError = error && String(error.message).includes('401')

  return (
    <div className="space-y-4">
      <PageHero
        icon={ShieldCheck}
        accent="indigo"
        eyebrow="Active Watchdog"
        title="Sentinel Watchdog"
        subtitle="Real-time watchtower protecting and verifying fleet services health."
        tiles={
          <>
            <StatTile label="Healthy" accent="emerald" glow value={counts.healthy} sub="online" />
            <StatTile label="Degraded" accent="amber" value={counts.degraded} sub="issues" />
            <StatTile label="Down" accent="red" value={counts.down} sub="offline" />
          </>
        }
      />

      {/* Token auth check card */}
      <Card
        title="AI-Hub Control Plane Configuration"
        action={
          <a
            href={cpUrl()}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 transition-colors"
          >
            <ExternalLink size={12} /> Open Control Plane
          </a>
        }
      >
        <div className="space-y-3">
          {editToken || !token ? (
            <div className="flex gap-2 max-w-md">
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="AI-Hub token"
                className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
              />
              <Btn variant="primary" size="sm" onClick={saveToken}>
                Save
              </Btn>
              {token && (
                <Btn variant="ghost" size="sm" onClick={() => setEditToken(false)}>
                  Cancel
                </Btn>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500">Token: ••••••</span>
                <Btn variant="ghost" size="sm" onClick={() => setEditToken(true)}>
                  Change
                </Btn>
              </div>
              <Btn variant="ghost" size="sm" onClick={() => refetch()} className="gap-1">
                <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} /> Refresh
              </Btn>
            </div>
          )}
          {token && (
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <Btn
                variant="primary"
                size="sm"
                loading={bulkPowerMutation.isPending}
                onClick={() => bulkPowerMutation.mutate('resume')}
              >
                <Power size={13} /> Resume All
              </Btn>
              <Btn
                variant="secondary"
                size="sm"
                loading={bulkPowerMutation.isPending}
                onClick={() => bulkPowerMutation.mutate('pause')}
              >
                <Power size={13} /> Pause All
              </Btn>
              <Btn
                variant={sentinelDisabled ? 'primary' : 'danger'}
                size="sm"
                loading={sentinelPowerMutation.isPending}
                onClick={() => sentinelPowerMutation.mutate()}
              >
                <Power size={13} /> {sentinelDisabled ? 'Enable Sentinel' : 'Disable Sentinel'}
              </Btn>
              <span className="text-xs text-gray-500">
                {sentinelDisabled ? 'Sentinel is intentionally paused.' : 'Pause Sentinel before planned downtime or internet disconnects.'}
              </span>
            </div>
          )}
          {(error || !token) && (
            <p className="text-xs text-red-400">
              {hasAuthError || !token
                ? 'Authentication required — set your AI-Hub token above.'
                : `Cannot reach AI-Hub at ${cpUrl()}. Is the control plane running?`}
            </p>
          )}
        </div>
      </Card>

      {/* Main Hero Graphic Card */}
      {token && !hasAuthError && (
        <Card
          title="Services Status"
          className="relative overflow-hidden"
        >
          {isLoading ? (
            <EmptyState
              icon="◎"
              text="Querying Sentinel..."
              hint="Establishing connection to the AI-Hub status watchtower."
            />
          ) : services.length === 0 ? (
            <EmptyState
              icon="◎"
              text="No services found"
              hint="Check control plane logs. Sentinel has no services registered."
            />
          ) : (
            <div className="flex flex-col items-center justify-center p-4 min-h-[500px]">
              {/* Heartbeat Status Bar */}
              <div className="w-full max-w-2xl px-4 py-2.5 rounded-lg border border-white/5 bg-white/[0.02] flex items-center justify-between text-xs text-gray-400 mb-6">
                <span className="font-mono">
                  Heartbeat: <span className="text-gray-200">{heartbeat.status || 'unknown'}</span> · {heartbeatTime}
                </span>
                <span className="flex items-center gap-4">
                  <span>healthy: <b className="text-emerald-400 font-mono">{counts.healthy}</b></span>
                  <span>degraded: <b className="text-amber-400 font-mono">{counts.degraded}</b></span>
                  <span>down: <b className="text-rose-400 font-mono">{counts.down}</b></span>
                </span>
              </div>

              {/* Radial SVG Container */}
              <div className="w-full max-w-[600px] aspect-[600/410] sentinel-wrap relative">
                <svg
                  viewBox={`0 0 ${viewW} ${viewH}`}
                  className="sentinel-graphic"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  {/* Spokes */}
                  {nodes.map(n => (
                    <line
                      key={n.id}
                      className={`sent-spoke ${n.state}`}
                      x1={cx}
                      y1={cy}
                      x2={n.x2}
                      y2={n.y2}
                    />
                  ))}

                  {/* Shield pulse */}
                  <circle
                    className="sent-shield-pulse animate-pulse"
                    cx={cx}
                    cy={cy}
                    r={shieldR}
                  />

                  {/* Shield Path */}
                  <path className="sent-shield-frame" d={shieldPath} />

                  {/* Central Text */}
                  <text className="sent-shield-label" x={cx} y={cy - 2}>
                    Sentinel
                  </text>
                  <text className="sent-node-sub font-mono" x={cx} y={cy + 13}>
                    {centerSub}
                  </text>

                  {/* Nodes */}
                  {nodes.map(n => (
                    <g key={n.id} className="sent-node-g group">
                      <title>{n.tooltip}</title>
                      <rect
                        className={`sent-node ${n.state}`}
                        x={n.nodeX - 52}
                        y={n.nodeY - 18}
                        width={104}
                        height={36}
                        rx={10}
                        ry={10}
                      />
                      <text className="sent-node-name" x={n.nodeX} y={n.nodeY - 1}>
                        {n.name}
                      </text>
                      <text className="sent-node-sub font-mono" x={n.nodeX} y={n.nodeY + 11}>
                        {n.sub}
                      </text>
                    </g>
                  ))}
                </svg>
              </div>

              {/* Custom Status Legend */}
              <div className="sent-legend mt-6">
                <span>
                  <i className="sent-dot healthy"></i> Healthy <b className="text-gray-200">{counts.healthy}</b>
                </span>
                <span>
                  <i className="sent-dot degraded"></i> Degraded <b className="text-gray-200">{counts.degraded}</b>
                </span>
                <span>
                  <i className="sent-dot down"></i> Down <b className="text-gray-200">{counts.down}</b>
                </span>
                {counts.unknown > 0 && (
                  <span>
                    <i className="sent-dot unknown"></i> Unknown <b className="text-gray-200">{counts.unknown}</b>
                  </span>
                )}
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
