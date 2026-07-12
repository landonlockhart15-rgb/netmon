import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import ReactECharts from 'echarts-for-react'
import { RefreshCw, Zap, Wifi, WifiOff, Timer, Activity, Download, Upload, Gauge, Waves, ShieldAlert } from 'lucide-react'
import {
  getHealthCurrent, getHealthHistory, runHealthCheck,
  getSpeedLatest, getSpeedHistory, runSpeedTest,
  getTelemetry,
  getCaptivePortalStatus, analyzeCaptivePortal,
  type HealthStatus, type HealthPoint, type SpeedResult,
} from '@/lib/api'
import { fmtTime, fmtDate, formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import EmptyState from '@/components/shared/EmptyState'
import StatTile from '@/components/shared/StatTile'
import { ACCENT, type Accent } from '@/components/shared/statTileStyles'

export default function Health() {
  const { data: health } = useQuery({
    queryKey: ['health-current'],
    queryFn: getHealthCurrent,
    refetchInterval: 30_000,
  })

  const { data: history = [] } = useQuery({
    queryKey: ['health-history'],
    queryFn: () => getHealthHistory(120),
    refetchInterval: 60_000,
  })

  const { data: speedLatest } = useQuery({
    queryKey: ['speed-latest'],
    queryFn: getSpeedLatest,
    refetchInterval: 300_000,
  })

  const { data: speedHistory = [] } = useQuery({
    queryKey: ['speed-history'],
    queryFn: () => getSpeedHistory(30),
    refetchInterval: 300_000,
  })

  const { data: telemetry } = useQuery({
    queryKey: ['telemetry'],
    queryFn: getTelemetry,
    refetchInterval: 10_000,
  })

  const qc = useQueryClient()

  const checkMutation = useMutation({
    mutationFn: runHealthCheck,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['health-current'] })
      qc.invalidateQueries({ queryKey: ['health-history'] })
      qc.invalidateQueries({ queryKey: ['status'] })
    },
  })

  const speedMutation = useMutation({
    mutationFn: runSpeedTest,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['speed-latest'] })
      qc.invalidateQueries({ queryKey: ['speed-history'] })
    },
  })

  // API returns status: "online"|"offline"|"degraded" not boolean online
  const h = health
  const sl = speedLatest
  const tel = telemetry

  return (
    <div className="space-y-4">
      <HealthHero
        h={h}
        sl={sl}
        checking={checkMutation.isPending}
        speeding={speedMutation.isPending}
        onCheck={() => checkMutation.mutate()}
        onSpeed={() => speedMutation.mutate()}
      />

      <CaptivePortalCard />

      {/* Latency chart */}
      <Card title="Latency History" badge={`${(history as HealthPoint[]).length} POINTS`}>
        {(history as HealthPoint[]).length < 2 ? (
          <EmptyState icon="◎" text="Not enough data" hint="Health checks run every 5 minutes." />
        ) : (
          <ReactECharts
            style={{ height: 200 }}
            option={latencyChartOption(history as HealthPoint[])}
            opts={{ renderer: 'canvas' }}
          />
        )}
      </Card>

      {/* Speed chart */}
      <Card title="Speed History" badge={`${(speedHistory as SpeedResult[]).length} TESTS`}>
        {(speedHistory as SpeedResult[]).length < 1 ? (
          <EmptyState icon="◎" text="No speed tests yet" hint="Run a speed test to populate this chart." />
        ) : (
          <ReactECharts
            style={{ height: 200 }}
            option={speedChartOption(speedHistory as SpeedResult[])}
            opts={{ renderer: 'canvas' }}
          />
        )}
      </Card>

      {/* Packet loss + telemetry */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card title="Connection Details">
          <div className="space-y-3 text-sm">
            <Row label="Packet Loss" value={h?.packet_loss != null ? `${h.packet_loss}%` : '—'} />
            <Row label="Local Latency" value={h?.local_latency_ms != null ? `${h.local_latency_ms}ms` : '—'} />
            <Row label="Last Check" value={h?.checked_at ? formatRelativeTime(h.checked_at) : '—'} />
          </div>
        </Card>

        <Card title="System Telemetry">
          {tel ? (
            <div className="space-y-3">
              <TelBar label="CPU" value={tel.cpu_pct ?? tel.cpu_percent ?? 0} color="blue" />
              <TelBar label="RAM" value={tel.mem_mb ?? tel.ram_percent ?? 0} color="purple" label2={tel.mem_mb != null ? 'MB' : '%'} />
              <div className="flex justify-between text-xs pt-1">
                <span className="text-gray-500">PID</span>
                <span className="text-gray-500 font-mono">{tel.pid ?? '—'}</span>
              </div>
            </div>
          ) : (
            <EmptyState icon="◎" text="Loading telemetry…" />
          )}
        </Card>
      </div>
    </div>
  )
}

function HealthHero({ h, sl, checking, speeding, onCheck, onSpeed }: {
  h?: HealthStatus
  sl?: SpeedResult
  checking: boolean
  speeding: boolean
  onCheck: () => void
  onSpeed: () => void
}) {
  const status = h?.status
  const view = status === 'online'
    ? { accent: 'emerald' as Accent, label: 'Connection Online', Icon: Wifi, sweep: 'rgba(16,185,129,0.5)', border: 'border-emerald-500/40', sub: 'Internet reachable — latency and loss within normal range.' }
    : status === 'degraded'
    ? { accent: 'amber' as Accent, label: 'Connection Degraded', Icon: Waves, sweep: 'rgba(245,158,11,0.5)', border: 'border-amber-500/40', sub: 'High latency or packet loss detected.' }
    : status === 'offline'
    ? { accent: 'red' as Accent, label: 'Connection Offline', Icon: WifiOff, sweep: 'rgba(239,68,68,0.55)', border: 'border-red-500/50', sub: 'No internet connectivity on the last check.' }
    : { accent: 'gray' as Accent, label: 'Checking…', Icon: Wifi, sweep: 'rgba(148,163,184,0.4)', border: 'border-white/15', sub: 'Running connectivity check.' }
  const a = ACCENT[view.accent]
  const Emblem = view.Icon
  const lat = h?.latency_ms
  const latAccent: Accent = lat == null ? 'gray' : lat < 50 ? 'emerald' : lat < 150 ? 'amber' : 'red'

  return (
    <div className={cn('relative overflow-hidden rounded-2xl border bg-[#0d0d18]', view.border, a.glow)}>
      <div className="absolute inset-0 nm-grid-bg opacity-50" />
      <div className="absolute inset-0 bg-gradient-to-br from-transparent to-black/40" />
      <div className="relative flex flex-col lg:flex-row lg:items-center gap-5 p-5 md:p-6">
        <div className="flex items-center gap-5">
          <div className="relative h-20 w-20 flex-shrink-0">
            <span className={cn('absolute inset-0 rounded-full border nm-pulse-ring', view.border)} />
            <span className="absolute inset-1 rounded-full nm-sweep"
              style={{ background: `conic-gradient(from 0deg, transparent 0deg, ${view.sweep} 60deg, transparent 120deg)` }} />
            <div className={cn('absolute inset-3 grid place-items-center rounded-full border bg-[#0a0a14]', view.border)}>
              <Emblem size={28} className={cn(a.text, 'nm-breathe')} />
            </div>
          </div>
          <div>
            <div className={cn('flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.2em]', a.text)}>
              <span className={cn('h-2 w-2 rounded-full nm-blip', a.dot, a.text)} />
              {h?.checked_at ? formatRelativeTime(h.checked_at) : 'no check yet'}
            </div>
            <h1 className="mt-1 text-2xl md:text-3xl font-bold text-white tracking-tight">{view.label}</h1>
            <p className="mt-1 text-sm text-gray-400 max-w-md">{view.sub}</p>
          </div>
        </div>

        <div className="lg:ml-auto w-full lg:w-auto">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
            <StatTile icon={<Timer size={11} />} label="Latency" accent={latAccent} glow value={lat != null ? `${lat}ms` : '—'} sub="internet RTT" />
            <StatTile icon={<Gauge size={11} />} label="Packet Loss" accent={h?.packet_loss ? 'red' : 'emerald'} value={h?.packet_loss != null ? `${h.packet_loss}%` : '—'} sub="last check" />
            <StatTile icon={<Activity size={11} />} label="Local RTT" accent="blue" value={h?.local_latency_ms != null ? `${h.local_latency_ms}ms` : '—'} sub="to gateway" />
            <StatTile icon={<Download size={11} />} label="Download" accent="cyan" value={sl ? `${sl.download_mbps}` : '—'} sub="Mbps" />
            <StatTile icon={<Upload size={11} />} label="Upload" accent="purple" value={sl ? `${sl.upload_mbps}` : '—'} sub="Mbps" />
            <StatTile icon={<Zap size={11} />} label="Speed Test" accent="gray" value={sl ? formatRelativeTime(sl.tested_at) : '—'} sub="last run" />
          </div>
          <div className="mt-3 flex justify-end gap-2">
            <Btn variant="secondary" size="sm" loading={checking} onClick={onCheck}>
              <RefreshCw size={13} /> Health Check
            </Btn>
            <Btn variant="secondary" size="sm" loading={speeding} onClick={onSpeed}>
              <Zap size={13} />{speeding ? 'Testing… (~10s)' : 'Speed Test'}
            </Btn>
          </div>
        </div>
      </div>
    </div>
  )
}

function CaptivePortalCard() {
  const qc = useQueryClient()
  const { data: portal, isLoading } = useQuery({
    queryKey: ['captive-portal-status'],
    queryFn: getCaptivePortalStatus,
    refetchInterval: 60_000,
  })

  const analyzeMutation = useMutation({
    mutationFn: analyzeCaptivePortal,
    onSuccess: (data) => {
      qc.setQueryData(['captive-portal-status'], data)
    },
  })

  if (isLoading && !portal) {
    return (
      <Card title="Captive Portal">
        <div className="flex items-center gap-2 py-4 justify-center">
          <RefreshCw className="animate-spin text-purple-500" size={18} />
          <span className="text-sm text-gray-400">Loading captive portal status…</span>
        </div>
      </Card>
    )
  }

  const captive = portal?.captive ?? false
  const page = portal?.page ?? null
  const badge = captive ? 'DETECTED' : portal?.status === 'unknown' ? 'NOT CHECKED' : 'CLEAR'

  return (
    <Card title="Captive Portal" badge={badge}>
      <div className="space-y-3">
        <div className="flex items-start gap-2">
          {captive && <ShieldAlert size={16} className="text-amber-400 mt-0.5 flex-shrink-0" />}
          <p className="text-sm text-gray-400">
            {captive
              ? 'A login page is intercepting this connection. NetMon only detects and displays what it found — open the landing page below and log in yourself.'
              : portal?.status === 'unknown'
              ? 'No captive-portal check has run yet.'
              : 'No captive portal detected on the last check.'}
          </p>
        </div>

        {captive && portal?.final_url && (
          <div className="text-xs text-gray-500 break-all">
            Landing page:{' '}
            <a href={portal.final_url} target="_blank" rel="noreferrer" className="text-purple-400 hover:underline">
              {portal.final_url}
            </a>
          </div>
        )}

        {captive && page && (
          <div className="space-y-2">
            {page.title && <div className="text-sm text-gray-300 font-medium">{page.title}</div>}
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="text-gray-500">
                {page.form_count} form{page.form_count === 1 ? '' : 's'} detected
              </span>
              {page.requires_identity && <span className="text-amber-400">asks for identity</span>}
              {page.requires_password && <span className="text-amber-400">asks for password</span>}
              {page.requires_otp && <span className="text-amber-400">asks for a code</span>}
            </div>

            {page.fields.length > 0 && (
              <div className="rounded-lg border border-white/10 divide-y divide-white/5">
                {page.fields.map((f, i) => (
                  <div key={`${f.name || 'field'}-${i}`} className="flex items-center justify-between px-3 py-2 text-xs">
                    <span className="text-gray-300 font-mono">{f.name || '(unnamed field)'}</span>
                    <span className="text-gray-500">{f.kind || f.type}</span>
                  </div>
                ))}
              </div>
            )}

            <p className="text-[11px] text-gray-600">
              Read-only — NetMon never fills in or submits this form on your behalf.
            </p>
          </div>
        )}

        {portal?.error && <div className="text-xs text-red-400">{portal.error}</div>}

        <div className="flex justify-end">
          <Btn variant="secondary" size="sm" loading={analyzeMutation.isPending} onClick={() => analyzeMutation.mutate()}>
            <RefreshCw size={13} /> Analyze Now
          </Btn>
        </div>
      </div>
    </Card>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-gray-500 text-xs">{label}</span>
      <span className="text-gray-200 text-xs font-mono">{value}</span>
    </div>
  )
}

function TelBar({ label, value, color, label2 = '%' }: { label: string; value: number; color: string; label2?: string }) {
  const bg: Record<string, string> = { blue: 'bg-blue-500', purple: 'bg-purple-500', cyan: 'bg-cyan-500' }
  const v = value ?? 0
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className="text-gray-400">{label}</span>
        <span className="text-gray-300">{v.toFixed(1)}{label2}</span>
      </div>
      <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${bg[color]}`}
          style={{ width: `${Math.min(100, v)}%`, transition: 'width 0.5s ease' }}
        />
      </div>
    </div>
  )
}

function latencyChartOption(points: HealthPoint[]) {
  const xData = points.map(p => fmtTime(p.checked_at))
  const yData = points.map(p => p.latency_ms)
  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#1a1d27',
      borderColor: '#2a3a56',
      textStyle: { color: '#c8d6e8', fontSize: 12 },
    },
    grid: { top: 16, right: 16, bottom: 28, left: 48 },
    xAxis: {
      type: 'category', data: xData,
      axisLine: { lineStyle: { color: '#1e2a3e' } },
      axisLabel: { color: '#3a4a5e', fontSize: 10, interval: 'auto' },
      axisTick: { show: false },
    },
    yAxis: {
      type: 'value', name: 'ms',
      nameTextStyle: { color: '#3a4a5e', fontSize: 10 },
      axisLine: { show: false }, axisTick: { show: false },
      axisLabel: { color: '#3a4a5e', fontSize: 10 },
      splitLine: { lineStyle: { color: '#141c2a' } },
    },
    series: [{
      type: 'line', data: yData, smooth: true, connectNulls: false,
      lineStyle: { color: '#00c8f0', width: 2 },
      itemStyle: { color: '#00c8f0' },
      areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(0,200,240,0.3)' }, { offset: 1, color: 'rgba(0,200,240,0)' }] } },
      symbol: 'none',
    }],
  }
}

function speedChartOption(points: SpeedResult[]) {
  const xData = points.map(p => fmtDate(p.tested_at))
  const dlData = points.map(p => p.download_mbps)
  const ulData = points.map(p => p.upload_mbps)
  return {
    backgroundColor: 'transparent',
    legend: { data: ['Download', 'Upload'], textStyle: { color: '#647a94', fontSize: 11 }, top: 0, right: 0 },
    tooltip: { trigger: 'axis', backgroundColor: '#1a1d27', borderColor: '#2a3a56', textStyle: { color: '#c8d6e8', fontSize: 12 } },
    grid: { top: 28, right: 16, bottom: 36, left: 56 },
    xAxis: {
      type: 'category', data: xData,
      axisLine: { lineStyle: { color: '#1e2a3e' } },
      axisLabel: { color: '#3a4a5e', fontSize: 9, rotate: 30 },
      axisTick: { show: false },
    },
    yAxis: {
      type: 'value', name: 'Mbps',
      nameTextStyle: { color: '#3a4a5e', fontSize: 10 },
      axisLine: { show: false }, axisTick: { show: false },
      axisLabel: { color: '#3a4a5e', fontSize: 10 },
      splitLine: { lineStyle: { color: '#141c2a' } },
    },
    series: [
      { name: 'Download', type: 'bar', data: dlData, itemStyle: { color: '#00c8f0', borderRadius: [3, 3, 0, 0] } },
      { name: 'Upload', type: 'bar', data: ulData, itemStyle: { color: '#00e676', borderRadius: [3, 3, 0, 0] } },
    ],
  }
}
