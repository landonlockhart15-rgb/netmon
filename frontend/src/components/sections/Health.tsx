import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import ReactECharts from 'echarts-for-react'
import { RefreshCw, Zap, Wifi, WifiOff, Timer, Activity } from 'lucide-react'
import {
  getHealthCurrent, getHealthHistory, runHealthCheck,
  getSpeedLatest, getSpeedHistory, runSpeedTest,
  getTelemetry,
  type HealthStatus, type HealthPoint, type SpeedResult, type Telemetry,
} from '@/lib/api'
import { fmtTime, fmtDate, formatRelativeTime } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'

export default function Health() {
  const { data: health, refetch: refetchHealth } = useQuery({
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
  const hRaw = health as any
  const h = hRaw ? { ...hRaw, online: hRaw.status === 'online' } as HealthStatus : undefined
  const sl = speedLatest as SpeedResult | undefined
  const tel = telemetry as Telemetry | undefined

  return (
    <div className="space-y-4">
      {/* Big status cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <BigStat
          icon={h?.online ? <Wifi size={20} className="text-emerald-400" /> : <WifiOff size={20} className="text-red-400" />}
          label="Status"
          value={h ? (h.online ? 'Online' : 'Offline') : '—'}
          sub={h?.checked_at ? formatRelativeTime(h.checked_at) : ''}
          color={h?.online ? 'emerald' : 'red'}
        />
        <BigStat
          icon={<Timer size={20} className="text-blue-400" />}
          label="Latency"
          value={h?.latency_ms != null ? `${h.latency_ms}ms` : '—'}
          sub="internet RTT"
          color={h?.latency_ms != null ? (h.latency_ms < 50 ? 'emerald' : h.latency_ms < 150 ? 'yellow' : 'red') : 'gray'}
        />
        <BigStat
          icon={<Zap size={20} className="text-cyan-400" />}
          label="Download"
          value={sl ? `${sl.download_mbps} Mbps` : '—'}
          sub={sl ? formatRelativeTime(sl.tested_at) : 'no test yet'}
          color="cyan"
        />
        <BigStat
          icon={<Activity size={20} className="text-purple-400" />}
          label="Upload"
          value={sl ? `${sl.upload_mbps} Mbps` : '—'}
          sub="last speed test"
          color="purple"
        />
      </div>

      {/* Action buttons */}
      <div className="flex gap-2">
        <Btn variant="secondary" size="sm" loading={checkMutation.isPending} onClick={() => checkMutation.mutate()}>
          <RefreshCw size={13} /> Run Health Check
        </Btn>
        <Btn variant="secondary" size="sm" loading={speedMutation.isPending} onClick={() => speedMutation.mutate()}>
          <Zap size={13} />
          {speedMutation.isPending ? 'Testing… (~10s)' : 'Speed Test'}
        </Btn>
      </div>

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
              <TelBar label="CPU" value={(tel as any).cpu_pct ?? (tel as any).cpu_percent ?? 0} color="blue" />
              <TelBar label="RAM" value={(tel as any).mem_mb ?? (tel as any).ram_percent ?? 0} color="purple" label2={(tel as any).mem_mb != null ? 'MB' : '%'} />
              <div className="flex justify-between text-xs pt-1">
                <span className="text-gray-500">PID</span>
                <span className="text-gray-500 font-mono">{(tel as any).pid ?? '—'}</span>
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

function BigStat({ icon, label, value, sub, color }: {
  icon: React.ReactNode; label: string; value: string; sub: string; color: string
}) {
  const textColors: Record<string, string> = {
    emerald: 'text-emerald-400', red: 'text-red-400', blue: 'text-blue-400',
    yellow: 'text-yellow-400', cyan: 'text-cyan-400', purple: 'text-purple-400', gray: 'text-gray-400',
  }
  return (
    <div className="rounded-xl border border-white/8 bg-[#12121e] p-4 space-y-2">
      {icon}
      <div>
        <p className={`text-xl font-bold ${textColors[color] ?? 'text-gray-200'}`}>{value}</p>
        <p className="text-xs text-gray-500">{label}</p>
        <p className="text-[10px] text-gray-600">{sub}</p>
      </div>
    </div>
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

function fmtUptime(s: number): string {
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (h > 24) return `${Math.floor(h / 24)}d ${h % 24}h`
  return `${h}h ${m}m`
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
