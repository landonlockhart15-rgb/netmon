import { useQuery } from '@tanstack/react-query'
import { Wifi, WifiOff, Timer, MonitorSmartphone, ScanLine } from 'lucide-react'
import { getHealthCurrent, getStatus } from '@/lib/api'
import { formatRelativeTime } from '@/lib/utils'

export default function StatStrip() {
  const { data: health } = useQuery({
    queryKey: ['health-current'],
    queryFn: getHealthCurrent,
    refetchInterval: 30_000,
  })
  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: getStatus,
    refetchInterval: 15_000,
  })

  // health API: { status: "online"|"offline"|"degraded", latency_ms, ... }
  const healthStatus = (health as any)?.status
  const online = healthStatus === 'online' ? true : healthStatus === 'offline' ? false : null
  const latency = (health as any)?.latency_ms
  // status API: { scan: { running, host_count, started_at, ... }, ai, capture }
  const scanState = (status as any)?.scan
  const deviceCount: number | null = scanState?.host_count ?? null
  const lastScan: string | null = scanState?.started_at ?? null
  const scanning: boolean = scanState?.running ?? false

  return (
    <div className="flex items-center gap-1 px-4 py-2 border-b border-white/5 bg-[#0d0d1a] overflow-x-auto flex-shrink-0">
      {/* Network status */}
      <StatCard>
        {online === null ? (
          <span className="text-gray-500">Checking…</span>
        ) : online ? (
          <span className="flex items-center gap-1.5 text-emerald-400">
            <Wifi size={12} />
            <span>Online</span>
          </span>
        ) : (
          <span className="flex items-center gap-1.5 text-red-400">
            <WifiOff size={12} />
            <span>Offline</span>
          </span>
        )}
      </StatCard>

      <Divider />

      {/* Latency */}
      <StatCard label="Latency">
        <span className={latency == null ? 'text-gray-500' : latency < 50 ? 'text-emerald-400' : latency < 150 ? 'text-yellow-400' : 'text-red-400'}>
          {latency != null ? `${latency}ms` : '—'}
        </span>
      </StatCard>

      <Divider />

      {/* Device count */}
      <StatCard label="Devices">
        <span className="flex items-center gap-1 text-gray-200">
          <MonitorSmartphone size={12} />
          {deviceCount ?? '—'}
        </span>
      </StatCard>

      <Divider />

      {/* Last scan */}
      <StatCard label={scanning ? 'Scanning…' : 'Last Scan'}>
        <span className={scanning ? 'text-blue-400 flex items-center gap-1' : 'text-gray-400'}>
          {scanning && <ScanLine size={12} className="animate-spin" />}
          {scanning ? 'Running' : lastScan ? formatRelativeTime(lastScan) : '—'}
        </span>
      </StatCard>

      {/* Timer */}
      {latency != null && (
        <>
          <Divider />
          <StatCard label="RTT">
            <span className="flex items-center gap-1 text-gray-400">
              <Timer size={12} />
              {(health as any)?.local_latency_ms != null ? `${(health as any).local_latency_ms}ms local` : '—'}
            </span>
          </StatCard>
        </>
      )}
    </div>
  )
}

function StatCard({ label, children }: { label?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 px-2 py-0.5 text-xs whitespace-nowrap flex-shrink-0">
      {label && <span className="text-gray-600">{label}</span>}
      {children}
    </div>
  )
}

function Divider() {
  return <span className="text-gray-800 flex-shrink-0">·</span>
}
