import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ScanLine, Wifi, Network, History, BrainCircuit } from 'lucide-react'
import {
  getDevices, getScans, getDiffLatest, getAILatest, getAIProgress,
  getNetworkInfo, runScan, runAIScanAnalysis,
  type Device, type Scan, type DiffResult, type AISummary
} from '@/lib/api'
import { fmtDateTime, formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge, { severityVariant } from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'
import DeviceModal from '@/components/shared/DeviceModal'
import Markdown from '@/components/shared/Markdown'

export default function Overview() {
  const qc = useQueryClient()
  const [selectedDevice, setSelectedDevice] = useState<number | null>(null)
  const [filter, setFilter] = useState<'current' | 'all'>('current')

  const { data: devices = [], isLoading: devicesLoading } = useQuery({
    queryKey: ['devices', filter],
    queryFn: () => getDevices(filter === 'current'),
    refetchInterval: 30_000,
  })

  const { data: scans = [] } = useQuery({
    queryKey: ['scans'],
    queryFn: getScans,
    refetchInterval: 60_000,
  })

  const { data: diff } = useQuery({
    queryKey: ['diff'],
    queryFn: getDiffLatest,
    refetchInterval: 60_000,
  })

  const { data: aiSummary } = useQuery({
    queryKey: ['ai-latest'],
    queryFn: getAILatest,
    refetchInterval: 120_000,
  })

  const { data: aiProgress } = useQuery({
    queryKey: ['ai-progress'],
    queryFn: getAIProgress,
    refetchInterval: 700,
  })

  const { data: netinfo } = useQuery({
    queryKey: ['netinfo'],
    queryFn: getNetworkInfo,
    staleTime: 300_000,
  })

  const scanMutation = useMutation({
    mutationFn: () => runScan(false),
    onSuccess: () => {
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ['devices'] })
        qc.invalidateQueries({ queryKey: ['scans'] })
        qc.invalidateQueries({ queryKey: ['diff'] })
        qc.invalidateQueries({ queryKey: ['status'] })
      }, 3000)
    },
  })

  const aiMutation = useMutation({
    mutationFn: runAIScanAnalysis,
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['ai-latest'] }), 5000),
  })

  window._nm_scanning = scanMutation.isPending
  window._nm_ai_running = !!aiProgress?.running

  const latestScan = scans[0] as Scan | undefined

  return (
    <div className="space-y-4">
      {/* Scan control */}
      <Card
        title="Network Scan"
        action={
          <Btn
            variant="primary"
            size="sm"
            loading={scanMutation.isPending}
            onClick={() => scanMutation.mutate()}
          >
            <ScanLine size={14} />
            {scanMutation.isPending ? 'Scanning…' : 'Scan Now'}
          </Btn>
        }
      >
        {latestScan ? (
          <div className="grid grid-cols-3 gap-4">
            <Stat label="Hosts Found" value={(latestScan as any).host_count ?? (latestScan as any).device_count ?? '—'} />
            <Stat label="Last Scan" value={formatRelativeTime(latestScan.started_at)} />
            <Stat label="Duration" value={(latestScan as any).duration_s != null ? `${Number((latestScan as any).duration_s).toFixed(1)}s` : `#${latestScan.id}`} />
          </div>
        ) : (
          <EmptyState icon="◎" text="No scan data yet" hint="Press Scan Now to discover devices on your network" />
        )}
      </Card>

      {/* Devices */}
      <Card
        title="Devices"
        badge={devices.length ? String(devices.length) : undefined}
        action={<FilterToggle value={filter} onChange={setFilter} />}
      >
        {devicesLoading ? (
          <SkeletonRows />
        ) : devices.length === 0 ? (
          <EmptyState icon="◉" text="No devices found" hint="Run a scan to discover devices on your network" />
        ) : (
          <DeviceTable devices={devices} onSelect={setSelectedDevice} />
        )}
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card title="Recent Changes" action={<Wifi size={14} className="text-gray-600" />}>
          <DiffPanel diff={diff as DiffResult | undefined} />
        </Card>

        <Card
          title="AI Analysis"
          badge="OPTIONAL"
          action={
            <Btn
              variant="ghost"
              size="sm"
              loading={aiMutation.isPending || !!aiProgress?.running}
              onClick={() => aiMutation.mutate()}
            >
              <BrainCircuit size={13} />
              Analyze
            </Btn>
          }
        >
          <AIPanel summary={aiSummary as AISummary | undefined} progress={aiProgress} />
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card title="Network Info" action={<Network size={14} className="text-gray-600" />}>
          {netinfo ? (
            <div className="space-y-2 text-sm">
              <InfoRow label="Local IP" value={netinfo.local_ip} />
              <InfoRow label="Scan Target" value={netinfo.scan_target} />
              <InfoRow label="Gateway" value={netinfo.gateway} />
              {netinfo.interface && <InfoRow label="Interface" value={netinfo.interface} />}
            </div>
          ) : (
            <EmptyState icon="◎" text="Loading network info…" />
          )}
        </Card>

        <Card title="Scan History" action={<History size={14} className="text-gray-600" />}>
          {scans.length === 0 ? (
            <EmptyState icon="◎" text="No scans yet" />
          ) : (
            <div className="space-y-1">
              {(scans as Scan[]).slice(0, 6).map(s => (
                <div key={s.id} className="flex items-center justify-between text-xs py-1 border-b border-white/5 last:border-0">
                  <span className="text-gray-400">{fmtDateTime(s.started_at)}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-gray-300">{(s as any).host_count ?? (s as any).device_count ?? '—'} devices</span>
                    {(s as any).status && (s as any).status !== 'complete' && <Badge variant="warn">{(s as any).status}</Badge>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {selectedDevice !== null && (
        <DeviceModal deviceId={selectedDevice} onClose={() => setSelectedDevice(null)} />
      )}
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="text-center">
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="text-xs text-gray-500 mt-0.5">{label}</div>
    </div>
  )
}

function FilterToggle({ value, onChange }: { value: 'current' | 'all'; onChange: (v: 'current' | 'all') => void }) {
  return (
    <div className="flex rounded-md overflow-hidden border border-white/10 text-xs">
      {(['current', 'all'] as const).map(v => (
        <button
          key={v}
          onClick={() => onChange(v)}
          className={cn(
            'px-3 py-1 capitalize transition-colors',
            value === v ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-200'
          )}
        >
          {v}
        </button>
      ))}
    </div>
  )
}

function DeviceTable({ devices, onSelect }: { devices: Device[]; onSelect: (id: number) => void }) {
  return (
    <div className="overflow-x-auto -mx-4 -mb-4">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-left text-gray-600 border-b border-white/5">
            <th className="px-4 py-2 font-medium">IP</th>
            <th className="px-4 py-2 font-medium">Name</th>
            <th className="hidden md:table-cell px-4 py-2 font-medium">MAC</th>
            <th className="hidden lg:table-cell px-4 py-2 font-medium">Vendor</th>
            <th className="px-4 py-2 font-medium">Ports</th>
            <th className="px-4 py-2 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {devices.map(d => (
            <tr
              key={d.id}
              className="border-b border-white/5 hover:bg-white/[0.03] cursor-pointer transition-colors"
              onClick={() => onSelect(d.id)}
            >
              <td className="px-4 py-2 font-mono text-blue-400">{d.ip}</td>
              <td className="px-4 py-2 text-gray-200">
                {d.label
                  ? <strong>{d.label}</strong>
                  : d.hostname ?? <span className="text-gray-600">—</span>}
              </td>
              <td className="hidden md:table-cell px-4 py-2 font-mono text-gray-500">{d.mac ?? '—'}</td>
              <td className="hidden lg:table-cell px-4 py-2 text-gray-400">{d.vendor ?? '—'}</td>
              <td className="px-4 py-2">
                {d.open_ports?.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {d.open_ports.slice(0, 5).map(p => (
                      <span key={p} className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 font-mono">{p}</span>
                    ))}
                    {d.open_ports.length > 5 && <span className="text-gray-600">+{d.open_ports.length - 5}</span>}
                  </div>
                ) : <span className="text-gray-600">—</span>}
              </td>
              <td className="px-4 py-2">
                <Badge variant={d.trusted ? 'ok' : 'warn'}>
                  {d.trusted ? 'Trusted' : 'Unknown'}
                </Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const CHANGE_ICONS: Record<string, { icon: string; cls: string }> = {
  new_device:       { icon: '▲', cls: 'text-emerald-400' },
  device_missing:   { icon: '▼', cls: 'text-red-400' },
  ip_changed:       { icon: '⇄', cls: 'text-yellow-400' },
  hostname_changed: { icon: '⇄', cls: 'text-yellow-400' },
  ports_changed:    { icon: '◈', cls: 'text-blue-400' },
}

function DiffPanel({ diff }: { diff?: DiffResult }) {
  if (!diff) return <EmptyState icon="◎" text="Loading…" />
  // API returns { changes: [{change_type, message, created_at}] }
  const rawChanges: any[] = (diff as any).changes ?? []
  const allChanges = rawChanges.map(c => ({
    type: c.change_type ?? 'unknown',
    message: c.message ?? '',
    time: c.created_at ?? '',
  }))
  if (!allChanges.length) {
    return <EmptyState icon="◬" text="No changes" hint="Run a second scan to see what changed." />
  }
  return (
    <div className="space-y-1">
      {allChanges.map((c, i) => {
        const s = CHANGE_ICONS[c.type] ?? { icon: '·', cls: 'text-gray-400' }
        return (
          <div key={i} className="flex items-center gap-2 py-1.5 border-b border-white/5 last:border-0 text-xs">
            <span className={cn('flex-shrink-0', s.cls)}>{s.icon}</span>
            <span className="flex-1 text-gray-300 truncate">{c.message}</span>
            <span className="text-gray-600 flex-shrink-0">{formatRelativeTime(c.time)}</span>
          </div>
        )
      })}
    </div>
  )
}

function AIPanel({ summary, progress }: {
  summary?: AISummary
  progress?: { running?: boolean; partial?: string | null }
}) {
  if (progress?.running) {
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-purple-400 text-xs">
          <BrainCircuit size={12} className="animate-pulse" />
          AI analyzing…
        </div>
        {progress.partial && (
          <pre className="text-[10px] text-gray-500 whitespace-pre-wrap font-mono leading-relaxed max-h-24 overflow-y-auto">
            {progress.partial.slice(-600)}
          </pre>
        )}
      </div>
    )
  }
  if (!summary?.summary) {
    return <EmptyState icon="◎" text="No analysis yet" hint="Click Analyze to run AI investigation of your network." />
  }
  return (
    <div className="space-y-2">
      {summary.verdict && (
        <Badge variant={severityVariant(summary.verdict)}>{summary.verdict}</Badge>
      )}
      <Markdown text={summary.summary} />
      {summary.created_at && (
        <p className="text-[10px] text-gray-600">
          {summary.provider && <span className="mr-2 text-purple-500">{summary.provider}</span>}
          {formatRelativeTime(summary.created_at)}
        </p>
      )}
    </div>
  )
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-gray-500 text-xs">{label}</span>
      <span className="font-mono text-gray-200 text-xs">{value}</span>
    </div>
  )
}

function SkeletonRows() {
  return (
    <div className="space-y-2 py-2">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="flex gap-4 animate-pulse">
          <div className="h-4 bg-white/5 rounded w-28 flex-shrink-0" />
          <div className="h-4 bg-white/5 rounded w-32 flex-shrink-0" />
          <div className="h-4 bg-white/5 rounded flex-1" />
        </div>
      ))}
    </div>
  )
}
