import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { LayoutGrid, List, Cpu, ScanLine, ShieldCheck, MonitorSmartphone, CircleHelp, Network } from 'lucide-react'
import { getDevices, runScan, trustAllDevices, type Device } from '@/lib/api'
import { formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Badge from '@/components/shared/Badge'
import Btn from '@/components/shared/Btn'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile from '@/components/shared/StatTile'
import DeviceModal from '@/components/shared/DeviceModal'

type View = 'list' | 'grid'
type Filter = 'current' | 'all'

export default function Devices() {
  const qc = useQueryClient()
  const [view, setView] = useState<View>('list')
  const [filter, setFilter] = useState<Filter>('current')
  const [selectedDevice, setSelectedDevice] = useState<number | null>(null)
  const [search, setSearch] = useState('')

  const trustAllMutation = useMutation({
    mutationFn: trustAllDevices,
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      if (data.updated === 0) alert('All devices are already trusted.')
    },
  })

  const scanMutation = useMutation({
    mutationFn: (quick: boolean) => runScan(quick),
    onSuccess: (_data, quick) => {
      const delay = quick ? 500 : 3000
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ['devices'] })
        qc.invalidateQueries({ queryKey: ['status'] })
        qc.invalidateQueries({ queryKey: ['scans'] })
      }, delay)
    },
  })

  const { data: devices = [], isLoading } = useQuery({
    queryKey: ['devices', filter],
    queryFn: () => getDevices(filter === 'current'),
    refetchInterval: 30_000,
  })

  const filtered = (devices as Device[]).filter(d => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      d.ip.includes(q) ||
      (d.hostname ?? '').toLowerCase().includes(q) ||
      (d.label ?? '').toLowerCase().includes(q) ||
      (d.vendor ?? '').toLowerCase().includes(q) ||
      (d.mac ?? '').toLowerCase().includes(q)
    )
  })

  const trustedCount = (devices as Device[]).filter(d => d.trusted).length
  const total = (devices as Device[]).length
  const withPorts = (devices as Device[]).filter(d => d.open_ports?.length > 0).length

  return (
    <div className="space-y-4">
      <PageHero
        icon={MonitorSmartphone}
        accent="cyan"
        pulse={scanMutation.isPending}
        eyebrow={scanMutation.isPending ? 'Scanning…' : filter === 'current' ? 'Devices on network now' : 'All known devices'}
        title="Devices"
        subtitle="Everything discovered on your network — trust the ones you recognize, investigate the rest."
        tiles={
          <>
            <StatTile icon={<MonitorSmartphone size={11} />} label="Total" accent="cyan" glow value={total} sub={filter === 'current' ? 'online now' : 'ever seen'} />
            <StatTile icon={<ShieldCheck size={11} />} label="Trusted" accent="emerald" value={trustedCount} sub="recognized" />
            <StatTile icon={<CircleHelp size={11} />} label="Unknown" accent={total - trustedCount > 0 ? 'amber' : 'gray'} value={total - trustedCount} sub="unverified" />
            <StatTile icon={<Network size={11} />} label="Open Ports" accent="blue" value={withPorts} sub="devices w/ ports" />
          </>
        }
        actions={
          <>
            <Btn variant="secondary" size="sm" loading={trustAllMutation.isPending} onClick={() => trustAllMutation.mutate()} title="Mark all current devices as trusted">
              <ShieldCheck size={13} /> Trust All
            </Btn>
            <Btn variant="secondary" size="sm" loading={scanMutation.isPending && scanMutation.variables === true} onClick={() => scanMutation.mutate(true)} title="Quick ping sweep — finds devices in ~5s, no port scanning">
              <ScanLine size={13} /> Quick Scan
            </Btn>
            <Btn variant="primary" size="sm" loading={scanMutation.isPending && scanMutation.variables === false} onClick={() => scanMutation.mutate(false)} title="Full scan — discovers devices and open ports (~30s)">
              <ScanLine size={13} /> Full Scan
            </Btn>
          </>
        }
      />

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          placeholder="Search devices…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="flex-1 min-w-32 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
        />
        <FilterToggle value={filter} onChange={setFilter} />
        <ViewToggle value={view} onChange={setView} />
      </div>

      {scanMutation.isPending && (
        <div className="flex items-center gap-2 text-xs text-blue-400 animate-pulse">
          <ScanLine size={12} className="animate-spin" />
          {scanMutation.variables ? 'Quick scan running… (~3-8s)' : 'Full scan running… (~30s)'}
        </div>
      )}

      <Card
        title={filter === 'current' ? 'Current Devices' : 'All Devices'}
        badge={filtered.length ? String(filtered.length) : undefined}
      >
        {isLoading ? (
          <SkeletonRows />
        ) : filtered.length === 0 ? (
          <EmptyState icon="◉" text={search ? 'No matches' : 'No devices found'} hint="Run a scan to discover devices." />
        ) : view === 'list' ? (
          <ListView devices={filtered} onSelect={setSelectedDevice} />
        ) : (
          <GridView devices={filtered} onSelect={setSelectedDevice} />
        )}
      </Card>

      {selectedDevice !== null && (
        <DeviceModal deviceId={selectedDevice} onClose={() => setSelectedDevice(null)} />
      )}
    </div>
  )
}

function FilterToggle({ value, onChange }: { value: Filter; onChange: (v: Filter) => void }) {
  return (
    <div className="flex rounded-md overflow-hidden border border-white/10 text-xs">
      {(['current', 'all'] as Filter[]).map(v => (
        <button key={v} onClick={() => onChange(v)}
          className={cn('px-3 py-2 capitalize transition-colors', value === v ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-200')}>
          {v}
        </button>
      ))}
    </div>
  )
}

function ViewToggle({ value, onChange }: { value: View; onChange: (v: View) => void }) {
  return (
    <div className="flex rounded-md overflow-hidden border border-white/10">
      <button onClick={() => onChange('list')}
        className={cn('p-2 transition-colors', value === 'list' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-200')}>
        <List size={14} />
      </button>
      <button onClick={() => onChange('grid')}
        className={cn('p-2 transition-colors', value === 'grid' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-gray-200')}>
        <LayoutGrid size={14} />
      </button>
    </div>
  )
}

function ListView({ devices, onSelect }: { devices: Device[]; onSelect: (id: number) => void }) {
  return (
    <div className="overflow-x-auto -mx-4 -mb-4">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-left text-gray-600 border-b border-white/5">
            <th className="px-4 py-2 font-medium">IP</th>
            <th className="px-4 py-2 font-medium">Name / Label</th>
            <th className="hidden sm:table-cell px-4 py-2 font-medium">MAC</th>
            <th className="hidden md:table-cell px-4 py-2 font-medium">Vendor</th>
            <th className="hidden lg:table-cell px-4 py-2 font-medium">OS</th>
            <th className="px-4 py-2 font-medium">Ports</th>
            <th className="px-4 py-2 font-medium">Last Seen</th>
            <th className="px-4 py-2 font-medium">Trust</th>
          </tr>
        </thead>
        <tbody>
          {devices.map(d => (
            <tr key={d.id} onClick={() => onSelect(d.id)}
              className="border-b border-white/5 hover:bg-white/[0.03] cursor-pointer transition-colors">
              <td className="px-4 py-2.5 font-mono text-blue-400">{d.ip}</td>
              <td className="px-4 py-2.5 text-gray-200 max-w-[140px] truncate">
                {d.label ? <strong className="text-white">{d.label}</strong> : d.hostname ?? <span className="text-gray-600">—</span>}
              </td>
              <td className="hidden sm:table-cell px-4 py-2.5 font-mono text-gray-500 text-[10px]">{d.mac ?? '—'}</td>
              <td className="hidden md:table-cell px-4 py-2.5 text-gray-400">{d.vendor ?? '—'}</td>
              <td className="hidden lg:table-cell px-4 py-2.5 text-gray-500">{d.os_guess ?? '—'}</td>
              <td className="px-4 py-2.5">
                {d.open_ports?.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {d.open_ports.slice(0, 4).map(p => (
                      <span key={p} className="px-1 py-0.5 rounded bg-blue-500/10 text-blue-400 font-mono">{p}</span>
                    ))}
                    {d.open_ports.length > 4 && <span className="text-gray-600">+{d.open_ports.length - 4}</span>}
                  </div>
                ) : <span className="text-gray-600">—</span>}
              </td>
              <td className="px-4 py-2.5 text-gray-500">{formatRelativeTime(d.last_seen)}</td>
              <td className="px-4 py-2.5">
                <Badge variant={d.trusted ? 'ok' : 'warn'}>{d.trusted ? 'Trusted' : 'Unknown'}</Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function GridView({ devices, onSelect }: { devices: Device[]; onSelect: (id: number) => void }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3 -m-4 p-4">
      {devices.map(d => (
        <div key={d.id} onClick={() => onSelect(d.id)}
          className="rounded-xl border border-white/8 bg-[#1a1a2e] p-3 cursor-pointer hover:border-purple-500/40 hover:bg-purple-500/5 transition-all group">
          <div className="flex items-start justify-between mb-2">
            <Cpu size={20} className="text-gray-600 group-hover:text-purple-400 transition-colors" />
            <Badge variant={d.trusted ? 'ok' : 'warn'} className="text-[9px]">{d.trusted ? '✓' : '?'}</Badge>
          </div>
          <p className="text-xs font-mono text-blue-400 mb-0.5">{d.ip}</p>
          <p className="text-xs text-gray-200 truncate">
            {d.label || d.hostname || <span className="text-gray-600">Unknown</span>}
          </p>
          {d.vendor && <p className="text-[10px] text-gray-600 truncate mt-0.5">{d.vendor}</p>}
          {d.open_ports?.length > 0 && (
            <p className="text-[10px] text-gray-600 mt-1">{d.open_ports.length} port{d.open_ports.length !== 1 ? 's' : ''}</p>
          )}
        </div>
      ))}
    </div>
  )
}

function SkeletonRows() {
  return (
    <div className="space-y-2 py-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="flex gap-4 animate-pulse">
          <div className="h-4 bg-white/5 rounded w-28" />
          <div className="h-4 bg-white/5 rounded w-32" />
          <div className="h-4 bg-white/5 rounded w-20 hidden sm:block" />
          <div className="h-4 bg-white/5 rounded flex-1 hidden md:block" />
        </div>
      ))}
    </div>
  )
}
