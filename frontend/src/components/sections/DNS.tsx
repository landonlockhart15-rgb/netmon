import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Power, RefreshCw, BarChart2, Globe, Ban, Search, Database, Clock } from 'lucide-react'
import { getDNSStatus, enableDNS, disableDNS, refreshBlocklist, resetDNSStats } from '@/lib/api'
import { formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile from '@/components/shared/StatTile'

// API shape: { enabled, running, upstream, local_ip, stats: { blocked_today, total_domains, last_updated, queries_today, top_blocked } }
interface DNSResponse {
  enabled: boolean
  running: boolean
  upstream: string
  local_ip: string
  stats: {
    blocked_today: number
    total_domains: number
    last_updated: string | null
    queries_today: number
    top_blocked: { domain: string; count: number }[]
  }
}

export default function DNS() {
  const qc = useQueryClient()

  const { data } = useQuery({
    queryKey: ['dns-status'],
    queryFn: getDNSStatus,
    refetchInterval: 15_000,
  })

  const enableMutation = useMutation({
    mutationFn: enableDNS,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dns-status'] }),
  })

  const disableMutation = useMutation({
    mutationFn: disableDNS,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dns-status'] }),
  })

  const refreshMutation = useMutation({
    mutationFn: refreshBlocklist,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dns-status'] }),
  })

  const resetMutation = useMutation({
    mutationFn: resetDNSStats,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dns-status'] }),
  })

  const d = data as DNSResponse | undefined
  const stats = d?.stats

  const running = d?.running ?? false
  const accent = running ? 'emerald' : d?.enabled ? 'amber' : 'gray'

  return (
    <div className="space-y-4">
      <PageHero
        icon={Globe}
        accent={accent}
        pulse={running}
        eyebrow={running ? 'Filtering DNS' : d?.enabled ? 'Enabled · not running' : 'Disabled'}
        title="DNS Ad Blocker"
        subtitle="Network-wide ad and tracker blocking at the DNS layer — point your router here to cover every device."
        tiles={
          <>
            <StatTile icon={<Ban size={11} />} label="Blocked Today" accent="red" glow value={(stats?.blocked_today ?? 0).toLocaleString()} sub="requests" />
            <StatTile icon={<Search size={11} />} label="Queries Today" accent="blue" value={(stats?.queries_today ?? 0).toLocaleString()} sub="total lookups" />
            <StatTile icon={<Database size={11} />} label="Blocklist" accent="purple" value={(stats?.total_domains ?? 0).toLocaleString()} sub="domains" />
            <StatTile icon={<Clock size={11} />} label="Updated" accent="cyan" value={stats?.last_updated ? formatRelativeTime(stats.last_updated) : '—'} sub="blocklist" />
          </>
        }
        actions={
          d?.enabled ? (
            <Btn variant="danger" size="sm" loading={disableMutation.isPending} onClick={() => disableMutation.mutate()}>
              <Power size={13} /> Disable
            </Btn>
          ) : (
            <Btn variant="primary" size="sm" loading={enableMutation.isPending} onClick={() => enableMutation.mutate()}>
              <Power size={13} /> Enable
            </Btn>
          )
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={running ? 'ok' : d?.enabled ? 'warn' : 'muted'}>
            {running ? 'Running' : d?.enabled ? 'Enabled (stopped)' : 'Disabled'}
          </Badge>
          {d?.upstream && <span className="text-xs text-gray-500">→ {d.upstream}</span>}
          {d?.local_ip && (
            <span className="text-xs text-gray-600">Router DNS → <span className="font-mono text-gray-400">{d.local_ip}</span></span>
          )}
        </div>
      </PageHero>

      {/* Top blocked domains */}
      {stats?.top_blocked && stats.top_blocked.length > 0 && (
        <Card title="Top Blocked Domains">
          <div className="space-y-1">
            {stats.top_blocked.map((b, i) => (
              <div key={i} className="flex items-center justify-between text-xs py-1 border-b border-white/5 last:border-0">
                <span className="font-mono text-red-400 truncate">{b.domain}</span>
                <span className="text-gray-500 flex-shrink-0 ml-2">{b.count}×</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card title="Blocklist Management">
        <div className="flex flex-wrap gap-2">
          <Btn variant="secondary" size="sm" loading={refreshMutation.isPending} onClick={() => refreshMutation.mutate()}>
            <RefreshCw size={13} /> Refresh Blocklist
          </Btn>
          <Btn variant="ghost" size="sm" loading={resetMutation.isPending} onClick={() => resetMutation.mutate()}>
            <BarChart2 size={13} /> Reset Stats
          </Btn>
        </div>
        <p className="text-xs text-gray-600 mt-3">
          Blocklist sources: StevenBlack, OISD, AdGuard. Refresh pulls the latest lists from the internet.
        </p>
      </Card>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg bg-white/3 border border-white/5 p-3">
      <p className="text-lg font-bold text-white">{value}</p>
      <p className="text-xs text-gray-500 mt-0.5">{label}</p>
    </div>
  )
}
