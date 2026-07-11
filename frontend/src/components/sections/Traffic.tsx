import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Play, Square, BrainCircuit, ShieldAlert, ShieldOff, ChevronDown, ChevronUp, Eye, Lock, Unlock, Globe, Radio, Gauge, MonitorSmartphone, Layers, AlertTriangle, CheckCircle2, ArrowRight } from 'lucide-react'
import {
  getTrafficInterfaces, getTrafficStatus, getTrafficDashboard,
  startCapture, stopCapture, analyzeTraffic,
  getMitmStatus, startMitm, stopMitm,
  getDNSLive, getDevices,
  getAILatest, getAIProgress,
  type Interface, type AISummary, type Device,
} from '@/lib/api'
import { humanBytes, formatRelativeTime } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge from '@/components/shared/Badge'
import { severityVariant } from '@/components/shared/badgeVariants'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile from '@/components/shared/StatTile'
import Markdown from '@/components/shared/Markdown'

interface TrafficStatusResponse { running: boolean; interface: string | null; started_at: string | null }
interface TrafficDashboardResponse {
  capture: { running: boolean; interface: string | null; started_at: string | null }
  stats: { pps: number; bps: number; devices: number; top_protocol: string }
  conversations: { src: string; dst: string; bytes: number; packets: number; country: string | null }[]
  incidents: { id: number; created_at: string; anomaly_type: string; device_ip: string | null }[]
}
interface MitmStatusResponse {
  active?: boolean
  running?: boolean
  interface?: string | null
  targets?: string[]
  error?: string | null
  active_count?: number
  target_count?: number
}
type InterfacePayload = Interface[] | { interfaces?: Interface[] }
type PerDeviceDns = Record<string, { domain: string; count: number }[]>

function isPerDeviceDns(value: unknown): value is PerDeviceDns {
  if (!value || typeof value !== 'object' || Array.isArray(value) || 'queries' in value || 'error' in value) return false
  return Object.values(value).every(entries => Array.isArray(entries))
}

export default function Traffic() {
  const qc = useQueryClient()
  const [selectedIface, setSelectedIface] = useState('')
  const [mitmIface, setMitmIface] = useState('')
  const [mitmMode, setMitmMode] = useState<'all' | 'select'>('all')
  const [mitmTargets, setMitmTargets] = useState<string[]>([])
  const [mitmExpanded, setMitmExpanded] = useState(false)

  const { data: ifacesRaw } = useQuery({ queryKey: ['traffic-interfaces'], queryFn: getTrafficInterfaces, staleTime: 60_000 })
  const { data: status } = useQuery({ queryKey: ['traffic-status'], queryFn: getTrafficStatus, refetchInterval: 5_000 })
  const { data: dashboard } = useQuery({ queryKey: ['traffic-dashboard'], queryFn: getTrafficDashboard, refetchInterval: 10_000 })
  const { data: mitmStatusRaw } = useQuery({ queryKey: ['mitm-status'], queryFn: getMitmStatus, refetchInterval: 5_000 })
  const { data: devicesRaw } = useQuery({ queryKey: ['devices', 'current'], queryFn: () => getDevices(true), staleTime: 60_000 })
  const { data: aiSummary } = useQuery({ queryKey: ['ai-latest'], queryFn: getAILatest, refetchInterval: 120_000 })
  const { data: aiProgress } = useQuery({ queryKey: ['ai-progress'], queryFn: getAIProgress, refetchInterval: 700 })

  const startMutation = useMutation({
    mutationFn: () => startCapture({ interface: selectedIface || undefined }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['traffic-status'] }),
  })
  const stopMutation = useMutation({
    mutationFn: stopCapture,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['traffic-status'] }),
  })
  const analyzeMutation = useMutation({
    mutationFn: analyzeTraffic,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['traffic-dashboard'] })
      qc.invalidateQueries({ queryKey: ['traffic-status'] })
      setTimeout(() => qc.invalidateQueries({ queryKey: ['ai-latest'] }), 5000)
    },
  })
  const startMitmMutation = useMutation({
    mutationFn: () => startMitm({
      interface: mitmIface || undefined,
      target_ips: mitmMode === 'select' ? mitmTargets : undefined,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mitm-status'] }),
  })
  const stopMitmMutation = useMutation({
    mutationFn: stopMitm,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mitm-status'] }),
  })

  const s = status as TrafficStatusResponse | undefined
  const d = dashboard as TrafficDashboardResponse | undefined
  const mitm = mitmStatusRaw as MitmStatusResponse | undefined
  const ifaceRaw = ifacesRaw as InterfacePayload | undefined
  const ifaceList: Interface[] = Array.isArray(ifaceRaw) ? ifaceRaw : (ifaceRaw?.interfaces ?? [])
  const devices: Device[] = Array.isArray(devicesRaw) ? devicesRaw : []
  const capturing = s?.running ?? d?.capture?.running ?? false
  // Backend state uses 'running' field
  const mitmActive = mitm?.running ?? mitm?.active ?? false
  const mitmError = mitm?.error ?? null

  useEffect(() => {
    window._nm_capturing = capturing
  }, [capturing])

  const toggleTarget = (ip: string) => {
    setMitmTargets(prev => prev.includes(ip) ? prev.filter(t => t !== ip) : [...prev, ip])
  }

  const trafficAccent = capturing ? 'red' : mitmActive ? 'amber' : 'gray'

  return (
    <div className="space-y-4">
      <PageHero
        icon={Radio}
        accent={trafficAccent}
        pulse={capturing || mitmActive}
        eyebrow={capturing ? `Capturing on ${s?.interface ?? d?.capture?.interface ?? 'auto'}` : mitmActive ? 'MitM active' : 'Capture idle'}
        title="Traffic Capture"
        subtitle="Deep packet inspection — see which sites and services every device talks to in real time."
        tiles={
          <>
            <StatTile icon={<Gauge size={11} />} label="Packets/s" accent="cyan" glow={capturing} value={d?.stats?.pps ?? 0} sub="live rate" />
            <StatTile icon={<Radio size={11} />} label="Bytes/s" accent="blue" value={humanBytes(d?.stats?.bps ?? 0)} sub="throughput" />
            <StatTile icon={<MonitorSmartphone size={11} />} label="Active" accent="purple" value={d?.stats?.devices ?? 0} sub="devices" />
            <StatTile icon={<Layers size={11} />} label="Top Proto" accent="emerald" value={<span className="text-base">{d?.stats?.top_protocol ?? '—'}</span>} sub="most traffic" />
          </>
        }
      />

      {/* ── Passive Capture ───────────────────────────────────────────── */}
      <Card
        title="Passive Capture"
        action={
          <div className="flex items-center gap-2">
            {capturing ? (
              <>
                <Btn variant="secondary" size="sm" loading={analyzeMutation.isPending} onClick={() => analyzeMutation.mutate()}>
                  <BrainCircuit size={13} /> Analyze
                </Btn>
                <Btn variant="danger" size="sm" loading={stopMutation.isPending} onClick={() => stopMutation.mutate()}>
                  <Square size={13} /> Stop
                </Btn>
              </>
            ) : (
              <Btn variant="primary" size="sm" loading={startMutation.isPending} onClick={() => startMutation.mutate()}>
                <Play size={13} /> Start
              </Btn>
            )}
          </div>
        }
      >
        {startMutation.isError && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-2 text-xs text-red-300 mb-2">
            {String((startMutation.error as Error)?.message)}
          </div>
        )}
        {capturing ? (
          <div className="flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            <span className="text-sm text-red-400">Capturing on {s?.interface ?? d?.capture?.interface ?? 'auto'}</span>
            {s?.started_at && <span className="text-xs text-gray-500">{formatRelativeTime(s.started_at)}</span>}
          </div>
        ) : (
          <div className="space-y-2">
            <p className="text-xs text-gray-500">Records all traffic on your network passively. No ARP spoofing — only traffic that naturally passes through this machine.</p>
            <select value={selectedIface} onChange={e => setSelectedIface(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-purple-500">
              <option value="">Auto-detect interface</option>
              {ifaceList.map(i => <option key={i.name} value={i.name}>{i.name}{i.ip ? ` (${i.ip})` : ''}</option>)}
            </select>
          </div>
        )}
      </Card>

      {/* ── AI Traffic Insights ────────────────────────────────────────── */}
      {(aiSummary || aiProgress?.running) && (
        <Card
          title="AI Traffic Insights"
          badge="TRAFFIC"
          action={
            <Btn
              variant="ghost"
              size="sm"
              loading={analyzeMutation.isPending || !!aiProgress?.running}
              onClick={() => analyzeMutation.mutate()}
            >
              <BrainCircuit size={13} />
              Re-Analyze
            </Btn>
          }
        >
          <AIPanel summary={aiSummary as AISummary | undefined} progress={aiProgress} />
        </Card>
      )}

      {/* ── Deep Capture / ARP Spoof MitM ─────────────────────────────── */}
      <Card
        title="Deep Capture — ARP Spoof MitM"
        action={
          <button onClick={() => setMitmExpanded(v => !v)} className="text-gray-500 hover:text-gray-300 transition-colors">
            {mitmExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        }
      >
        <div className="space-y-3">
          {mitmError && !mitmActive && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-300 space-y-1 mb-2">
              <p className="font-medium">MitM failed:</p>
              <p>{mitmError}</p>
            </div>
          )}

          {mitmActive ? (
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-orange-500 animate-pulse" />
                <span className="text-sm text-orange-400 font-medium">MitM Active</span>
                <span className="text-xs text-gray-500">
                  {mitm?.target_count ? `${mitm.target_count} target${mitm.target_count !== 1 ? 's' : ''}` : mitm?.targets?.length ? `${mitm.targets.length} targets` : 'all devices'}
                </span>
              </div>
              {mitm?.targets && mitm.targets.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {mitm.targets.map((ip: string) => (
                    <span key={ip} className="px-2 py-0.5 rounded bg-orange-500/10 text-orange-300 text-xs font-mono">{ip}</span>
                  ))}
                </div>
              )}
              <p className="text-xs text-gray-500">All traffic from targeted devices is flowing through this machine. Full packet visibility.</p>
              <Btn variant="danger" size="sm" loading={stopMitmMutation.isPending} onClick={() => stopMitmMutation.mutate()}>
                <ShieldOff size={13} /> Stop MitM &amp; Restore ARP
              </Btn>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-gray-500">
                ARP spoofs target devices so their traffic routes through this machine. Gives full visibility into encrypted and unencrypted traffic. Use only on your own network.
              </p>

              {mitmExpanded && (
                <>
                  {/* Interface */}
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Network interface</label>
                    <select value={mitmIface} onChange={e => setMitmIface(e.target.value)}
                      className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-purple-500">
                      <option value="">Auto-detect</option>
                      {ifaceList.map(i => <option key={i.name} value={i.name}>{i.name}{i.ip ? ` (${i.ip})` : ''}</option>)}
                    </select>
                  </div>

                  {/* Target mode */}
                  <div>
                    <label className="text-xs text-gray-500 block mb-1.5">Targets</label>
                    <div className="flex rounded-md overflow-hidden border border-white/10 text-xs w-fit">
                      {(['all', 'select'] as const).map(m => (
                        <button key={m} onClick={() => setMitmMode(m)}
                          className={`px-4 py-1.5 capitalize transition-colors ${mitmMode === m ? 'bg-orange-600 text-white' : 'text-gray-400 hover:text-gray-200'}`}>
                          {m === 'all' ? 'Whole network' : 'Specific IPs'}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Device picker */}
                  {mitmMode === 'select' && (
                    <MitmTargetPicker
                      devices={devices}
                      targets={mitmTargets}
                      onToggle={toggleTarget}
                      onAddManual={(ip) => !mitmTargets.includes(ip) && setMitmTargets(prev => [...prev, ip])}
                      onRemove={(ip) => setMitmTargets(prev => prev.filter(t => t !== ip))}
                    />
                  )}
                </>
              )}

              <Btn
                variant={mitmExpanded ? 'primary' : 'secondary'}
                size="sm"
                loading={startMitmMutation.isPending}
                className={mitmExpanded ? 'bg-orange-600 hover:bg-orange-500' : ''}
                onClick={() => {
                  if (!mitmExpanded) { setMitmExpanded(true); return }
                  if (mitmMode === 'select' && mitmTargets.length === 0) { setMitmExpanded(true); return }
                  startMitmMutation.mutate()
                }}
              >
                <ShieldAlert size={13} />
                {mitmExpanded
                  ? mitmMode === 'all' ? 'Start MitM (whole network)' : `Start MitM (${mitmTargets.length || '?'} devices)`
                  : 'Configure MitM…'}
              </Btn>
              {startMitmMutation.isError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-2 text-xs text-red-300">
                  {String((startMitmMutation.error as Error)?.message)}
                </div>
              )}
            </div>
          )}
        </div>
      </Card>

      {/* ── Conversations ─────────────────────────────────────────────── */}
      {d?.conversations && d.conversations.length > 0 && (
        <Card title="Connections" badge={String(d.conversations.length)}>
          <div className="overflow-x-auto -mx-4 -mb-4">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-gray-600 border-b border-white/5">
                  <th className="px-4 py-2">Source</th>
                  <th className="px-4 py-2">Destination</th>
                  <th className="hidden md:table-cell px-4 py-2">Country</th>
                  <th className="px-4 py-2">Bytes</th>
                  <th className="px-4 py-2">Packets</th>
                </tr>
              </thead>
              <tbody>
                {d.conversations.slice(0, 20).map((c, i) => (
                  <tr key={i} className="border-b border-white/5">
                    <td className="px-4 py-2 font-mono text-blue-400">{c.src}</td>
                    <td className="px-4 py-2 font-mono text-gray-300">{c.dst}</td>
                    <td className="hidden md:table-cell px-4 py-2 text-gray-500">{c.country ?? '—'}</td>
                    <td className="px-4 py-2 text-gray-400">{humanBytes(c.bytes)}</td>
                    <td className="px-4 py-2 text-gray-500">{(c.packets ?? 0).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* ── Incidents ─────────────────────────────────────────────────── */}
      {d?.incidents && d.incidents.length > 0 && (
        <Card title="Incidents" badge={String(d.incidents.length)}>
          <div className="space-y-1">
            {d.incidents.slice(0, 10).map(inc => (
              <div key={inc.id} className="flex items-center gap-3 text-xs py-1.5 border-b border-white/5 last:border-0">
                <Badge variant="error">{inc.anomaly_type}</Badge>
                {inc.device_ip && <span className="font-mono text-blue-400">{inc.device_ip}</span>}
                <span className="text-gray-500 ml-auto">{formatRelativeTime(inc.created_at)}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* ── Live Device Monitor ───────────────────────────────────────── */}
      <LiveMonitor capturing={capturing} mitmActive={mitmActive} />

      {d?.conversations?.length === 0 && !capturing && !mitmActive && (
        <EmptyState icon="◎" text="No traffic data yet" hint="Start passive capture or MitM to see connections." />
      )}
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
    return <EmptyState icon="◎" text="No analysis yet" hint="Start capture and click Analyze to run AI investigation of traffic." />
  }

  const isTraffic = summary.model?.toLowerCase().includes('traffic') || false

  return (
    <div className="space-y-4">
      {!isTraffic && (
        <div className="rounded-lg bg-white/5 border border-white/10 p-2.5 text-[11px] text-gray-400">
          💡 Showing last Scan analysis. Start traffic capture and click <strong className="text-purple-300">Analyze</strong> to generate traffic-specific insights.
        </div>
      )}

      <div className="flex items-center justify-between">
        {summary.verdict && (
          <Badge variant={severityVariant(summary.verdict)}>{summary.verdict}</Badge>
        )}
        {summary.model && (
          <span className="text-[10px] text-gray-500 font-mono">{summary.model}</span>
        )}
      </div>
      
      <div className="text-xs text-gray-300 leading-relaxed">
        <Markdown text={summary.summary} />
      </div>

      {summary.concerning && summary.concerning.length > 0 && (
        <div className="space-y-1.5 border-t border-white/5 pt-3">
          <h4 className="text-[10px] font-semibold text-red-400 uppercase tracking-wider flex items-center gap-1.5">
            <AlertTriangle size={11} className="text-red-400" /> Concerning Observations
          </h4>
          <ul className="space-y-1 text-xs text-gray-400 pl-4 list-disc">
            {summary.concerning.map((item, idx) => (
              <li key={idx} className="leading-normal">{item}</li>
            ))}
          </ul>
        </div>
      )}

      {summary.benign && summary.benign.length > 0 && (
        <div className="space-y-1.5 border-t border-white/5 pt-3">
          <h4 className="text-[10px] font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
            <CheckCircle2 size={11} className="text-emerald-400" /> Normal / Expected Activity
          </h4>
          <ul className="space-y-1 text-xs text-gray-400 pl-4 list-disc">
            {summary.benign.map((item, idx) => (
              <li key={idx} className="leading-normal">{item}</li>
            ))}
          </ul>
        </div>
      )}

      {summary.next_steps && summary.next_steps.length > 0 && (
        <div className="space-y-1.5 border-t border-white/5 pt-3">
          <h4 className="text-[10px] font-semibold text-purple-400 uppercase tracking-wider flex items-center gap-1.5">
            <ArrowRight size={11} className="text-purple-400" /> Recommended Actions
          </h4>
          <ol className="space-y-1 text-xs text-gray-300 pl-4 list-decimal">
            {summary.next_steps.map((item, idx) => (
              <li key={idx} className="leading-normal">{item}</li>
            ))}
          </ol>
        </div>
      )}

      {summary.created_at && (
        <p className="text-[10px] text-gray-600 border-t border-white/5 pt-2 flex justify-between items-center">
          <span>
            {summary.provider && <span className="mr-2 text-purple-500 font-mono">{summary.provider}</span>}
            {formatRelativeTime(summary.created_at)}
          </span>
        </p>
      )}
    </div>
  )
}

function MitmTargetPicker({ devices, targets, onToggle, onAddManual, onRemove }: {
  devices: Device[]
  targets: string[]
  onToggle: (ip: string) => void
  onAddManual: (ip: string) => void
  onRemove: (ip: string) => void
}) {
  const [manualIp, setManualIp] = useState('')

  const addManual = () => {
    const ip = manualIp.trim()
    if (!ip) return
    onAddManual(ip)
    setManualIp('')
  }

  return (
    <div className="space-y-2">
      {/* Manual IP entry */}
      <div className="flex gap-2">
        <input
          value={manualIp}
          onChange={e => setManualIp(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && addManual()}
          placeholder="Type IP address (e.g. 192.168.1.50)"
          className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-orange-500 font-mono"
        />
        <Btn variant="secondary" size="sm" onClick={addManual}>Add</Btn>
      </div>

      {/* Selected IPs (includes manual entries) */}
      {targets.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {targets.map(ip => (
            <span key={ip} className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-orange-500/15 border border-orange-500/30 text-orange-300 text-xs font-mono">
              {ip}
              <button onClick={() => onRemove(ip)} className="hover:text-white ml-0.5">×</button>
            </span>
          ))}
        </div>
      )}

      {/* Scanned device grid */}
      {devices.length > 0 && (
        <>
          <p className="text-[10px] text-gray-600 uppercase tracking-wider">Or pick from last scan</p>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 max-h-40 overflow-y-auto">
            {devices.map(dev => {
              const selected = targets.includes(dev.ip)
              return (
                <button key={dev.ip} onClick={() => onToggle(dev.ip)}
                  className={`flex items-center gap-2 p-2 rounded-lg border text-xs text-left transition-all ${
                    selected ? 'border-orange-500/50 bg-orange-500/10 text-orange-300' : 'border-white/8 hover:border-white/15 text-gray-400'
                  }`}>
                  <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${selected ? 'bg-orange-400' : 'bg-gray-700'}`} />
                  <div className="min-w-0">
                    <div className="font-mono truncate">{dev.ip}</div>
                    <div className="text-[10px] text-gray-600 truncate">{dev.label ?? dev.hostname ?? dev.vendor ?? ''}</div>
                  </div>
                </button>
              )
            })}
          </div>
        </>
      )}

      {targets.length > 0 && (
        <p className="text-xs text-orange-400">{targets.length} target{targets.length !== 1 ? 's' : ''} selected</p>
      )}
    </div>
  )
}

// ── Domain categorization ─────────────────────────────────────────────────────
const CATS: [string, string[], string][] = [
  ['Streaming',    ['netflix','youtube','spotify','hulu','twitch','tiktok','disneyplus','hbomax','peacock','primevideo','appletvplus','crunchyroll'], 'text-purple-400'],
  ['Social',       ['instagram','facebook','twitter','x.com','snapchat','reddit','pinterest','linkedin','discord','whatsapp','telegram'], 'text-blue-400'],
  ['Shopping',     ['amazon','ebay','etsy','walmart','target','shopify'], 'text-yellow-400'],
  ['Ads/Tracking', ['doubleclick','googlesyndication','facebook.net','scorecardresearch','moatads','adnxs','outbrain','taboola'], 'text-red-400'],
  ['Cloud/Sync',   ['icloud','dropbox','onedrive','gdrive','google.com','googleapis','gstatic','apple.com','microsoft.com','windows.com'], 'text-cyan-400'],
  ['IoT/Home',     ['tuya','smartlife','meethue','kasa','govee','ring.com','nest.google','alexa','echo'], 'text-orange-400'],
]

function categorizeDomain(domain: string): { label: string; color: string } {
  const d = domain.toLowerCase()
  for (const [label, keywords, color] of CATS) {
    if (keywords.some(k => d.includes(k))) return { label, color }
  }
  return { label: '', color: 'text-gray-400' }
}

function isTracking(domain: string): boolean {
  return CATS[3][1].some(k => domain.toLowerCase().includes(k))
}

// ── Live Monitor component ────────────────────────────────────────────────────
function LiveMonitor({ capturing, mitmActive }: { capturing: boolean; mitmActive: boolean }) {
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null)

  const { data: dnsRaw } = useQuery({
    queryKey: ['dns-live'],
    queryFn: getDNSLive,
    refetchInterval: capturing || mitmActive ? 3000 : 30_000,
  })

  // DNS live returns { "ip": [{"domain": "x", "count": n}] } (per-device)
  // OR { queries: [...] } — handle both
  const raw: unknown = dnsRaw
  const perDevice: PerDeviceDns = isPerDeviceDns(raw) ? raw : {}

  const deviceIPs = Object.keys(perDevice).sort()
  const activeDevice = selectedDevice && perDevice[selectedDevice] ? selectedDevice : (deviceIPs[0] ?? null)
  const domains = activeDevice ? (perDevice[activeDevice] ?? []) : []
  const sortedDomains = [...domains].sort((a, b) => b.count - a.count)

  if (!capturing && !mitmActive) return null

  return (
    <Card
      title="Live Device Monitor"
      badge="LIVE"
      action={
        <div className="flex items-center gap-1.5 text-xs text-gray-500">
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          Updating every 3s
        </div>
      }
    >
      <div className="space-y-3">
        {/* What you're seeing explanation */}
        <div className="rounded-lg bg-blue-500/5 border border-blue-500/20 p-3 text-xs text-gray-400 space-y-1">
          <p><Lock size={10} className="inline mr-1 text-blue-400" /><strong className="text-blue-300">Encrypted (HTTPS/TLS):</strong> You can see which site/service — not what they're doing on it.</p>
          <p><Unlock size={10} className="inline mr-1 text-orange-400" /><strong className="text-orange-300">Unencrypted (HTTP):</strong> Full content visible — images, files, form data. Rare on modern phones, common on old IoT.</p>
          <p><Globe size={10} className="inline mr-1 text-emerald-400" /><strong className="text-emerald-300">DNS queries:</strong> Every domain looked up, before the connection. Reveals all activity even for encrypted traffic.</p>
        </div>

        {deviceIPs.length === 0 ? (
          <EmptyState icon="◎" text="No device activity captured yet" hint="Capture needs a moment to collect DNS/TLS data. Make sure tshark (Wireshark) is installed." />
        ) : (
          <div className="flex gap-3 flex-col md:flex-row">
            {/* Device list */}
            <div className="flex md:flex-col gap-1.5 overflow-x-auto md:overflow-visible md:w-40 flex-shrink-0">
              {deviceIPs.map(ip => (
                <button key={ip} onClick={() => setSelectedDevice(ip)}
                  className={`flex-shrink-0 px-3 py-2 rounded-lg text-xs text-left transition-colors border ${
                    ip === activeDevice
                      ? 'border-purple-500/40 bg-purple-500/10 text-purple-300'
                      : 'border-white/8 hover:border-white/15 text-gray-400'
                  }`}>
                  <div className="font-mono">{ip}</div>
                  <div className="text-[10px] text-gray-600 mt-0.5">{perDevice[ip]?.length ?? 0} domains</div>
                </button>
              ))}
            </div>

            {/* Domain feed for selected device */}
            <div className="flex-1 min-w-0">
              {activeDevice && (
                <div className="space-y-1.5">
                  <p className="text-xs text-gray-500 mb-2">
                    Activity for <span className="text-white font-mono">{activeDevice}</span>
                    {' '}— {sortedDomains.length} domain{sortedDomains.length !== 1 ? 's' : ''} seen
                  </p>
                  <div className="space-y-1 max-h-64 overflow-y-auto pr-1">
                    {sortedDomains.map((d, i) => {
                      const cat = categorizeDomain(d.domain)
                      const tracking = isTracking(d.domain)
                      return (
                        <div key={i} className="flex items-center gap-2 py-1 border-b border-white/5 last:border-0 text-xs">
                          {tracking
                            ? <Eye size={10} className="text-red-400 flex-shrink-0" />
                            : <Globe size={10} className="text-gray-700 flex-shrink-0" />}
                          <span className="font-mono text-gray-200 flex-1 min-w-0 truncate">{d.domain}</span>
                          {cat.label && (
                            <span className={`text-[10px] flex-shrink-0 ${cat.color}`}>{cat.label}</span>
                          )}
                          <span className="text-gray-600 flex-shrink-0">{d.count}×</span>
                        </div>
                      )
                    })}
                  </div>

                  {/* Vulnerability assessment */}
                  {mitmActive && (
                    <div className="mt-3 pt-3 border-t border-white/5 space-y-1.5">
                      <p className="text-xs text-gray-500 font-medium">MitM Vulnerability Assessment</p>
                      <div className="rounded-lg bg-orange-500/5 border border-orange-500/20 p-3 text-xs text-gray-400 space-y-1.5">
                        <p className="text-orange-300 font-medium">
                          {sortedDomains.length > 0 ? '⚠ Device traffic is visible — ARP spoofing successful.' : 'Waiting for traffic…'}
                        </p>
                        <p>
                          <strong className="text-white">What this means:</strong> This device is vulnerable to network-level interception.
                          An attacker on the same network could see all unencrypted traffic and the metadata of encrypted traffic.
                        </p>
                        <p>
                          <strong className="text-white">Encrypted traffic (HTTPS):</strong> Site names are visible, content is not.
                          If the device shows certificate errors, the app has no cert pinning and SSL stripping could expose content.
                        </p>
                        <p>
                          <strong className="text-white">Unencrypted traffic:</strong> Any HTTP requests would be fully readable —
                          check for domains without TLS by looking for repeated queries to unusual non-HTTPS services.
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}
