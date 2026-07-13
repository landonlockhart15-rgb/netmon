import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { X, Save, ShieldAlert, ShieldOff, Globe, AlertTriangle, BrainCircuit } from 'lucide-react'
import { getDevices, getDeviceProfile, patchDevice, startMitm, stopMitm, getMitmStatus, getDeviceActivity, startCapture, type Device, type DeviceProfile, type DeviceUpdate } from '@/lib/api'
import { formatRelativeTime } from '@/lib/utils'
import Btn from './Btn'
import Badge from './Badge'
import DeviceChat from './DeviceChat'

interface Props {
  deviceId: number
  onClose: () => void
}

interface ExtendedMitmStatus {
  running?: boolean
  active?: boolean
  error?: string | null
  targets?: string[]
  active_count?: number
  target_count?: number
}
interface HttpActivity { time?: string; host?: string; uri?: string; full_url?: string }
interface TlsActivity { time?: string; sni?: string; full_url?: string }
interface DnsActivity { domain?: string }
interface ActivityResponse {
  http_requests?: HttpActivity[]
  tls_sessions?: TlsActivity[]
  dns_queries?: DnsActivity[]
}
type ActivityItem = (HttpActivity & { _type: 'http' }) | (TlsActivity & { _type: 'https' })

export default function DeviceModal({ deviceId, onClose }: Props) {
  const qc = useQueryClient()
  const [label, setLabel] = useState('')
  const [trusted, setTrusted] = useState(false)
  const [profileOverride, setProfileOverride] = useState('')
  const [initialized, setInitialized] = useState(false)

  const { data: devices = [] } = useQuery({
    queryKey: ['devices', 'current'],
    queryFn: () => getDevices(true),
  })

  const device = (devices as Device[]).find(d => d.id === deviceId)
  const { data: profile } = useQuery<DeviceProfile>({
    queryKey: ['device-profile', deviceId],
    queryFn: () => getDeviceProfile(deviceId),
    enabled: !!device,
  })

  if (device && !initialized) {
    setLabel(device.label ?? '')
    setTrusted(device.trusted)
    let parsedAllow: { profile_override?: string } = {}
    try {
      parsedAllow = JSON.parse(device.allow_json || '{}')
    } catch { /* ignore parsing errors */ }
    setProfileOverride(parsedAllow.profile_override ?? '')
    setInitialized(true)
  }

  const patchMutation = useMutation({
    mutationFn: (body: DeviceUpdate) => patchDevice(deviceId, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      qc.invalidateQueries({ queryKey: ['device-profile', deviceId] })
    },
  })

  const { data: mitmStatusRaw, refetch: refetchMitm } = useQuery({
    queryKey: ['mitm-status'],
    queryFn: getMitmStatus,
    refetchInterval: 2000,
  })
  const mitmStatus = mitmStatusRaw as ExtendedMitmStatus | undefined
  const mitmActive = mitmStatus?.running ?? mitmStatus?.active ?? false
  const mitmError = mitmStatus?.error ?? null
  const mitmTargets: string[] = mitmStatus?.targets ?? []
  const mitmTargetingThis = mitmActive && mitmTargets.includes(device?.ip ?? '')
  const mitmActiveCount: number = mitmStatus?.active_count ?? 0
  const mitmTargetCount: number = mitmStatus?.target_count ?? 0
  const mitmPartialFail = mitmTargetingThis && mitmTargetCount > 0 && mitmActiveCount === 0

  const startMitmMutation = useMutation({
    mutationFn: async () => {
      // Always stop first — don't rely on stale closure for mitmActive check
      try { await stopMitm() } catch { /* already stopped */ }
      await new Promise(r => setTimeout(r, 500))
      // Start MitM + passive capture together so live feed works immediately
      const [mitmResult] = await Promise.all([
        startMitm({ target_ips: [device!.ip] }),
        startCapture({}).catch(() => {}),  // best-effort, don't fail if already capturing
      ])
      return mitmResult
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['mitm-status'] })
      qc.invalidateQueries({ queryKey: ['traffic-status'] })
      setTimeout(() => {
        refetchMitm()
        qc.invalidateQueries({ queryKey: ['dns-live'] })
      }, 3000)
    },
    onError: () => qc.invalidateQueries({ queryKey: ['mitm-status'] }),
  })
  const stopMitmMutation = useMutation({
    mutationFn: stopMitm,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mitm-status'] }),
  })

  if (!device) return null

  return (
    <div className="fixed inset-0 z-50 flex items-end md:items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/70" />
      <div
        className="relative w-full max-w-lg bg-[#1a1a2e] rounded-2xl border border-white/10 shadow-2xl overflow-hidden max-h-[85vh] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/10">
          <div>
            <h2 className="text-base font-semibold text-white">{device.label || device.hostname || device.ip}</h2>
            <p className="text-xs text-gray-500 font-mono">{device.ip} · {device.mac ?? 'no MAC'}</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors">
            <X size={18} />
          </button>
        </div>

        <div className="overflow-y-auto flex-1 p-5 space-y-4">
          {/* Device info */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <InfoItem label="Vendor" value={device.vendor ?? '—'} />
            <InfoItem label="OS Guess" value={device.os_guess ?? '—'} />
            <InfoItem label="Last Seen" value={formatRelativeTime(device.last_seen)} />
            <InfoItem label="Status" value={<Badge variant={device.trusted ? 'ok' : 'warn'}>{device.trusted ? 'Trusted' : 'Unknown'}</Badge>} />
          </div>

          {/* Learned from traffic */}
          <ProfileSection profile={profile} onApplyLabel={setLabel} />
          <LearnedSection device={device} />

          {/* Open ports */}
          {device.open_ports?.length > 0 && (
            <div>
              <p className="text-xs text-gray-500 mb-2">Open Ports</p>
              <div className="flex flex-wrap gap-1.5">
                {device.open_ports.map(p => (
                  <span key={p} className="px-2 py-1 rounded-md bg-blue-500/10 text-blue-400 text-xs font-mono">{p}</span>
                ))}
              </div>
            </div>
          )}

          {/* Edit label / trust */}
          <div className="space-y-3 pt-2 border-t border-white/5">
            <p className="text-xs text-gray-500 uppercase tracking-wider">Edit Device</p>
            <div className="flex gap-2">
              <input
                type="text"
                value={label}
                onChange={e => setLabel(e.target.value)}
                placeholder="Device label (optional)"
                className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
              />
            </div>
            <div className="space-y-1">
              <label className="text-[10px] text-gray-500 uppercase tracking-wider">Profile Category Override</label>
              <select
                value={profileOverride}
                onChange={e => setProfileOverride(e.target.value)}
                className="w-full bg-[#1a1a2e] border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500 font-sans"
              >
                <option value="" className="bg-[#1a1a2e] text-white">Automatically inferred (heuristics)</option>
                <option value="router" className="bg-[#1a1a2e] text-white">Router / gateway</option>
                <option value="phone" className="bg-[#1a1a2e] text-white">Phone / tablet</option>
                <option value="computer" className="bg-[#1a1a2e] text-white">Computer / workstation</option>
                <option value="camera" className="bg-[#1a1a2e] text-white">Camera / security device</option>
                <option value="printer" className="bg-[#1a1a2e] text-white">Printer</option>
                <option value="storage" className="bg-[#1a1a2e] text-white">Storage / server</option>
                <option value="streaming" className="bg-[#1a1a2e] text-white">Streaming / media device</option>
                <option value="iot" className="bg-[#1a1a2e] text-white">Smart home / IoT</option>
                <option value="unknown" className="bg-[#1a1a2e] text-white">Unknown / mixed</option>
              </select>
            </div>
            <label className="flex items-center gap-2 cursor-pointer text-sm text-gray-300">
              <input
                type="checkbox"
                checked={trusted}
                onChange={e => setTrusted(e.target.checked)}
                className="rounded"
              />
              Mark as trusted
            </label>
            <Btn
              variant="primary"
              size="sm"
              loading={patchMutation.isPending}
              onClick={() => patchMutation.mutate({
                label: label || null,
                trusted,
                allow: { profile_override: profileOverride || null }
              })}
            >
              <Save size={13} />
              Save Changes
            </Btn>
          </div>

          {/* AI investigation — interactive chat */}
          <div className="space-y-3 pt-2 border-t border-white/5">
            <p className="text-xs text-gray-500 uppercase tracking-wider">AI Investigation</p>
            <DeviceChat
              deviceId={deviceId}
              onDeviceUpdated={() => qc.invalidateQueries({ queryKey: ['devices'] })}
            />
          </div>

          {/* MitM Deep Capture */}
          <div className="space-y-3 pt-2 border-t border-white/5">
            <div className="flex items-center justify-between">
              <p className="text-xs text-gray-500 uppercase tracking-wider">ARP Spoof / Deep Capture</p>
              {mitmTargetingThis ? (
                <Btn variant="danger" size="sm" loading={stopMitmMutation.isPending} onClick={() => stopMitmMutation.mutate()}>
                  <ShieldOff size={13} /> Stop MitM
                </Btn>
              ) : (
                <Btn
                  variant="ghost"
                  size="sm"
                  loading={startMitmMutation.isPending}
                  className="text-orange-400 hover:text-orange-300"
                  onClick={() => startMitmMutation.mutate()}
                >
                  <ShieldAlert size={13} /> Start MitM
                </Btn>
              )}
            </div>

            {/* API / mutation error */}
            {startMitmMutation.isError && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-300">
                <p className="font-medium mb-1">Failed to start:</p>
                <p>{String((startMitmMutation.error as Error)?.message)}</p>
              </div>
            )}
            {/* Engine error from status */}
            {mitmError && !mitmActive && !startMitmMutation.isError && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-300">
                <p className="font-medium mb-1">MitM stopped with error:</p>
                <p>{mitmError}</p>
              </div>
            )}

            {mitmTargetingThis ? (
              <div className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-3 space-y-2 text-xs">
                <div className="flex items-center gap-2 text-orange-300 font-medium">
                  <div className="w-1.5 h-1.5 rounded-full bg-orange-400 animate-pulse" />
                  MitM active — intercepting {device.ip}
                  {mitmActiveCount > 0 && <span className="text-orange-500/70 font-normal ml-1">· ARP poison sent</span>}
                </div>
                {mitmPartialFail && (
                  <div className="flex items-center gap-1.5 text-yellow-400">
                    <AlertTriangle size={11} />
                    <span>Device MAC not resolved — it may be offline or rejecting ARP probes.</span>
                  </div>
                )}
                <ActivityFeed deviceIp={device.ip} />
              </div>
            ) : mitmActive ? (
              <p className="text-xs text-yellow-500/80">⚠ MitM is active on another device. Clicking Start MitM will retarget to {device.ip} only.</p>
            ) : !mitmError ? (
              <p className="text-xs text-gray-600">ARP spoofs this device so its traffic routes through this machine. Also auto-starts passive capture so traffic is visible immediately.</p>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  )
}

function LearnedSection({ device }: { device: Device }) {
  // allow_json stores learned_domains and last_activity_ip from MitM sessions
  let learned: { learned_domains?: string[]; last_activity_ip?: string; behavior_profile?: string } = {}
  try { learned = JSON.parse(device.allow_json || '{}') } catch { /* ignore malformed legacy metadata */ }

  const domains = learned.learned_domains ?? []
  if (!domains.length && !device.vendor && !device.os_guess && !learned.behavior_profile) return null

  return (
    <div className="space-y-2 pt-1 border-t border-white/5">
      <p className="text-xs text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
        <span>Learned from traffic</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-600/20 text-purple-400">MitM</span>
      </p>
      {learned.behavior_profile && (
        <p className="text-xs text-gray-300">
          <span className="text-gray-500">Behavior profile: </span>
          <span className="text-white font-medium">{learned.behavior_profile}</span>
        </p>
      )}
      {device.vendor && device.vendor !== 'unknown' && (
        <p className="text-xs text-gray-300">
          <span className="text-gray-500">Device type: </span>
          <span className="text-white font-medium">{device.vendor}</span>
        </p>
      )}
      {domains.length > 0 && (
        <div>
          <p className="text-[10px] text-gray-600 mb-1">Top domains seen</p>
          <div className="flex flex-wrap gap-1">
            {domains.slice(0, 12).map((d, i) => (
              <a key={i} href={`https://${d}`} target="_blank" rel="noopener noreferrer"
                className="px-1.5 py-0.5 rounded bg-white/5 text-[10px] text-gray-300 hover:text-purple-300 hover:bg-purple-500/10 transition-colors font-mono truncate max-w-[160px]">
                {d}
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function ProfileSection({ profile, onApplyLabel }: { profile?: DeviceProfile; onApplyLabel: (label: string) => void }) {
  if (!profile) return null
  const confidence = Math.round((profile.confidence ?? 0) * 100)
  const alternatives = profile.alternatives ?? []
  const signalRows = [
    { label: 'Vendor', value: profile.signals.vendor },
    { label: 'Hostname', value: profile.signals.hostname },
    { label: 'OS guess', value: profile.signals.os_guess },
    { label: 'DHCP 60', value: profile.signals.dhcp_option60 },
    { label: 'DHCP 55', value: profile.signals.dhcp_option55 },
    { label: 'Learned domains', value: profile.signals.learned_domains?.slice(0, 3).join(', ') },
    { label: 'Open ports', value: profile.signals.open_ports?.length ? profile.signals.open_ports.join(', ') : '' },
  ].filter(row => Boolean(row.value))

  return (
    <div className="space-y-3 pt-1 border-t border-white/5">
      <p className="text-xs text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
        <BrainCircuit size={11} />
        <span>Profile suggestion</span>
        <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-600/20 text-cyan-300">
          {profile.source || 'model'}
        </span>
      </p>
      <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <p className="text-[10px] uppercase tracking-wider text-gray-500">Likely profile</p>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="ok">{profile.label}</Badge>
              <span className="text-xs text-gray-400">{confidence}% confidence</span>
            </div>
            {profile.latest_ip && <p className="text-[10px] text-gray-600 font-mono">Latest IP: {profile.latest_ip}</p>}
          </div>
          <Btn variant="ghost" size="sm" onClick={() => onApplyLabel(profile.label)}>
            Use label
          </Btn>
        </div>

        {signalRows.length > 0 && (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {signalRows.map(row => (
              <div key={row.label} className="rounded-md border border-white/5 bg-black/10 px-2 py-1.5">
                <p className="text-[10px] uppercase tracking-wider text-gray-500">{row.label}</p>
                <p className="text-xs text-gray-200 truncate">{row.value}</p>
              </div>
            ))}
          </div>
        )}

        {Array.isArray(profile.evidence) && profile.evidence.length > 0 && (
          <div className="space-y-1">
            <p className="text-[10px] uppercase tracking-wider text-gray-500">Why this fit</p>
            <ul className="space-y-1 text-xs text-gray-300">
              {profile.evidence.slice(0, 4).map((item: string, i: number) => (
                <li key={i}>• {item}</li>
              ))}
            </ul>
          </div>
        )}

        {alternatives.length > 0 && (
          <p className="text-[10px] text-gray-600">
            Also considered: {alternatives.map(alt => alt.label).join(', ')}
          </p>
        )}
      </div>
    </div>
  )
}

function ActivityFeed({ deviceIp }: { deviceIp: string }) {
  const [tab, setTab] = useState<'all' | 'http' | 'https' | 'dns'>('all')

  const { data: raw, isLoading } = useQuery({
    queryKey: ['device-activity', deviceIp],
    queryFn: () => getDeviceActivity(deviceIp),
    refetchInterval: 5000,
  })

  const activity = raw as ActivityResponse | undefined
  const http = activity?.http_requests ?? []
  const tls = activity?.tls_sessions ?? []
  const dns = activity?.dns_queries ?? []

  // Combined feed sorted by time
  const allItems: ActivityItem[] = [
    ...http.map(i => ({ ...i, _type: 'http' as const })),
    ...tls.map(i => ({ ...i, _type: 'https' as const })),
  ].sort((a, b) => parseFloat(b.time || '0') - parseFloat(a.time || '0')).slice(0, 80)

  const shown: ActivityItem[] = tab === 'all' ? allItems
    : tab === 'http'  ? allItems.filter(i => i._type === 'http')
    : tab === 'https' ? allItems.filter(i => i._type === 'https')
    : []

  if (isLoading) return (
    <div className="flex items-center gap-2 text-gray-500">
      <div className="w-1 h-1 rounded-full bg-orange-400 animate-pulse" />
      <span>Reading capture files…</span>
    </div>
  )

  if (!allItems.length && !dns.length) return (
    <div className="flex items-center gap-2 text-gray-500">
      <div className="w-1 h-1 rounded-full bg-orange-400 animate-pulse" />
      <span>Waiting for first packets from this device…</span>
    </div>
  )

  return (
    <div className="space-y-2">
      {/* Stats + tabs */}
      <div className="flex items-center gap-1 flex-wrap">
        {([
          { id: 'all',   label: `All (${allItems.length})` },
          { id: 'http',  label: `HTTP ${http.length > 0 ? `(${http.length} unencrypted)` : ''}` },
          { id: 'https', label: `HTTPS (${tls.length})` },
          { id: 'dns',   label: `DNS (${dns.length})` },
        ] satisfies { id: typeof tab; label: string }[]).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-2 py-0.5 rounded text-[10px] transition-colors ${tab === t.id ? 'bg-orange-500/20 text-orange-300' : 'text-gray-600 hover:text-gray-300'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Activity list */}
      <div className="max-h-48 overflow-y-auto space-y-0.5">
        {shown.length === 0 && tab !== 'dns' && (
          <p className="text-gray-600 text-[10px]">No {tab} traffic captured yet</p>
        )}
        {tab === 'dns' ? dns.slice(0, 60).map((item, i) => (
          <div key={i} className="flex items-center gap-2 py-0.5 text-[11px]">
            <Globe size={9} className="text-gray-600 flex-shrink-0" />
            <span className="font-mono text-gray-300 flex-1 truncate">{item.domain}</span>
          </div>
        )) : shown.map((item, i) => (
          <div key={i} className="flex items-center gap-1.5 py-0.5 text-[11px] group">
            {item._type === 'http' ? (
              <span className="text-[9px] px-1 py-0.5 rounded bg-orange-500/20 text-orange-300 flex-shrink-0">HTTP</span>
            ) : (
              <span className="text-[9px] px-1 py-0.5 rounded bg-blue-500/20 text-blue-400 flex-shrink-0">HTTPS</span>
            )}
            <span className="font-mono text-gray-200 flex-1 truncate">
              {item._type === 'http' ? (
                <span title={item.full_url}>{item.host}{item.uri !== '/' ? item.uri : ''}</span>
              ) : (
                item.sni
              )}
            </span>
            <a
              href={item.full_url}
              target="_blank"
              rel="noopener noreferrer"
              className="opacity-0 group-hover:opacity-100 text-[9px] text-purple-400 hover:text-purple-300 flex-shrink-0 transition-opacity"
              onClick={e => e.stopPropagation()}
            >
              Visit ↗
            </a>
          </div>
        ))}
      </div>

      {http.length > 0 && (
        <p className="text-[10px] text-orange-400">
          ⚠ {http.length} unencrypted HTTP request{http.length !== 1 ? 's' : ''} — full URLs visible
        </p>
      )}
    </div>
  )
}

function InfoItem({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <p className="text-gray-600 text-[10px] uppercase tracking-wider mb-0.5">{label}</p>
      <div className="text-gray-200">{value}</div>
    </div>
  )
}
