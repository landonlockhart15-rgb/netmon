import { useState, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Play, Square, Send, AlertTriangle, Upload, ExternalLink, Info, Terminal } from 'lucide-react'
import {
  checkWSL, getSecLabHistory,
  startNikto, startHydra, startJohn, startMetasploit,
  startWifiCapture, startAircrack, shodanCheck,
  securityChat, cancelSecurityRun,
} from '@/lib/api'
import { formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge, { severityVariant } from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'
import Markdown from '@/components/shared/Markdown'

type Tab = 'vulnerability' | 'password' | 'exploit' | 'wifi' | 'exposure'

const TABS: { id: Tab; label: string }[] = [
  { id: 'vulnerability', label: 'Vulnerability Scan' },
  { id: 'password',      label: 'Password Test' },
  { id: 'exploit',       label: 'Exploit Test' },
  { id: 'wifi',          label: 'WiFi Test' },
  { id: 'exposure',      label: 'Internet Exposure' },
]

// Upload a file to /api/security/upload and return the file_id
async function uploadSecFile(file: File, fileType: string): Promise<number> {
  const fd = new FormData()
  fd.append('file', file)
  fd.append('file_type', fileType)
  const res = await fetch('/api/security/upload', { method: 'POST', body: fd, credentials: 'same-origin' })
  if (!res.ok) throw new Error(`Upload failed: ${res.status}`)
  const j = await res.json()
  return j.file_id
}

export default function SecurityLab() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>('vulnerability')
  const [activeRunId, setActiveRunId] = useState<number | null>(null)
  const [streamOutput, setStreamOutput] = useState('')
  const [chatHistory, setChatHistory] = useState<{ role: string; content: string }[]>([])
  const [chatMsg, setChatMsg] = useState('')
  const [fixSuggestions, setFixSuggestions] = useState<any[]>([])
  const [fixResult, setFixResult] = useState<{ text?: string; url?: string } | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const lastSeqRef = useRef(0)

  const { data: wsl } = useQuery({
    queryKey: ['wsl-check'],
    queryFn: checkWSL,
    staleTime: 300_000,
  })

  const { data: historyRaw, refetch: refetchHistory } = useQuery({
    queryKey: ['seclab-history'],
    queryFn: () => getSecLabHistory({ limit: 20 }),
    refetchInterval: activeRunId ? 5000 : 30_000,
  })

  const w = wsl as any
  const wslAvailable = w?.wsl_installed && w?.kali_present
  const raw = historyRaw as any
  const runs: any[] = Array.isArray(raw) ? raw : (raw?.runs ?? [])
  const activeRun = runs.find((r: any) => r.id === activeRunId)

  // Polling-based output — polls /api/security/run/stream until done
  const startPolling = useCallback((runId: number) => {
    setStreamOutput('')
    setActiveRunId(runId)
    lastSeqRef.current = 0
    if (pollingRef.current) clearInterval(pollingRef.current)

    pollingRef.current = setInterval(async () => {
      try {
        const res = await fetch('/api/security/run/stream', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ run_id: runId, after_sequence: lastSeqRef.current }),
        })
        if (!res.ok) return
        const data = await res.json()
        const chunks: any[] = data.chunks ?? []
        if (chunks.length > 0) {
          const text = chunks.map((c: any) => c.content).join('')
          setStreamOutput(prev => prev + text)
          lastSeqRef.current = chunks[chunks.length - 1].sequence
        }
        if (data.status !== 'running' && data.status !== 'pending') {
          clearInterval(pollingRef.current!)
          pollingRef.current = null
          refetchHistory()
          // Fetch fix suggestions when scan completes
          try {
            const fixRes = await fetch('/api/security/fix/suggestions', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'same-origin',
              body: JSON.stringify({ run_id: runId }),
            })
            if (fixRes.ok) {
              const fixData = await fixRes.json()
              setFixSuggestions(fixData.suggestions ?? [])
            }
          } catch {}
        }
      } catch {}
    }, 1500)
  }, [refetchHistory])

  // Open a run from history. Live runs stream; finished runs load their saved output.
  const showRun = useCallback(async (runId: number, status: string) => {
    if (pollingRef.current) { clearInterval(pollingRef.current); pollingRef.current = null }
    setActiveRunId(runId)
    setFixSuggestions([])
    setFixResult(null)
    if (status === 'running' || status === 'pending') {
      startPolling(runId)
      return
    }
    setStreamOutput('Loading…')
    try {
      const res = await fetch('/api/security/run/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ run_id: runId, after_sequence: 0 }),
      })
      if (res.ok) {
        const data = await res.json()
        const text = (data.chunks ?? []).map((c: any) => c.content).join('')
        setStreamOutput(text || '(no output was recorded for this run)')
      } else {
        setStreamOutput(`Could not load output (HTTP ${res.status}).`)
      }
      try {
        const fixRes = await fetch('/api/security/fix/suggestions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ run_id: runId }),
        })
        if (fixRes.ok) {
          const fixData = await fixRes.json()
          setFixSuggestions(fixData.suggestions ?? [])
        }
      } catch {}
    } catch (e: any) {
      setStreamOutput(`Could not load output: ${e?.message ?? e}`)
    }
  }, [startPolling])

  const chatMutation = useMutation({
    mutationFn: (msg: string) => securityChat({ message: msg, run_id: activeRunId }),
    onSuccess: (data: any) => setChatHistory(h => [...h, { role: 'assistant', content: data.reply }]),
  })

  const runFix = async (actionKey: string) => {
    setFixResult(null)
    const res = await fetch('/api/security/fix/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ action_key: actionKey }),
    })
    if (!res.ok) return
    const data = await res.json()
    if (data.open_in_browser && data.url) {
      window.open(data.url, '_blank')
    } else if (data.info_text) {
      setFixResult({ text: data.info_text })
    } else if (data.output) {
      setFixResult({ text: data.output })
    }
  }

  const cancelMutation = useMutation({
    mutationFn: () => cancelSecurityRun({ run_id: activeRunId }),
    onSuccess: () => {
      if (pollingRef.current) { clearInterval(pollingRef.current); pollingRef.current = null }
      refetchHistory()
    },
  })

  const sendChat = () => {
    if (!chatMsg.trim()) return
    setChatHistory(h => [...h, { role: 'user', content: chatMsg }])
    chatMutation.mutate(chatMsg)
    setChatMsg('')
  }

  // Run a tool action and surface any failure instead of silently doing nothing.
  const runAction = async (fn: () => Promise<void>) => {
    setActionError(null)
    try {
      await fn()
    } catch (e: any) {
      setActionError(e?.message ? String(e.message) : String(e))
    }
  }

  return (
    <div className="space-y-4">
      {w && !wslAvailable && (
        <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-3 flex items-center gap-2 text-sm text-yellow-300">
          <AlertTriangle size={16} />
          WSL not available. Security Lab tools require WSL 2 with Kali Linux.
        </div>
      )}

      {actionError && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 flex items-start gap-2 text-sm text-red-300">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <div className="flex-1">
            <div className="font-medium">Couldn't start the scan</div>
            <div className="text-red-300/80 text-xs mt-0.5 break-words">{actionError}</div>
          </div>
          <button onClick={() => setActionError(null)} className="text-red-300/60 hover:text-red-300 text-xs">✕</button>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 overflow-x-auto border-b border-white/8 pb-0">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={cn('px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors border-b-2 -mb-px',
              tab === t.id ? 'text-purple-300 border-purple-500' : 'text-gray-500 border-transparent hover:text-gray-300')}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'vulnerability' && <NiktoPanel onStart={(target, opts) => runAction(async () => {
        const r = await startNikto({ target, ...opts, authorization_confirmed: true })
        startPolling((r as any).run_id)
      })} />}

      {tab === 'password' && <PasswordPanel
        onStartHydra={(body) => runAction(async () => {
          const r = await startHydra({ ...body, authorization_confirmed: true })
          startPolling((r as any).run_id)
        })}
        onStartJohn={(body) => runAction(async () => {
          const r = await startJohn({ ...body, authorization_confirmed: true })
          startPolling((r as any).run_id)
        })}
      />}

      {tab === 'exploit' && <ExploitPanel onStart={(body) => runAction(async () => {
        const r = await startMetasploit({ ...body, authorization_confirmed: true })
        startPolling((r as any).run_id)
      })} />}

      {tab === 'wifi' && <WifiPanel
        onStartCapture={(body) => runAction(async () => {
          const r = await startWifiCapture({ ...body, authorization_confirmed: true })
          startPolling((r as any).run_id)
        })}
        onStartCrack={(body) => runAction(async () => {
          const r = await startAircrack({ ...body, authorization_confirmed: true })
          startPolling((r as any).run_id)
        })}
      />}

      {tab === 'exposure' && <ShodanPanel />}

      {/* Live output */}
      {activeRunId != null && (
        <Card title={`Live Output — Run #${activeRunId}`}
          action={
            activeRun?.status === 'running' || pollingRef.current ? (
              <Btn variant="danger" size="sm" loading={cancelMutation.isPending} onClick={() => cancelMutation.mutate()}>
                <Square size={12} /> Cancel
              </Btn>
            ) : (
              <Badge variant={severityVariant(activeRun?.risk_level ?? 'muted')}>
                {activeRun?.status ?? 'done'}
              </Badge>
            )
          }
        >
          <pre className="text-[11px] font-mono text-gray-300 whitespace-pre-wrap max-h-72 overflow-y-auto bg-black/30 rounded-lg p-3 leading-relaxed">
            {streamOutput || 'Waiting for output…'}
          </pre>
          {/* Fix buttons — shown when scan completes and findings matched */}
          {fixSuggestions.length > 0 && (
            <div className="mt-3 pt-3 border-t border-white/5 space-y-2">
              <p className="text-xs text-gray-500 font-medium uppercase tracking-wider">Suggested Fixes</p>
              <div className="flex flex-wrap gap-2">
                {fixSuggestions.map((fix: any) => (
                  <button key={fix.action_key} onClick={() => runFix(fix.action_key)}
                    className={cn(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors',
                      fix.type === 'router_link'
                        ? 'bg-blue-500/10 border-blue-500/30 text-blue-300 hover:bg-blue-500/20'
                        : fix.type === 'info'
                        ? 'bg-gray-500/10 border-gray-500/30 text-gray-400 hover:bg-gray-500/20'
                        : 'bg-orange-500/10 border-orange-500/30 text-orange-300 hover:bg-orange-500/20'
                    )}>
                    {fix.type === 'router_link' && <ExternalLink size={11} />}
                    {fix.type === 'info' && <Info size={11} />}
                    {fix.type === 'windows_cmd' && <Terminal size={11} />}
                    {fix.label}
                  </button>
                ))}
              </div>
              {fixResult?.text && (
                <div className="rounded-lg bg-white/5 border border-white/10 p-3 text-xs text-gray-300 leading-relaxed">
                  {fixResult.text}
                </div>
              )}
            </div>
          )}

          {activeRun?.ai_explanation && (
            <div className="mt-3 pt-3 border-t border-white/5">
              <p className="text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">AI Analysis</p>
              <Markdown text={activeRun.ai_explanation} />
            </div>
          )}
        </Card>
      )}

      {/* Chat */}
      {activeRunId != null && (
        <Card title="AI Chat">
          <div className="space-y-3">
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {chatHistory.map((m, i) => (
                <div key={i} className={`text-xs rounded-lg px-3 py-2 ${m.role === 'user' ? 'bg-purple-600/15 text-purple-200 ml-8' : 'bg-white/5 text-gray-300'}`}>
                  {m.content}
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <input value={chatMsg} onChange={e => setChatMsg(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && sendChat()}
                placeholder="Ask about the scan results…"
                className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500" />
              <Btn variant="primary" size="sm" loading={chatMutation.isPending} onClick={sendChat}>
                <Send size={13} />
              </Btn>
            </div>
          </div>
        </Card>
      )}

      {/* History */}
      <Card title="Scan History" badge={runs.length ? String(runs.length) : undefined}>
        {runs.length === 0 ? (
          <EmptyState icon="◎" text="No scans yet" hint="Run a security scan to see results here." />
        ) : (
          <div className="overflow-x-auto -mx-4 -mb-4">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-gray-600 border-b border-white/5">
                  <th className="px-4 py-2">#</th>
                  <th className="px-4 py-2">Tool</th>
                  <th className="px-4 py-2">Target</th>
                  <th className="px-4 py-2">Status</th>
                  <th className="px-4 py-2">Risk</th>
                  <th className="px-4 py-2">When</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r: any) => (
                  <tr key={r.id} onClick={() => showRun(r.id, r.status)}
                    className={cn('border-b border-white/5 cursor-pointer transition-colors',
                      r.id === activeRunId ? 'bg-purple-500/5' : 'hover:bg-white/[0.02]')}>
                    <td className="px-4 py-2 text-gray-500">#{r.id}</td>
                    <td className="px-4 py-2 font-medium text-gray-200">{r.tool}</td>
                    <td className="px-4 py-2 font-mono text-blue-400 max-w-[120px] truncate">{r.target ?? '—'}</td>
                    <td className="px-4 py-2">
                      <Badge variant={r.status === 'completed' ? 'ok' : r.status === 'failed' ? 'error' : r.status === 'running' ? 'info' : 'muted'}>
                        {r.status}
                      </Badge>
                    </td>
                    <td className="px-4 py-2">
                      {r.risk_level ? <Badge variant={severityVariant(r.risk_level)}>{r.risk_level}</Badge> : '—'}
                    </td>
                    <td className="px-4 py-2 text-gray-500">{formatRelativeTime(r.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

// ── Tool panels ──────────────────────────────────────────────────────────────

function NiktoPanel({ onStart }: { onStart: (target: string, opts: { auto?: boolean; ports?: string }) => void }) {
  const [target, setTarget] = useState('')
  const [auto, setAuto] = useState(true)
  const [ports, setPorts] = useState('')
  const [loading, setLoading] = useState(false)
  return (
    <Card title="Nikto — Web Vulnerability Scanner">
      <p className="text-xs text-gray-500 mb-3">Scan a web server for known vulnerabilities, misconfigurations, and outdated software.</p>
      <div className="flex gap-2 mb-2">
        <input value={target} onChange={e => setTarget(e.target.value)}
          placeholder="Target URL or IP (e.g. 192.168.1.1)"
          className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500" />
        <Btn variant="primary" size="sm" loading={loading} onClick={async () => {
          if (!target) return
          setLoading(true)
          try {
            const opts: { auto?: boolean; ports?: string } = auto
              ? { auto: true }
              : (ports.trim() ? { ports: ports.trim() } : { auto: true })
            await onStart(target, opts)
          } finally { setLoading(false) }
        }}>
          <Play size={13} /> Scan
        </Btn>
      </div>
      <div className="flex items-center gap-3 text-xs text-gray-400">
        <label className="flex items-center gap-1.5 cursor-pointer select-none">
          <input type="checkbox" checked={auto} onChange={e => setAuto(e.target.checked)}
            className="accent-purple-500" />
          Auto-detect HTTP ports
        </label>
        <input value={ports} onChange={e => setPorts(e.target.value)}
          disabled={auto}
          placeholder={auto ? 'nmap will probe 80, 443, 8080, 8443, 8000, 8888, …' : 'Ports (e.g. 80,443,8080)'}
          className="flex-1 bg-white/5 border border-white/10 rounded-md px-2.5 py-1.5 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-purple-500 disabled:opacity-50" />
      </div>
      <p className="text-[11px] text-gray-600 mt-1.5">
        Auto mode runs a quick nmap probe first, then scans every open HTTP/HTTPS port it finds. Slower but catches admin panels on uncommon ports.
      </p>
    </Card>
  )
}

function PasswordPanel({ onStartHydra, onStartJohn }: {
  onStartHydra: (body: object) => void
  onStartJohn: (body: object) => void
}) {
  const [hydraTarget, setHydraTarget] = useState('')
  const [hydraService, setHydraService] = useState('ssh')
  const [hydraAuto, setHydraAuto] = useState(true)
  const [hydraUser, setHydraUser] = useState('')
  const [hydraPass, setHydraPass] = useState('')
  const [hydraLoading, setHydraLoading] = useState(false)
  const [hashFile, setHashFile] = useState<File | null>(null)
  const [johnLoading, setJohnLoading] = useState(false)

  return (
    <div className="space-y-4">
      <Card title="Hydra — Online Password Test">
        <p className="text-xs text-gray-500 mb-3">Check whether a device on your network is using a weak or default login. Just enter the target — NetMon can auto-detect which login services are open and test them.</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={hydraTarget} onChange={e => setHydraTarget(e.target.value)} placeholder="Target IP"
            className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500" />
          <select value={hydraService} onChange={e => setHydraService(e.target.value)} disabled={hydraAuto}
            className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-purple-500 disabled:opacity-40 disabled:cursor-not-allowed">
            {['ssh', 'ftp', 'http', 'https', 'smb', 'rdp', 'telnet'].map(s => <option key={s}>{s}</option>)}
          </select>
          <input value={hydraUser} onChange={e => setHydraUser(e.target.value)} placeholder="Username (blank = try common: admin, root…)"
            className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500" />
          <input value={hydraPass} onChange={e => setHydraPass(e.target.value)} placeholder="Password (blank = common/default list)"
            className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500" />
        </div>
        <div className="mt-2 flex items-center gap-3 flex-wrap">
          <label className="flex items-center gap-1.5 cursor-pointer select-none text-xs text-gray-400">
            <input type="checkbox" checked={hydraAuto} onChange={e => setHydraAuto(e.target.checked)} className="accent-purple-500" />
            Auto-detect &amp; test open services
          </label>
          <Btn variant="primary" size="sm" loading={hydraLoading} onClick={async () => {
            if (!hydraTarget) return
            setHydraLoading(true)
            try {
              const base = { target: hydraTarget, username: hydraUser || undefined, single_password: hydraPass || undefined }
              await onStartHydra(hydraAuto ? { ...base, auto: true } : { ...base, service: hydraService })
            } finally { setHydraLoading(false) }
          }}>
            <Play size={13} /> Start
          </Btn>
        </div>
        <p className="text-[11px] text-gray-600 mt-1.5">
          {hydraAuto
            ? 'Auto mode runs a quick nmap probe, then tests each open login service (ssh, ftp, telnet, rdp, smb, http/https) with a built-in list of common/default credentials.'
            : 'Manual mode tests only the selected service.'}
        </p>
      </Card>

      <Card title="John the Ripper — Offline Hash Cracker">
        <p className="text-xs text-gray-500 mb-3">Upload a hash file from your own system to test password strength offline.</p>
        <div className="space-y-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <div className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-400">
              {hashFile ? hashFile.name : 'Choose hash file…'}
            </div>
            <Btn variant="secondary" size="sm" onClick={() => document.getElementById('john-hash-input')?.click()}>
              <Upload size={13} /> Browse
            </Btn>
            <input id="john-hash-input" type="file" className="hidden"
              onChange={e => setHashFile(e.target.files?.[0] ?? null)} />
          </label>
          <Btn variant="primary" size="sm" loading={johnLoading}
            disabled={!hashFile}
            onClick={async () => {
              if (!hashFile) return
              setJohnLoading(true)
              try {
                const fileId = await uploadSecFile(hashFile, 'hash')
                await onStartJohn({ hash_file_id: fileId })
              } finally { setJohnLoading(false) }
            }}>
            <Play size={13} /> Crack
          </Btn>
        </div>
      </Card>
    </div>
  )
}

function ExploitPanel({ onStart }: { onStart: (body: object) => void }) {
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  return (
    <Card title="Metasploit — Exploit Framework">
      <p className="text-xs text-gray-500 mb-3">Run Metasploit against a target on your network. Use only on devices you own.</p>
      <div className="flex gap-2">
        <input value={target} onChange={e => setTarget(e.target.value)} placeholder="Target IP"
          className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500" />
        <Btn variant="primary" size="sm" loading={loading} onClick={async () => {
          if (!target) return
          setLoading(true)
          try { await onStart({ target }) } finally { setLoading(false) }
        }}>
          <Play size={13} /> Start
        </Btn>
      </div>
    </Card>
  )
}

function WifiPanel({ onStartCapture, onStartCrack }: {
  onStartCapture: (body: object) => void
  onStartCrack: (body: object) => void
}) {
  const [iface, setIface] = useState('')
  const [capLoading, setCapLoading] = useState(false)
  const [capFile, setCapFile] = useState<File | null>(null)
  const [crackLoading, setCrackLoading] = useState(false)
  return (
    <div className="space-y-4">
      <Card title="WiFi Capture">
        <p className="text-xs text-gray-500 mb-3">Capture WPA handshakes from your own WiFi network.</p>
        <div className="flex gap-2">
          <input value={iface} onChange={e => setIface(e.target.value)} placeholder="WiFi interface (e.g. wlan0)"
            className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500" />
          <Btn variant="primary" size="sm" loading={capLoading} onClick={async () => {
            setCapLoading(true)
            try { await onStartCapture({ interface: iface }) } finally { setCapLoading(false) }
          }}>
            <Play size={13} /> Capture
          </Btn>
        </div>
      </Card>
      <Card title="Aircrack-ng — Crack Handshake">
        <p className="text-xs text-gray-500 mb-3">Upload a capture file (.cap/.pcap) and crack the WPA handshake against a wordlist.</p>
        <div className="space-y-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <div className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-400">
              {capFile ? capFile.name : 'Choose .cap file…'}
            </div>
            <Btn variant="secondary" size="sm" onClick={() => document.getElementById('cap-file-input')?.click()}>
              <Upload size={13} /> Browse
            </Btn>
            <input id="cap-file-input" type="file" accept=".cap,.pcap,.pcapng" className="hidden"
              onChange={e => setCapFile(e.target.files?.[0] ?? null)} />
          </label>
          <Btn variant="primary" size="sm" loading={crackLoading} disabled={!capFile}
            onClick={async () => {
              if (!capFile) return
              setCrackLoading(true)
              try {
                const fileId = await uploadSecFile(capFile, 'capture')
                await onStartCrack({ capture_file_id: fileId })
              } finally { setCrackLoading(false) }
            }}>
            <Play size={13} /> Crack
          </Btn>
        </div>
      </Card>
    </div>
  )
}

function ShodanPanel() {
  const [ip, setIp] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  return (
    <Card title="Shodan — Internet Exposure">
      <p className="text-xs text-gray-500 mb-3">Check if your devices are visible on the public internet via Shodan.</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
        <input value={ip} onChange={e => setIp(e.target.value)} placeholder="IP to check"
          className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500" />
        <input value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder="Shodan API key"
          type="password"
          className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500" />
      </div>
      <Btn variant="primary" size="sm" loading={loading} onClick={async () => {
        setLoading(true)
        try { setResult(await shodanCheck({ ip, api_key: apiKey })) } finally { setLoading(false) }
      }}>
        <Play size={13} /> Check
      </Btn>
      {result && (
        <div className="mt-4 space-y-1 text-xs">
          {result.ports?.length > 0 && <p className="text-yellow-400">Open ports: {result.ports.join(', ')}</p>}
          {result.vulns?.length > 0 && <p className="text-red-400">CVEs: {result.vulns.join(', ')}</p>}
          {result.hostnames?.length > 0 && <p className="text-gray-400">Hostnames: {result.hostnames.join(', ')}</p>}
          {!result.ports?.length && !result.vulns?.length && <p className="text-emerald-400">No public exposure found.</p>}
        </div>
      )}
    </Card>
  )
}
