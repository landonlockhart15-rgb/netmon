/** Base API client — mirrors _apiFetch from app.js */

const BASE = ''

async function apiFetch<T = unknown>(
  url: string,
  opts: RequestInit & { timeoutMs?: number } = {}
): Promise<T> {
  const { timeoutMs, ...fetchOpts } = opts
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  if (timeoutMs) timer = setTimeout(() => controller.abort(), timeoutMs)

  const res = await fetch(BASE + url, {
    ...fetchOpts,
    signal: controller.signal,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...fetchOpts.headers },
  })
  if (timer) clearTimeout(timer)

  if (res.status === 401) {
    window.location.href = '/login'
    throw new Error('Not authenticated')
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`API ${res.status}: ${text}`)
  }
  const ct = res.headers.get('content-type') ?? ''
  if (ct.includes('application/json')) return res.json() as Promise<T>
  return res.text() as unknown as T
}

// ── Scan / Devices ────────────────────────────────────────────────────────────

export const getStatus = () => apiFetch<AppStatus>('/api/status')
export const runScan = (quick = false) =>
  apiFetch<void>('/api/scan', { method: 'POST', body: JSON.stringify({ quick }) })
// Normalize is_known → trusted and latest_ip → ip across both device endpoints
type RawDevice = Partial<Device> & { device_id?: number; latest_ip?: string; is_known?: boolean }
type DeviceListResponse = RawDevice[] | { devices?: RawDevice[] }

function normalizeDevice(d: RawDevice): Device {
  return {
    ...d,
    id: d.id ?? d.device_id ?? 0,
    ip: d.ip ?? d.latest_ip ?? '',
    mac: d.mac ?? null,
    hostname: d.hostname ?? null,
    vendor: d.vendor ?? null,
    label: d.label ?? null,
    trusted: d.trusted ?? d.is_known ?? false,
    last_seen: d.last_seen ?? '',
    open_ports: d.open_ports ?? [],
    os_guess: d.os_guess ?? null,
    ghost_detection: d.ghost_detection ?? null,
  }
}

export const getDevices = async (currentOnly = true): Promise<Device[]> => {
  const raw = await apiFetch<DeviceListResponse>(`/api/devices/all?current_only=${currentOnly}`)
  const arr: RawDevice[] = Array.isArray(raw) ? raw : (raw.devices ?? [])
  return arr.map(normalizeDevice)
}

export const getDevicesSimple = async (): Promise<Device[]> => {
  const raw = await apiFetch<DeviceListResponse>('/api/devices')
  const arr: RawDevice[] = Array.isArray(raw) ? raw : (raw.devices ?? [])
  return arr.map(normalizeDevice)
}

export const trustAllDevices = () =>
  apiFetch<{ updated: number }>('/api/devices/trust-all', { method: 'POST' })
export const getScans = () => apiFetch<Scan[]>('/api/scans')
export const getDevicesAtScan = async (scanId: number): Promise<Device[]> => {
  const raw = await apiFetch<RawDevice[]>(`/api/devices/at-scan/${scanId}`)
  return raw.map(normalizeDevice)
}
export const getDiffLatest = () => apiFetch<DiffResult>('/api/diff/latest')
export const getDeviceHistory = (id: number) => apiFetch<DeviceScan[]>(`/api/device/${id}/history`)
export const getDeviceProfile = (id: number) => apiFetch<DeviceProfile>(`/api/device/${id}/profile`)
export const patchDevice = (id: number, body: Partial<Device & { is_known?: boolean }>) => {
  // Backend uses is_known, frontend uses trusted — normalize
  const payload: Partial<Device> & { is_known?: boolean } = { ...body }
  if ('trusted' in payload) { payload.is_known = payload.trusted; delete payload.trusted }
  return apiFetch<Device>(`/api/device/${id}`, { method: 'PATCH', body: JSON.stringify(payload) })
}

export const getDeviceActivity = (deviceIp: string) =>
  apiFetch<DeviceActivity>(`/api/traffic/device/${encodeURIComponent(deviceIp)}/activity`)

// ── Health ────────────────────────────────────────────────────────────────────

export const getHealthCurrent = () => apiFetch<HealthStatus>('/api/health/current')
export const getHealthHistory = (limit = 120) => apiFetch<HealthPoint[]>(`/api/health/history?limit=${limit}`)
export const runHealthCheck = () => apiFetch<HealthStatus>('/api/health/check', { method: 'POST' })
export const getSpeedLatest = () => apiFetch<SpeedResult>('/api/speed/latest')
export const getSpeedHistory = (limit = 30) => apiFetch<SpeedResult[]>(`/api/speed/history?limit=${limit}`)
export const runSpeedTest = () => apiFetch<SpeedResult>('/api/speed/test', { method: 'POST' })
export const getTelemetry = () => apiFetch<Telemetry>('/api/telemetry')
export const getNetworkInfo = () => apiFetch<NetworkInfo>('/api/network/info')
export const detectNetwork = () => apiFetch<NetworkInfo>('/api/network/detect', { method: 'POST' })

// ── Captive portal (read-only detection — never fills in or submits a form) ───

export interface CaptivePortalField {
  name: string
  type: string
  kind: string | null
}

export interface CaptivePortalPage {
  title: string | null
  form_count: number
  fields: CaptivePortalField[]
  hidden_field_count: number
  requires_identity: boolean
  requires_password: boolean
  requires_otp: boolean
  truncated: boolean
  bytes_read: number
}

export interface CaptivePortalStatus {
  status: 'open' | 'captive' | 'unknown'
  captive: boolean
  url: string | null
  final_url: string | null
  http_status: number | null
  error: string | null
  page: CaptivePortalPage | null
  checked_at: string | null
}

export const getCaptivePortalStatus = () => apiFetch<CaptivePortalStatus>('/api/health/captive-portal')
export const analyzeCaptivePortal = () =>
  apiFetch<CaptivePortalStatus>('/api/health/captive-portal/analyze', { method: 'POST' })

// ── AI ────────────────────────────────────────────────────────────────────────

export const getAILatest = () => apiFetch<AISummary>('/api/ai/latest')
export const getAIProgress = () => apiFetch<AIProgress>('/api/ai/progress', { timeoutMs: 5000 })
export const runAIAnalysis = () => apiFetch<void>('/api/ai/analyze', { method: 'POST' })
export const runAIScanAnalysis = () => apiFetch<void>('/api/ai/analyze/scan', { method: 'POST' })
export const runAITrafficAnalysis = () => apiFetch<void>('/api/ai/analyze/traffic', { method: 'POST' })
export const investigateAI = (body: { item: string; context: string }) =>
  apiFetch<AIInvestigateResult>('/api/ai/investigate', { method: 'POST', body: JSON.stringify(body) })
export const resolveAI = (body: object) =>
  apiFetch<AIResolveResult>('/api/ai/resolve', { method: 'POST', body: JSON.stringify(body) })
export const runHistorySynthesis = (days = 7) =>
  apiFetch<AISynthesisResult>('/api/ai/history-synthesis', { method: 'POST', body: JSON.stringify({ days }) })
export const learnNoise = (apply = false) =>
  apiFetch('/api/autonomy/learn-noise', { method: 'POST', body: JSON.stringify({ apply }) })

// ── Device Investigation Chat ────────────────────────────────────────────────

export interface DeviceChatTurn {
  id: number
  role: 'user' | 'assistant' | 'tool' | 'system'
  content: string
  meta?: DeviceChatMeta
  created_at: string
}
export interface DeviceChatNote {
  id: number
  kind: string
  body: string
  confidence: number | null
  source: string | null
  created_at: string
}
export interface DeviceChatToolReq {
  name: string
  args?: Record<string, unknown>
  rationale?: string
}
export interface DeviceChatMeta {
  tool?: string
  tool_request?: DeviceChatToolReq
  proposal?: DeviceChatProposal
  manual_accept?: boolean
  manual_reject?: boolean
  explanation?: string
  [key: string]: unknown
}
export interface DeviceChatProposal {
  name?: string
  category?: string
  os?: string
  confidence: number
  reasoning?: string
}
export interface DeviceChatResponse {
  appended: DeviceChatTurn[]
  notes: DeviceChatNote[]
  proposal: DeviceChatProposal | null
  proposal_applied: boolean
  applied_changes: string[]
  tool_request: DeviceChatToolReq | null
  pending_approval: boolean
  device: { id: number; label: string | null; os_guess: string | null; is_known: boolean }
}

export const getDeviceChat = (id: number) =>
  apiFetch<{ history: DeviceChatTurn[]; notes: DeviceChatNote[] }>(`/api/device/${id}/chat`)
export const getDeviceChatTools = (id: number) =>
  apiFetch<{ tools: { name: string; active: boolean; desc: string }[] }>(`/api/device/${id}/chat/tools`)
export const postDeviceChat = (id: number, body: {
  message?: string
  approve_tool?: DeviceChatToolReq
  reject_tool?: { name: string }
}) =>
  apiFetch<DeviceChatResponse>(`/api/device/${id}/chat`, { method: 'POST', body: JSON.stringify(body), timeoutMs: 120000 })
export const postDeviceChatProposal = (id: number, body: {
  action: 'accept' | 'reject'
  proposal: DeviceChatProposal
  name?: string
  os?: string
}) =>
  apiFetch<{ applied: boolean; changes: string[]; device?: Partial<Device> }>(`/api/device/${id}/chat/proposal`,
    { method: 'POST', body: JSON.stringify(body) })
export const undoDeviceChat = (id: number) =>
  apiFetch<{ undone: boolean; device?: Partial<Device>; reason?: string }>(`/api/device/${id}/chat/undo`, { method: 'POST' })
export const clearDeviceChat = (id: number) =>
  apiFetch<{ cleared: boolean }>(`/api/device/${id}/chat`, { method: 'DELETE' })
export const explainDeviceChatTurn = (deviceId: number, turnId: number) =>
  apiFetch<{ explanation: string }>(`/api/device/${deviceId}/chat/${turnId}/explain`, { method: 'POST' })

// ── Alerts ───────────────────────────────────────────────────────────────────

export const getAlerts = () => apiFetch<Alert[] | { unread_count: number; alerts: Alert[] }>('/api/alerts')
export const readAlert = (id: number) => apiFetch<void>(`/api/alerts/${id}/read`, { method: 'POST' })
export const readAllAlerts = () => apiFetch<void>('/api/alerts/read-all', { method: 'POST' })
export const deleteAlert = (id: number) => apiFetch<void>(`/api/alerts/${id}`, { method: 'DELETE' })
export const clearReadAlerts = () => apiFetch<{ deleted: number }>('/api/alerts/clear-read', { method: 'DELETE' })
export const explainAlert = (id: number) =>
  apiFetch<{ explanation: string }>(`/api/alerts/${id}/explain`, { method: 'POST' })
export const getContextualInsight = (text: string, context?: string) =>
  apiFetch<{ explanation: string }>('/api/ai/contextual-insight', {
    method: 'POST',
    body: JSON.stringify({ text, context }),
  })

// ── Router firmware (Security Lab remediation) ──────────────────────────────

export const getFirmwareStatus = () =>
  apiFetch<{
    configured: boolean
    success?: boolean
    error?: string | null
    current_version?: string
    new_version?: string | null
    update_available?: boolean
    release_note?: string
  }>('/api/security/firmware-status')

export const updateFirmware = () =>
  apiFetch<{ success: boolean; detail?: string; error?: string | null }>('/api/security/firmware-update', {
    method: 'POST',
    body: JSON.stringify({ confirm: true }),
  })

// ── Logs ─────────────────────────────────────────────────────────────────────

export const getLogs = (params?: Record<string, string>) => {
  const q = params ? '?' + new URLSearchParams(params).toString() : ''
  return apiFetch<LogEntry[] | { total: number; entries: LogEntry[] }>(`/api/logs${q}`)
}
export const getLogFacets = () => apiFetch<LogFacets>('/api/logs/facets')
export const getLogInsights = (days = 7) => apiFetch<LogInsights>(`/api/logs/insights?days=${days}`)
export const clearLogs = () => apiFetch<void>('/api/logs', { method: 'DELETE' })

// ── Traffic ──────────────────────────────────────────────────────────────────

export const getTrafficInterfaces = () => apiFetch<Interface[]>('/api/traffic/interfaces')
export const getTrafficStatus = () => apiFetch<TrafficStatus>('/api/traffic/status')
export const startCapture = (body: object) =>
  apiFetch<void>('/api/traffic/start', { method: 'POST', body: JSON.stringify(body) })
export const stopCapture = () => apiFetch<void>('/api/traffic/stop', { method: 'POST' })
export const getTrafficSummary = () => apiFetch<TrafficSummary>('/api/traffic/summary')
export const getTrafficDashboard = () => apiFetch<TrafficDashboard>('/api/traffic/dashboard')
export const getTrafficDevice = (id: number) => apiFetch<TrafficDeviceDetail>(`/api/traffic/device/${id}`)
export const getDNSLive = () => apiFetch<DNSLiveResult>('/api/traffic/dns-live')
export const getMitmStatus = () => apiFetch<MitmStatus>('/api/traffic/mitm/status')
export const startMitm = (body: object) =>
  apiFetch<void>('/api/traffic/mitm/start', { method: 'POST', body: JSON.stringify(body) })
export const stopMitm = () => apiFetch<void>('/api/traffic/mitm/stop', { method: 'POST' })
export const getIncidents = () => apiFetch<Incident[]>('/api/incidents')
export const getLearningOverview = (limit = 20) =>
  apiFetch<LearningOverview>(`/api/learning/overview?limit=${limit}`)
export const getHuntRules = () => apiFetch<HuntRule[]>('/api/hunt/rules')
export const addHuntRule = (body: object) =>
  apiFetch<HuntRule>('/api/hunt/rules', { method: 'POST', body: JSON.stringify(body) })
export const deleteHuntRule = (id: number) =>
  apiFetch<void>(`/api/hunt/rules/${id}`, { method: 'DELETE' })
export const startDeepCapture = (body: object) =>
  apiFetch<{ capture_id: string }>('/api/ai/deep_capture/start', { method: 'POST', body: JSON.stringify(body) })
export const getDeepCaptureStatus = (id: string) => apiFetch<DeepCaptureStatus>(`/api/ai/deep_capture/${id}`)
export const analyzeTraffic = () =>
  apiFetch<void>('/api/ai/analyze/traffic', { method: 'POST' })

// ── Shield ───────────────────────────────────────────────────────────────────

export const getShield = () => apiFetch<ShieldData>('/api/shield')
export const dismissShieldEvent = (id: number) =>
  apiFetch<void>(`/api/shield/events/${id}/dismiss`, { method: 'POST' })
export const dismissAllShield = () => apiFetch<void>('/api/shield/dismiss-all', { method: 'POST' })
export const clearDNSLogs = () => apiFetch<void>('/api/shield/clear-dns-logs', { method: 'POST' })
export const clearAllLogs = () => apiFetch<void>('/api/shield/clear-all-logs', { method: 'POST' })
export const getAutonomousActions = (status = 'active') =>
  apiFetch<AutonomousAction[]>(`/api/autonomous-actions?status=${status}&limit=50`)
export const revertAction = (id: number) =>
  apiFetch<void>(`/api/autonomous-actions/${id}/revert`, { method: 'POST' })

// ── Uptime Guardian (auto-heal) ───────────────────────────────────────────────

export const getAutoHeal = () => apiFetch<AutoHealData>('/api/autoheal')
export const saveAutoHealConfig = (body: Record<string, unknown>) =>
  apiFetch<{ saved: string[]; password_set: boolean }>('/api/autoheal/config', { method: 'POST', body: JSON.stringify(body) })
export const autoHealRebootNow = (force = false) =>
  apiFetch<Record<string, unknown>>('/api/autoheal/reboot-now', { method: 'POST', body: JSON.stringify({ force }) })
export const autoHealResetCounter = () =>
  apiFetch<{ status: string; cleared_reboots_today: number; counter_reset_at: string }>('/api/autoheal/reset-counter', { method: 'POST' })
export const autoHealSimulate = () =>
  apiFetch<{ dry_run: boolean; enabled: boolean; scenarios: { scenario: string; decision: { action: string; reason?: string } }[] }>(
    '/api/autoheal/simulate', { method: 'POST', body: JSON.stringify({}) })

// ── Reports ──────────────────────────────────────────────────────────────────

export const getReports = (limit = 48) => apiFetch<Report[]>(`/api/reports?limit=${limit}`)
export const runReport = () => apiFetch<void>('/api/reports/run-now', { method: 'POST' })
export const chatReport = (body: object) =>
  apiFetch<ChatResponse>('/api/reports/chat', { method: 'POST', body: JSON.stringify(body) })

// ── DNS Blocker ──────────────────────────────────────────────────────────────

export const getDNSStatus = () => apiFetch<DNSBlockerStatus>('/api/dns/status')
export const enableDNS = () => apiFetch<void>('/api/dns/enable', { method: 'POST' })
export const disableDNS = () => apiFetch<void>('/api/dns/disable', { method: 'POST' })
export const refreshBlocklist = () => apiFetch<void>('/api/dns/blocklist/refresh', { method: 'POST' })
export const resetDNSStats = () => apiFetch<void>('/api/dns/stats/reset', { method: 'POST' })

// ── Settings ─────────────────────────────────────────────────────────────────

export const getSettings = () => apiFetch<Settings>('/api/settings')
export const saveSettings = (body: Partial<Settings>) =>
  apiFetch<Settings>('/api/settings', { method: 'POST', body: JSON.stringify(body) })
export const testNotification = (body: object) =>
  apiFetch<NotifTestResult>('/api/notifications/test', { method: 'POST', body: JSON.stringify(body) })
export const getDiagnostics = () => apiFetch<Diagnostics>('/api/diagnostics/notifications')

// ── Security Lab ─────────────────────────────────────────────────────────────

export const checkWSL = () => apiFetch<WSLCheck>('/api/security/wsl/check', { method: 'POST' })
export const getSecurityRuns = () => apiFetch<SecurityRun[] | { runs: SecurityRun[] }>('/api/security/runs', { method: 'POST', body: JSON.stringify({}) })
export const startNikto = (body: object) =>
  apiFetch<{ run_id: number }>('/api/security/nikto/start', { method: 'POST', body: JSON.stringify(body) })
export const startHydra = (body: object) =>
  apiFetch<{ run_id: number }>('/api/security/hydra/start', { method: 'POST', body: JSON.stringify(body) })
export const startJohn = (body: object) =>
  apiFetch<{ run_id: number }>('/api/security/john/start', { method: 'POST', body: JSON.stringify(body) })
export const startMetasploit = (body: object) =>
  apiFetch<{ run_id: number }>('/api/security/metasploit/start', { method: 'POST', body: JSON.stringify(body) })
export const startWifiCapture = (body: object) =>
  apiFetch<{ run_id: number }>('/api/security/wifi/capture/start', { method: 'POST', body: JSON.stringify(body) })
export const startAircrack = (body: object) =>
  apiFetch<{ run_id: number }>('/api/security/wifi/aircrack/start', { method: 'POST', body: JSON.stringify(body) })
export const shodanSaveSettings = (body: object) =>
  apiFetch<void>('/api/security/shodan/settings', { method: 'POST', body: JSON.stringify(body) })
export const shodanCheck = (body: object) =>
  apiFetch<ShodanResult>('/api/security/shodan/check', { method: 'POST', body: JSON.stringify(body) })
export const securityChat = (body: object) =>
  apiFetch<ChatResponse>('/api/security/chat', { method: 'POST', body: JSON.stringify(body) })
export const cancelSecurityRun = (body: object) =>
  apiFetch<void>('/api/security/run/cancel', { method: 'POST', body: JSON.stringify(body) })
export const getSecLabHistory = (body: object) =>
  apiFetch<SecurityRun[] | { runs: SecurityRun[] }>('/api/security/runs', { method: 'POST', body: JSON.stringify(body) })

// ── Notifications / Command ───────────────────────────────────────────────────

export const sendCommand = (body: object) =>
  apiFetch<void>('/api/command', { method: 'POST', body: JSON.stringify(body) })

// ── Exports ──────────────────────────────────────────────────────────────────

export const exportDevicesCSV = () => window.open('/api/export/devices.csv')
export const exportScansCSV = () => window.open('/api/export/scans.csv')

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AppStatus {
  scanning: boolean
  last_scan: string | null
  device_count: number
  scan?: { running?: boolean; host_count?: number; started_at?: string | null }
}

export interface Device {
  id: number
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  label: string | null
  trusted: boolean
  last_seen: string
  open_ports: number[]
  os_guess: string | null
  is_new?: boolean
  vulnerability_count?: number
  max_cve_risk?: string | null
  ghost_detection?: GhostDetection | null
}

export interface DeviceActivity {
  domains?: { domain: string; count?: number; last_seen?: string }[]
  connections?: Connection[]
  [key: string]: unknown
}

export interface GhostDetection {
  is_ghost: boolean
  kind: 'rogue_ap' | 'shadow_device'
  score: number
  confidence: number
  reasons: string[]
}

export interface LearningLesson {
  id: number | string
  source?: string
  service?: string
  service_label?: string
  pattern?: string
  plain_english?: string
  action?: string
  action_plain_english?: string
  learned_from?: string
  success?: number
  fail?: number
  confidence?: number | null
  suppressed?: boolean
  last_outcome?: string | null
  last_used_at?: string | null
}

export interface LearningTimelineEvent {
  id: number | string
  correlation_id?: string
  source?: string
  service?: string
  event_type?: string
  severity?: string
  summary?: string
  created_at?: string
}

export interface LearningFeedback {
  id: number | string
  source?: string
  target_type?: string
  target?: string
  verdict?: string
  note?: string
  created_at?: string
}

export interface LearningOverview {
  available: boolean
  lessons: LearningLesson[]
  timeline: LearningTimelineEvent[]
  feedback: LearningFeedback[]
  error?: string
}

export interface Scan {
  id: number
  started_at: string
  finished_at: string | null
  device_count: number
  new_devices: number
  host_count?: number
  status?: string
  duration_s?: number
}

export interface DiffResult {
  new_devices: Device[]
  gone_devices: Device[]
  changed_devices: Device[]
  changes?: { change_type?: string; message?: string; created_at?: string }[]
}

export interface DeviceScan {
  scan_id: number
  scanned_at: string
  open_ports: number[]
}

export interface DeviceProfile {
  category: string
  label: string
  confidence: number
  score: number
  evidence: string[]
  signals: {
    vendor: string
    hostname: string
    os_guess: string
    dhcp_option60: string
    dhcp_option55: string
    learned_domains: string[]
    open_ports: number[]
  }
  alternatives: { category: string; label: string; score: number }[]
  source: string
  device?: { id: number; label: string; vendor: string; hostname: string; os_guess: string; is_known: boolean }
  latest_ip?: string | null
}

export interface HealthStatus {
  status?: 'online' | 'offline' | 'degraded'
  online: boolean
  latency_ms: number | null
  packet_loss: number | null
  local_latency_ms: number | null
  download_mbps: number | null
  upload_mbps: number | null
  checked_at: string
}

export interface AutoHealData {
  config?: {
    enabled: boolean; dry_run: boolean; interval_s: number; confirm_checks: number
    method: string; router_host: string; router_user: string; has_password: boolean
    max_per_outage: number; cooldown_s: number; max_per_day: number
    recovery_window_s: number; internet_targets: string[]
    router_ssl?: boolean; router_port?: number | null
    smartplug_method?: string; smartplug_host?: string; smartplug_user?: string; smartplug_has_password?: boolean
  }
  state?: Record<string, unknown> & { offline?: boolean; consecutive_offline?: number; rebooted_this_outage?: boolean }
  stats?: Record<string, unknown> & {
    reboots_today?: number; last_reboot?: string; counter_reset_at?: string
    uptime?: {
      uptime_pct?: number; clean_uptime_pct?: number; degraded_pct?: number; offline_pct?: number; total_checks?: number
      online_checks?: number; degraded_checks?: number; offline_checks?: number
    }
  }
  events?: Record<string, unknown>[]
  incidents?: Record<string, unknown>[]
  playbook?: {
    ai_enabled: boolean; diagnosis: string; proposed_action: string
    safety_checks?: { name: string; passed: boolean; detail: string }[]
  }
}

export interface HealthPoint {
  checked_at: string
  latency_ms: number | null
  online: boolean
}

export interface SpeedResult {
  download_mbps: number
  upload_mbps: number
  tested_at: string
}

export interface Telemetry {
  cpu_percent: number
  ram_percent: number
  disk_percent: number
  uptime_s: number
  cpu_pct?: number
  mem_mb?: number
  pid?: number
}

export interface NetworkInfo {
  local_ip: string
  scan_target: string
  gateway: string
  interface: string | null
}

export interface AISummary {
  summary: string | null
  verdict: string | null
  created_at: string | null
  provider: string | null
  severity?: string | null
  benign?: string[]
  concerning?: string[]
  next_steps?: string[]
  model?: string | null
  error?: string | null
}

export interface AIProgress {
  running: boolean
  partial: string | null
  elapsed_s: number | null
  kind: string | null
}

export interface AIInvestigateResult {
  verdict: string
  what: string
  findings: string[]
  auto_execute: boolean
  proposed_resolutions: Resolution[]
}

export interface Resolution {
  label: string
  action_type: string
  params: Record<string, unknown>
}

export interface AIResolveResult {
  success: boolean
  message: string
}

export interface AISynthesisResult {
  summary: string
}

export interface Alert {
  id: number
  created_at: string
  alert_type: string
  message: string
  read: boolean
  device_id: number | null
}

export interface LogEntry {
  id: number
  event: string
  summary: string
  detail: string | null
  actor: string
  device_ip: string | null
  created_at: string
  revert_json: string | null
  reverted_at: string | null
  level?: string
  category?: string
  reversible?: boolean
}

export interface LogFacets {
  events: { event: string; count: number }[]
  actors: { actor: string; count: number }[]
}

export interface LogInsights {
  total: number
  by_event: Record<string, number>
  by_actor: Record<string, number>
  period_days: number
}

export interface Interface {
  name: string
  ip: string | null
  description: string | null
}

export interface TrafficStatus {
  capturing: boolean
  interface: string | null
  started_at: string | null
  packets_captured: number
}

export interface TrafficSummary {
  top_talkers: { ip: string; bytes: number }[]
  top_dests: { ip: string; bytes: number }[]
  protocol_mix: Record<string, number>
  total_bytes: number
  period_s: number
}

export interface TrafficDashboard {
  capture: TrafficStatus
  summary: TrafficSummary | null
  incidents: Incident[]
  conversations: Conversation[]
}

export interface TrafficDeviceDetail {
  ip: string
  bytes_in: number
  bytes_out: number
  connections: Connection[]
}

export interface Conversation {
  src_ip: string
  dst_ip: string
  dst_port: number
  protocol: string
  bytes: number
  packets?: number
}

export interface Connection {
  remote_ip: string
  port: number
  protocol: string
}

export interface Incident {
  id: number
  severity: string
  title: string
  detail: string | null
  created_at: string
}

export interface HuntRule {
  id: number
  pattern: string
  description: string | null
  enabled: boolean
}

export interface DNSLiveResult {
  queries: DNSQuery[]
}

export interface DNSQuery {
  domain: string
  client_ip: string
  blocked: boolean
  timestamp: string
}

export interface MitmStatus {
  active: boolean
  interface: string | null
  targets: string[]
}

export interface DeepCaptureStatus {
  status: string
  partial: string | null
  result: string | null
}

export interface ShieldData {
  events: ShieldEvent[]
  firewall_rules: FirewallRule[]
  dns_blocks: DNSBlock[]
}

export interface ShieldEvent {
  id: number
  severity: string
  title: string
  detail: string | null
  device_ip: string | null
  created_at: string
  dismissed: boolean
}

export interface FirewallRule {
  name: string
  ip: string
  direction: string
  created_at: string | null
}

export interface DNSBlock {
  domain: string
  count: number
  last_seen: string
}

export interface AutonomousAction {
  id: number
  event: string
  summary: string
  actor: string
  created_at: string
  reverted_at: string | null
  revert_json: string | null
}

export interface Report {
  id: number
  created_at: string
  severity: string
  summary: string
  detail: string | null
  headline?: string
  body?: string | null
}

export interface ChatResponse {
  reply: string
}

export interface DNSBlockerStatus {
  enabled: boolean
  blocked_today: number
  total_blocked: number
  blocklist_size: number
  last_refresh: string | null
}

export interface Settings {
  [key: string]: string | number | boolean | null
}

export interface NotifTestResult {
  success: boolean
  message: string
}

export interface Diagnostics {
  ntfy_url: string | null
  ntfy_topic: string | null
  smtp_host: string | null
}

export interface WSLCheck {
  wsl_available: boolean
  distros: string[]
  tools: Record<string, boolean>
  wsl_installed?: boolean
  kali_present?: boolean
}

export interface SecurityRun {
  id: number
  tool: string
  target: string | null
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  started_at: string
  finished_at: string | null
  ai_explanation: string | null
  risk_level: string | null
}

export interface ShodanResult {
  ip: string
  ports: number[]
  vulns: string[]
  hostnames: string[]
}
