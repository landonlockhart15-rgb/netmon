import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { PlugZap, RotateCw, FlaskConical, Save, Power, Clock, Router as RouterIcon, Activity, ShieldCheck } from 'lucide-react'
import { getAutoHeal, saveAutoHealConfig, autoHealRebootNow, autoHealResetCounter, autoHealSimulate } from '@/lib/api'
import { formatRelativeTime, cn } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile, { type Accent } from '@/components/shared/StatTile'

interface Cfg {
  enabled: boolean; dry_run: boolean; interval_s: number; confirm_checks: number
  method: string; router_host: string; router_user: string; has_password: boolean
  max_per_outage: number; cooldown_s: number; max_per_day: number
  recovery_window_s: number; internet_targets: string[]
  router_ssl?: boolean; router_port?: number | null
  smartplug_method?: string; smartplug_host?: string; smartplug_user?: string; smartplug_has_password?: boolean
}

const ACTION_ACCENT: Record<string, Accent> = {
  online: 'emerald', confirming: 'amber', awaiting_recovery: 'blue',
  cooldown: 'blue', reboot: 'red', giveup: 'red', disabled: 'gray',
}

export default function UptimeGuardian() {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({ queryKey: ['autoheal'], queryFn: getAutoHeal, refetchInterval: 15_000 })
  const [form, setForm] = useState<Record<string, any>>({})
  const [pw, setPw] = useState('')
  const [spw, setSpw] = useState('')
  const [sim, setSim] = useState<any[] | null>(null)

  const cfg: Cfg | undefined = data?.config
  const state = data?.state
  const stats = data?.stats
  const events: any[] = data?.events ?? []
  const incidents: any[] = data?.incidents ?? []
  const rebootsUsed = Number(stats?.reboots_today ?? 0)
  const maxReboots = Number(cfg?.max_per_day ?? 0)
  const rebootsRemaining = Math.max(maxReboots - rebootsUsed, 0)
  const rebootPct = maxReboots > 0 ? Math.min(100, Math.round((rebootsUsed / maxReboots) * 100)) : 0
  const uptime = stats?.uptime
  const uptimePct = uptime?.uptime_pct
  const cleanPct = uptime?.clean_uptime_pct
  const degradedPct = uptime?.degraded_pct
  const offlinePct = uptime?.offline_pct
  const trackedChecks = Number(uptime?.total_checks ?? 0)

  // Seed the editable form once config arrives
  useEffect(() => {
    if (cfg && Object.keys(form).length === 0) {
      setForm({
        autoheal_enabled: cfg.enabled, autoheal_dry_run: cfg.dry_run,
        autoheal_router_host: cfg.router_host, autoheal_router_user: cfg.router_user,
        autoheal_confirm_checks: cfg.confirm_checks, autoheal_interval_s: cfg.interval_s,
        autoheal_max_reboots_per_outage: cfg.max_per_outage,
        autoheal_cooldown_min: Math.round(cfg.cooldown_s / 60),
        autoheal_max_reboots_per_day: cfg.max_per_day,
        autoheal_recovery_window_s: cfg.recovery_window_s,
        autoheal_internet_targets: (cfg.internet_targets || []).join(', '),
        autoheal_reboot_method: cfg.method,
        autoheal_router_ssl: cfg.router_ssl ?? false,
        autoheal_router_port: cfg.router_port ?? '',
        autoheal_smartplug_method: cfg.smartplug_method ?? 'none',
        autoheal_smartplug_host: cfg.smartplug_host ?? '',
        autoheal_smartplug_user: cfg.smartplug_user ?? '',
      })
    }
  }, [cfg]) // eslint-disable-line react-hooks/exhaustive-deps

  const saveMut = useMutation({
    mutationFn: () => {
      const body: Record<string, any> = { ...form }
      if (pw.trim()) body.autoheal_router_pass = pw.trim()
      if (spw.trim()) body.autoheal_smartplug_pass = spw.trim()
      return saveAutoHealConfig(body)
    },
    onSuccess: () => { setPw(''); setSpw(''); qc.invalidateQueries({ queryKey: ['autoheal'] }) },
  })
  const rebootMut = useMutation({
    mutationFn: (force: boolean) => autoHealRebootNow(force),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['autoheal'] }),
  })
  const resetMut = useMutation({
    mutationFn: autoHealResetCounter,
    onSuccess: d => {
      qc.setQueryData(['autoheal'], (old: any) => old ? {
        ...old,
        stats: {
          ...(old.stats ?? {}),
          reboots_today: 0,
          counter_reset_at: d.counter_reset_at,
        },
      } : old)
      qc.invalidateQueries({ queryKey: ['autoheal'] })
    },
  })
  const simMut = useMutation({ mutationFn: autoHealSimulate, onSuccess: d => setSim(d.scenarios) })

  const set = (k: string, v: any) => setForm(f => ({ ...f, [k]: v }))

  // Hero theming
  const offline = state?.offline
  const enabled = cfg?.enabled
  const dry = cfg?.dry_run
  const accent: Accent = !enabled ? 'gray' : offline ? 'red' : dry ? 'amber' : 'emerald'
  const eyebrow = !enabled ? 'Disabled' : offline ? 'Outage in progress' : dry ? 'Armed · dry-run' : 'Armed · live'
  const mode = !enabled ? 'Off' : dry ? 'Dry-run' : 'Live'

  return (
    <div className="space-y-4">
      <PageHero
        icon={PlugZap}
        accent={accent}
        pulse={!!offline || (enabled && !dry)}
        eyebrow={eyebrow}
        title="Uptime Guardian"
        subtitle="Watches for internet outages and reboots the router to bring you back online — diagnosed locally, no cloud."
        tiles={
          <>
            <StatTile icon={<Power size={11} />} label="Mode" accent={accent} glow value={<span className="text-base">{mode}</span>} sub={cfg ? `checks every ${cfg.interval_s}s` : ''} />
            <StatTile icon={<Activity size={11} />} label="Availability" accent={uptimePct == null ? 'gray' : uptimePct >= 99 ? 'emerald' : uptimePct >= 95 ? 'amber' : 'red'} value={<span className="text-base">{formatPct(uptimePct)}</span>} sub={trackedChecks ? `${trackedChecks} tracked checks` : 'starts on next check'} />
            <StatTile icon={<Clock size={11} />} label="Last Reboot" accent="blue" value={stats?.last_reboot ? formatRelativeTime(stats.last_reboot) : '—'} sub="most recent" />
            <StatTile icon={<RouterIcon size={11} />} label="Router" accent="cyan" value={<span className="text-sm font-mono">{cfg?.router_host ?? '—'}</span>} sub={cfg?.has_password ? 'password set' : 'no password'} />
          </>
        }
      />

      {/* Live state banner */}
      {offline && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 flex items-center gap-2 text-sm text-red-300">
          <Activity size={16} className="animate-pulse" />
          Internet outage detected{state?.consecutive_offline ? ` — ${state.consecutive_offline} consecutive failed checks` : ''}
          {state?.rebooted_this_outage && ' · reboot already attempted this outage'}
        </div>
      )}

      {/* Test + manual controls */}
      <Card title="Test & Manual Control"
        action={
          <div className="flex flex-wrap justify-end gap-2">
            <Btn variant="secondary" size="sm" loading={simMut.isPending} onClick={() => simMut.mutate()}>
              <FlaskConical size={13} /> Test Logic
            </Btn>
            <Btn variant="secondary" size="sm" loading={rebootMut.isPending}
              onClick={() => {
                if (cfg && !cfg.dry_run) { if (!confirm('Send a REAL reboot now? Your network will drop for ~2–4 min.')) return }
                rebootMut.mutate(false)
              }}>
              <RotateCw size={13} /> Reboot Now
            </Btn>
            <Btn variant="secondary" size="sm" loading={resetMut.isPending}
              onClick={() => {
                if (!confirm('Reset the Uptime Guardian reboot counter to 0? Prior events stay in the activity log.')) return
                resetMut.mutate()
              }}>
              <RotateCw size={13} /> Reset Count
            </Btn>
          </div>
        }>
        <p className="text-xs text-gray-500">
          <strong className="text-gray-300">Test Logic</strong> runs the decision engine against synthetic outages (no side effects).
          {' '}<strong className="text-gray-300">Reboot Now</strong> {cfg?.dry_run ? 'is in dry-run — it logs the intent but sends no real reboot.' : 'sends a REAL reboot immediately.'}
        </p>
        <div className="mt-3 rounded-lg border border-white/8 bg-[#0f0f1a] p-3">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
            <span className="font-medium text-gray-300">Connection quality</span>
            <span className="font-mono text-emerald-300">{formatPct(uptimePct)} available</span>
          </div>
          <div className="mt-2 flex h-2 overflow-hidden rounded-full bg-white/8">
            <QualitySegment label="Clean" value={cleanPct} color="bg-emerald-400" />
            <QualitySegment label="Degraded" value={degradedPct} color="bg-amber-400" />
            <QualitySegment label="Offline" value={offlinePct} color="bg-red-400" />
          </div>
          <div className="mt-2 grid grid-cols-1 gap-2 text-[11px] text-gray-500 sm:grid-cols-3">
            <QualityStat label="Clean" value={cleanPct} count={uptime?.online_checks} />
            <QualityStat label="Degraded" value={degradedPct} count={uptime?.degraded_checks} />
            <QualityStat label="Offline" value={offlinePct} count={uptime?.offline_checks} />
          </div>
          <p className="mt-2 text-[11px] text-gray-600">
            Availability counts clean and degraded checks as up; degraded and offline are tracked separately.
          </p>
        </div>
        <div className="mt-3 rounded-lg border border-white/8 bg-[#0f0f1a] p-3">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
            <span className="font-medium text-gray-300">Counted reboot attempts</span>
            <span className={cn('font-mono', rebootsUsed >= maxReboots && maxReboots > 0 ? 'text-red-300' : rebootsUsed ? 'text-amber-300' : 'text-emerald-300')}>
              {rebootsUsed} used / {maxReboots || '—'} max
            </span>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-white/8">
            <div
              className={cn('h-full rounded-full transition-all', rebootsUsed >= maxReboots && maxReboots > 0 ? 'bg-red-400' : rebootsUsed ? 'bg-amber-400' : 'bg-emerald-400')}
              style={{ width: `${rebootPct}%` }}
            />
          </div>
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-gray-600">
            <span>{rebootsRemaining} reboot attempt{rebootsRemaining === 1 ? '' : 's'} remaining before the daily cap</span>
            <span>Last reset: {stats?.counter_reset_at ? formatRelativeTime(stats.counter_reset_at) : 'never'}</span>
          </div>
        </div>
        {rebootMut.data && (
          <div className={cn('mt-2 rounded-lg border p-2 text-xs', rebootMut.data.success ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300' : 'border-red-500/30 bg-red-500/5 text-red-300')}>
            {rebootMut.data.dry_run ? 'Dry-run: no real reboot sent.' : rebootMut.data.success ? 'Reboot command sent to router.' : `Reboot failed: ${rebootMut.data.error}`}
          </div>
        )}
        {resetMut.data && (
          <div className="mt-2 rounded-lg border border-blue-500/30 bg-blue-500/5 p-2 text-xs text-blue-300">
            Reboot counter reset to 0. Cleared {resetMut.data.cleared_reboots_today} counted attempt{resetMut.data.cleared_reboots_today === 1 ? '' : 's'}.
          </div>
        )}
        {sim && (
          <div className="mt-3 space-y-1.5">
            {sim.map((s, i) => (
              <div key={i} className="flex items-center justify-between gap-2 rounded-lg border border-white/8 bg-[#0f0f1a] px-3 py-2 text-xs">
                <span className="text-gray-300 truncate">{s.scenario}</span>
                <Badge variant={ACTION_ACCENT[s.decision.action] === 'red' ? 'error' : ACTION_ACCENT[s.decision.action] === 'amber' ? 'warn' : ACTION_ACCENT[s.decision.action] === 'emerald' ? 'ok' : 'info'}>
                  {s.decision.action}
                </Badge>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Configuration */}
      <Card title="Configuration"
        action={<Btn variant="primary" size="sm" loading={saveMut.isPending} onClick={() => saveMut.mutate()}><Save size={13} /> Save</Btn>}>
        {isLoading || !cfg ? (
          <EmptyState icon="◎" text="Loading…" />
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-6">
              <Toggle label="Enabled" hint="Master switch for the Uptime Guardian" checked={!!form.autoheal_enabled} onChange={v => set('autoheal_enabled', v)} />
              <Toggle label="Dry-run" hint="Detect & log only — never sends a real reboot" checked={!!form.autoheal_dry_run} onChange={v => set('autoheal_dry_run', v)} />
              <Toggle label="Use HTTPS (SSL)" hint="Enforce SSL (required for Orbi/CBR)" checked={!!form.autoheal_router_ssl} onChange={v => set('autoheal_router_ssl', v)} />
            </div>

            {form.autoheal_enabled && !form.autoheal_dry_run && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-2.5 text-xs text-amber-300 flex items-center gap-2">
                <ShieldCheck size={14} /> Live mode is on — confirmed outages will trigger a real router reboot.
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="col-span-1 sm:col-span-2 border-b border-white/5 pb-1">
                <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Primary Reboot Method</span>
              </div>

              <Field label="Reboot Method">
                <select value={form.autoheal_reboot_method ?? 'netgear_soap'} onChange={e => set('autoheal_reboot_method', e.target.value)}
                  className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-purple-500 w-full">
                  <option value="netgear_soap" className="bg-[#0f0f1a]">Netgear SOAP (Orbi/CBR)</option>
                  <option value="tasmota" className="bg-[#0f0f1a]">Tasmota Smart Plug (local HTTP)</option>
                  <option value="shelly" className="bg-[#0f0f1a]">Shelly Smart Plug (local HTTP)</option>
                  <option value="kasa" className="bg-[#0f0f1a]">TP-Link Kasa Smart Plug (local TCP)</option>
                </select>
              </Field>

              <Field label={form.autoheal_reboot_method === 'netgear_soap' ? 'Router admin host' : 'Smart plug host (IP/Name)'}>
                <Input value={form.autoheal_router_host ?? ''} onChange={v => set('autoheal_router_host', v)} placeholder={form.autoheal_reboot_method === 'netgear_soap' ? '192.168.1.1 (auto)' : 'e.g. 192.168.1.100'} mono />
              </Field>

              {form.autoheal_reboot_method !== 'kasa' && (
                <Field label={form.autoheal_reboot_method === 'netgear_soap' ? 'Router admin user' : 'Smart plug username'}>
                  <Input value={form.autoheal_router_user ?? ''} onChange={v => set('autoheal_router_user', v)} placeholder={form.autoheal_reboot_method === 'netgear_soap' ? 'admin' : 'optional'} />
                </Field>
              )}

              <Field label={form.autoheal_reboot_method === 'netgear_soap' ? `Router password ${cfg.has_password ? '(set — leave blank to keep)' : '(not set)'}` : `Smart plug password ${cfg.has_password ? '(set — leave blank to keep)' : '(not set)'}`}>
                <Input type="password" value={pw} onChange={setPw} placeholder={cfg.has_password ? '••••••••' : 'enter password'} />
              </Field>

              {form.autoheal_reboot_method === 'netgear_soap' && (
                <Field label="Router port (blank = 443 with SSL, otherwise auto)">
                  <Input value={form.autoheal_router_port ?? ''} onChange={v => set('autoheal_router_port', v)} placeholder="e.g. 443 or 5000" mono />
                </Field>
              )}

              {form.autoheal_reboot_method === 'netgear_soap' && (
                <>
                  <div className="col-span-1 sm:col-span-2 border-b border-white/5 pt-2 pb-1">
                    <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Smart Plug Fallback (Power-Cycle Router)</span>
                    <p className="text-[10px] text-gray-500 mt-0.5">Physically power-cycle the router if the primary SOAP reboot is unresponsive during network lockup.</p>
                  </div>

                  <Field label="Smart Plug Fallback Method">
                    <select value={form.autoheal_smartplug_method ?? 'none'} onChange={e => set('autoheal_smartplug_method', e.target.value)}
                      className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-purple-500 w-full">
                      <option value="none" className="bg-[#0f0f1a]">None (No fallback)</option>
                      <option value="tasmota" className="bg-[#0f0f1a]">Tasmota Smart Plug (local HTTP)</option>
                      <option value="shelly" className="bg-[#0f0f1a]">Shelly Smart Plug (local HTTP)</option>
                      <option value="kasa" className="bg-[#0f0f1a]">TP-Link Kasa Smart Plug (local TCP)</option>
                    </select>
                  </Field>

                  {form.autoheal_smartplug_method && form.autoheal_smartplug_method !== 'none' && (
                    <>
                      <Field label="Fallback Plug Host (IP)">
                        <Input value={form.autoheal_smartplug_host ?? ''} onChange={v => set('autoheal_smartplug_host', v)} placeholder="e.g. 192.168.1.100" mono />
                      </Field>
                      
                      {form.autoheal_smartplug_method !== 'kasa' && (
                        <Field label="Fallback Plug Username">
                          <Input value={form.autoheal_smartplug_user ?? ''} onChange={v => set('autoheal_smartplug_user', v)} placeholder="optional" />
                        </Field>
                      )}

                      <Field label={`Fallback Plug Password ${cfg.smartplug_has_password ? '(set — leave blank to keep)' : '(not set)'}`}>
                        <Input type="password" value={spw} onChange={setSpw} placeholder={cfg.smartplug_has_password ? '••••••••' : 'enter password'} />
                      </Field>
                    </>
                  )}
                </>
              )}

              <div className="col-span-1 sm:col-span-2 border-b border-white/5 pt-2 pb-1">
                <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">Guardian Parameters</span>
              </div>

              <Field label="Internet targets (comma-sep)"><Input value={form.autoheal_internet_targets ?? ''} onChange={v => set('autoheal_internet_targets', v)} mono /></Field>
              <Field label="Confirm checks before acting"><Input type="number" value={form.autoheal_confirm_checks ?? ''} onChange={v => set('autoheal_confirm_checks', v)} /></Field>
              <Field label="Check interval (seconds)"><Input type="number" value={form.autoheal_interval_s ?? ''} onChange={v => set('autoheal_interval_s', v)} /></Field>
              <Field label="Max reboots per outage"><Input type="number" value={form.autoheal_max_reboots_per_outage ?? ''} onChange={v => set('autoheal_max_reboots_per_outage', v)} /></Field>
              <Field label="Cooldown between reboots (min)"><Input type="number" value={form.autoheal_cooldown_min ?? ''} onChange={v => set('autoheal_cooldown_min', v)} /></Field>
              <Field label="Max reboots per day"><Input type="number" value={form.autoheal_max_reboots_per_day ?? ''} onChange={v => set('autoheal_max_reboots_per_day', v)} /></Field>
              <Field label="Recovery window (seconds)"><Input type="number" value={form.autoheal_recovery_window_s ?? ''} onChange={v => set('autoheal_recovery_window_s', v)} /></Field>
            </div>
            <p className="text-[11px] text-gray-600">
              Supports Netgear SOAP API or local smart plug (Tasmota, Shelly, TP-Link Kasa) to power-cycle the router. Passwords are stored server-side and never leave your machine.
            </p>
          </div>
        )}
      </Card>

      {/* Event feed -> AI Narrated Timeline */}
      <Card title="AI-Narrated Self-Healing Timeline" badge={incidents.length ? String(incidents.length) : undefined}>
        {incidents.length === 0 ? (
          <EmptyState icon="◎" text="No auto-heal events yet" hint="Outage detections, reboots, and recoveries will appear here." />
        ) : (
          <div className="space-y-4">
            {incidents.map((inc) => {
              const isReset = inc.type === 'reset'
              const isResolved = inc.status === 'resolved'
              const isFailed = inc.status === 'failed'
              const isRebooting = inc.status === 'rebooting'
              const isOngoing = inc.status === 'outage'
              
              let statusLabel = 'Outage Detected'
              let dotColor = 'bg-amber-400'
              if (isReset) {
                statusLabel = 'Safety Counter Reset'
                dotColor = 'bg-blue-400'
              } else if (isResolved) {
                statusLabel = 'Internet Restored'
                dotColor = 'bg-emerald-400'
              } else if (isFailed) {
                statusLabel = 'Outage Recovery Failed (Safety Limit)'
                dotColor = 'bg-red-400'
              } else if (isRebooting) {
                statusLabel = 'Reboot Action Triggered'
                dotColor = 'bg-purple-400'
              } else if (isOngoing) {
                statusLabel = 'Outage Active'
                dotColor = 'bg-red-500 animate-pulse'
              }

              return (
                <div key={inc.id} className="relative pl-6 border-l border-white/10 last:border-0 pb-2">
                  {/* Timeline Dot */}
                  <span className={cn('absolute -left-1.5 top-1.5 h-3 w-3 rounded-full border border-[#0f0f1a]', dotColor)} />

                  {/* Header info */}
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                    <span className="font-semibold text-gray-200">{statusLabel}</span>
                    <span className="text-gray-500 font-mono text-[10px]">
                      {formatRelativeTime(inc.start_time)}
                      {inc.downtime_s != null && ` (downtime: ${formatDowntime(inc.downtime_s)})`}
                    </span>
                  </div>

                  {/* AI Narrative Section */}
                  {inc.ai_narrative ? (
                    <div className="mt-1.5 rounded-lg border border-purple-500/20 bg-purple-500/5 px-3 py-2 text-xs">
                      <div className="flex items-center gap-1.5 text-[10px] font-semibold text-purple-400 uppercase tracking-wider mb-1">
                        <PlugZap size={10} className="text-purple-400" />
                        <span>Guardian Report</span>
                        {inc.ai_narrative === 'Generating AI narrative...' && (
                          <span className="inline-block h-1.5 w-1.5 animate-ping rounded-full bg-purple-400" />
                        )}
                      </div>
                      <p className={cn(
                        'text-gray-300 italic leading-relaxed',
                        inc.ai_narrative === 'Generating AI narrative...' && 'animate-pulse text-gray-500'
                      )}>
                        {inc.ai_narrative}
                      </p>
                    </div>
                  ) : (
                    /* Fallback when AI is off/failed: show storyline directly */
                    <p className="mt-1 text-gray-400 text-xs leading-relaxed">
                      {inc.storyline}
                    </p>
                  )}

                  {/* Expandable Technical steps if AI narrative is shown or if they want full info */}
                  {inc.ai_narrative && (
                    <details className="group mt-2">
                      <summary className="cursor-pointer text-[10px] text-gray-500 hover:text-gray-300 select-none flex items-center gap-1 font-mono">
                        <span className="transition-transform group-open:rotate-90">▶</span> Technical sequence details
                      </summary>
                      <div className="mt-1.5 pl-3 border-l border-white/5 space-y-1">
                        {inc.events.map((e: any) => (
                          <div key={e.id} className="text-[11px] text-gray-400 flex items-center justify-between gap-4">
                            <span>• {e.summary}</span>
                            <span className="text-gray-600 font-mono text-[9px] flex-shrink-0">{formatRelativeTime(e.created_at)}</span>
                          </div>
                        ))}
                      </div>
                    </details>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </Card>
    </div>
  )
}

function Toggle({ label, hint, checked, onChange }: { label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-3 cursor-pointer group">
      <div className="relative">
        <input type="checkbox" className="sr-only peer" checked={checked} onChange={e => onChange(e.target.checked)} />
        <div className="w-10 h-5 bg-white/10 peer-checked:bg-purple-600 rounded-full transition-colors" />
        <div className="absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-5" />
      </div>
      <div>
        <span className="text-sm text-gray-200 group-hover:text-white transition-colors">{label}</span>
        {hint && <p className="text-[10px] text-gray-600">{hint}</p>}
      </div>
    </label>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <label className="text-xs text-gray-500">{label}</label>
      {children}
    </div>
  )
}

function Input({ value, onChange, type = 'text', placeholder, mono }: {
  value: string | number; onChange: (v: string) => void; type?: string; placeholder?: string; mono?: boolean
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      className={cn('w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500', mono && 'font-mono')}
    />
  )
}

function QualitySegment({ label, value, color }: { label: string; value?: number | null; color: string }) {
  const pct = value == null ? 0 : Math.max(0, Math.min(100, Number(value)))
  return (
    <div
      className={cn('h-full transition-all', color)}
      style={{ width: `${pct}%`, minWidth: pct > 0 && pct < 1 ? 2 : undefined }}
    >
      <span className="sr-only">{label}</span>
    </div>
  )
}

function QualityStat({ label, value, count }: { label: string; value?: number | null; count?: number }) {
  return (
    <div className="rounded-md border border-white/5 bg-white/[0.02] px-2 py-1.5">
      <div className="flex items-center justify-between gap-2">
        <span>{label}</span>
        <span className="font-mono text-gray-300">{formatPct(value)}</span>
      </div>
      <div className="mt-0.5 font-mono text-[10px] text-gray-700">{Number(count ?? 0)} checks</div>
    </div>
  )
}

function formatPct(value?: number | null) {
  return value == null ? '—' : `${Number(value).toFixed(3).replace(/\.?0+$/, '')}%`
}

function formatDowntime(seconds: number) {
  if (seconds < 90) return `${Math.round(seconds)}s`
  const minutes = seconds / 60
  if (minutes < 60) return `${minutes.toFixed(1)}m`
  return `${(minutes / 60).toFixed(1)}h`
}
