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
  const [sim, setSim] = useState<any[] | null>(null)

  const cfg: Cfg | undefined = data?.config
  const state = data?.state
  const stats = data?.stats
  const events: any[] = data?.events ?? []
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
      })
    }
  }, [cfg]) // eslint-disable-line react-hooks/exhaustive-deps

  const saveMut = useMutation({
    mutationFn: () => {
      const body: Record<string, any> = { ...form }
      if (pw.trim()) body.autoheal_router_pass = pw.trim()
      return saveAutoHealConfig(body)
    },
    onSuccess: () => { setPw(''); qc.invalidateQueries({ queryKey: ['autoheal'] }) },
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
              <Field label="Router admin host"><Input value={form.autoheal_router_host ?? ''} onChange={v => set('autoheal_router_host', v)} placeholder="192.168.1.1 (auto)" mono /></Field>
              <Field label="Router admin user"><Input value={form.autoheal_router_user ?? ''} onChange={v => set('autoheal_router_user', v)} placeholder="admin" /></Field>
              <Field label={`Router password ${cfg.has_password ? '(set — leave blank to keep)' : '(not set)'}`}>
                <Input type="password" value={pw} onChange={setPw} placeholder={cfg.has_password ? '••••••••' : 'enter admin password'} />
              </Field>
              <Field label="Router port (blank = 443 with SSL, otherwise auto)"><Input value={form.autoheal_router_port ?? ''} onChange={v => set('autoheal_router_port', v)} placeholder="e.g. 443 or 5000" mono /></Field>
              <Field label="Internet targets (comma-sep)"><Input value={form.autoheal_internet_targets ?? ''} onChange={v => set('autoheal_internet_targets', v)} mono /></Field>
              <Field label="Confirm checks before acting"><Input type="number" value={form.autoheal_confirm_checks ?? ''} onChange={v => set('autoheal_confirm_checks', v)} /></Field>
              <Field label="Check interval (seconds)"><Input type="number" value={form.autoheal_interval_s ?? ''} onChange={v => set('autoheal_interval_s', v)} /></Field>
              <Field label="Max reboots per outage"><Input type="number" value={form.autoheal_max_reboots_per_outage ?? ''} onChange={v => set('autoheal_max_reboots_per_outage', v)} /></Field>
              <Field label="Cooldown between reboots (min)"><Input type="number" value={form.autoheal_cooldown_min ?? ''} onChange={v => set('autoheal_cooldown_min', v)} /></Field>
              <Field label="Max reboots per day"><Input type="number" value={form.autoheal_max_reboots_per_day ?? ''} onChange={v => set('autoheal_max_reboots_per_day', v)} /></Field>
              <Field label="Recovery window (seconds)"><Input type="number" value={form.autoheal_recovery_window_s ?? ''} onChange={v => set('autoheal_recovery_window_s', v)} /></Field>
            </div>
            <p className="text-[11px] text-gray-600">
              Router: Netgear Orbi CBR750 (all-in-one modem + router) — reboot via the Netgear SOAP API. The password is stored server-side and never leaves your machine.
            </p>
          </div>
        )}
      </Card>

      {/* Event feed */}
      <Card title="Recent Activity" badge={events.length ? String(events.length) : undefined}>
        {events.length === 0 ? (
          <EmptyState icon="◎" text="No auto-heal events yet" hint="Outage detections, reboots, and recoveries will appear here." />
        ) : (
          <div className="space-y-1.5">
            {events.map(e => (
              <div key={e.id} className="flex items-start gap-3 rounded-lg border border-white/5 bg-[#0f0f1a] px-3 py-2 text-xs">
                <span className={cn('mt-0.5 h-1.5 w-1.5 rounded-full flex-shrink-0',
                  e.level === 'warning' ? 'bg-amber-400' : e.level === 'action' ? 'bg-purple-400' : 'bg-emerald-400')} />
                <span className="flex-1 text-gray-300">{e.summary}</span>
                <span className="text-gray-600 flex-shrink-0">{formatRelativeTime(e.created_at)}</span>
              </div>
            ))}
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
