import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { PlugZap, RotateCw, FlaskConical, Save, Power, Clock, Router as RouterIcon, Activity, ShieldCheck } from 'lucide-react'
import { getAutoHeal, saveAutoHealConfig, autoHealRebootNow, autoHealSimulate } from '@/lib/api'
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
            <StatTile icon={<RotateCw size={11} />} label="Reboots Today" accent={stats?.reboots_today ? 'amber' : 'gray'} value={stats?.reboots_today ?? 0} sub={`max ${cfg?.max_per_day ?? '—'}/day`} />
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
          <div className="flex gap-2">
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
          </div>
        }>
        <p className="text-xs text-gray-500">
          <strong className="text-gray-300">Test Logic</strong> runs the decision engine against synthetic outages (no side effects).
          {' '}<strong className="text-gray-300">Reboot Now</strong> {cfg?.dry_run ? 'is in dry-run — it logs the intent but sends no real reboot.' : 'sends a REAL reboot immediately.'}
        </p>
        {rebootMut.data && (
          <div className={cn('mt-2 rounded-lg border p-2 text-xs', rebootMut.data.success ? 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300' : 'border-red-500/30 bg-red-500/5 text-red-300')}>
            {rebootMut.data.dry_run ? 'Dry-run: no real reboot sent.' : rebootMut.data.success ? 'Reboot command sent to router.' : `Reboot failed: ${rebootMut.data.error}`}
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
