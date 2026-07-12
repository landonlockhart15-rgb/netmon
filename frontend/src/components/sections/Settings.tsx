import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Save, Send, RefreshCw, SlidersHorizontal } from 'lucide-react'
import { getSettings, saveSettings, testNotification, getDiagnostics, detectNetwork, type Settings } from '@/lib/api'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import PageHero from '@/components/shared/PageHero'
import { GuestModeToggle } from '@/components/shared/GuestModeToggle'

export default function Settings() {
  const qc = useQueryClient()
  const { data: settings } = useQuery({ queryKey: ['settings'], queryFn: getSettings })
  const { data: diag } = useQuery({ queryKey: ['diagnostics'], queryFn: getDiagnostics })

  const saveMutation = useMutation({
    mutationFn: (body: Partial<Settings>) => saveSettings(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings'] }),
  })

  const testNotifMutation = useMutation({ mutationFn: () => testNotification({}) })
  const detectMutation = useMutation({ mutationFn: detectNetwork, onSuccess: () => qc.invalidateQueries({ queryKey: ['netinfo'] }) })

  if (!settings) return <div className="text-sm text-gray-500">Loading settings…</div>

  return (
    <div className="space-y-4">
      <PageHero
        icon={SlidersHorizontal}
        accent="purple"
        eyebrow="Configuration"
        title="Settings"
        subtitle="Tune scanning, health checks, AI, notifications, and anomaly detection. Changes save instantly."
      />

      {/* Guest Mode — master safety switch for untrusted networks */}
      <GuestModeToggle />

      {/* Service controls */}
      <CfgCard title="Service Controls" icon="⏻">
        <Toggle label="NetMon enabled" settingKey="netmon_enabled" settings={settings} onSave={saveMutation.mutate} />
        <p className="mt-2 text-xs text-gray-500">
          Turn this off before planned lock-screen, travel, or internet-offline windows. The dashboard stays reachable, but scans, health checks, auto-heal, and anomaly reactions pause.
        </p>
      </CfgCard>

      {/* Scanning */}
      <CfgCard title="Scanning" icon="◉">
        <Toggle label="Auto-scan enabled" settingKey="auto_scan_enabled" settings={settings} onSave={saveMutation.mutate} />
        <TextInput label="Scan interval (hours)" settingKey="auto_scan_interval_h" type="number" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
      </CfgCard>

      {/* Health */}
      <CfgCard title="Health Checks" icon="◎">
        <Toggle label="Health alerts enabled" settingKey="health_alerts_enabled" settings={settings} onSave={saveMutation.mutate} />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
          <TextInput label="Check interval (s)" settingKey="health_check_interval_s" type="number" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
          <TextInput label="Internet target" settingKey="health_target" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
          <TextInput label="Local target (router)" settingKey="health_local_target" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
          <TextInput label="Latency warn (ms)" settingKey="latency_warn_ms" type="number" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
          <TextInput label="Latency critical (ms)" settingKey="latency_crit_ms" type="number" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
          <TextInput label="Packet loss warn (%)" settingKey="packet_loss_warn_pct" type="number" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
        </div>
      </CfgCard>

      {/* Speed test */}
      <CfgCard title="Speed Test" icon="⟋">
        <TextInput label="Speed test URL" settingKey="speed_test_url" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
      </CfgCard>

      {/* AI */}
      <CfgCard title="AI Analysis" icon="◈">
        <Toggle label="AI enabled" settingKey="ai_enabled" settings={settings} onSave={saveMutation.mutate} />
        <Toggle label="Auto-analyze after scan" settingKey="ai_auto_analyze" settings={settings} onSave={saveMutation.mutate} />
      </CfgCard>

      {/* Notifications */}
      <CfgCard title="Notifications" icon="◎">
        <div className="space-y-4">
          <div>
            <p className="text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">ntfy</p>
            <Toggle label="ntfy enabled" settingKey="ntfy_enabled" settings={settings} onSave={saveMutation.mutate} />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
              <TextInput label="Server URL" settingKey="ntfy_server" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} hint={diag?.ntfy_url ?? undefined} />
              <TextInput label="Topic" settingKey="ntfy_topic" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} hint={diag?.ntfy_topic ?? undefined} />
              <TextInput label="Username" settingKey="ntfy_user" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
              <TextInput label="Password" settingKey="ntfy_pass" type="password" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
            </div>
          </div>
          <div>
            <p className="text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">Email (SMTP)</p>
            <Toggle label="Email enabled" settingKey="email_enabled" settings={settings} onSave={saveMutation.mutate} />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
              <TextInput label="To address" settingKey="email_to" type="email" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
              <TextInput label="SMTP user" settingKey="smtp_user" type="email" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
              <TextInput label="SMTP password" settingKey="smtp_pass" type="password" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
            </div>
          </div>
          <Btn variant="secondary" size="sm" loading={testNotifMutation.isPending} onClick={() => testNotifMutation.mutate()}>
            <Send size={13} /> Send Test Notification
          </Btn>
          {testNotifMutation.data && (
            <p className={`text-xs ${testNotifMutation.data.success ? 'text-emerald-400' : 'text-red-400'}`}>
              {testNotifMutation.data.message}
            </p>
          )}
        </div>
      </CfgCard>

      {/* Anomaly detection */}
      <CfgCard title="Anomaly Detection" icon="⬡">
        <Toggle label="Anomaly detection enabled" settingKey="anomaly_detection_enabled" settings={settings} onSave={saveMutation.mutate} />
        <div className="mt-3">
          <TextInput label="Spike multiplier" settingKey="anomaly_spike_multiplier" type="number" settings={settings} onSave={(k, v) => saveMutation.mutate({ [k]: v })} />
        </div>
      </CfgCard>

      {/* Network */}
      <CfgCard title="Network" icon="⬡">
        <div className="flex items-center gap-2">
          <Btn variant="secondary" size="sm" loading={detectMutation.isPending} onClick={() => detectMutation.mutate()}>
            <RefreshCw size={13} /> Re-detect Network
          </Btn>
        </div>
      </CfgCard>
    </div>
  )
}

function CfgCard({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) {
  return (
    <Card title={`${icon} ${title}`}>
      {children}
    </Card>
  )
}

function Toggle({ label, settingKey, settings, onSave }: {
  label: string
  settingKey: string
  settings: Settings
  onSave: (body: Partial<Settings>) => void
}) {
  const value = settings[settingKey]
  const checked = value === true || value === 'true' || value === 1
  return (
    <label className="flex items-center gap-3 cursor-pointer group">
      <div className="relative">
        <input
          type="checkbox"
          className="sr-only peer"
          checked={checked}
          onChange={e => onSave({ [settingKey]: e.target.checked ? 'true' : 'false' })}
        />
        <div className="w-10 h-5 bg-white/10 peer-checked:bg-purple-600 rounded-full transition-colors" />
        <div className="absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-5" />
      </div>
      <span className="text-sm text-gray-300 group-hover:text-white transition-colors">{label}</span>
    </label>
  )
}

function TextInput({ label, settingKey, type = 'text', settings, onSave, hint }: {
  label: string
  settingKey: string
  type?: string
  settings: Settings
  onSave: (key: string, value: string) => void
  hint?: string
}) {
  const raw = settings[settingKey]
  const initial = raw != null ? String(raw) : ''
  const [val, setVal] = useState(initial)

  return (
    <div className="space-y-1">
      <label className="text-xs text-gray-500">{label}</label>
      <div className="flex gap-2">
        <input
          type={type}
          value={val}
          onChange={e => setVal(e.target.value)}
          placeholder={hint}
          className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
        />
        <Btn variant="ghost" size="sm" onClick={() => onSave(settingKey, val)}>
          <Save size={12} />
        </Btn>
      </div>
    </div>
  )
}
