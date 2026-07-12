import { ShieldAlert } from 'lucide-react'
import { useGuestMode } from '@/lib/useGuestMode'
import { cn } from '@/lib/utils'

const suppressedFeatureLabels: Record<string, string> = {
  mitm: 'Traffic interception (ARP)',
  auto_scan: 'Network scans',
  active_discovery: 'Active device discovery',
  port_refresh: 'Port scanning',
  ssl_cert_scan: 'SSL certificate probing',
  deep_scan_ai: 'AI deep scan',
  hunt: 'Host hunting',
  capture: 'Packet capture',
  incident_capture: 'Incident capture',
  autoheal: 'Auto-heal actions',
  blocker: 'Device blocking',
  dns_blocker: 'DNS blocking',
  dhcp: 'DHCP actions',
  router_reboot: 'Router reboot',
  router_firmware: 'Router firmware access',
}

const getSuppressedFeatureLabel = (feature: string) => suppressedFeatureLabels[feature] ?? feature

export const GuestModeToggle = () => {
  const { state, loading, toggle } = useGuestMode()

  const enabled = state?.guest_mode ?? false
  const suppressedFeatures = state?.suppressed ?? []

  return (
    <div className="bg-white/[0.03] border border-white/5 rounded-xl p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <div
              className={cn(
                'flex h-8 w-8 items-center justify-center rounded-lg border',
                enabled
                  ? 'border-amber-500/20 bg-amber-500/10 text-amber-300'
                  : 'border-white/5 bg-white/[0.03] text-gray-500',
              )}
            >
              <ShieldAlert className="h-4 w-4" />
            </div>

            <div>
              <h3 className="text-sm font-medium text-white/90">Guest Mode</h3>
              {loading && <p className="text-xs text-gray-500">Checking current state…</p>}
            </div>
          </div>

          <p className="mt-3 max-w-3xl text-sm leading-6 text-gray-500">
            Turn this on before joining a network you don&apos;t own — hotels, airports, cafes. It
            suppresses all active scanning, port scans, and traffic capture, leaving only passive
            monitoring of your own connection.
          </p>
        </div>

        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            className="sr-only peer"
            checked={enabled}
            onChange={(event) => {
              void toggle(event.target.checked)
            }}
          />
          <div className="w-10 h-5 bg-white/10 peer-checked:bg-purple-600 rounded-full transition-colors" />
          <div className="absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-5" />
        </label>
      </div>

      {enabled && suppressedFeatures.length > 0 && (
        <div className="mt-4 rounded-lg border border-amber-500/10 bg-amber-500/[0.06] p-3">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-amber-300/90">
            Suppressed while Guest Mode is active
          </div>

          <div className="flex flex-wrap gap-2">
            {suppressedFeatures.map((feature) => (
              <span
                key={feature}
                className="rounded-full border border-amber-500/15 bg-orange-500/10 px-2.5 py-1 text-xs text-orange-100"
              >
                {getSuppressedFeatureLabel(feature)}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
