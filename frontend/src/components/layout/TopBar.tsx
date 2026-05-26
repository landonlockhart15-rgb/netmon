import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { Activity, Cpu, Zap } from 'lucide-react'
import { cn } from '@/lib/utils'

const SECTION_LABELS: Record<string, string> = {
  '/':        'Overview',
  '/health':  'Network Health',
  '/uptime':  'Uptime Guardian',
  '/devices': 'Devices',
  '/alerts':  'Alerts',
  '/traffic': 'Traffic Capture',
  '/shield':  'Security Shield',
  '/reports': 'Security Reports',
  '/dns':     'DNS Ad Blocker',
  '/logs':    'Activity Logs',
  '/lessons': 'Learned Lessons',
  '/seclab':  'Security Lab',
  '/settings':'Settings',
}

// Chip visibility driven by global flags set by section components
declare global {
  interface Window {
    _nm_scanning?: boolean
    _nm_ai_running?: boolean
    _nm_capturing?: boolean
  }
}

export default function TopBar() {
  const { pathname } = useLocation()
  const [time, setTime] = useState('')
  const [scanning, setScanning] = useState(false)
  const [aiRunning, setAiRunning] = useState(false)
  const [capturing, setCapturing] = useState(false)

  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }))
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  // Poll global flags for activity chips
  useEffect(() => {
    const id = setInterval(() => {
      setScanning(!!window._nm_scanning)
      setAiRunning(!!window._nm_ai_running)
      setCapturing(!!window._nm_capturing)
    }, 500)
    return () => clearInterval(id)
  }, [])

  const label = SECTION_LABELS[pathname] ?? 'NetMon'

  return (
    <header className="flex items-center justify-between px-4 py-2.5 border-b border-white/5 bg-[#0d0d1a] flex-shrink-0 min-h-[44px]">
      {/* Section title */}
      <h1 className="text-sm font-semibold text-white/90 tracking-wide hidden md:block">{label}</h1>
      <div className="md:hidden w-6" />

      {/* Activity chips */}
      <div className="flex items-center gap-2">
        {scanning && (
          <Chip color="blue" icon={<Cpu size={10} />} label="Scanning" />
        )}
        {aiRunning && (
          <Chip color="purple" icon={<Activity size={10} />} label="AI" />
        )}
        {capturing && (
          <Chip color="orange" icon={<Zap size={10} />} label="Capturing" />
        )}
      </div>

      {/* Clock */}
      <time className="text-xs text-gray-500 font-mono tabular-nums">{time}</time>
    </header>
  )
}

function Chip({ color, icon, label }: { color: string; icon: React.ReactNode; label: string }) {
  const colors: Record<string, string> = {
    blue:   'bg-blue-500/15 text-blue-400 border-blue-500/30',
    purple: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
    orange: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  }
  return (
    <span className={cn('flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] border animate-pulse', colors[color])}>
      {icon}
      {label}
    </span>
  )
}
