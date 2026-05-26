import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, HeartPulse, Cpu, Bell, Radio,
  Shield, FileText, Globe, ScrollText, BookOpen,
  FlaskConical, Settings, PlugZap,
} from 'lucide-react'
import { cn } from '@/lib/utils'

const NAV = [
  { to: '/',        icon: LayoutDashboard, label: 'Overview'  },
  { to: '/health',  icon: HeartPulse,      label: 'Health'    },
  { to: '/uptime',  icon: PlugZap,         label: 'Uptime Guardian' },
  { to: '/devices', icon: Cpu,             label: 'Devices'   },
  { to: '/alerts',  icon: Bell,            label: 'Alerts'    },
  { to: '/traffic', icon: Radio,           label: 'Traffic'   },
  { to: '/shield',  icon: Shield,          label: 'Shield'    },
  { to: '/reports', icon: FileText,        label: 'Reports'   },
  { to: '/dns',     icon: Globe,           label: 'DNS'       },
  { to: '/logs',    icon: ScrollText,      label: 'Logs'      },
  { to: '/lessons', icon: BookOpen,        label: 'Lessons'   },
  { to: '/seclab',  icon: FlaskConical,    label: 'Security Lab' },
  { to: '/settings',icon: Settings,        label: 'Settings'  },
]

export default function Sidebar() {
  return (
    <aside className="hidden md:flex flex-col w-14 lg:w-52 border-r border-white/5 bg-[#0d0d1a] flex-shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-2 px-3 py-4 border-b border-white/5">
        <div className="w-7 h-7 rounded-md bg-purple-600 flex items-center justify-center flex-shrink-0">
          <span className="text-white font-bold text-xs">N</span>
        </div>
        <span className="hidden lg:block text-white font-semibold text-sm tracking-wide">NetMon</span>
      </div>

      {/* Nav items */}
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => cn(
              'flex items-center gap-3 px-3 py-2.5 mx-1 my-0.5 rounded-lg text-sm transition-colors',
              isActive
                ? 'bg-purple-600/20 text-purple-300'
                : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
            )}
          >
            <Icon size={16} className="flex-shrink-0" />
            <span className="hidden lg:block truncate">{label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}
