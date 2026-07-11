import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, HeartPulse, Cpu, Bell, Radio,
  Shield, FileText, Globe, ScrollText, BookOpen,
  FlaskConical, Settings, PlugZap, ShieldAlert,
} from 'lucide-react'
import { cn } from '@/lib/utils'

const NAV = [
  { to: '/',        icon: LayoutDashboard, label: 'Overview'  },
  { to: '/health',  icon: HeartPulse,      label: 'Health'    },
  { to: '/uptime',  icon: PlugZap,         label: 'Uptime Guardian' },
  { to: '/sentinel',icon: ShieldAlert,     label: 'Sentinel'  },
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
    <aside className="hidden md:flex h-full overflow-hidden flex-col w-14 lg:w-52 border-r border-white/5 bg-[#0d0d1a] flex-shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-2 px-3 py-4 border-b border-white/5">
        <img
          src="/lockhartlabs-logo.png"
          alt="LockhartLabs logo"
          className="w-8 h-8 rounded-md object-contain flex-shrink-0 drop-shadow-[0_0_10px_rgba(168,85,247,0.28)]"
        />
        <span className="hidden lg:flex flex-col leading-tight">
          <span className="text-white font-semibold text-sm tracking-wide">NetMon</span>
          <span className="text-[10px] uppercase tracking-[0.18em] text-purple-300/80">LockhartLabs</span>
        </span>
      </div>

      {/* Nav items */}
      <nav className="nm-sidebar-scroll flex-1 py-2 overflow-y-auto overscroll-contain">
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
