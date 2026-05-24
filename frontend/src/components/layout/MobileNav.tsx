import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, HeartPulse, Cpu, Bell, Shield,
  MoreHorizontal, Radio, FileText, Globe, ScrollText,
  BookOpen, FlaskConical, Settings, X,
} from 'lucide-react'
import { cn } from '@/lib/utils'

const PRIMARY = [
  { to: '/',        icon: LayoutDashboard, label: 'Overview' },
  { to: '/devices', icon: Cpu,             label: 'Devices'  },
  { to: '/alerts',  icon: Bell,            label: 'Alerts'   },
  { to: '/shield',  icon: Shield,          label: 'Shield'   },
]

const MORE = [
  { to: '/health',  icon: HeartPulse,   label: 'Health'       },
  { to: '/traffic', icon: Radio,        label: 'Traffic'      },
  { to: '/reports', icon: FileText,     label: 'Reports'      },
  { to: '/dns',     icon: Globe,        label: 'DNS'          },
  { to: '/logs',    icon: ScrollText,   label: 'Logs'         },
  { to: '/lessons', icon: BookOpen,     label: 'Lessons'      },
  { to: '/seclab',  icon: FlaskConical, label: 'Security Lab' },
  { to: '/settings',icon: Settings,     label: 'Settings'     },
]

export default function MobileNav() {
  const [open, setOpen] = useState(false)

  return (
    <>
      {/* More drawer */}
      {open && (
        <div className="md:hidden fixed inset-0 z-40" onClick={() => setOpen(false)}>
          <div className="absolute inset-0 bg-black/60" />
          <div
            className="absolute bottom-16 left-0 right-0 bg-[#12121e] border-t border-white/10 rounded-t-2xl p-4"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">More</span>
              <button onClick={() => setOpen(false)} className="text-gray-400 hover:text-white">
                <X size={18} />
              </button>
            </div>
            <div className="grid grid-cols-4 gap-2">
              {MORE.map(({ to, icon: Icon, label }) => (
                <NavLink
                  key={to}
                  to={to}
                  onClick={() => setOpen(false)}
                  className={({ isActive }) => cn(
                    'flex flex-col items-center gap-1.5 p-3 rounded-xl text-xs transition-colors',
                    isActive
                      ? 'bg-purple-600/20 text-purple-300'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                  )}
                >
                  <Icon size={20} />
                  <span className="text-center leading-tight">{label}</span>
                </NavLink>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Bottom tab bar */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 z-30 bg-[#0d0d1a] border-t border-white/10 flex safe-bottom">
        {PRIMARY.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => cn(
              'flex-1 flex flex-col items-center gap-1 py-2 text-[10px] transition-colors',
              isActive ? 'text-purple-400' : 'text-gray-500 hover:text-gray-300'
            )}
          >
            <Icon size={22} />
            <span>{label}</span>
          </NavLink>
        ))}
        <button
          onClick={() => setOpen(v => !v)}
          className="flex-1 flex flex-col items-center gap-1 py-2 text-[10px] text-gray-500 hover:text-gray-300 transition-colors"
        >
          <MoreHorizontal size={22} />
          <span>More</span>
        </button>
      </nav>
    </>
  )
}
