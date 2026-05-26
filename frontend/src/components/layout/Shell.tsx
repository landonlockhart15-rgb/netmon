import { Suspense } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import TopBar from './TopBar'
import StatStrip from './StatStrip'
import MobileNav from './MobileNav'
import SectionErrorBoundary from '@/components/shared/SectionErrorBoundary'

export default function Shell() {
  return (
    <div className="flex h-screen overflow-hidden bg-[#0a0a14]">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar />
        <StatStrip />
        <main className="flex-1 overflow-y-auto p-4 md:p-6 pb-20 md:pb-6">
          {/* Error boundary outside Suspense so a failed chunk load is caught too */}
          <SectionErrorBoundary>
            <Suspense fallback={<SectionFallback />}>
              <Outlet />
            </Suspense>
          </SectionErrorBoundary>
        </main>
      </div>
      <MobileNav />
    </div>
  )
}

/** Shown while a lazily-loaded section chunk downloads. */
function SectionFallback() {
  return (
    <div className="flex items-center justify-center py-24" role="status" aria-label="Loading section">
      <div className="relative h-14 w-14">
        <span className="absolute inset-0 rounded-full border border-cyan-500/30 nm-pulse-ring" />
        <span className="absolute inset-1 rounded-full nm-sweep"
          style={{ background: 'conic-gradient(from 0deg, transparent 0deg, rgba(34,211,238,0.45) 60deg, transparent 120deg)' }} />
        <div className="absolute inset-3 rounded-full border border-cyan-500/30 bg-[#0a0a14]" />
      </div>
    </div>
  )
}
