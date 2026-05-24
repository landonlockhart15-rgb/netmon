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
          <SectionErrorBoundary>
            <Outlet />
          </SectionErrorBoundary>
        </main>
      </div>
      <MobileNav />
    </div>
  )
}
