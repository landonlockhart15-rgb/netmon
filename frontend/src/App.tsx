import { lazy } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Shell from '@/components/layout/Shell'

// Sections are lazy-loaded so each becomes its own chunk and only downloads
// when its route is visited. This keeps heavy, page-specific deps (notably
// echarts in Health) out of the initial bundle. The Suspense boundary lives in
// Shell, so the sidebar/topbar stay put while a section chunk loads.
const Overview = lazy(() => import('@/components/sections/Overview'))
const Health = lazy(() => import('@/components/sections/Health'))
const Devices = lazy(() => import('@/components/sections/Devices'))
const Alerts = lazy(() => import('@/components/sections/Alerts'))
const Traffic = lazy(() => import('@/components/sections/Traffic'))
const Shield = lazy(() => import('@/components/sections/Shield'))
const Reports = lazy(() => import('@/components/sections/Reports'))
const DNS = lazy(() => import('@/components/sections/DNS'))
const Logs = lazy(() => import('@/components/sections/Logs'))
const Lessons = lazy(() => import('@/components/sections/Lessons'))
const SecurityLab = lazy(() => import('@/components/sections/SecurityLab'))
const Settings = lazy(() => import('@/components/sections/Settings'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Shell />}>
            <Route index element={<Overview />} />
            <Route path="health" element={<Health />} />
            <Route path="devices" element={<Devices />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="traffic" element={<Traffic />} />
            <Route path="shield" element={<Shield />} />
            <Route path="reports" element={<Reports />} />
            <Route path="dns" element={<DNS />} />
            <Route path="logs" element={<Logs />} />
            <Route path="lessons" element={<Lessons />} />
            <Route path="seclab" element={<SecurityLab />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
