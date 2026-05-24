import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Shell from '@/components/layout/Shell'
import Overview from '@/components/sections/Overview'
import Health from '@/components/sections/Health'
import Devices from '@/components/sections/Devices'
import Alerts from '@/components/sections/Alerts'
import Traffic from '@/components/sections/Traffic'
import Shield from '@/components/sections/Shield'
import Reports from '@/components/sections/Reports'
import DNS from '@/components/sections/DNS'
import Logs from '@/components/sections/Logs'
import Lessons from '@/components/sections/Lessons'
import SecurityLab from '@/components/sections/SecurityLab'
import Settings from '@/components/sections/Settings'

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
