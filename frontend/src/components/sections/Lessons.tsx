import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { BookOpen, Check, X, ExternalLink, ListChecks, GraduationCap } from 'lucide-react'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile from '@/components/shared/StatTile'

const CP_PORT = 8091
const CP_TOKEN_KEY = 'netmon_cp_token'

function cpUrl() {
  // Use whatever hostname NetMon was loaded from. On the PC that's localhost;
  // over Tailscale on a phone it's the 100.x.x.x address. Hardcoding 'localhost'
  // here broke the phone case because localhost = the phone itself.
  const host = typeof window !== 'undefined' ? window.location.hostname : 'localhost'
  return `http://${host}:${CP_PORT}`
}

async function cpFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem(CP_TOKEN_KEY) ?? ''
  const res = await fetch(cpUrl() + path, {
    ...opts,
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', ...opts.headers },
  })
  if (!res.ok) throw new Error(`CP ${res.status}`)
  return res.json()
}

interface Remediation {
  id: string | number
  severity?: string
  source?: string
  service?: string
  action?: string
  args?: string | Record<string, unknown>
  status?: string
}

interface Lesson {
  id: string | number
  description?: string
  outcome?: string
  created_at?: string
}

export default function Lessons() {
  const [token, setToken] = useState(localStorage.getItem(CP_TOKEN_KEY) ?? '')
  const [editToken, setEditToken] = useState(false)

  const { data: pendingRaw, error: pendingError, refetch } = useQuery({
    queryKey: ['cp-remediations'],
    queryFn: () => cpFetch<any>('/remediation/pending'),
    retry: false,
    staleTime: 30_000,
  })

  const { data: lessonsRaw } = useQuery({
    queryKey: ['cp-lessons'],
    queryFn: () => cpFetch<any>('/lessons'),
    retry: false,
    staleTime: 60_000,
  })

  // API returns { ok, source, pending: [...] } and { ok, source, lessons: [...] }
  const pending: Remediation[] = Array.isArray(pendingRaw) ? pendingRaw : (pendingRaw?.pending ?? [])
  const lessons: Lesson[] = Array.isArray(lessonsRaw) ? lessonsRaw : (lessonsRaw?.lessons ?? [])

  const approveMutation = useMutation({
    mutationFn: (id: string | number) => cpFetch(`/remediation/${id}/approve`, { method: 'POST' }),
    onSuccess: () => refetch(),
  })

  const rejectMutation = useMutation({
    mutationFn: (id: string | number) => cpFetch(`/remediation/${id}/reject`, { method: 'POST' }),
    onSuccess: () => refetch(),
  })

  const saveToken = () => {
    localStorage.setItem(CP_TOKEN_KEY, token)
    setEditToken(false)
    refetch()
  }

  const pendingCount = (pending as Remediation[]).length
  const lessonsCount = (lessons as Lesson[]).length

  return (
    <div className="space-y-4">
      <PageHero
        icon={GraduationCap}
        accent="indigo"
        pulse={pendingCount > 0}
        eyebrow={pendingCount > 0 ? `${pendingCount} awaiting approval` : 'Self-improving defense'}
        title="Learned Lessons"
        subtitle="The AI-Hub control plane proposes remediations and learns from what you approve or reject."
        tiles={
          <>
            <StatTile icon={<ListChecks size={11} />} label="Pending" accent={pendingCount > 0 ? 'amber' : 'gray'} glow value={pendingCount} sub="to review" />
            <StatTile icon={<GraduationCap size={11} />} label="Lessons" accent="indigo" value={lessonsCount} sub="learned" />
          </>
        }
      />

      {/* AI Hub link */}
      <Card title="AI-Hub Control Plane" action={
        <a href={cpUrl()} target="_blank" rel="noopener noreferrer"
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 transition-colors">
          <ExternalLink size={12} /> Open Dashboard
        </a>
      }>
        <div className="space-y-3">
          {editToken ? (
            <div className="flex gap-2">
              <input
                type="password"
                value={token}
                onChange={e => setToken(e.target.value)}
                placeholder="AI-Hub token"
                className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
              />
              <Btn variant="primary" size="sm" onClick={saveToken}>Save</Btn>
              <Btn variant="ghost" size="sm" onClick={() => setEditToken(false)}>Cancel</Btn>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-500">Token: {token ? '••••••' : 'not set'}</span>
              <Btn variant="ghost" size="sm" onClick={() => setEditToken(true)}>Change</Btn>
            </div>
          )}
          {pendingError && (
            <p className="text-xs text-red-400">
              {String((pendingError as Error)?.message).match(/401|403/)
                ? 'Authentication failed — set your AI-Hub token above.'
                : `Cannot reach AI-Hub at localhost:${CP_PORT}. Is it running?`}
            </p>
          )}
        </div>
      </Card>

      {/* Pending remediations */}
      <Card title="Pending Remediations" badge={(pending as Remediation[]).length ? String((pending as Remediation[]).length) : undefined}>
        {(pending as Remediation[]).length === 0 ? (
          <EmptyState icon="◎" text="No pending remediations" hint="Remediations from the AI-Hub control plane appear here." />
        ) : (
          <div className="space-y-2">
            {(pending as Remediation[]).map(p => (
              <div key={p.id} className="rounded-lg border border-white/10 bg-[#1a1a2e] p-3">
                <div className="flex items-start gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      {p.severity && <Badge variant="warn">{p.severity}</Badge>}
                      {p.source && <span className="text-xs text-gray-500">{p.source}</span>}
                      {p.service && <span className="text-xs text-gray-400">{p.service}</span>}
                    </div>
                    <p className="text-xs text-gray-300">{p.action ?? 'Unknown action'}</p>
                    {p.args != null && (
                      <code className="text-[10px] text-gray-500 font-mono mt-1 block truncate">
                        {typeof p.args === 'string' ? p.args : JSON.stringify(p.args)}
                      </code>
                    )}
                  </div>
                  <div className="flex gap-1 flex-shrink-0">
                    <Btn variant="primary" size="sm" loading={approveMutation.isPending} onClick={() => approveMutation.mutate(p.id)}>
                      <Check size={12} />
                    </Btn>
                    <Btn variant="danger" size="sm" loading={rejectMutation.isPending} onClick={() => rejectMutation.mutate(p.id)}>
                      <X size={12} />
                    </Btn>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Learned lessons */}
      <Card title="Learned Lessons" badge={(lessons as Lesson[]).length ? String((lessons as Lesson[]).length) : undefined}>
        {(lessons as Lesson[]).length === 0 ? (
          <EmptyState icon="◎" text="No lessons recorded yet" hint="Lessons are learned from approved/rejected remediations." />
        ) : (
          <div className="space-y-2">
            {(lessons as Lesson[]).map(l => (
              <div key={l.id} className="text-xs py-2 border-b border-white/5 last:border-0">
                <p className="text-gray-300">{l.description ?? JSON.stringify(l)}</p>
                {l.outcome && <p className="text-gray-500 mt-0.5">{l.outcome}</p>}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
