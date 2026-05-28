import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Check, X, ExternalLink, ListChecks, GraduationCap, GitBranch, MessageSquare } from 'lucide-react'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile from '@/components/shared/StatTile'
import { getLearningOverview, type LearningLesson } from '@/lib/api'

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
  pattern?: string
  service?: string
  action?: string
  success?: number
  fail?: number
  confidence?: number | null
  suppressed?: boolean
  last_outcome?: string
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

  const { data: learning } = useQuery({
    queryKey: ['learning-overview'],
    queryFn: () => getLearningOverview(20),
    retry: false,
    staleTime: 60_000,
  })

  // API returns { ok, source, pending: [...] } and { ok, source, lessons: [...] }
  const pending: Remediation[] = Array.isArray(pendingRaw) ? pendingRaw : (pendingRaw?.pending ?? [])
  const cpLessons: Lesson[] = Array.isArray(lessonsRaw) ? lessonsRaw : (lessonsRaw?.lessons ?? [])
  const lessons: Lesson[] = (learning?.lessons?.length ? learning.lessons : cpLessons) as Lesson[]
  const timeline = learning?.timeline ?? []
  const feedback = learning?.feedback ?? []

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
                : `Cannot reach AI-Hub at ${cpUrl()}. Is it running?`}
            </p>
          )}
        </div>
      </Card>

      <Card title="Learning Timeline" badge={timeline.length ? String(timeline.length) : undefined}>
        {!learning?.available ? (
          <EmptyState icon="◎" text="Shared learning unavailable" hint={learning?.error || 'NetMon will keep running; the shared knowledge bridge may be offline.'} />
        ) : timeline.length === 0 ? (
          <EmptyState icon="◎" text="No timeline events yet" hint="NetMon and Sentinel add events here as incidents, device learning, and remediations happen." />
        ) : (
          <div className="space-y-2">
            {timeline.slice(0, 8).map(e => (
              <div key={e.id} className="rounded-lg border border-white/8 bg-white/[0.02] p-3">
                <div className="flex items-start gap-3">
                  <GitBranch size={14} className="mt-0.5 text-indigo-300 flex-shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      {e.service && <Badge variant={e.severity === 'high' ? 'error' : e.severity === 'medium' ? 'warn' : 'info'}>{e.service}</Badge>}
                      {e.event_type && <span className="text-[10px] uppercase tracking-wide text-gray-500">{e.event_type}</span>}
                      {e.source && <span className="text-[10px] text-gray-600">{e.source}</span>}
                    </div>
                    <p className="mt-1 text-xs text-gray-300">{e.summary || 'Timeline event'}</p>
                    {e.created_at && <p className="mt-1 text-[10px] text-gray-600">{new Date(e.created_at).toLocaleString()}</p>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
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
              <LessonRow key={l.id} lesson={l} />
            ))}
          </div>
        )}
      </Card>

      <Card title="Feedback Loop" badge={feedback.length ? String(feedback.length) : undefined}>
        {feedback.length === 0 ? (
          <EmptyState icon="◎" text="No feedback recorded yet" hint="Accepting or rejecting device identities records feedback here." />
        ) : (
          <div className="space-y-2">
            {feedback.slice(0, 6).map(f => (
              <div key={f.id} className="flex items-start gap-3 rounded-lg border border-white/8 bg-white/[0.02] p-3 text-xs">
                <MessageSquare size={14} className="mt-0.5 text-cyan-300 flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-gray-300">{f.verdict || 'feedback'} <span className="text-gray-600">on</span> {f.target_type || 'target'}</p>
                  {f.note && <p className="mt-1 truncate text-gray-500">{f.note}</p>}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

function LessonRow({ lesson }: { lesson: Lesson | LearningLesson }) {
  const confidence = typeof lesson.confidence === 'number' ? Math.round(lesson.confidence * 100) : null
  const success = Number(lesson.success ?? 0)
  const fail = Number(lesson.fail ?? 0)
  const description = 'description' in lesson ? lesson.description : undefined
  return (
    <div className="text-xs py-2 border-b border-white/5 last:border-0">
      <div className="flex flex-wrap items-center gap-2 mb-1">
        {lesson.service && <Badge variant="info">{lesson.service}</Badge>}
        {lesson.action && <span className="font-mono text-gray-400">{lesson.action}</span>}
        {confidence != null && <span className="text-emerald-300">{confidence}% confidence</span>}
        {lesson.suppressed && <Badge variant="warn">suppressed</Badge>}
      </div>
      <p className="text-gray-300">{description ?? lesson.pattern ?? JSON.stringify(lesson)}</p>
      <p className="text-gray-500 mt-0.5">
        {success} success / {fail} fail{lesson.last_outcome ? ` · last ${lesson.last_outcome}` : ''}
      </p>
    </div>
  )
}
