import { useMemo, useState } from 'react'
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

interface RemediationResponse {
  pending?: Remediation[]
}

interface Lesson {
  id: string | number
  source?: string
  description?: string
  pattern?: string
  service?: string
  service_label?: string
  plain_english?: string
  action?: string
  recommended_action?: string
  action_plain_english?: string
  success?: number
  success_count?: number
  fail?: number
  fail_count?: number
  confidence?: number | null
  suppressed?: boolean
  last_outcome?: string
  outcome?: string
  created_at?: string
  updated_at?: string
  last_used_at?: string
  pattern_summary?: string
}

interface LessonsResponse {
  lessons?: Lesson[]
}

export default function Lessons() {
  const [token, setToken] = useState(localStorage.getItem(CP_TOKEN_KEY) ?? '')
  const [editToken, setEditToken] = useState(false)
  const [lessonSearch, setLessonSearch] = useState('')
  const [lessonSource, setLessonSource] = useState('all')
  const [lessonService, setLessonService] = useState('all')
  const [lessonAction, setLessonAction] = useState('all')
  const [lessonOutcome, setLessonOutcome] = useState('all')

  const { data: pendingRaw, error: pendingError, refetch } = useQuery({
    queryKey: ['cp-remediations'],
    queryFn: () => cpFetch<RemediationResponse | Remediation[]>('/remediation/pending'),
    retry: false,
    staleTime: 30_000,
  })

  const { data: lessonsRaw } = useQuery({
    queryKey: ['cp-lessons'],
    queryFn: () => cpFetch<LessonsResponse | Lesson[]>('/lessons'),
    retry: false,
    staleTime: 60_000,
  })

  const { data: learning } = useQuery({
    queryKey: ['learning-overview'],
    queryFn: () => getLearningOverview(100),
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
  const lessonOptions = useMemo(() => buildLessonOptions(lessons), [lessons])
  const filteredLessons = useMemo(
    () => filterLessons(lessons, {
      search: lessonSearch,
      source: lessonSource,
      service: lessonService,
      action: lessonAction,
      outcome: lessonOutcome,
    }),
    [lessons, lessonSearch, lessonSource, lessonService, lessonAction, lessonOutcome],
  )

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
          <div className="space-y-3">
            <div className="grid gap-2 md:grid-cols-[minmax(180px,1fr)_repeat(4,minmax(120px,160px))]">
              <input
                value={lessonSearch}
                onChange={e => setLessonSearch(e.target.value)}
                placeholder="Search lessons"
                className="min-w-0 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-gray-200 placeholder-gray-600 outline-none focus:border-cyan-400/60"
              />
              <LessonSelect value={lessonSource} onChange={setLessonSource} options={lessonOptions.sources} allLabel="All sources" />
              <LessonSelect value={lessonService} onChange={setLessonService} options={lessonOptions.services} allLabel="All services" />
              <LessonSelect value={lessonAction} onChange={setLessonAction} options={lessonOptions.actions} allLabel="All actions" />
              <LessonSelect value={lessonOutcome} onChange={setLessonOutcome} options={lessonOptions.outcomes} allLabel="All outcomes" />
            </div>
            <div className="text-[10px] uppercase tracking-wide text-gray-600">
              Showing {filteredLessons.length} of {(lessons as Lesson[]).length}
            </div>
            {filteredLessons.length === 0 ? (
              <EmptyState icon="◎" text="No matching lessons" hint="Adjust the search or filters." />
            ) : (
              <div className="overflow-x-auto rounded-lg border border-white/8">
                <table className="min-w-[900px] w-full text-left text-xs">
                  <thead className="bg-white/[0.03] text-[10px] uppercase tracking-wide text-gray-500">
                    <tr>
                      <th className="px-3 py-2 font-semibold">Service</th>
                      <th className="px-3 py-2 font-semibold">Plain-English Lesson</th>
                      <th className="px-3 py-2 font-semibold">Action</th>
                      <th className="px-3 py-2 font-semibold">Outcome</th>
                      <th className="px-3 py-2 font-semibold">Confidence</th>
                      <th className="px-3 py-2 font-semibold">Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLessons.map(l => (
                      <LessonTableRow key={l.id} lesson={l} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
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

function LessonTableRow({ lesson }: { lesson: Lesson | LearningLesson }) {
  const confidence = typeof lesson.confidence === 'number' ? Math.round(lesson.confidence * 100) : null
  const success = lessonSuccess(lesson)
  const fail = lessonFail(lesson)
  const description = 'description' in lesson ? lesson.description : undefined
  const service = lesson.service || 'netmon'
  const serviceLabel = lesson.service_label || serviceLabelFor(service)
  const plainEnglish = lesson.plain_english || describeLessonForUser(lesson, description)
  const action = lessonAction(lesson)
  const actionPlainEnglish = lesson.action_plain_english || describeActionForUser(action)
  const source = 'source' in lesson ? lesson.source : undefined
  return (
    <tr className="border-t border-white/6 align-top hover:bg-white/[0.03]">
      <td className="px-3 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="info">{serviceLabel}</Badge>
          {source && <span className="rounded border border-white/10 bg-white/[0.03] px-2 py-0.5 text-[10px] uppercase tracking-wide text-gray-500">{source}</span>}
          {lesson.suppressed && <Badge variant="warn">suppressed</Badge>}
        </div>
      </td>
      <td className="px-3 py-3">
        <p className="text-sm text-gray-200">{plainEnglish}</p>
        {lessonPattern(lesson) && <p className="mt-1 max-w-[520px] truncate text-[10px] text-gray-600">signal: {lessonPattern(lesson)}</p>}
      </td>
      <td className="px-3 py-3">
        <p className="text-gray-300">{actionPlainEnglish}</p>
        {action && <p className="mt-1 font-mono text-[10px] text-gray-600">{action}</p>}
      </td>
      <td className="px-3 py-3 text-gray-400">
        <p>{success} success / {fail} fail</p>
        {lesson.last_outcome && <p className="mt-1 text-[10px] text-gray-600">last {lesson.last_outcome}</p>}
      </td>
      <td className="px-3 py-3">
        {confidence != null ? <span className="text-emerald-300">{confidence}%</span> : <span className="text-gray-600">—</span>}
      </td>
      <td className="px-3 py-3 text-gray-500">{lessonUpdatedAt(lesson)}</td>
    </tr>
  )
}

function LessonSelect({ value, onChange, options, allLabel }: {
  value: string
  onChange: (value: string) => void
  options: string[]
  allLabel: string
}) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className="min-w-0 rounded-lg border border-white/10 bg-[#0d1220] px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-400/60"
    >
      <option value="all">{allLabel}</option>
      {options.map(option => <option key={option} value={option}>{option}</option>)}
    </select>
  )
}

function buildLessonOptions(lessons: (Lesson | LearningLesson)[]) {
  const unique = (values: string[]) => Array.from(new Set(values.filter(Boolean))).sort((a, b) => a.localeCompare(b))
  return {
    sources: unique(lessons.map(l => ('source' in l ? l.source || '' : ''))),
    services: unique(lessons.map(l => l.service_label || serviceLabelFor(l.service))),
    actions: unique(lessons.map(lessonAction)),
    outcomes: unique(lessons.map(l => l.last_outcome || '').filter(Boolean)),
  }
}

function filterLessons(lessons: (Lesson | LearningLesson)[], filters: {
  search: string
  source: string
  service: string
  action: string
  outcome: string
}) {
  const q = filters.search.trim().toLowerCase()
  return lessons.filter(lesson => {
    const source = 'source' in lesson ? lesson.source || '' : ''
    const serviceLabel = lesson.service_label || serviceLabelFor(lesson.service)
    const action = lessonAction(lesson)
    const outcome = lesson.last_outcome || ''
    const haystack = [
      source,
      serviceLabel,
      lesson.service,
      lessonPattern(lesson),
      lesson.plain_english,
      lesson.action_plain_english,
      action,
      outcome,
    ].join(' ').toLowerCase()
    return (!q || haystack.includes(q))
      && (filters.source === 'all' || source === filters.source)
      && (filters.service === 'all' || serviceLabel === filters.service)
      && (filters.action === 'all' || action === filters.action)
      && (filters.outcome === 'all' || outcome === filters.outcome)
  })
}

function lessonAction(lesson: Lesson | LearningLesson) {
  return lesson.action || ('recommended_action' in lesson ? lesson.recommended_action || '' : '')
}

function lessonPattern(lesson: Lesson | LearningLesson) {
  return lesson.pattern || ('pattern_summary' in lesson ? lesson.pattern_summary || '' : '')
}

function lessonSuccess(lesson: Lesson | LearningLesson) {
  return Number(lesson.success ?? ('success_count' in lesson ? lesson.success_count : 0) ?? 0)
}

function lessonFail(lesson: Lesson | LearningLesson) {
  return Number(lesson.fail ?? ('fail_count' in lesson ? lesson.fail_count : 0) ?? 0)
}

function lessonUpdatedAt(lesson: Lesson | LearningLesson) {
  const value = lesson.last_used_at || ('updated_at' in lesson ? lesson.updated_at : undefined) || ('created_at' in lesson ? lesson.created_at : undefined)
  if (!value) return '—'
  const d = new Date(value)
  return isNaN(d.getTime()) ? value : d.toLocaleString()
}

function serviceLabelFor(service?: string) {
  const key = (service || 'netmon').toLowerCase()
  const labels: Record<string, string> = {
    device: 'Device identity',
    dns: 'DNS',
    netmon: 'NetMon',
    ntfy: 'Notifications',
    router: 'Router / internet',
    security: 'Security',
    sentinel: 'Sentinel',
    traffic: 'Network traffic',
    wifi: 'Wi-Fi',
  }
  return labels[key] || key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function describeActionForUser(action?: string | null) {
  const key = (action || '').toLowerCase()
  if (!key) return 'Keep it as context for future checks.'
  if (key === 'device_profile' || key === 'device_profile_update') {
    return 'Use this evidence when naming or confirming the device later.'
  }
  if (key === 'label_device') return 'Save a clearer device label for future scans.'
  if (key === 'restart') return 'Restart the affected service only when policy allows it.'
  if (key === 'suggested') return 'Show the suggestion for human review before taking action.'
  return key.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase())
}

function describeLessonForUser(lesson: Lesson | LearningLesson, description?: string) {
  const service = lesson.service || 'netmon'
  const serviceLabel = serviceLabelFor(service)
  const pattern = (description || lessonPattern(lesson) || '').trim()
  const lower = pattern.toLowerCase()

  if (service === 'device') {
    return 'NetMon learned a device identity clue so future scans can label that device more accurately.'
  }
  if (service === 'traffic') {
    return 'NetMon learned a recurring traffic pattern and will use it when reviewing future network activity.'
  }
  if (service === 'security') {
    return 'NetMon learned a security-related pattern so similar activity is easier to recognize later.'
  }
  if (service === 'router' || service === 'dns' || service === 'wifi') {
    return `NetMon learned a ${serviceLabel.toLowerCase()} pattern that can help explain future connectivity problems.`
  }
  if (lower.includes('vendor=') || lower.includes('label=')) {
    return 'NetMon matched technical traffic evidence to a more useful device label.'
  }
  if (pattern) return `${serviceLabel} learned this recurring pattern: ${pattern.slice(0, 180)}`
  return `${serviceLabel} learned a new pattern it can reuse during future checks.`
}
