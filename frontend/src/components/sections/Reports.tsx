import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Play, Send, ScrollText, Clock, ShieldAlert } from 'lucide-react'
import { getReports, runReport, chatReport, type Report } from '@/lib/api'
import { fmtDateTime, formatRelativeTime } from '@/lib/utils'
import Card from '@/components/shared/Card'
import Btn from '@/components/shared/Btn'
import Badge, { severityVariant } from '@/components/shared/Badge'
import EmptyState from '@/components/shared/EmptyState'
import PageHero from '@/components/shared/PageHero'
import StatTile from '@/components/shared/StatTile'
import Markdown from '@/components/shared/Markdown'

export default function Reports() {
  const qc = useQueryClient()
  const [chatMsg, setChatMsg] = useState('')
  const [chatHistory, setChatHistory] = useState<{ role: string; content: string }[]>([])
  const [selectedReport, setSelectedReport] = useState<number | null>(null)

  const { data: reports = [], isLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => getReports(48),
    refetchInterval: 60_000,
  })

  const runMutation = useMutation({
    mutationFn: runReport,
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['reports'] }), 5000),
  })

  const chatMutation = useMutation({
    mutationFn: (msg: string) => chatReport({ message: msg, report_id: selectedReport }),
    onSuccess: (data) => {
      setChatHistory(h => [...h, { role: 'assistant', content: data.reply }])
    },
  })

  const sendChat = () => {
    if (!chatMsg.trim()) return
    setChatHistory(h => [...h, { role: 'user', content: chatMsg }])
    chatMutation.mutate(chatMsg)
    setChatMsg('')
  }

  const list = reports as Report[]
  const selected = list.find(r => r.id === selectedReport)
  const elevated = list.filter(r => ['high', 'critical'].includes((r.severity ?? '').toLowerCase())).length

  return (
    <div className="space-y-4">
      <PageHero
        icon={ScrollText}
        accent="purple"
        eyebrow="Autonomous AI analysis"
        title="Security Reports"
        subtitle="Hourly plain-English reports on traffic, health, and anomalies — written by the local AI."
        tiles={
          <>
            <StatTile icon={<ScrollText size={11} />} label="Reports" accent="purple" glow value={list.length} sub="on file" />
            <StatTile icon={<Clock size={11} />} label="Latest" accent="blue" value={list[0] ? formatRelativeTime(list[0].created_at) : '—'} sub="most recent" />
            <StatTile icon={<ShieldAlert size={11} />} label="Elevated" accent={elevated > 0 ? 'amber' : 'gray'} value={elevated} sub="high/critical" />
          </>
        }
        actions={
          <Btn variant="primary" size="sm" loading={runMutation.isPending} onClick={() => runMutation.mutate()}>
            <Play size={13} /> Run Now
          </Btn>
        }
      />

      <Card
        title="Security Reports"
        badge={list.length ? String(list.length) : undefined}
      >
        {isLoading ? (
          <SkeletonRows />
        ) : list.length === 0 ? (
          <EmptyState icon="◎" text="No reports yet" hint="Reports are generated automatically or click Run Now." />
        ) : (
          <div className="space-y-2">
            {list.slice(0, 24).map(r => (
              <div
                key={r.id}
                onClick={() => setSelectedReport(r.id === selectedReport ? null : r.id)}
                className={`rounded-lg border p-3 cursor-pointer transition-all ${selectedReport === r.id ? 'border-purple-500/40 bg-purple-500/5' : 'border-white/8 hover:border-white/15'}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant={severityVariant(r.severity)}>{r.severity}</Badge>
                      <span className="text-xs text-gray-400">{fmtDateTime(r.created_at)}</span>
                    </div>
                    <p className="text-xs text-gray-300 leading-relaxed line-clamp-2">{(r as any).headline ?? (r as any).summary ?? ''}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Chat with selected report */}
      <Card title={selected ? `Chat — Report #${selected.id}` : 'AI Chat'}>
        {!selected ? (
          <EmptyState icon="◎" text="Select a report above to chat about it" />
        ) : (
          <div className="space-y-3">
            {((selected as any).body ?? (selected as any).detail) && (
              <p className="text-xs text-gray-400 leading-relaxed border-b border-white/5 pb-3">{(selected as any).body ?? (selected as any).detail}</p>
            )}
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {chatHistory.map((m, i) => (
                <div key={i} className={`text-xs rounded-lg px-3 py-2 ${m.role === 'user' ? 'bg-purple-600/15 text-purple-200 ml-8' : 'bg-white/5'}`}>
                  {m.role === 'assistant' ? <Markdown text={m.content} /> : m.content}
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={chatMsg}
                onChange={e => setChatMsg(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && sendChat()}
                placeholder="Ask about this report…"
                className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
              />
              <Btn variant="primary" size="sm" loading={chatMutation.isPending} onClick={sendChat}>
                <Send size={13} />
              </Btn>
            </div>
          </div>
        )}
      </Card>
    </div>
  )
}

function SkeletonRows() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="rounded-lg border border-white/5 p-3 animate-pulse">
          <div className="h-4 bg-white/5 rounded w-32 mb-2" />
          <div className="h-3 bg-white/5 rounded w-full" />
        </div>
      ))}
    </div>
  )
}
