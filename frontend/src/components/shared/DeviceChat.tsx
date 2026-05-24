import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Send, Wand2, Check, X, Edit2, Undo2, Trash2, ChevronDown, ChevronUp, Loader2 } from 'lucide-react'
import {
  getDeviceChat, postDeviceChat, postDeviceChatProposal, undoDeviceChat,
  clearDeviceChat,
  type DeviceChatTurn, type DeviceChatProposal, type DeviceChatToolReq,
} from '@/lib/api'

interface Props {
  deviceId: number
  onDeviceUpdated?: () => void
}

export default function DeviceChat({ deviceId, onDeviceUpdated }: Props) {
  const qc = useQueryClient()
  const [input, setInput] = useState('')
  const [pendingProposal, setPendingProposal] = useState<DeviceChatProposal | null>(null)
  const [pendingTool, setPendingTool] = useState<DeviceChatToolReq | null>(null)
  const [autoApplied, setAutoApplied] = useState<{ name?: string; changes: string[] } | null>(null)
  const [editingProposalName, setEditingProposalName] = useState<string | null>(null)
  const [showNotes, setShowNotes] = useState(false)
  const endRef = useRef<HTMLDivElement>(null)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['device-chat', deviceId],
    queryFn: () => getDeviceChat(deviceId),
  })
  const history: DeviceChatTurn[] = data?.history ?? []
  const notes = data?.notes ?? []

  // Initial scan of latest assistant turn to surface pending state on first load
  useEffect(() => {
    if (!history.length) return
    for (let i = history.length - 1; i >= 0; i--) {
      const t = history[i]
      if (t.role !== 'assistant' || !t.meta) continue
      if (pendingTool == null && t.meta.tool_request) {
        // Only resurrect if we haven't already resolved it (no subsequent tool turn)
        const subsequent = history.slice(i + 1).some(x => x.role === 'tool')
        if (!subsequent) setPendingTool(t.meta.tool_request)
      }
      if (pendingProposal == null && t.meta.proposal) {
        const subsequent = history.slice(i + 1).some(x =>
          x.role === 'system' && (x.meta?.manual_accept || x.meta?.manual_reject))
        if (!subsequent) setPendingProposal(t.meta.proposal)
      }
      break
    }
  }, [history.length])

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [history.length, autoApplied])

  const chatMutation = useMutation({
    mutationFn: (body: Parameters<typeof postDeviceChat>[1]) => postDeviceChat(deviceId, body),
    onSuccess: (res) => {
      qc.setQueryData(['device-chat', deviceId], (old: any) => ({
        ...(old ?? { history: [], notes: [] }),
        history: [...(old?.history ?? []), ...res.appended],
        notes: res.notes,
      }))
      if (res.proposal_applied) {
        const name = res.device.label || undefined
        setAutoApplied({ name, changes: res.applied_changes })
        setPendingProposal(null)
        onDeviceUpdated?.()
      } else if (res.proposal) {
        setPendingProposal(res.proposal)
      }
      if (res.pending_approval && res.tool_request) {
        setPendingTool(res.tool_request)
      } else {
        setPendingTool(null)
      }
    },
  })

  const proposalMutation = useMutation({
    mutationFn: (body: Parameters<typeof postDeviceChatProposal>[1]) =>
      postDeviceChatProposal(deviceId, body),
    onSuccess: (res) => {
      if (res.applied) {
        setAutoApplied({
          name: res.device?.label,
          changes: res.changes,
        })
        onDeviceUpdated?.()
      }
      setPendingProposal(null)
      setEditingProposalName(null)
      refetch()
    },
  })

  const undoMutation = useMutation({
    mutationFn: () => undoDeviceChat(deviceId),
    onSuccess: (res) => {
      if (res.undone) {
        setAutoApplied(null)
        onDeviceUpdated?.()
        refetch()
      }
    },
  })

  const clearMutation = useMutation({
    mutationFn: () => clearDeviceChat(deviceId),
    onSuccess: () => {
      qc.setQueryData(['device-chat', deviceId], { history: [], notes: notes })
      setPendingProposal(null)
      setPendingTool(null)
      setAutoApplied(null)
    },
  })

  const submit = () => {
    const text = input.trim()
    if (!text || chatMutation.isPending) return
    setInput('')
    chatMutation.mutate({ message: text })
  }

  return (
    <div className="space-y-3">
      {/* Chat thread */}
      <div className="max-h-80 overflow-y-auto space-y-2 pr-1">
        {isLoading && <p className="text-xs text-gray-600">Loading chat…</p>}
        {!isLoading && history.length === 0 && (
          <p className="text-xs text-gray-600">
            Start chatting to identify this device. Ask questions like "is this my phone?"
            or "what is this thing?" — the AI can run scans to figure it out.
          </p>
        )}
        {history.map(turn => <ChatTurn key={turn.id} turn={turn} />)}
        {chatMutation.isPending && (
          <div className="flex items-center gap-2 text-xs text-purple-400">
            <Loader2 size={12} className="animate-spin" />
            Thinking…
          </div>
        )}
        <div ref={endRef} />
      </div>

      {/* Pending tool approval */}
      {pendingTool && (
        <ToolApprovalCard
          tool={pendingTool}
          disabled={chatMutation.isPending}
          onApprove={() => {
            chatMutation.mutate({ approve_tool: pendingTool })
            setPendingTool(null)
          }}
          onReject={() => {
            chatMutation.mutate({ reject_tool: { name: pendingTool.name } })
            setPendingTool(null)
          }}
        />
      )}

      {/* Auto-applied banner (with undo) */}
      {autoApplied && (
        <div className="rounded-lg border border-green-500/30 bg-green-500/5 p-3 text-xs space-y-1">
          <div className="flex items-center justify-between">
            <p className="text-green-300 font-medium">
              ✓ Auto-applied identity{autoApplied.name ? `: ${autoApplied.name}` : ''}
            </p>
            <button
              onClick={() => undoMutation.mutate()}
              disabled={undoMutation.isPending}
              className="flex items-center gap-1 text-yellow-400 hover:text-yellow-300"
            >
              <Undo2 size={11} /> Undo
            </button>
          </div>
          {autoApplied.changes.length > 0 && (
            <ul className="text-gray-400 ml-2">
              {autoApplied.changes.map((c, i) => <li key={i}>• {c}</li>)}
            </ul>
          )}
        </div>
      )}

      {/* Pending proposal (below threshold) */}
      {pendingProposal && (
        <ProposalCard
          proposal={pendingProposal}
          editingName={editingProposalName}
          onEdit={setEditingProposalName}
          disabled={proposalMutation.isPending}
          onAccept={() => proposalMutation.mutate({
            action: 'accept',
            proposal: pendingProposal,
            name: editingProposalName ?? pendingProposal.name,
          })}
          onReject={() => proposalMutation.mutate({
            action: 'reject', proposal: pendingProposal,
          })}
        />
      )}

      {/* Composer */}
      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && submit()}
          placeholder="Ask the AI to help identify this device…"
          disabled={chatMutation.isPending}
          className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500"
        />
        <button
          onClick={submit}
          disabled={!input.trim() || chatMutation.isPending}
          className="px-3 rounded-lg bg-purple-600/20 text-purple-300 hover:bg-purple-600/30 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <Send size={14} />
        </button>
      </div>

      {/* Quick prompts */}
      {history.length === 0 && (
        <div className="flex flex-wrap gap-1.5">
          {[
            'What is this device?',
            'Is this my phone?',
            'Identify it as precisely as possible',
            'Look for any suspicious behavior',
          ].map(q => (
            <button key={q}
              onClick={() => { setInput(q); setTimeout(submit, 0) }}
              disabled={chatMutation.isPending}
              className="text-[10px] px-2 py-1 rounded-md bg-white/5 text-gray-300 hover:bg-purple-500/20 hover:text-purple-200 transition-colors">
              <Wand2 size={9} className="inline mr-1" />{q}
            </button>
          ))}
        </div>
      )}

      {/* Notes + clear */}
      <div className="pt-2 border-t border-white/5 space-y-2">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setShowNotes(s => !s)}
            className="text-[10px] text-gray-500 hover:text-gray-300 flex items-center gap-1"
          >
            {showNotes ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
            Durable notes ({notes.length})
          </button>
          {history.length > 0 && (
            <button
              onClick={() => clearMutation.mutate()}
              disabled={clearMutation.isPending}
              className="text-[10px] text-gray-600 hover:text-red-400 flex items-center gap-1"
            >
              <Trash2 size={10} /> Clear chat
            </button>
          )}
        </div>
        {showNotes && (
          <ul className="text-[11px] text-gray-400 space-y-1 max-h-32 overflow-y-auto">
            {notes.length === 0 && <li className="text-gray-600">No durable notes yet</li>}
            {notes.map(n => (
              <li key={n.id} className="flex gap-1.5">
                <span className="text-gray-600">[{n.kind}{n.confidence ? ` ${Math.round(n.confidence * 100)}%` : ''}]</span>
                <span className="flex-1">{n.body}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function ChatTurn({ turn }: { turn: DeviceChatTurn }) {
  if (turn.role === 'user') {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-lg bg-purple-600/20 text-purple-100 px-3 py-1.5 text-xs">
          {turn.content}
        </div>
      </div>
    )
  }
  if (turn.role === 'tool') {
    const toolName = turn.meta?.tool ?? 'tool'
    return (
      <details className="rounded-lg border border-blue-500/20 bg-blue-500/5 text-[11px]">
        <summary className="cursor-pointer px-3 py-1.5 text-blue-300 font-mono">
          ⚙ {toolName} result
        </summary>
        <pre className="px-3 pb-2 pt-1 whitespace-pre-wrap text-gray-300 max-h-64 overflow-y-auto">{turn.content}</pre>
      </details>
    )
  }
  if (turn.role === 'system') {
    return <p className="text-[10px] text-gray-500 italic">— {turn.content} —</p>
  }
  return (
    <div className="flex justify-start">
      <div className="max-w-[90%] rounded-lg bg-white/5 text-gray-200 px-3 py-1.5 text-xs whitespace-pre-wrap">
        {turn.content || <span className="text-gray-600 italic">(no reply)</span>}
      </div>
    </div>
  )
}

function ToolApprovalCard({ tool, disabled, onApprove, onReject }: {
  tool: DeviceChatToolReq
  disabled: boolean
  onApprove: () => void
  onReject: () => void
}) {
  return (
    <div className="rounded-lg border border-orange-500/30 bg-orange-500/5 p-3 text-xs space-y-2">
      <div>
        <p className="text-orange-300 font-medium">AI wants to run an active tool</p>
        <p className="font-mono text-orange-200 mt-1">{tool.name}{tool.args && Object.keys(tool.args).length ? ` ${JSON.stringify(tool.args)}` : ''}</p>
        {tool.rationale && <p className="text-gray-400 mt-1">{tool.rationale}</p>}
      </div>
      <div className="flex gap-2">
        <button onClick={onApprove} disabled={disabled}
          className="flex items-center gap-1 px-2 py-1 rounded-md bg-orange-600/30 text-orange-200 hover:bg-orange-600/40 disabled:opacity-40">
          <Check size={11} /> Approve & Run
        </button>
        <button onClick={onReject} disabled={disabled}
          className="flex items-center gap-1 px-2 py-1 rounded-md bg-white/5 text-gray-400 hover:bg-white/10 disabled:opacity-40">
          <X size={11} /> Decline
        </button>
      </div>
    </div>
  )
}

function ProposalCard({ proposal, editingName, onEdit, disabled, onAccept, onReject }: {
  proposal: DeviceChatProposal
  editingName: string | null
  onEdit: (v: string | null) => void
  disabled: boolean
  onAccept: () => void
  onReject: () => void
}) {
  const conf = Math.round((proposal.confidence ?? 0) * 100)
  return (
    <div className="rounded-lg border border-purple-500/30 bg-purple-500/5 p-3 text-xs space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-purple-300 font-medium">AI proposes an identity ({conf}% confidence)</p>
      </div>
      <div className="bg-black/30 rounded p-2 space-y-1 font-mono">
        <div className="flex items-center gap-2">
          <span className="text-gray-500">Name:</span>
          {editingName !== null ? (
            <input
              autoFocus
              value={editingName}
              onChange={e => onEdit(e.target.value)}
              className="flex-1 bg-white/5 border border-purple-500/40 rounded px-1.5 py-0.5 text-white"
            />
          ) : (
            <>
              <span className="text-white">{proposal.name ?? '(none)'}</span>
              <button onClick={() => onEdit(proposal.name ?? '')} className="text-gray-500 hover:text-purple-300">
                <Edit2 size={10} />
              </button>
            </>
          )}
        </div>
        {proposal.category && <div><span className="text-gray-500">Category:</span> <span className="text-white">{proposal.category}</span></div>}
        {proposal.os && <div><span className="text-gray-500">OS:</span> <span className="text-white">{proposal.os}</span></div>}
      </div>
      {proposal.reasoning && (
        <p className="text-gray-400">{proposal.reasoning}</p>
      )}
      <div className="flex gap-2">
        <button onClick={onAccept} disabled={disabled}
          className="flex items-center gap-1 px-2 py-1 rounded-md bg-green-600/30 text-green-200 hover:bg-green-600/40 disabled:opacity-40">
          <Check size={11} /> Accept
        </button>
        <button onClick={onReject} disabled={disabled}
          className="flex items-center gap-1 px-2 py-1 rounded-md bg-white/5 text-gray-400 hover:bg-white/10 disabled:opacity-40">
          <X size={11} /> Reject
        </button>
      </div>
    </div>
  )
}
