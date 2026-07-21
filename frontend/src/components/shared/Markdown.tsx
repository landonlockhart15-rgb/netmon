import { safeUrl } from '../../lib/utils'

/** Lightweight markdown renderer — headers, bold, bullets, code, links */
export default function Markdown({ text, className = '' }: { text: string; className?: string }) {
  if (!text) return null

  const lines = text.split('\n')
  const elements: React.ReactNode[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    // H3/H2/H1
    if (line.startsWith('### ')) {
      elements.push(<h3 key={i} className="text-xs font-semibold text-white/90 mt-3 mb-1">{inline(line.slice(4))}</h3>)
    } else if (line.startsWith('## ')) {
      elements.push(<h3 key={i} className="text-sm font-semibold text-white mt-3 mb-1">{inline(line.slice(3))}</h3>)
    } else if (line.startsWith('# ')) {
      elements.push(<h2 key={i} className="text-sm font-bold text-white mt-3 mb-1">{inline(line.slice(2))}</h2>)
    // Bullet
    } else if (/^[-*•]\s/.test(line)) {
      const items: React.ReactNode[] = []
      while (i < lines.length && /^[-*•]\s/.test(lines[i])) {
        items.push(<li key={i} className="ml-3">{inline(lines[i].replace(/^[-*•]\s/, ''))}</li>)
        i++
      }
      elements.push(<ul key={`ul-${i}`} className="list-disc list-inside space-y-0.5 text-gray-300">{items}</ul>)
      continue
    // Numbered list
    } else if (/^\d+\.\s/.test(line)) {
      const items: React.ReactNode[] = []
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        items.push(<li key={i} className="ml-3">{inline(lines[i].replace(/^\d+\.\s/, ''))}</li>)
        i++
      }
      elements.push(<ol key={`ol-${i}`} className="list-decimal list-inside space-y-0.5 text-gray-300">{items}</ol>)
      continue
    // Code block
    } else if (line.startsWith('```')) {
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      elements.push(
        <pre key={i} className="bg-black/30 rounded px-3 py-2 text-[11px] font-mono text-emerald-300 overflow-x-auto my-1">
          {codeLines.join('\n')}
        </pre>
      )
    // Horizontal rule
    } else if (/^---+$/.test(line.trim())) {
      elements.push(<hr key={i} className="border-white/10 my-2" />)
    // Empty line → spacer
    } else if (line.trim() === '') {
      elements.push(<div key={i} className="h-1" />)
    // Normal paragraph
    } else {
      elements.push(<p key={i} className="text-gray-300 leading-relaxed">{inline(line)}</p>)
    }
    i++
  }

  return <div className={`text-xs space-y-1 ${className}`}>{elements}</div>
}

function inline(text: string): React.ReactNode {
  // Split on **bold**, `code`, and URLs
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|\[.*?\]\(.*?\))/g)
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="text-white font-semibold">{part.slice(2, -2)}</strong>
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} className="bg-black/30 px-1 py-0.5 rounded text-emerald-300 font-mono text-[10px]">{part.slice(1, -1)}</code>
    }
    const linkMatch = part.match(/^\[(.+)\]\((.+)\)$/)
    if (linkMatch) {
      // Allow-list safe protocols to mitigate XSS (javascript:/data:/vbscript:)
      const url = safeUrl(linkMatch[2])
      if (url) {
        return (
          <a key={i} href={url} target="_blank" rel="noopener noreferrer" className="text-purple-400 underline hover:text-purple-300">
            {linkMatch[1]}
          </a>
        )
      } else {
        return (
          <span
            key={i}
            className="text-gray-400 font-medium cursor-help"
            title="Link blocked for security reasons"
          >
            {linkMatch[1]}
          </span>
        )
      }
    }
    return part
  })
}
