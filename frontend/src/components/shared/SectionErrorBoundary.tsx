import { Component, type ReactNode } from 'react'

interface Props { children: ReactNode }
interface State { error: Error | null }

export default class SectionErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-6 space-y-2">
          <p className="text-sm font-semibold text-red-400">Section crashed</p>
          <pre className="text-xs text-red-300 font-mono whitespace-pre-wrap break-all">
            {this.state.error.message}
            {'\n'}
            {this.state.error.stack?.split('\n').slice(0, 6).join('\n')}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            className="text-xs text-red-400 hover:text-red-300 underline"
          >
            Retry
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
