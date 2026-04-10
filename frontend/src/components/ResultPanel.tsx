import type { AnyResult, Command } from '../types'
import type {
  ReconResult, AnalyzeResult, BBScanResult, PayloadResult,
  WorkflowResult, LastScanResult, ChatResult,
  ExpandResult, EndpointsResult, ParamsResult,
} from '../types'
import {
  ReconSection, AnalyzeSection, BBScanSection, PayloadSection,
  WorkflowSection, LastScanSection, ChatSection,
  ExpandSection, EndpointsSection, ParamsSection,
} from './results'

interface ResultPanelProps {
  result: AnyResult | null
  loading: boolean
  loadingMsg: string
  error: string | null
  activeCmd: Command | null
}

function EmptyState() {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      height: '100%', gap: 16, color: 'var(--text-muted)',
    }}>
      <div style={{ fontSize: '2rem', opacity: 0.3 }}>⌖</div>
      <div style={{ fontSize: '0.75rem', letterSpacing: 2, textTransform: 'uppercase' }}>
        Enter a target and run a command
      </div>
      <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', opacity: 0.6, textAlign: 'center', maxWidth: 280, lineHeight: 1.8 }}>
        Try <span style={{ color: 'var(--lime)' }}>Workflow</span> for a full scan,
        or <span style={{ color: 'var(--lime)' }}>Recon</span> to start with IP + SSL info.
      </div>
    </div>
  )
}

function LoadingState({ msg }: { msg: string }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      height: '100%', gap: 20,
    }}>
      <div style={{
        width: 36, height: 36, borderRadius: '50%',
        border: '2px solid var(--border)',
        borderTopColor: 'var(--lime)',
        animation: 'spin 0.8s linear infinite',
      }} />
      <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', letterSpacing: 1 }}>{msg}</div>
      <div style={{
        fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: 2,
        textTransform: 'uppercase', animation: 'blink 1.5s step-end infinite',
      }}>scanning...</div>
    </div>
  )
}

function ErrorState({ msg }: { msg: string }) {
  return (
    <div style={{
      border: '1px solid var(--border)', borderRadius: 'var(--radius)',
      padding: '14px 16px', background: 'var(--red-dim)',
    }}>
      <div style={{ fontSize: '0.7rem', letterSpacing: 2, textTransform: 'uppercase', color: 'var(--red)', marginBottom: 8 }}>
        ✗ Error
      </div>
      <div style={{ fontSize: '0.78rem', color: 'var(--text)', lineHeight: 1.6 }}>{msg}</div>
    </div>
  )
}

function renderResult(result: AnyResult, cmd: Command | null) {
  if (!cmd) return null
  switch (cmd) {
    case 'recon':     return <ReconSection     d={result as ReconResult} />
    case 'analyze':   return <AnalyzeSection   d={result as AnalyzeResult} />
    case 'bb-scan':   return <BBScanSection    d={result as BBScanResult} />
    case 'payloads':  return <PayloadSection   d={result as PayloadResult} />
    case 'workflow':  return <WorkflowSection  d={result as WorkflowResult} />
    case 'last-scan': return <LastScanSection  d={result as LastScanResult} />
    case 'chat':      return <ChatSection      d={result as ChatResult} />
    case 'expand':    return <ExpandSection    d={result as ExpandResult} />
    case 'endpoints': return <EndpointsSection d={result as EndpointsResult} />
    case 'params':    return <ParamsSection    d={result as ParamsResult} />
    default: return null
  }
}

export default function ResultPanel({ result, loading, loadingMsg, error, activeCmd }: ResultPanelProps) {
  return (
    <main style={{
      padding: '24px 28px',
      overflowY: 'auto',
      height: 'calc(100vh - 49px)',
      position: 'relative', zIndex: 1,
    }}>
      {/* Header bar */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: 20, paddingBottom: 14,
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ fontSize: '0.6rem', letterSpacing: 3, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
          {activeCmd ? `Output › ${activeCmd}` : 'Output'}
        </div>
        <div style={{
          display: 'flex', gap: 16, fontSize: '0.65rem',
          color: 'var(--text-muted)', letterSpacing: 1,
        }}>
          <span>17 endpoints</span>
          <span style={{ color: 'var(--border-h)' }}>|</span>
          <span>0 auth required</span>
          <span style={{ color: 'var(--border-h)' }}>|</span>
          <span>∞ free</span>
        </div>
      </div>

      {/* Content */}
      {loading   ? <LoadingState msg={loadingMsg} /> :
       error     ? <ErrorState  msg={error} /> :
       result    ? renderResult(result, activeCmd) :
                   <EmptyState />}
    </main>
  )
}