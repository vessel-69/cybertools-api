import { useState } from 'react'
import type { AnyResult, Command, PayloadType, ScanStats } from './types'
import type {
  ReconResult, WorkflowResult,
  ExpressWorkflowResult, BugBountyWorkflowResult,
} from './types'
import { api } from './api/client'
import Navbar from './components/Navbar'
import LeftPanel from './components/LeftPanel'
import ResultPanel from './components/ResultPanel'
import ChatPanel from './components/ChatPanel'

const DEFAULT_STATS: ScanStats = { ip: '—', status: '—', ssl: '—' }

function extractStats(cmd: Command, data: AnyResult): ScanStats {
  const recon =
    cmd === 'recon'              ? (data as ReconResult) :
    cmd === 'workflow'           ? (data as WorkflowResult).recon :
    cmd === 'workflow-express'   ? (data as ExpressWorkflowResult).recon :
    cmd === 'workflow-bugbounty' ? (data as BugBountyWorkflowResult).recon :
    null

  if (!recon) return DEFAULT_STATS
  return {
    ip:     recon.ip ?? '—',
    status: recon.status_code != null ? String(recon.status_code) : '—',
    ssl:    recon.ssl
      ? recon.ssl.valid ? `✓ ${recon.ssl.days_remaining}d` : '✗ invalid'
      : '—',
  }
}

export default function App() {
  const [target,      setTarget]      = useState('')
  const [payloadType, setPayloadType] = useState<PayloadType>('xss')
  const [activeCmd,   setActiveCmd]   = useState<Command | null>(null)
  const [result,      setResult]      = useState<AnyResult | null>(null)
  const [loading,     setLoading]     = useState(false)
  const [loadingMsg,  setLoadingMsg]  = useState('')
  const [error,       setError]       = useState<string | null>(null)
  const [stats,       setStats]       = useState<ScanStats>(DEFAULT_STATS)

  async function run(cmd: Command) {
    setLoading(true)
    setError(null)
    setResult(null)
    setActiveCmd(cmd)

    const msgs: Record<Command, string> = {
      recon:               `Recon: ${target}`,
      analyze:             `Analyzing: ${target}`,
      'bb-scan':           `BB Scan: ${target}`,
      workflow:            `Full workflow: ${target}`,
      payloads:            `Loading ${payloadType.toUpperCase()} payloads…`,
      'last-scan':         'Fetching last scan…',
      expand:              `Expanding subdomains: ${target}`,
      endpoints:           `Enumerating endpoints: ${target}`,
      params:              `Probing parameters: ${target}`,
      'workflow-express':  `Express workflow: ${target}`,
      'workflow-bugbounty':`Bug bounty workflow: ${target}`,
      'workflow-subdomains':`Subdomain workflow: ${target}`,
      'workflow-api':      `API scan workflow: ${target}`,
    }
    setLoadingMsg(msgs[cmd] ?? cmd)

    try {
      const url = target.startsWith('http') ? target : `https://${target}`
      let data: AnyResult

      switch (cmd) {
        case 'recon':                data = await api.recon(target);               break
        case 'analyze':              data = await api.analyze(url);                break
        case 'bb-scan':              data = await api.bbScan(url);                 break
        case 'workflow':             data = await api.workflow(target);            break
        case 'payloads':             data = await api.payloads(payloadType);       break
        case 'last-scan':            data = await api.lastScan();                  break
        case 'expand':               data = await api.expand(target);             break
        case 'endpoints':            data = await api.endpoints(url);             break
        case 'params':               data = await api.params(url);                break
        case 'workflow-express':     data = await api.workflowExpress(target);    break
        case 'workflow-bugbounty':   data = await api.workflowBugBounty(target);  break
        case 'workflow-subdomains':  data = await api.workflowSubdomains(target); break
        case 'workflow-api':         data = await api.workflowApi(url);           break
        default: return
      }

      setResult(data)
      if (['recon', 'workflow', 'workflow-express', 'workflow-bugbounty'].includes(cmd)) {
        setStats(extractStats(cmd, data))
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ position: 'relative', zIndex: 1 }}>
      <Navbar activeCmd={activeCmd} />
      <div style={{
        display: 'grid',
        gridTemplateColumns: '280px 1fr 320px',
        minHeight: 'calc(100vh - 49px)',
      }}>
        <LeftPanel
          target={target}           onTargetChange={setTarget}
          payloadType={payloadType} onPayloadTypeChange={setPayloadType}
          loading={loading}
          stats={stats}
          onRun={run}
          activeCmd={activeCmd}
        />
        <ResultPanel
          result={result}
          loading={loading}
          loadingMsg={loadingMsg}
          error={error}
          activeCmd={activeCmd}
        />
        <ChatPanel />
      </div>
    </div>
  )
}