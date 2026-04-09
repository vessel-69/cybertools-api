import { useState } from 'react'
import type { AnyResult, Command, PayloadType, ScanStats } from './types'
import type { ReconResult, WorkflowResult } from './types'
import { api } from './api/client'
import Navbar from './components/Navbar'
import LeftPanel from './components/LeftPanel'
import ResultPanel from './components/ResultPanel'

const DEFAULT_STATS: ScanStats = { ip: '—', status: '—', ssl: '—' }

function extractStats(cmd: Command, data: AnyResult): ScanStats {
  const recon =
    cmd === 'recon'    ? (data as ReconResult) :
    cmd === 'workflow' ? (data as WorkflowResult).recon :
    null

  if (!recon) return DEFAULT_STATS

  return {
    ip:     recon.ip ?? '—',
    status: recon.status_code != null ? String(recon.status_code) : '—',
    ssl:    recon.ssl
      ? recon.ssl.valid
        ? `✓ ${recon.ssl.days_remaining}d`
        : '✗ invalid'
      : '—',
  }
}

export default function App() {
  const [target,       setTarget]       = useState('')
  const [chatQ,        setChatQ]        = useState('')
  const [payloadType,  setPayloadType]  = useState<PayloadType>('xss')
  const [activeCmd,    setActiveCmd]    = useState<Command | null>(null)
  const [result,       setResult]       = useState<AnyResult | null>(null)
  const [loading,      setLoading]      = useState(false)
  const [loadingMsg,   setLoadingMsg]   = useState('')
  const [error,        setError]        = useState<string | null>(null)
  const [stats,        setStats]        = useState<ScanStats>(DEFAULT_STATS)

  async function run(cmd: Command) {
    setLoading(true)
    setError(null)
    setResult(null)
    setActiveCmd(cmd)

    const msgs: Record<Command, string> = {
      recon:       `Recon: ${target}`,
      analyze:     `Analyzing: ${target}`,
      'bb-scan':   `BB Scan: ${target}`,
      workflow:    `Full workflow: ${target}`,
      payloads:    `Loading ${payloadType.toUpperCase()} payloads…`,
      'last-scan': 'Fetching last scan…',
      chat:        `Asking: ${chatQ}`,
    }
    setLoadingMsg(msgs[cmd])

    try {
      const url = target.startsWith('http') ? target : `https://${target}`
      let data: AnyResult

      switch (cmd) {
        case 'recon':     data = await api.recon(target);         break
        case 'analyze':   data = await api.analyze(url);          break
        case 'bb-scan':   data = await api.bbScan(url);           break
        case 'workflow':  data = await api.workflow(target);      break
        case 'payloads':  data = await api.payloads(payloadType); break
        case 'last-scan': data = await api.lastScan();            break
        case 'chat':      data = await api.chat(chatQ);           break
        default: return
      }

      setResult(data)
      if (cmd === 'recon' || cmd === 'workflow') {
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
        gridTemplateColumns: '320px 1fr',
        minHeight: 'calc(100vh - 49px)',
      }}>
        <LeftPanel
          target={target}             onTargetChange={setTarget}
          chatQ={chatQ}               onChatQChange={setChatQ}
          payloadType={payloadType}   onPayloadTypeChange={setPayloadType}
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
      </div>
    </div>
  )
}
