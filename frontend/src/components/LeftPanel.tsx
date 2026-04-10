import { useState } from 'react'
import type { Command, PayloadType, ScanStats } from '../types'

interface LeftPanelProps {
  target: string
  onTargetChange: (v: string) => void
  loading: boolean
  stats: ScanStats
  chatQ: string
  onChatQChange: (v: string) => void
  payloadType: PayloadType
  onPayloadTypeChange: (v: PayloadType) => void
  onRun: (cmd: Command) => void
  activeCmd: Command | null
}

function Btn({
  label, icon, active, disabled, full, primary, onClick,
}: {
  label: string; icon: string; active?: boolean
  disabled?: boolean; full?: boolean; primary?: boolean
  onClick: () => void
}) {
  const [hov, setHov] = useState(false)
  const isActive = active || hov

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        gridColumn: full ? '1 / -1' : undefined,
        padding: '10px 8px',
        borderRadius: 'var(--radius)',
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '0.72rem', letterSpacing: 1,
        textTransform: 'uppercase',
        cursor: disabled ? 'not-allowed' : 'pointer',
        border: `1px solid ${isActive || primary ? 'var(--border-h)' : 'var(--border)'}`,
        background: isActive || primary ? 'var(--lime-dim)' : 'var(--surface)',
        color: isActive || primary ? 'var(--lime)' : 'var(--text-dim)',
        boxShadow: isActive ? '0 0 12px var(--lime-dim)' : 'none',
        opacity: disabled ? 0.4 : 1,
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
        width: '100%',
        transition: 'all 0.15s',
      }}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >
      <span>{icon}</span>
      <span>{label}</span>
    </button>
  )
}

function StatPill({ label, value }: { label: string; value: string }) {
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      padding: '6px 10px',
      background: 'var(--surface2)',
      borderRadius: 6,
      border: '1px solid var(--border)',
      fontSize: '0.7rem',
    }}>
      <span style={{ color: 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</span>
      <span style={{ color: value === '—' ? 'var(--text-muted)' : 'var(--lime)', fontWeight: 500 }}>{value}</span>
    </div>
  )
}

const PAYLOAD_TYPES: PayloadType[] = ['xss', 'sqli', 'lfi', 'ssrf', 'open_redirect', 'idor']

export default function LeftPanel({
  target, onTargetChange, loading, stats,
  chatQ, onChatQChange,
  payloadType, onPayloadTypeChange,
  onRun, activeCmd,
}: LeftPanelProps) {
  return (
    <aside style={{
      borderRight: '1px solid var(--border)',
      padding: '24px 20px',
      display: 'flex', flexDirection: 'column', gap: 20,
      position: 'sticky', top: 49,
      height: 'calc(100vh - 49px)',
      overflowY: 'auto',
    }}>
      {/* Target input */}
      <div>
        <div style={{ fontSize: '0.6rem', letterSpacing: 3, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
          Target
        </div>
        <input
          type="text"
          placeholder="example.com"
          value={target}
          onChange={e => onTargetChange(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && onRun('recon')}
          style={{
            width: '100%',
            background: 'var(--surface2)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '10px 14px',
            color: 'var(--lime)',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '0.82rem',
            outline: 'none',
            caretColor: 'var(--lime)',
          }}
          onFocus={e => {
            e.target.style.borderColor = 'var(--border-h)'
            e.target.style.boxShadow = '0 0 0 3px var(--lime-dim), 0 0 20px var(--lime-dim)'
          }}
          onBlur={e => {
            e.target.style.borderColor = 'var(--border)'
            e.target.style.boxShadow = 'none'
          }}
        />
      </div>

      {/* Action buttons */}
      <div>
        <div style={{ fontSize: '0.6rem', letterSpacing: 3, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
          Commands
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Btn label="Workflow" icon="⚡" full primary
            active={activeCmd === 'workflow'} disabled={loading || !target}
            onClick={() => onRun('workflow')} />
          <Btn label="Recon" icon="◎"
            active={activeCmd === 'recon'} disabled={loading || !target}
            onClick={() => onRun('recon')} />
          <Btn label="Analyze" icon="⟳"
            active={activeCmd === 'analyze'} disabled={loading || !target}
            onClick={() => onRun('analyze')} />
          <Btn label="BB Scan" icon="◈"
            active={activeCmd === 'bb-scan'} disabled={loading || !target}
            onClick={() => onRun('bb-scan')} />
          <Btn label="Last Scan" icon="⊙" full
            active={activeCmd === 'last-scan'} disabled={loading}
            onClick={() => onRun('last-scan')} />
        </div>
      </div>

      <div style={{ height: 1, background: 'var(--border)' }} />

      {/* Recon Tools */}
      <div>
        <div style={{ fontSize: '0.6rem', letterSpacing: 3, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
          Recon Tools
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Btn label="Expand" icon="⊞" full
            active={activeCmd === 'expand'} disabled={loading || !target}
            onClick={() => onRun('expand')} />
          <Btn label="Endpoints" icon="⊡"
            active={activeCmd === 'endpoints'} disabled={loading || !target}
            onClick={() => onRun('endpoints')} />
          <Btn label="Params" icon="⊟"
            active={activeCmd === 'params'} disabled={loading || !target}
            onClick={() => onRun('params')} />
        </div>
      </div>

      {/* Payloads */}
      <div>
        <div style={{ fontSize: '0.6rem', letterSpacing: 3, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
          Payloads
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' as const, marginBottom: 8 }}>
          {PAYLOAD_TYPES.map(pt => (
            <button key={pt} onClick={() => onPayloadTypeChange(pt)}
              style={{
                padding: '4px 10px', borderRadius: 4,
                fontSize: '0.68rem', letterSpacing: 1,
                textTransform: 'uppercase',
                border: `1px solid ${payloadType === pt ? 'var(--border-h)' : 'var(--border)'}`,
                background: payloadType === pt ? 'var(--lime-dim)' : 'transparent',
                color: payloadType === pt ? 'var(--lime)' : 'var(--text-muted)',
                cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
              }}
            >{pt}</button>
          ))}
        </div>
        <Btn label={`Get ${payloadType.toUpperCase()} Payloads`} icon="◇" full
          disabled={loading} onClick={() => onRun('payloads')} />
      </div>

      <div style={{ height: 1, background: 'var(--border)' }} />

      {/* Chat */}
      <div>
        <div style={{ fontSize: '0.6rem', letterSpacing: 3, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
          Ask Assistant
        </div>
        <input
          type="text"
          placeholder="What should I test?"
          value={chatQ}
          onChange={e => onChatQChange(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && onRun('chat')}
          style={{
            width: '100%',
            background: 'var(--surface2)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '10px 14px',
            color: 'var(--lime)',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '0.78rem',
            outline: 'none',
            caretColor: 'var(--lime)',
            marginBottom: 8,
          }}
          onFocus={e => {
            e.target.style.borderColor = 'var(--border-h)'
            e.target.style.boxShadow = '0 0 0 3px var(--lime-dim)'
          }}
          onBlur={e => {
            e.target.style.borderColor = 'var(--border)'
            e.target.style.boxShadow = 'none'
          }}
        />
        <Btn label="Ask" icon="▸" full
          disabled={loading || !chatQ.trim()} onClick={() => onRun('chat')} />
      </div>

      <div style={{ height: 1, background: 'var(--border)' }} />

      {/* Stats */}
      <div>
        <div style={{ fontSize: '0.6rem', letterSpacing: 3, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
          Last Scan Stats
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <StatPill label="IP" value={stats.ip} />
          <StatPill label="Status" value={stats.status} />
          <StatPill label="SSL" value={stats.ssl} />
        </div>
      </div>
    </aside>
  )
}