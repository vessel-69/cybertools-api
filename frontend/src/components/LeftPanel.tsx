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

function ActionBtn({
  label, icon, active, disabled, full, primary, onClick,
}: {
  label: string
  icon: string
  active?: boolean
  disabled?: boolean
  full?: boolean
  primary?: boolean
  onClick: () => void
}) {
  const [hov, setHov] = useState(false)
  const lit = active || hov || primary
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        gridColumn: full ? '1 / -1' : undefined,
        padding: '10px 8px',
        borderRadius: 'var(--radius)',
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '0.72rem',
        letterSpacing: 1,
        textTransform: 'uppercase' as const,
        cursor: disabled ? 'not-allowed' : 'pointer',
        border: `1px solid ${lit ? 'var(--border-h)' : 'var(--border)'}`,
        background: lit ? 'var(--lime-dim)' : 'var(--surface)',
        color: lit ? 'var(--lime)' : 'var(--text-dim)',
        boxShadow: lit ? '0 0 12px var(--lime-dim)' : 'none',
        opacity: disabled ? 0.4 : 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
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
  const hasValue = value !== '—'
  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '6px 10px',
      background: 'var(--surface2)',
      borderRadius: 6,
      border: '1px solid var(--border)',
      fontSize: '0.7rem',
    }}>
      <span style={{ color: 'var(--text-muted)', letterSpacing: 1, textTransform: 'uppercase' as const }}>
        {label}
      </span>
      <span style={{ color: hasValue ? 'var(--lime)' : 'var(--text-muted)', fontWeight: 500 }}>
        {value}
      </span>
    </div>
  )
}

const PAYLOAD_TYPES: PayloadType[] = ['xss', 'sqli', 'lfi', 'ssrf']

export default function LeftPanel({
  target, onTargetChange,
  loading, stats,
  chatQ, onChatQChange,
  payloadType, onPayloadTypeChange,
  onRun, activeCmd,
}: LeftPanelProps) {

  const inputStyle = (focused: boolean) => ({
    width: '100%',
    background: 'var(--surface2)',
    border: `1px solid ${focused ? 'var(--border-h)' : 'var(--border)'}`,
    boxShadow: focused ? '0 0 0 3px var(--lime-dim), 0 0 20px var(--lime-dim)' : 'none',
    borderRadius: 'var(--radius)',
    padding: '10px 14px',
    color: 'var(--lime)',
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '0.82rem',
    outline: 'none',
    caretColor: 'var(--lime)',
    transition: 'border-color 0.2s, box-shadow 0.2s',
  })

  const [targetFocus, setTargetFocus] = useState(false)
  const [chatFocus,   setChatFocus]   = useState(false)

  return (
    <aside style={{
      borderRight: '1px solid var(--border)',
      padding: '24px 20px',
      display: 'flex',
      flexDirection: 'column',
      gap: 20,
      position: 'sticky',
      top: 49,
      height: 'calc(100vh - 49px)',
      overflowY: 'auto',
    }}>

      {/* ── Target ── */}
      <div>
        <div style={{
          fontSize: '0.6rem', letterSpacing: 3,
          textTransform: 'uppercase' as const,
          color: 'var(--text-muted)', marginBottom: 8,
        }}>
          Target
        </div>
        <input
          type="text"
          placeholder="example.com"
          value={target}
          onChange={e => onTargetChange(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && target && onRun('recon')}
          onFocus={() => setTargetFocus(true)}
          onBlur={() => setTargetFocus(false)}
          style={inputStyle(targetFocus)}
        />
      </div>

      {/* ── Commands ── */}
      <div>
        <div style={{
          fontSize: '0.6rem', letterSpacing: 3,
          textTransform: 'uppercase' as const,
          color: 'var(--text-muted)', marginBottom: 8,
        }}>
          Commands
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <ActionBtn
            label="Workflow" icon="⚡" full primary
            active={activeCmd === 'workflow'}
            disabled={loading || !target}
            onClick={() => onRun('workflow')}
          />
          <ActionBtn
            label="Recon" icon="◎"
            active={activeCmd === 'recon'}
            disabled={loading || !target}
            onClick={() => onRun('recon')}
          />
          <ActionBtn
            label="Analyze" icon="⟳"
            active={activeCmd === 'analyze'}
            disabled={loading || !target}
            onClick={() => onRun('analyze')}
          />
          <ActionBtn
            label="BB Scan" icon="◈"
            active={activeCmd === 'bb-scan'}
            disabled={loading || !target}
            onClick={() => onRun('bb-scan')}
          />
          <ActionBtn
            label="Last Scan" icon="⊙" full
            active={activeCmd === 'last-scan'}
            disabled={loading}
            onClick={() => onRun('last-scan')}
          />
        </div>
      </div>

      <div style={{ height: 1, background: 'var(--border)' }} />

      {/* ── Payloads ── */}
      <div>
        <div style={{
          fontSize: '0.6rem', letterSpacing: 3,
          textTransform: 'uppercase' as const,
          color: 'var(--text-muted)', marginBottom: 8,
        }}>
          Payloads
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' as const, marginBottom: 8 }}>
          {PAYLOAD_TYPES.map(pt => (
            <button
              key={pt}
              onClick={() => onPayloadTypeChange(pt)}
              style={{
                padding: '4px 10px', borderRadius: 4,
                fontSize: '0.68rem', letterSpacing: 1,
                textTransform: 'uppercase' as const,
                border: `1px solid ${payloadType === pt ? 'var(--border-h)' : 'var(--border)'}`,
                background: payloadType === pt ? 'var(--lime-dim)' : 'transparent',
                color: payloadType === pt ? 'var(--lime)' : 'var(--text-muted)',
                cursor: 'pointer',
                fontFamily: "'JetBrains Mono', monospace",
                transition: 'all 0.15s',
              }}
            >
              {pt}
            </button>
          ))}
        </div>
        <ActionBtn
          label={`Get ${payloadType.toUpperCase()} Payloads`}
          icon="◇" full
          active={activeCmd === 'payloads'}
          disabled={loading}
          onClick={() => onRun('payloads')}
        />
      </div>

      <div style={{ height: 1, background: 'var(--border)' }} />

      {/* ── Chat ── */}
      <div>
        <div style={{
          fontSize: '0.6rem', letterSpacing: 3,
          textTransform: 'uppercase' as const,
          color: 'var(--text-muted)', marginBottom: 8,
        }}>
          Ask Assistant
        </div>
        <input
          type="text"
          placeholder="What should I test?"
          value={chatQ}
          onChange={e => onChatQChange(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && chatQ.trim() && onRun('chat')}
          onFocus={() => setChatFocus(true)}
          onBlur={() => setChatFocus(false)}
          style={{ ...inputStyle(chatFocus), fontSize: '0.78rem', marginBottom: 8 }}
        />
        <ActionBtn
          label="Ask" icon="▸" full
          active={activeCmd === 'chat'}
          disabled={loading || !chatQ.trim()}
          onClick={() => onRun('chat')}
        />
      </div>

      <div style={{ height: 1, background: 'var(--border)' }} />

      {/* ── Stats ── */}
      <div>
        <div style={{
          fontSize: '0.6rem', letterSpacing: 3,
          textTransform: 'uppercase' as const,
          color: 'var(--text-muted)', marginBottom: 8,
        }}>
          Last Scan Stats
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <StatPill label="IP"     value={stats.ip} />
          <StatPill label="Status" value={stats.status} />
          <StatPill label="SSL"    value={stats.ssl} />
        </div>
      </div>

    </aside>
  )
}
