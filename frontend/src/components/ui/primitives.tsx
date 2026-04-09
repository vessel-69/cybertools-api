import { useState } from 'react'

export function KVRow({
  label, value, tone,
}: {
  label: string
  value?: string | number | null
  tone?: 'good' | 'bad' | 'warn'
}) {
  const color =
    tone === 'good' ? 'var(--lime)' :
    tone === 'bad'  ? 'var(--red)'  :
    tone === 'warn' ? 'var(--yellow)' :
    'var(--text)'
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      padding: '5px 0', borderBottom: '1px solid var(--border)',
    }}>
      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem', letterSpacing: 1 }}>{label}</span>
      <span style={{
        color, fontSize: '0.78rem', fontWeight: 500,
        maxWidth: '65%', textAlign: 'right', wordBreak: 'break-all',
      }}>{value ?? '—'}</span>
    </div>
  )
}

export function HintItem({ text, tone = 'bad' }: { text: string; tone?: 'bad' | 'warn' | 'ok' }) {
  const icon  = tone === 'ok' ? '✓' : tone === 'warn' ? '⚠' : '✗'
  const color = tone === 'ok' ? 'var(--lime)' : tone === 'warn' ? 'var(--yellow)' : 'var(--red)'
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '5px 0', fontSize: '0.75rem' }}>
      <span style={{ color, flexShrink: 0 }}>{icon}</span>
      <span style={{ color: 'var(--text)', lineHeight: 1.5 }}>{text}</span>
    </div>
  )
}

export function SummaryItem({ text }: { text: string }) {
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '4px 0', fontSize: '0.75rem' }}>
      <span style={{ color: 'var(--lime)', flexShrink: 0 }}>›</span>
      <span style={{ color: 'var(--text)', lineHeight: 1.5 }}>{text}</span>
    </div>
  )
}

export function NextStep({ index, text }: { index: number; text: string }) {
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '5px 0', fontSize: '0.75rem' }}>
      <span style={{
        color: 'var(--bg)', background: 'var(--lime)',
        borderRadius: 3, padding: '1px 5px',
        fontSize: '0.65rem', fontWeight: 700, flexShrink: 0,
      }}>{index}</span>
      <span style={{ color: 'var(--text)', lineHeight: 1.5 }}>{text}</span>
    </div>
  )
}

export function PathRow({ path, status }: { path: string; status: number }) {
  const color =
    status === 200  ? 'var(--lime)'   :
    status < 400    ? 'var(--yellow)' :
    'var(--red)'
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      padding: '4px 8px', borderRadius: 4, marginBottom: 3,
      background: 'var(--surface2)', fontSize: '0.73rem',
    }}>
      <span style={{ color: 'var(--text)', fontFamily: 'monospace' }}>{path}</span>
      <span style={{ color, fontWeight: 700, flexShrink: 0 }}>{status}</span>
    </div>
  )
}

export function PayloadItem({ payload, label }: { payload: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(payload)
    setCopied(true)
    setTimeout(() => setCopied(false), 1200)
  }
  return (
    <div
      onClick={copy}
      title="Click to copy"
      style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '6px 10px', borderRadius: 6, marginBottom: 4,
        background: copied ? 'rgba(130,255,80,0.08)' : 'var(--surface2)',
        border: `1px solid ${copied ? 'var(--border-h)' : 'var(--border)'}`,
        cursor: 'pointer', gap: 8,
      }}
    >
      <code style={{ color: 'var(--lime)', fontSize: '0.72rem', wordBreak: 'break-all', flex: 1 }}>
        {payload}
      </code>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem', letterSpacing: 1, flexShrink: 0 }}>
        {copied ? '✓ copied' : label}
      </span>
    </div>
  )
}

export function Section({
  title, children, defaultOpen = true,
}: {
  title: string
  children: React.ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div style={{
      border: '1px solid var(--border)', borderRadius: 'var(--radius)',
      overflow: 'hidden', marginBottom: 12,
    }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '10px 14px', background: 'var(--surface)',
          border: 'none', color: 'var(--text-dim)', cursor: 'pointer',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '0.72rem', letterSpacing: 1, textTransform: 'uppercase',
        }}
      >
        <span>{title}</span>
        <span style={{ color: 'var(--lime)', fontSize: '0.8rem' }}>{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div style={{ padding: '12px 14px', background: 'var(--bg)', borderTop: '1px solid var(--border)' }}>
          {children}
        </div>
      )}
    </div>
  )
}
