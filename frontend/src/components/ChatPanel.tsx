import { useState, useRef, useEffect, KeyboardEvent } from 'react'

interface Msg {
  id: number
  role: 'user' | 'assistant'
  text: string
  ts: string
  loading?: boolean
}

let _seq = 1
const uid = () => _seq++
const now = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

const SYSTEM = `You are a red team security assistant embedded in CyberTools API — a free security utility API for bug bounty hunters, red teamers, and developers.

CyberTools API features:
- /recon?domain= : IP, DNS (A/MX/TXT/NS), SSL cert+SAN, tech stack, security headers
- /analyze-url?url= : redirect chain, header misconfigurations (CORS, HSTS, CSP)
- /bb-scan?url= : concurrent probe of 30+ common paths (admin, .env, .git, api docs)
- /expand?domain= : subdomain enumeration via crt.sh, hackertarget, SSL SAN
- /endpoints?url= : 60+ path scan, tagged by type (api/admin/auth/sensitive/monitoring)
- /params?url= : 26 common injectable params probed, flagged by risk (high/medium/low)
- /payloads?type= : xss, sqli, lfi, ssrf, open_redirect, idor payloads with context tags
- /workflow?target= : full 5-stage pipeline (recon+analyze+scan+endpoints+params)
- /workflows/express : fast recon+analyze only
- /workflows/bugbounty : recon+scan+auto-recommended payloads
- /workflows/subdomains : subdomain enum + recon on each live sub
- /workflows/api : endpoint enum + param probing
- /workflows/batch : batch scan up to 5 targets
- /last-scan : last cached result
- Hashing: /hash/{algo}/{text} — md5, sha1, sha256, sha384, sha512, blake2b, blake2s
- Encoding: /encode/{method}/{text} — base64, hex, url
- /ip/{ip} : IP geolocation via ipinfo.io
- /password/analyze : password strength, entropy, actionable feedback
- /time : UTC time in multiple formats

Answer questions about cybersecurity, bug bounty, penetration testing, web security, and how to use CyberTools API. Give specific, actionable, expert-level advice. When asked about vulnerabilities, give real technical detail. When asked about this API's features, explain them accurately. Keep responses concise but complete.`

async function callClaude(messages: { role: string; content: string }[]): Promise<string> {
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system: SYSTEM,
        messages,
      }),
    })
    const data = await res.json()
    if (data.error) return `Error: ${data.error.message}`
    return data.content?.find((b: { type: string }) => b.type === 'text')?.text ?? 'No response.'
  } catch {
    return 'Connection error. Make sure the API is running.'
  }
}

// ── Bubble components ─────────────────────────────────────────────────────────

function UserBubble({ msg }: { msg: Msg }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
      <div>
        <div style={{
          background: 'rgba(220,38,38,0.15)',
          border: '1px solid rgba(220,38,38,0.3)',
          borderRadius: '14px 14px 3px 14px',
          padding: '9px 13px',
          fontSize: '0.8rem', lineHeight: 1.55,
          color: '#f0e0e0', maxWidth: 240, wordBreak: 'break-word',
        }}>
          {msg.text}
        </div>
        <div style={{ fontSize: '0.58rem', color: '#4a2a2a', textAlign: 'right', marginTop: 3 }}>
          {msg.ts}
        </div>
      </div>
    </div>
  )
}

function AssistantBubble({ msg }: { msg: Msg }) {
  return (
    <div style={{ display: 'flex', gap: 9, marginBottom: 12, alignItems: 'flex-start' }}>
      {/* Avatar */}
      <div style={{
        width: 30, height: 30, borderRadius: '50%', flexShrink: 0,
        background: 'rgba(220,38,38,0.12)',
        border: '1.5px solid rgba(220,38,38,0.35)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: '0.75rem', color: '#e63030', fontWeight: 700,
        marginTop: 2,
      }}>
        ⌖
      </div>
      <div style={{ flex: 1 }}>
        <div style={{
          fontSize: '0.62rem', color: '#6b2a2a', letterSpacing: 1,
          textTransform: 'uppercase', marginBottom: 4,
        }}>
          CyberTools AI
        </div>
        {msg.loading ? (
          <div style={{
            background: '#121515', border: '1px solid #1e0808',
            borderRadius: '3px 14px 14px 14px',
            padding: '10px 14px', display: 'flex', gap: 5, alignItems: 'center',
          }}>
            {[0,1,2].map(i => (
              <span key={i} style={{
                width: 6, height: 6, borderRadius: '50%', background: '#e63030',
                display: 'inline-block', opacity: 0.3,
                animation: `dots 1.2s ${i*0.18}s ease-in-out infinite`,
              }} />
            ))}
          </div>
        ) : (
          <div style={{
            background: '#121515',
            border: '1px solid #1e0808',
            borderRadius: '3px 14px 14px 14px',
            padding: '10px 13px',
            fontSize: '0.78rem', lineHeight: 1.65,
            color: '#ddd5d5', maxWidth: 260, wordBreak: 'break-word',
            whiteSpace: 'pre-wrap',
          }}>
            {msg.text}
          </div>
        )}
        {!msg.loading && (
          <div style={{ fontSize: '0.58rem', color: '#4a2a2a', marginTop: 3, paddingLeft: 2 }}>
            {msg.ts}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const SUGGESTIONS = [
  'How do I find XSS?',
  'What does /bb-scan do?',
  'How to test for IDOR?',
  'What payloads for SQLi?',
  'How to find subdomains?',
  'What is SSRF?',
]

export default function ChatPanel() {
  const [open,     setOpen]     = useState(false)
  const [msgs,     setMsgs]     = useState<Msg[]>([{
    id: 0, role: 'assistant', ts: now(),
    text: "Hey! I'm CyberTools AI — your red team assistant. Ask me about bug bounty, web security, or how to use any feature of this API.",
  }])
  const [input,    setInput]    = useState('')
  const [thinking, setThinking] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef  = useRef<HTMLTextAreaElement>(null)
  const histRef   = useRef<{ role: string; content: string }[]>([])

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [msgs])

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 80)
  }, [open])

  async function send(text?: string) {
    const q = (text ?? input).trim()
    if (!q || thinking) return
    setInput('')

    const userMsg: Msg = { id: uid(), role: 'user', text: q, ts: now() }
    const thinkId = uid()
    const thinkMsg: Msg = { id: thinkId, role: 'assistant', text: '', ts: now(), loading: true }

    histRef.current.push({ role: 'user', content: q })
    setMsgs(prev => [...prev, userMsg, thinkMsg])
    setThinking(true)

    const reply = await callClaude(histRef.current)
    histRef.current.push({ role: 'assistant', content: reply })

    setMsgs(prev => prev.map(m =>
      m.id === thinkId ? { ...m, text: reply, loading: false } : m
    ))
    setThinking(false)
  }

  function clear() {
    histRef.current = []
    setMsgs([{
      id: uid(), role: 'assistant', ts: now(),
      text: "Chat cleared. What do you want to know?",
    }])
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  return (
    <>
      {/* ── Popup window ── */}
      {open && (
        <div style={{
          position: 'fixed', bottom: 88, right: 24,
          width: 360, height: 540,
          background: '#0d0f0f',
          border: '1px solid rgba(220,38,38,0.25)',
          borderRadius: 18,
          boxShadow: '0 24px 60px rgba(0,0,0,0.7), 0 0 0 1px rgba(220,38,38,0.08)',
          display: 'flex', flexDirection: 'column',
          zIndex: 9998,
          overflow: 'hidden',
          animation: 'chatOpen 0.22s cubic-bezier(.34,1.56,.64,1) forwards',
        }}>
          {/* Header */}
          <div style={{
            padding: '14px 16px 12px',
            background: 'linear-gradient(135deg, #1a0808 0%, #0d0f0f 100%)',
            borderBottom: '1px solid rgba(220,38,38,0.15)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            flexShrink: 0,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 36, height: 36, borderRadius: '50%',
                background: 'rgba(220,38,38,0.15)',
                border: '2px solid rgba(220,38,38,0.4)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '1rem', color: '#e63030',
              }}>⌖</div>
              <div>
                <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#f0e0e0', fontFamily: "'Syne', sans-serif", letterSpacing: 0.5 }}>
                  CyberTools AI
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginTop: 2 }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#4ade80', display: 'inline-block' }} />
                  <span style={{ fontSize: '0.62rem', color: '#6b2a2a' }}>Online · Red Team Assistant</span>
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button onClick={clear}
                style={{
                  background: 'none', border: '1px solid rgba(220,38,38,0.2)',
                  borderRadius: 6, padding: '4px 9px',
                  fontSize: '0.6rem', letterSpacing: 1, textTransform: 'uppercase',
                  color: '#6b2a2a', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(220,38,38,0.5)'; e.currentTarget.style.color = '#e63030' }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(220,38,38,0.2)'; e.currentTarget.style.color = '#6b2a2a' }}
              >CLR</button>
              <button onClick={() => setOpen(false)}
                style={{
                  background: 'none', border: '1px solid rgba(220,38,38,0.2)',
                  borderRadius: 6, padding: '4px 9px',
                  fontSize: '0.7rem', color: '#6b2a2a', cursor: 'pointer',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(220,38,38,0.5)'; e.currentTarget.style.color = '#e63030' }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(220,38,38,0.2)'; e.currentTarget.style.color = '#6b2a2a' }}
              >✕</button>
            </div>
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '14px 14px 6px' }}>
            {msgs.map(m =>
              m.role === 'user'
                ? <UserBubble key={m.id} msg={m} />
                : <AssistantBubble key={m.id} msg={m} />
            )}
            <div ref={scrollRef} />
          </div>

          {/* Suggestions */}
          <div style={{
            padding: '8px 14px', borderTop: '1px solid rgba(220,38,38,0.08)',
            display: 'flex', gap: 5, flexWrap: 'wrap', flexShrink: 0,
          }}>
            {SUGGESTIONS.slice(0, 3).map(s => (
              <button key={s} onClick={() => send(s)}
                style={{
                  padding: '4px 9px', borderRadius: 20,
                  fontSize: '0.62rem', border: '1px solid rgba(220,38,38,0.18)',
                  background: 'transparent', color: '#6b4a4a',
                  cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
                  whiteSpace: 'nowrap',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(220,38,38,0.45)'; e.currentTarget.style.color = '#e63030' }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(220,38,38,0.18)'; e.currentTarget.style.color = '#6b4a4a' }}
              >{s}</button>
            ))}
          </div>

          {/* Input */}
          <div style={{
            padding: '10px 14px 14px',
            borderTop: '1px solid rgba(220,38,38,0.1)',
            display: 'flex', gap: 8, alignItems: 'flex-end', flexShrink: 0,
          }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={onKey}
              placeholder="Ask about security, exploits, this API…"
              rows={2}
              style={{
                flex: 1, background: '#121515',
                border: '1px solid rgba(220,38,38,0.15)',
                borderRadius: 10, padding: '8px 11px',
                color: '#ddd5d5', fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.76rem', outline: 'none', resize: 'none',
                caretColor: '#e63030', lineHeight: 1.5,
              }}
              onFocus={e => { e.target.style.borderColor = 'rgba(220,38,38,0.45)' }}
              onBlur={e => { e.target.style.borderColor = 'rgba(220,38,38,0.15)' }}
            />
            <button onClick={() => send()}
              disabled={thinking || !input.trim()}
              style={{
                width: 38, height: 38, borderRadius: 10, flexShrink: 0,
                background: input.trim() && !thinking ? '#e63030' : '#1a0808',
                border: '1px solid rgba(220,38,38,0.3)',
                color: input.trim() && !thinking ? '#fff' : '#4a2020',
                cursor: input.trim() && !thinking ? 'pointer' : 'not-allowed',
                fontSize: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'center',
                transition: 'all 0.15s',
              }}
            >▸</button>
          </div>
        </div>
      )}

      {/* ── Floating button ── */}
      <button
        onClick={() => setOpen(o => !o)}
        title="Ask CyberTools AI"
        style={{
          position: 'fixed', bottom: 24, right: 24,
          width: 56, height: 56, borderRadius: '50%',
          background: open ? '#1a0808' : '#e63030',
          border: '2px solid rgba(220,38,38,0.5)',
          boxShadow: `0 4px 20px rgba(220,38,38,${open ? 0.2 : 0.45})`,
          cursor: 'pointer', zIndex: 9999,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: open ? '1.1rem' : '1.4rem',
          color: open ? '#e63030' : '#fff',
          transition: 'all 0.22s cubic-bezier(.34,1.56,.64,1)',
          transform: open ? 'rotate(45deg)' : 'rotate(0deg)',
        }}
      >
        {open ? '✕' : '⌖'}
      </button>

      <style>{`
        @keyframes chatOpen {
          from { opacity: 0; transform: scale(0.88) translateY(16px); transform-origin: bottom right; }
          to   { opacity: 1; transform: scale(1) translateY(0); }
        }
        @keyframes dots {
          0%, 60%, 100% { opacity: 0.2; transform: scale(0.75); }
          30%            { opacity: 1;   transform: scale(1); }
        }
      `}</style>
    </>
  )
}