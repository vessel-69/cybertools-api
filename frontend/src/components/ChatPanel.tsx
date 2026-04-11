import { useState, useRef, useEffect, KeyboardEvent } from 'react'
import { api } from '../api/client'
import type { ChatMessage } from '../types'

let _id = 1
function mkId() { return _id++ }

const WELCOME: ChatMessage = {
  id: 0,
  role: 'assistant',
  lines: [
    'Red team assistant ready.',
    'Run a scan first, then ask me anything about the results.',
  ],
  tip: 'Try: "What should I test?", "What parameters are injectable?", "What subdomains were found?"',
  timestamp: new Date().toLocaleTimeString(),
}

function TypingDots() {
  return (
    <div style={{ display: 'flex', gap: 5, padding: '10px 14px', alignItems: 'center' }}>
      {[0, 1, 2].map(i => (
        <span key={i} style={{
          width: 7, height: 7, borderRadius: '50%',
          background: 'var(--lime)',
          display: 'inline-block',
          animation: `dots 1.2s ${i * 0.18}s ease-in-out infinite`,
        }} />
      ))}
    </div>
  )
}

function UserBubble({ msg }: { msg: ChatMessage }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 14 }}>
      <div style={{ maxWidth: '85%' }}>
        <div style={{
          background: 'var(--lime-dim)',
          border: '1px solid var(--border-h)',
          borderRadius: '12px 12px 2px 12px',
          padding: '8px 12px',
          fontSize: '0.78rem', lineHeight: 1.55,
          color: 'var(--text)',
        }}>
          {msg.lines[0]}
        </div>
        <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textAlign: 'right', marginTop: 3 }}>
          {msg.timestamp}
        </div>
      </div>
    </div>
  )
}

function AssistantBubble({ msg }: { msg: ChatMessage }) {
  if (msg.isLoading) {
    return (
      <div style={{ display: 'flex', marginBottom: 14 }}>
        <div style={{
          background: 'var(--surface2)',
          border: '1px solid var(--border)',
          borderRadius: '12px 12px 12px 2px',
          overflow: 'hidden',
        }}>
          <TypingDots />
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', marginBottom: 14 }}>
      <div style={{ maxWidth: '95%' }}>
        <div style={{
          background: 'var(--surface2)',
          border: '1px solid var(--border)',
          borderRadius: '12px 12px 12px 2px',
          padding: '10px 12px',
          fontSize: '0.76rem', lineHeight: 1.6,
        }}>
          {msg.lines.map((line, i) => (
            <div key={i} style={{
              display: 'flex', gap: 8, alignItems: 'flex-start',
              marginBottom: i < msg.lines.length - 1 ? 5 : 0,
            }}>
              <span style={{ color: 'var(--lime)', flexShrink: 0, fontSize: '0.7rem', marginTop: 2 }}>›</span>
              <span style={{ color: 'var(--text)' }}>{line}</span>
            </div>
          ))}
          {msg.tip && (
            <div style={{
              marginTop: 8, paddingTop: 8,
              borderTop: '1px solid var(--border)',
              fontSize: '0.68rem', color: 'var(--text-muted)',
            }}>
              <span style={{ color: 'var(--lime)' }}>tip: </span>{msg.tip}
            </div>
          )}
        </div>
        <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: 3, paddingLeft: 2 }}>
          {msg.timestamp}
        </div>
      </div>
    </div>
  )
}

export default function ChatPanel() {
  const [messages, setMessages]   = useState<ChatMessage[]>([WELCOME])
  const [input,    setInput]      = useState('')
  const [loading,  setLoading]    = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef  = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  async function send() {
    const q = input.trim()
    if (!q || loading) return
    setInput('')

    const userMsg: ChatMessage = {
      id: mkId(), role: 'user', lines: [q],
      timestamp: new Date().toLocaleTimeString(),
    }
    const thinkingMsg: ChatMessage = {
      id: mkId(), role: 'assistant', lines: [],
      isLoading: true,
      timestamp: new Date().toLocaleTimeString(),
    }
    const thinkingId = thinkingMsg.id

    setMessages(prev => [...prev, userMsg, thinkingMsg])
    setLoading(true)

    try {
      const d = await api.chat(q)
      setMessages(prev => prev.map(m =>
        m.id === thinkingId
          ? { ...m, lines: d.response, tip: d.tip, isLoading: false }
          : m
      ))
    } catch (err) {
      setMessages(prev => prev.map(m =>
        m.id === thinkingId
          ? { ...m, lines: ['Connection error — is the API running?'], isLoading: false }
          : m
      ))
    } finally {
      setLoading(false)
    }
  }

  function clearChat() {
    setMessages([{
      id: mkId(), role: 'assistant',
      lines: ['Chat cleared. Run a scan and ask me anything.'],
      timestamp: new Date().toLocaleTimeString(),
    }])
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  return (
    <aside style={{
      borderLeft: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column',
      height: 'calc(100vh - 49px)',
      position: 'sticky', top: 49,
      width: 320, minWidth: 320,
      background: 'var(--bg)',
      zIndex: 1,
    }}>

      {/* Header */}
      <div style={{
        padding: '12px 16px',
        borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            width: 7, height: 7, borderRadius: '50%',
            background: 'var(--lime)',
            boxShadow: '0 0 8px var(--lime)',
            display: 'inline-block',
            animation: 'blink 2s step-end infinite',
          }} />
          <span style={{
            fontSize: '0.65rem', letterSpacing: 2,
            textTransform: 'uppercase', color: 'var(--lime)',
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            Assistant
          </span>
        </div>
        <button
          onClick={clearChat}
          style={{
            background: 'none', border: '1px solid var(--border)',
            borderRadius: 4, padding: '3px 8px',
            fontSize: '0.6rem', letterSpacing: 1,
            textTransform: 'uppercase', color: 'var(--text-muted)',
            cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
          }}
          onMouseEnter={e => {
            e.currentTarget.style.borderColor = 'var(--border-h)'
            e.currentTarget.style.color = 'var(--lime)'
          }}
          onMouseLeave={e => {
            e.currentTarget.style.borderColor = 'var(--border)'
            e.currentTarget.style.color = 'var(--text-muted)'
          }}
        >
          CLR
        </button>
      </div>

      {/* Messages */}
      <div style={{
        flex: 1, overflowY: 'auto',
        padding: '16px 14px',
        display: 'flex', flexDirection: 'column',
      }}>
        {messages.map(msg =>
          msg.role === 'user'
            ? <UserBubble key={msg.id} msg={msg} />
            : <AssistantBubble key={msg.id} msg={msg} />
        )}
        <div ref={scrollRef} />
      </div>

      {/* Suggested prompts */}
      <div style={{
        padding: '8px 14px',
        borderTop: '1px solid var(--border)',
        display: 'flex', gap: 6, flexWrap: 'wrap',
        flexShrink: 0,
      }}>
        {['What to test?', 'Vulns found?', 'Missing headers?', 'Injectable params?'].map(q => (
          <button
            key={q}
            onClick={() => { setInput(q); inputRef.current?.focus() }}
            style={{
              padding: '3px 8px', borderRadius: 4,
              fontSize: '0.62rem', letterSpacing: 0.5,
              border: '1px solid var(--border)',
              background: 'transparent', color: 'var(--text-dim)',
              cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--border-h)'
              e.currentTarget.style.color = 'var(--lime)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--border)'
              e.currentTarget.style.color = 'var(--text-dim)'
            }}
          >
            {q}
          </button>
        ))}
      </div>

      {/* Input */}
      <div style={{
        padding: '12px 14px',
        borderTop: '1px solid var(--border)',
        display: 'flex', gap: 8, alignItems: 'flex-end',
        flexShrink: 0,
      }}>
        <textarea
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={onKey}
          placeholder="Ask about your scan… (Enter to send)"
          rows={2}
          style={{
            flex: 1,
            background: 'var(--surface2)',
            border: '1px solid var(--border)',
            borderRadius: 8,
            padding: '8px 10px',
            color: 'var(--text)',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '0.75rem',
            outline: 'none',
            resize: 'none',
            caretColor: 'var(--lime)',
            lineHeight: 1.5,
          }}
          onFocus={e => {
            e.target.style.borderColor = 'var(--border-h)'
            e.target.style.boxShadow = '0 0 0 2px var(--lime-dim)'
          }}
          onBlur={e => {
            e.target.style.borderColor = 'var(--border)'
            e.target.style.boxShadow = 'none'
          }}
        />
        <button
          onClick={send}
          disabled={loading || !input.trim()}
          style={{
            padding: '8px 12px',
            background: input.trim() && !loading ? 'var(--lime-dim)' : 'var(--surface)',
            border: `1px solid ${input.trim() && !loading ? 'var(--border-h)' : 'var(--border)'}`,
            borderRadius: 8,
            color: input.trim() && !loading ? 'var(--lime)' : 'var(--text-muted)',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '0.68rem', letterSpacing: 1,
            textTransform: 'uppercase', cursor: input.trim() && !loading ? 'pointer' : 'not-allowed',
            opacity: loading ? 0.5 : 1,
            alignSelf: 'stretch',
          }}
        >
          {loading ? '…' : '▸'}
        </button>
      </div>

    </aside>
  )
}