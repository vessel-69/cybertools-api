import type { Command } from '../types'

interface NavbarProps {
  activeCmd: Command | null
}

export default function Navbar({ activeCmd }: NavbarProps) {
  return (
    <nav style={{
      position: 'sticky', top: 0, zIndex: 100,
      background: 'rgba(8,11,15,0.92)',
      backdropFilter: 'blur(12px)',
      borderBottom: '1px solid var(--border)',
      padding: '12px 24px',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          fontFamily: "'Syne', sans-serif",
          fontSize: '1rem', fontWeight: 800,
          letterSpacing: 2, textTransform: 'uppercase' as const,
          color: 'var(--lime)',
          textShadow: '0 0 20px var(--lime-glow)',
          display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <span style={{
            width: 8, height: 8, borderRadius: '50%',
            background: 'var(--lime)',
            boxShadow: '0 0 10px var(--lime)',
            display: 'inline-block',
            animation: 'blink 2s step-end infinite',
          }} />
          CyberTools
        </div>
        {activeCmd && (
          <span style={{
            fontSize: '0.65rem', letterSpacing: 2,
            color: 'var(--text-muted)', textTransform: 'uppercase' as const,
          }}>
            › {activeCmd}
          </span>
        )}
      </div>

      <div style={{ display: 'flex', gap: 6 }}>
        {[
          { label: 'Docs',   href: '/docs' },
          { label: 'GitHub', href: 'https://github.com/vessel-69/cybertools-api' },
        ].map(item => (
          <a
            key={item.label}
            href={item.href}
            target={item.href.startsWith('http') ? '_blank' : undefined}
            rel="noreferrer"
            style={{
              padding: '5px 12px', borderRadius: 4,
              fontSize: '0.68rem', letterSpacing: 1,
              color: 'var(--text-dim)', textDecoration: 'none',
              border: '1px solid transparent',
              textTransform: 'uppercase' as const,
            }}
            onMouseEnter={e => {
              const el = e.currentTarget
              el.style.color = 'var(--lime)'
              el.style.borderColor = 'var(--border)'
              el.style.background = 'var(--lime-dim)'
            }}
            onMouseLeave={e => {
              const el = e.currentTarget
              el.style.color = 'var(--text-dim)'
              el.style.borderColor = 'transparent'
              el.style.background = 'transparent'
            }}
          >
            {item.label}
          </a>
        ))}
      </div>
    </nav>
  )
}
