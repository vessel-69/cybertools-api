import type {
  ReconResult, AnalyzeResult, BBScanResult,
  PayloadResult, WorkflowResult, LastScanResult, ChatResult,
} from '../../types'
import {
  KVRow, HintItem, SummaryItem, NextStep, PathRow, PayloadItem, Section,
} from '../ui/primitives'

export function ReconSection({ d }: { d: ReconResult }) {
  return (
    <div className="fade-in">
      <Section title="◉ Host Info">
        <KVRow label="Domain"   value={d.domain} />
        <KVRow label="IP"       value={d.ip} tone="good" />
        <KVRow label="Protocol" value={d.protocol?.toUpperCase()} />
        <KVRow label="Status"   value={d.status_code}
          tone={d.status_code && d.status_code < 400 ? 'good' : 'bad'} />
        {d.ssl && (
          <>
            <KVRow label="SSL Valid"  value={d.ssl.valid ? 'Yes' : 'No'} tone={d.ssl.valid ? 'good' : 'bad'} />
            <KVRow label="Expires"    value={d.ssl.expires} />
            <KVRow label="Days Left"  value={d.ssl.days_remaining}
              tone={d.ssl.days_remaining && d.ssl.days_remaining > 30 ? 'good' : 'bad'} />
            <KVRow label="Issuer"     value={d.ssl.issuer} />
            {d.ssl.warning && <HintItem text={d.ssl.warning} tone="warn" />}
          </>
        )}
      </Section>

      <Section title="◉ Security Headers">
        {d.missing_security_headers?.length
          ? d.missing_security_headers.map(h => <HintItem key={h} text={`Missing: ${h}`} />)
          : <HintItem text="All major security headers present." tone="ok" />}
      </Section>

      <Section title="◉ Tech Stack" defaultOpen={false}>
        {d.tech_hints?.length
          ? d.tech_hints.map(t => <SummaryItem key={t} text={t} />)
          : <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No tech hints detected.</span>}
      </Section>

      {d.smart_summary?.length ? (
        <Section title="◉ Smart Summary">
          {d.smart_summary.map((s, i) => <SummaryItem key={i} text={s} />)}
        </Section>
      ) : null}

      {d.next_steps?.length ? (
        <Section title="◉ Next Steps">
          {d.next_steps.map((s, i) => <NextStep key={i} index={i + 1} text={s} />)}
        </Section>
      ) : null}
    </div>
  )
}

export function AnalyzeSection({ d }: { d: AnalyzeResult }) {
  return (
    <div className="fade-in">
      <Section title="◉ Redirect Chain">
        {d.redirect_chain?.length
          ? d.redirect_chain.map((hop, i) => <PathRow key={i} path={hop.url} status={hop.status} />)
          : <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No redirects.</span>}
        {d.final_url    && <KVRow label="Final URL"    value={d.final_url} />}
        {d.final_status && <KVRow label="Final Status" value={d.final_status}
          tone={d.final_status < 400 ? 'good' : 'bad'} />}
      </Section>

      <Section title="◉ Misconfigurations">
        {d.misconfig_hints?.length
          ? d.misconfig_hints.map((h, i) => <HintItem key={i} text={h} />)
          : <HintItem text="No obvious misconfigurations found." tone="ok" />}
      </Section>

      {d.smart_summary?.length ? (
        <Section title="◉ Smart Summary">
          {d.smart_summary.map((s, i) => <SummaryItem key={i} text={s} />)}
        </Section>
      ) : null}

      {d.next_steps?.length ? (
        <Section title="◉ Next Steps">
          {d.next_steps.map((s, i) => <NextStep key={i} index={i + 1} text={s} />)}
        </Section>
      ) : null}
    </div>
  )
}

export function BBScanSection({ d }: { d: BBScanResult }) {
  return (
    <div className="fade-in">
      <Section title={`◉ Interesting Paths (${d.interesting_paths?.length ?? 0})`}>
        {d.interesting_paths?.length
          ? d.interesting_paths.map((p, i) => <PathRow key={i} path={p.path} status={p.status} />)
          : <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No interesting paths found.</span>}
      </Section>

      <Section title="◉ All Results" defaultOpen={false}>
        {d.all_results?.map((p, i) => <PathRow key={i} path={p.path} status={p.status} />)}
      </Section>

      <Section title="◉ Bug Bounty Hints">
        {d.bug_bounty_hints?.map((h, i) => <SummaryItem key={i} text={h} />)}
      </Section>

      {d.next_steps?.length ? (
        <Section title="◉ Next Steps">
          {d.next_steps.map((s, i) => <NextStep key={i} index={i + 1} text={s} />)}
        </Section>
      ) : null}
    </div>
  )
}

export function PayloadSection({ d }: { d: PayloadResult }) {
  return (
    <div className="fade-in">
      <Section title={`◉ ${d.type.toUpperCase()} Payloads (${d.count})`}>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginBottom: 12 }}>
          {d.description} · Click any payload to copy.
        </p>
        {d.payloads.map((p, i) => <PayloadItem key={i} payload={p.payload} label={p.label} />)}
      </Section>

      <Section title="◉ Usage Tips">
        {d.usage_tips.map((t, i) => <NextStep key={i} index={i + 1} text={t} />)}
      </Section>
    </div>
  )
}

export function WorkflowSection({ d }: { d: WorkflowResult }) {
  return (
    <div className="fade-in">
      <Section title={`◉ Full Workflow — ${d.target}`}>
        <KVRow label="Target"  value={d.target} />
        <KVRow label="Elapsed" value={`${d.elapsed_seconds}s`} tone="good" />
        {d.recon?.ip          && <KVRow label="IP"     value={d.recon.ip} />}
        {d.recon?.status_code && <KVRow label="Status" value={d.recon.status_code} />}
      </Section>

      {d.smart_summary?.length ? (
        <Section title="◉ Smart Summary">
          {d.smart_summary.map((s, i) => <SummaryItem key={i} text={s} />)}
        </Section>
      ) : null}

      <Section title={`◉ Interesting Paths (${d.bb_scan?.interesting_paths?.length ?? 0})`}>
        {d.bb_scan?.interesting_paths?.length
          ? d.bb_scan.interesting_paths.map((p, i) => <PathRow key={i} path={p.path} status={p.status} />)
          : <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No exposed paths found.</span>}
      </Section>

      <Section title="◉ Misconfigurations">
        {d.analysis?.misconfig_hints?.length
          ? d.analysis.misconfig_hints.map((h, i) => <HintItem key={i} text={h} />)
          : <HintItem text="No misconfigurations detected." tone="ok" />}
      </Section>

      {d.next_steps?.length ? (
        <Section title="◉ Next Steps">
          {d.next_steps.map((s, i) => <NextStep key={i} index={i + 1} text={s} />)}
        </Section>
      ) : null}
    </div>
  )
}

export function LastScanSection({ d }: { d: LastScanResult }) {
  const summary =
    (d.data as ReconResult).smart_summary ??
    (d.data as WorkflowResult).recon?.smart_summary ??
    []
  return (
    <div className="fade-in">
      <Section title={`◉ Last Scan — ${d.key}`}>
        <KVRow label="Target"    value={d.key} />
        <KVRow label="Timestamp" value={d.timestamp} />
      </Section>
      {summary.length > 0 && (
        <Section title="◉ Summary">
          {summary.map((s, i) => <SummaryItem key={i} text={s} />)}
        </Section>
      )}
    </div>
  )
}

export function ChatSection({ d }: { d: ChatResult }) {
  return (
    <div className="fade-in">
      <Section title={`◉ ${d.question}`}>
        {d.response.map((line, i) => <SummaryItem key={i} text={line} />)}
        {d.tip && (
          <div style={{
            marginTop: 12, padding: '8px 10px',
            background: 'var(--surface2)', borderRadius: 6,
            fontSize: '0.72rem', color: 'var(--text-muted)',
          }}>
            <span style={{ color: 'var(--lime)' }}>tip: </span>{d.tip}
          </div>
        )}
      </Section>
    </div>
  )
}
