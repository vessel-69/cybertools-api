import type {
  ReconResult, AnalyzeResult, BBScanResult,
  PayloadResult, WorkflowResult, LastScanResult, ChatResult,
  ExpandResult, EndpointsResult, ParamsResult,
  ExpressWorkflowResult, BugBountyWorkflowResult,
  SubdomainsWorkflowResult, ApiWorkflowResult,
} from '../../types'
import { KVRow, HintItem, SummaryItem, NextStep, PathRow, PayloadItem, Section } from '../ui/primitives'

// ── Recon ─────────────────────────────────────────────────────────────────────

export function ReconSection({ d }: { d: ReconResult }) {
  return (
    <div className="fade-in">
      <Section title="◉ Host Info">
        <KVRow label="Domain"   value={d.domain} />
        <KVRow label="IP"       value={d.ip} tone="good" />
        <KVRow label="Protocol" value={d.protocol?.toUpperCase()} />
        <KVRow label="Status"   value={d.status_code} tone={d.status_code && d.status_code < 400 ? 'good' : 'bad'} />
        {d.ssl && <>
          <KVRow label="SSL Valid"  value={d.ssl.valid ? 'Yes' : 'No'} tone={d.ssl.valid ? 'good' : 'bad'} />
          <KVRow label="Expires"    value={d.ssl.expires} />
          <KVRow label="Days Left"  value={d.ssl.days_remaining} tone={d.ssl.days_remaining && d.ssl.days_remaining > 30 ? 'good' : 'bad'} />
          <KVRow label="Issuer"     value={d.ssl.issuer} />
          {d.ssl.warning && <HintItem text={d.ssl.warning} tone="warn" />}
        </>}
      </Section>

      <Section title="◉ Security Headers">
        {d.missing_security_headers?.length
          ? d.missing_security_headers.map(h => <HintItem key={h} text={`Missing: ${h}`} tone="missing" />)
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

// ── Analyze URL ───────────────────────────────────────────────────────────────

export function AnalyzeSection({ d }: { d: AnalyzeResult }) {
  return (
    <div className="fade-in">
      <Section title="◉ Redirect Chain">
        {d.redirect_chain?.length
          ? d.redirect_chain.map((hop, i) => <PathRow key={i} path={hop.url} status={hop.status} />)
          : <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No redirects.</span>}
        {d.final_url && <KVRow label="Final URL" value={d.final_url} />}
        {d.final_status && <KVRow label="Final Status" value={d.final_status} tone={d.final_status < 400 ? 'good' : 'bad'} />}
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

// ── BB Scan ───────────────────────────────────────────────────────────────────

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

// ── Payloads ──────────────────────────────────────────────────────────────────

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

// ── Workflow ──────────────────────────────────────────────────────────────────

export function WorkflowSection({ d }: { d: WorkflowResult }) {
  return (
    <div className="fade-in">
      <Section title={`◉ Full Workflow — ${d.target}`}>
        <KVRow label="Target"  value={d.target} />
        <KVRow label="Elapsed" value={`${d.elapsed_seconds}s`} tone="good" />
        {d.recon?.ip && <KVRow label="IP" value={d.recon.ip} />}
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

// ── Last Scan ─────────────────────────────────────────────────────────────────

export function LastScanSection({ d }: { d: LastScanResult }) {
  const summary = (d.data as ReconResult).smart_summary
    ?? (d.data as WorkflowResult).recon?.smart_summary
    ?? []
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

// ── Chat ──────────────────────────────────────────────────────────────────────

export function ChatSection({ d }: { d: ChatResult }) {
  return (
    <div className="fade-in">
      <Section title={`◉ ${d.question}`}>
        {d.response.map((line, i) => <SummaryItem key={i} text={line} />)}
        {d.tip && (
          <div style={{ marginTop: 12, padding: '8px 10px', background: 'var(--surface2)', borderRadius: 6, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            <span style={{ color: 'var(--lime)' }}>tip: </span>{d.tip}
          </div>
        )}
      </Section>
    </div>
  )
}

// ── Expand ─────────────────────────────────────────────────────────────────────

export function ExpandSection({ d }: { d: ExpandResult }) {
  const live = d.subdomains.filter(s => s.live)
  const dead = d.subdomains.filter(s => !s.live)

  return (
    <div className="fade-in">
      <Section title="◉ Overview">
        <KVRow label="Domain"      value={d.domain} />
        <KVRow label="Total found" value={d.total_found} />
        <KVRow label="Live"        value={d.live_count} tone={d.live_count > 0 ? 'good' : 'warn'} />
        <KVRow label="Sources"     value={d.sources.join(', ')} />
      </Section>

      <Section title={`◉ Live Subdomains (${live.length})`}>
        {live.length ? live.map((s, i) => (
          <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0', fontSize: '0.74rem', borderBottom: '1px solid var(--border)' }}>
            <span style={{ color: 'var(--lime)', fontWeight: 500 }}>● {s.subdomain}</span>
            <span style={{ color: 'var(--text-muted)' }}>{s.ip}</span>
          </div>
        )) : <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No live subdomains found.</span>}
      </Section>

      {dead.length > 0 && (
        <Section title={`◉ Non-resolving (${dead.length})`} defaultOpen={false}>
          {dead.map((s, i) => (
            <div key={i} style={{ padding: '3px 0', fontSize: '0.73rem', color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}>
              ○ {s.subdomain}
            </div>
          ))}
        </Section>
      )}

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

// ── Endpoints ──────────────────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  sensitive:  'var(--red)',
  admin:      'var(--red)',
  api:        'var(--lime)',
  auth:       'var(--yellow)',
  monitoring: 'var(--yellow)',
  other:      'var(--text-dim)',
}

export function EndpointsSection({ d }: { d: EndpointsResult }) {
  const byType = ['sensitive', 'admin', 'api', 'auth', 'monitoring', 'other']

  return (
    <div className="fade-in">
      <Section title="◉ Overview">
        <KVRow label="Target"         value={d.target} />
        <KVRow label="Paths probed"   value={d.paths_probed} />
        <KVRow label="Endpoints found" value={d.endpoints_found} tone={d.endpoints_found > 0 ? 'good' : undefined} />
      </Section>

      {d.endpoints.length > 0 && (
        <Section title={`◉ Found Endpoints (${d.endpoints.length})`}>
          {byType.map(type => {
            const group = d.endpoints.filter(ep => ep.type === type)
            if (!group.length) return null
            return (
              <div key={type} style={{ marginBottom: 10 }}>
                <div style={{ fontSize: '0.62rem', letterSpacing: 2, textTransform: 'uppercase', color: TYPE_COLORS[type] || 'var(--text-dim)', marginBottom: 4 }}>
                  {type}
                </div>
                {group.map((ep, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 8px', borderRadius: 4, marginBottom: 3, background: 'var(--surface2)', fontSize: '0.73rem' }}>
                    <span style={{ color: 'var(--text)', fontFamily: 'monospace' }}>{ep.path}</span>
                    <span style={{ color: ep.status === 200 ? 'var(--lime)' : ep.status < 400 ? 'var(--yellow)' : 'var(--red)', fontWeight: 700 }}>{ep.status}</span>
                  </div>
                ))}
              </div>
            )
          })}
        </Section>
      )}

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

// ── Params ─────────────────────────────────────────────────────────────────────

export function ParamsSection({ d }: { d: ParamsResult }) {
  const riskColor = (r: string) =>
    r === 'high' ? 'var(--red)' : r === 'medium' ? 'var(--yellow)' : 'var(--lime)'

  return (
    <div className="fade-in">
      <Section title="◉ Overview">
        <KVRow label="Target"       value={d.target} />
        <KVRow label="Params tested" value={d.params_tested} />
        <KVRow label="Interesting"  value={d.interesting.length} tone={d.interesting.length > 0 ? 'warn' : undefined} />
        <KVRow label="High risk"    value={d.high_risk.length}   tone={d.high_risk.length > 0 ? 'bad' : undefined} />
      </Section>

      {d.interesting.length > 0 && (
        <Section title={`◉ Interesting Parameters (${d.interesting.length})`}>
          {d.interesting.map((p, i) => (
            <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ color: riskColor(p.risk), fontSize: '0.65rem', letterSpacing: 1, textTransform: 'uppercase', border: `1px solid ${riskColor(p.risk)}`, padding: '1px 6px', borderRadius: 3 }}>
                  {p.risk}
                </span>
                <code style={{ color: 'var(--lime)', fontSize: '0.78rem', fontWeight: 600 }}>?{p.name}=FUZZ</code>
              </div>
              <div style={{ fontSize: '0.71rem', color: 'var(--text-dim)', paddingLeft: 4 }}>↳ {p.test}</div>
            </div>
          ))}
        </Section>
      )}

      <Section title={`◉ All High-Risk Parameters (${d.high_risk.length})`} defaultOpen={d.interesting.length === 0}>
        {d.high_risk.length ? d.high_risk.map((p, i) => (
          <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0', fontSize: '0.74rem', borderBottom: '1px solid var(--border)' }}>
            <code style={{ color: 'var(--lime)' }}>?{p.name}=</code>
            <span style={{ color: 'var(--text-dim)', fontSize: '0.68rem', maxWidth: '60%', textAlign: 'right' }}>{p.test}</span>
          </div>
        )) : <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>None found.</span>}
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

// ── Express Workflow ──────────────────────────────────────────────────────────

export function ExpressWorkflowSection({ d }: { d: ExpressWorkflowResult }) {
  return (
    <div className="fade-in">
      <Section title={`◉ Express Workflow — ${d.target}`}>
        <KVRow label="Mode"    value="Express (Recon + Analyze)" />
        <KVRow label="Elapsed" value={`${d.elapsed_seconds}s`} tone="good" />
        {d.recon?.ip         && <KVRow label="IP"       value={d.recon.ip} tone="good" />}
        {d.recon?.status_code && <KVRow label="Status"  value={d.recon.status_code} />}
        {d.recon?.protocol   && <KVRow label="Protocol" value={d.recon.protocol.toUpperCase()} />}
      </Section>
      {d.recon?.ssl && (
        <Section title="◉ SSL">
          <KVRow label="Valid"   value={d.recon.ssl.valid ? 'Yes' : 'No'} tone={d.recon.ssl.valid ? 'good' : 'bad'} />
          <KVRow label="Expires" value={d.recon.ssl.expires} />
          <KVRow label="Days"    value={d.recon.ssl.days_remaining} tone={d.recon.ssl.days_remaining && d.recon.ssl.days_remaining > 30 ? 'good' : 'bad'} />
        </Section>
      )}
      {d.analysis?.misconfig_hints?.length ? (
        <Section title="◉ Misconfigurations">
          {d.analysis.misconfig_hints.map((h, i) => <HintItem key={i} text={h} />)}
        </Section>
      ) : null}
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

// ── Bug Bounty Workflow ───────────────────────────────────────────────────────

export function BugBountyWorkflowSection({ d }: { d: BugBountyWorkflowResult }) {
  return (
    <div className="fade-in">
      <Section title={`◉ Bug Bounty Workflow — ${d.target}`}>
        <KVRow label="Mode"    value="Bug Bounty (Recon + Scan + Payloads)" />
        <KVRow label="Elapsed" value={`${d.elapsed_seconds}s`} tone="good" />
        {d.recon?.ip && <KVRow label="IP" value={d.recon.ip} tone="good" />}
      </Section>
      {d.bb_scan?.interesting_paths?.length ? (
        <Section title={`◉ Interesting Paths (${d.bb_scan.interesting_paths.length})`}>
          {d.bb_scan.interesting_paths.map((p, i) => (
            <PathRow key={i} path={p.path} status={p.status as number} />
          ))}
        </Section>
      ) : null}
      {d.recommended_payloads?.length ? (
        <Section title="◉ Recommended Payload Types">
          {d.recommended_payloads.map((pt, i) => (
            <div key={i} style={{ padding: '4px 0', fontSize: '0.74rem', display: 'flex', gap: 8 }}>
              <span style={{ color: 'var(--lime)' }}>◇</span>
              <span style={{ color: 'var(--text)', textTransform: 'uppercase', letterSpacing: 1 }}>{pt}</span>
            </div>
          ))}
        </Section>
      ) : null}
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

// ── Subdomains Workflow ───────────────────────────────────────────────────────

export function SubdomainsWorkflowSection({ d }: { d: SubdomainsWorkflowResult }) {
  const live = d.expansion?.subdomains?.filter(s => s.live) ?? []
  const reconEntries = Object.entries(d.subdomain_recons ?? {})

  return (
    <div className="fade-in">
      <Section title={`◉ Subdomains Workflow — ${d.domain}`}>
        <KVRow label="Mode"        value="Subdomain Enumeration + Recon" />
        <KVRow label="Elapsed"     value={`${d.elapsed_seconds}s`} tone="good" />
        <KVRow label="Live found"  value={d.expansion?.live_count ?? 0} tone={d.expansion?.live_count ? 'good' : 'warn'} />
        <KVRow label="Sources"     value={d.expansion?.sources?.join(', ')} />
      </Section>
      {live.length > 0 && (
        <Section title={`◉ Live Subdomains (${live.length})`}>
          {live.map((s, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', fontSize: '0.74rem', borderBottom: '1px solid var(--border)' }}>
              <span style={{ color: 'var(--lime)' }}>● {s.subdomain}</span>
              <span style={{ color: 'var(--text-muted)' }}>{s.ip}</span>
            </div>
          ))}
        </Section>
      )}
      {reconEntries.length > 0 && (
        <Section title={`◉ Subdomain Recon Results (${reconEntries.length})`} defaultOpen={false}>
          {reconEntries.map(([sub, r], i) => (
            <div key={i} style={{ marginBottom: 12, paddingBottom: 10, borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--lime)', marginBottom: 4, fontWeight: 600 }}>{sub}</div>
              <KVRow label="IP"     value={r.ip} />
              <KVRow label="Status" value={r.status_code} />
              {r.missing_security_headers?.length ? <HintItem text={`${r.missing_security_headers.length} header(s) missing`} /> : null}
            </div>
          ))}
        </Section>
      )}
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

// ── API Workflow ──────────────────────────────────────────────────────────────

export function ApiWorkflowSection({ d }: { d: ApiWorkflowResult }) {
  const apiEps = d.endpoints?.endpoints?.filter(ep => ep.type === 'api') ?? []
  const adminEps = d.endpoints?.endpoints?.filter(ep => ep.type === 'admin') ?? []
  const sensitiveEps = d.endpoints?.endpoints?.filter(ep => ep.type === 'sensitive') ?? []

  return (
    <div className="fade-in">
      <Section title={`◉ API Scan Workflow — ${d.target}`}>
        <KVRow label="Mode"              value="Endpoint Enum + Param Probing" />
        <KVRow label="Elapsed"           value={`${d.elapsed_seconds}s`} tone="good" />
        <KVRow label="API endpoints"     value={d.api_endpoints_found} tone={d.api_endpoints_found > 0 ? 'good' : undefined} />
        <KVRow label="Total endpoints"   value={d.endpoints?.endpoints_found ?? 0} />
        <KVRow label="Injectable params" value={d.params?.interesting?.length ?? 0} tone={d.params?.interesting?.length ? 'warn' : undefined} />
      </Section>
      {apiEps.length > 0 && (
        <Section title={`◉ API Endpoints (${apiEps.length})`}>
          {apiEps.map((ep, i) => <PathRow key={i} path={ep.path} status={ep.status} />)}
        </Section>
      )}
      {sensitiveEps.length > 0 && (
        <Section title={`◉ Sensitive Paths (${sensitiveEps.length})`}>
          {sensitiveEps.map((ep, i) => <HintItem key={i} text={`${ep.path} → ${ep.status}`} tone="bad" />)}
        </Section>
      )}
      {adminEps.length > 0 && (
        <Section title={`◉ Admin Panels (${adminEps.length})`}>
          {adminEps.map((ep, i) => <HintItem key={i} text={`${ep.path} → ${ep.status}`} tone="warn" />)}
        </Section>
      )}
      {d.params?.interesting?.length ? (
        <Section title={`◉ Injectable Parameters (${d.params.interesting.length})`}>
          {d.params.interesting.map((p, i) => (
            <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 3 }}>
                <span style={{ color: p.risk === 'high' ? 'var(--red)' : 'var(--yellow)', fontSize: '0.65rem', textTransform: 'uppercase', letterSpacing: 1 }}>[{p.risk}]</span>
                <code style={{ color: 'var(--lime)', fontSize: '0.76rem' }}>?{p.name}=FUZZ</code>
              </div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', paddingLeft: 4 }}>↳ {p.test}</div>
            </div>
          ))}
        </Section>
      ) : null}
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