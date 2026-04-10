// ── API response types ────────────────────────────────────────────────────────

export interface SSLInfo {
  valid: boolean
  expires?: string
  days_remaining?: number
  issuer?: string
  subject?: string
  warning?: string | null
  error?: string
}

export interface ReconResult {
  domain: string
  ip?: string
  protocol?: string
  status_code?: number
  ssl?: SSLInfo
  missing_security_headers?: string[]
  tech_hints?: string[]
  smart_summary?: string[]
  next_steps?: string[]
  error?: string
}

export interface RedirectHop {
  url: string
  status: number
}

export interface AnalyzeResult {
  redirect_chain?: RedirectHop[]
  final_url?: string
  final_status?: number
  misconfig_hints?: string[]
  smart_summary?: string[]
  next_steps?: string[]
}

export interface PathResult {
  path: string
  status: number
  url?: string
}

export interface BBScanResult {
  target: string
  paths_probed: number
  interesting_paths?: PathResult[]
  all_results?: PathResult[]
  bug_bounty_hints?: string[]
  smart_summary?: string[]
  next_steps?: string[]
}

export interface Payload {
  payload: string
  label: string
}

export interface PayloadResult {
  type: string
  description: string
  count: number
  payloads: Payload[]
  usage_tips: string[]
  smart_summary?: string[]
}

export interface SubdomainEntry {
  subdomain: string
  ip: string | null
  live: boolean
}

export interface ExpandResult {
  domain: string
  sources: string[]
  total_found: number
  live_count: number
  subdomains: SubdomainEntry[]
  smart_summary?: string[]
  next_steps?: string[]
}

export interface EndpointEntry {
  path: string
  url: string
  status: number
  size: number
  type: 'api' | 'admin' | 'auth' | 'sensitive' | 'monitoring' | 'other'
}

export interface EndpointsResult {
  target: string
  paths_probed: number
  endpoints_found: number
  endpoints: EndpointEntry[]
  all_results?: EndpointEntry[]
  smart_summary?: string[]
  next_steps?: string[]
}

export interface ParamEntry {
  name: string
  risk: 'high' | 'medium' | 'low'
  test: string
  url: string
  status: number
  size: number
  interesting: boolean
}

export interface ParamsResult {
  target: string
  params_tested: number
  interesting: ParamEntry[]
  all_params: ParamEntry[]
  high_risk: ParamEntry[]
  smart_summary?: string[]
  next_steps?: string[]
}

export interface WorkflowResult {
  target: string
  elapsed_seconds: number
  recon: ReconResult
  analysis: AnalyzeResult
  bb_scan: BBScanResult
  endpoints: EndpointsResult
  params: ParamsResult
  next_steps?: string[]
  smart_summary?: string[]
}

export interface LastScanResult {
  key: string
  timestamp: string
  data: ReconResult | BBScanResult | WorkflowResult | ExpandResult | EndpointsResult | ParamsResult
}

export interface ChatResult {
  question: string
  response: string[]
  sources: string[]
  tip?: string
}

// ── App state types ───────────────────────────────────────────────────────────

export type Command =
  | 'recon'
  | 'analyze'
  | 'bb-scan'
  | 'workflow'
  | 'payloads'
  | 'last-scan'
  | 'chat'
  | 'expand'
  | 'endpoints'
  | 'params'

export type PayloadType = 'xss' | 'sqli' | 'lfi' | 'ssrf' | 'open_redirect' | 'idor'

export type AnyResult =
  | ReconResult
  | AnalyzeResult
  | BBScanResult
  | PayloadResult
  | WorkflowResult
  | LastScanResult
  | ChatResult
  | ExpandResult
  | EndpointsResult
  | ParamsResult

export interface AppState {
  target: string
  activeCmd: Command | null
  result: AnyResult | null
  loading: boolean
  loadingMsg: string
  error: string | null
}

// ── Stats shown in sidebar ────────────────────────────────────────────────────

export interface ScanStats {
  ip: string
  status: string
  ssl: string
}