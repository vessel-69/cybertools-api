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

export interface WorkflowResult {
  target: string
  elapsed_seconds: number
  recon: ReconResult
  analysis: AnalyzeResult
  bb_scan: BBScanResult
  next_steps?: string[]
  smart_summary?: string[]
}

export interface LastScanResult {
  key: string
  timestamp: string
  data: ReconResult | BBScanResult | WorkflowResult
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

export type PayloadType = 'xss' | 'sqli' | 'lfi' | 'ssrf'

export type AnyResult =
  | ReconResult
  | AnalyzeResult
  | BBScanResult
  | PayloadResult
  | WorkflowResult
  | LastScanResult
  | ChatResult

export interface ScanStats {
  ip: string
  status: string
  ssl: string
}
