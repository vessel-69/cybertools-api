import type {
  ReconResult, AnalyzeResult, BBScanResult,
  PayloadResult, WorkflowResult, LastScanResult, ChatResult,
  ExpandResult, EndpointsResult, ParamsResult,
  ExpressWorkflowResult, BugBountyWorkflowResult,
  SubdomainsWorkflowResult, ApiWorkflowResult, CacheStatus,
} from '../types'

async function _get<T>(path: string): Promise<T> {
  const res = await fetch(path)
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail ?? JSON.stringify(data))
  return data as T
}

async function _post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.detail ?? JSON.stringify(data))
  return data as T
}

export const api = {
  recon: (domain: string) =>
    _get<ReconResult>(`/recon?domain=${encodeURIComponent(domain)}`),

  analyze: (url: string) =>
    _get<AnalyzeResult>(`/analyze-url?url=${encodeURIComponent(url)}`),

  bbScan: (url: string) =>
    _get<BBScanResult>(`/bb-scan?url=${encodeURIComponent(url)}`),

  payloads: (type: string) =>
    _get<PayloadResult>(`/payloads?type=${encodeURIComponent(type)}`),

  workflow: (target: string) =>
    _get<WorkflowResult>(`/workflow?target=${encodeURIComponent(target)}`),

  lastScan: () =>
    _get<LastScanResult>('/last-scan'),

  chat: (question: string) =>
    _post<ChatResult>('/chat-assist', { question }),

  expand: (domain: string) =>
    _get<ExpandResult>(`/expand?domain=${encodeURIComponent(domain)}`),

  endpoints: (url: string) =>
    _get<EndpointsResult>(`/endpoints?url=${encodeURIComponent(url)}`),

  params: (url: string) =>
    _get<ParamsResult>(`/params?url=${encodeURIComponent(url)}`),

  workflowExpress: (target: string) =>
    _get<ExpressWorkflowResult>(`/workflows/express?target=${encodeURIComponent(target)}`),

  workflowBugBounty: (target: string) =>
    _get<BugBountyWorkflowResult>(`/workflows/bugbounty?target=${encodeURIComponent(target)}`),

  workflowSubdomains: (domain: string) =>
    _get<SubdomainsWorkflowResult>(`/workflows/subdomains?domain=${encodeURIComponent(domain)}`),

  workflowApi: (url: string) =>
    _get<ApiWorkflowResult>(`/workflows/api?url=${encodeURIComponent(url)}`),

  cacheStatus: () =>
    _get<CacheStatus>('/workflows/cache/status'),

  clearCache: () =>
    _post<{ cleared: number; message: string }>('/workflows/cache', {}),
}