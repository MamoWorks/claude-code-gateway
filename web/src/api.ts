const BASE = ''

let authToken = ''

export function setAuth(token: string) {
  authToken = token
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${authToken}`,
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || res.statusText)
  }
  return res.json()
}

export interface Account {
  id: number
  name: string
  email: string
  status: string
  auth_type: string
  setup_token: string
  access_token: string
  refresh_token: string
  expires_at?: number | null
  oauth_refreshed_at?: string
  auth_error?: string
  proxy_url: string
  device_id: string
  canonical_env?: Record<string, unknown>
  canonical_prompt_env?: Record<string, unknown>
  canonical_process?: {
    constrained_memory?: number
    rss_range?: number[]
    heap_total_range?: number[]
    heap_used_range?: number[]
  }
  billing_mode: string
  account_uuid?: string | null
  organization_uuid?: string | null
  subscription_type?: string | null
  concurrency: number
  priority: number
  auto_telemetry: boolean
  telemetry_count: number
  telemetry_expires_at?: string
  rate_limited_at?: string
  rate_limit_reset_at?: string
  disable_reason?: string
  usage_data?: UsageData
  usage_fetched_at?: string
  created_at: string
  updated_at: string
}

export interface PagedResult<T> {
  data: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface UsageWindow {
  utilization: number
  resets_at: string
  /** 每窗口独立状态：allowed / allowed_warning / rejected。响应头源才有，/api/oauth/usage 缺失。 */
  status?: string
  /** 上游在撞墙前发出的阈值（0-1），通常 0.8 / 0.9 / 0.97。 */
  surpassed_threshold?: number
}

export interface UsageData {
  five_hour?: UsageWindow
  seven_day?: UsageWindow
  seven_day_sonnet?: UsageWindow
  /** 数据来源：'headers'（响应头吸取）/ undefined（/api/oauth/usage 旧数据）。 */
  source?: string
  /** 全局状态（所有窗口中最紧张的）。 */
  status?: string
  /** 上游标记的瓶颈窗口：'five_hour' / 'seven_day' / 'seven_day_opus'。 */
  representative_claim?: string
  /** 全局 -reset 头，瓶颈窗口的重置时刻。 */
  resets_at?: string
  /** 回退配额百分比。 */
  fallback_percentage?: number
  /** Overage（超量付费）状态：allowed / allowed_warning / rejected。 */
  overage_status?: string
  /** Overage 被禁用的原因（如 org_level_disabled）。 */
  overage_disabled_reason?: string
}

export interface ApiToken {
  id: number;
  name: string;
  token: string;
  allowed_accounts: string;
  blocked_accounts: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface Dashboard {
  accounts: { total: number; active: number; error: number; disabled: number };
  tokens: number;
}

export interface OAuthGenerateResult {
  auth_url: string;
  session_id: string;
}

export interface OAuthExchangeResult {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at: number;
  scope: string;
  account_uuid: string;
  organization_uuid: string;
  email_address: string;
}

export const api = {
  listAccounts: (page = 1, pageSize = 12) =>
    request<PagedResult<Account>>('GET', `/admin/accounts?page=${page}&page_size=${pageSize}`),
  createAccount: (a: Partial<Account>) => request<Account>('POST', '/admin/accounts', a),
  updateAccount: (id: number, a: Partial<Account>) => request<Account>('PUT', `/admin/accounts/${id}`, a),
  deleteAccount: (id: number) => request<void>('DELETE', `/admin/accounts/${id}`),
  testAccount: (id: number) => request<{ status: string; message?: string }>('POST', `/admin/accounts/${id}/test`),
  refreshUsage: (id: number) => request<{ status: string; usage?: UsageData; message?: string }>('POST', `/admin/accounts/${id}/usage`),
  listTokens: (page = 1, pageSize = 20) =>
    request<PagedResult<ApiToken>>('GET', `/admin/tokens?page=${page}&page_size=${pageSize}`),
  createToken: (t: Partial<ApiToken>) => request<ApiToken>('POST', '/admin/tokens', t),
  updateToken: (id: number, t: Partial<ApiToken>) => request<ApiToken>('PUT', `/admin/tokens/${id}`, t),
  deleteToken: (id: number) => request<void>('DELETE', `/admin/tokens/${id}`),
  getDashboard: () => request<Dashboard>('GET', '/admin/dashboard'),

  generateAuthUrl: (proxyUrl?: string) =>
    request<OAuthGenerateResult>('POST', '/admin/oauth/generate-auth-url', { proxy_url: proxyUrl || null }),
  generateSetupTokenUrl: (proxyUrl?: string) =>
    request<OAuthGenerateResult>('POST', '/admin/oauth/generate-setup-token-url', { proxy_url: proxyUrl || null }),
  exchangeCode: (sessionId: string, code: string) =>
    request<OAuthExchangeResult>('POST', '/admin/oauth/exchange-code', { session_id: sessionId, code }),
  exchangeSetupTokenCode: (sessionId: string, code: string) =>
    request<OAuthExchangeResult>('POST', '/admin/oauth/exchange-setup-token-code', { session_id: sessionId, code }),
}
