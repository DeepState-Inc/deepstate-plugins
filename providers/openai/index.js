/**
 * OpenAI provider for DeepState.
 *
 *   - API key: platform.openai.com, Chat Completions, rate-limit tracking.
 *   - Codex OAuth: ChatGPT Pro/Plus subscription. PKCE flow against
 *     auth.openai.com with a loopback redirect on port 1455; requests are
 *     rewritten to the ChatGPT Codex backend, which only speaks the Responses
 *     API and requires `store: false`.
 *
 * Based on the opencode codex plugin implementation.
 */

'use strict'

module.exports = function createProvider(host) {
  const crypto = host.require('node:crypto')
  const { createOpenAI } = host.require('@ai-sdk/openai')

  // ── Constants ──────────────────────────────────────────────────────

  const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann'
  const ISSUER = 'https://auth.openai.com'
  const CODEX_API_ENDPOINT = 'https://chatgpt.com/backend-api/codex/responses'
  const OAUTH_PORT = 1455
  const REDIRECT_URI = `http://localhost:${OAUTH_PORT}/auth/callback`
  const SCOPES = 'openid profile email offline_access'
  const REFRESH_BUFFER_MS = 5 * 60 * 1000
  // Dummy API key used when OAuth is active (stripped by the fetch wrapper)
  const OAUTH_DUMMY_KEY = 'codex-oauth-dummy-key'

  const TOKENS_KEY = 'codex-oauth-tokens'
  const PKCE_KEY = 'codex-pkce-pending'

  const FALLBACK_MODELS = [
    { id: 'gpt-5.2', name: 'GPT-5.2', description: 'Latest and most capable', contextWindow: 200000, supportsVision: true, supportsTools: true },
    { id: 'gpt-5.1', name: 'GPT-5.1', description: 'Highly capable multimodal', contextWindow: 200000, supportsVision: true, supportsTools: true },
    { id: 'gpt-5', name: 'GPT-5', description: 'Powerful multimodal model', contextWindow: 200000, supportsVision: true, supportsTools: true },
    { id: 'gpt-5-mini', name: 'GPT-5 Mini', description: 'Fast and affordable', contextWindow: 128000, supportsVision: true, supportsTools: true },
    { id: 'gpt-4.1', name: 'GPT-4.1', description: 'Reliable multimodal', contextWindow: 128000, supportsVision: true, supportsTools: true },
    { id: 'gpt-4.1-mini', name: 'GPT-4.1 Mini', description: 'Efficient and cost-effective', contextWindow: 128000, supportsVision: true, supportsTools: true },
    { id: 'o4-mini', name: 'o4 Mini', description: 'Latest reasoning model', contextWindow: 200000, supportsVision: false, supportsTools: true },
    { id: 'o3', name: 'o3', description: 'Advanced reasoning', contextWindow: 200000, supportsVision: false, supportsTools: true },
    { id: 'o3-mini', name: 'o3 Mini', description: 'Fast reasoning', contextWindow: 200000, supportsVision: false, supportsTools: true }
  ]

  // Additional Codex models available via OAuth (free with ChatGPT subscription)
  const CODEX_MODELS = [
    { id: 'gpt-5.4', name: 'GPT-5.4', description: 'Latest GPT model via Codex', contextWindow: 200000, supportsVision: true, supportsTools: true, pricingTier: 'free' },
    { id: 'gpt-5.4-mini', name: 'GPT-5.4 Mini', description: 'Fast GPT model via Codex', contextWindow: 128000, supportsVision: true, supportsTools: true, pricingTier: 'free' },
    { id: 'gpt-5.3-codex', name: 'GPT-5.3 Codex', description: 'GPT-5.3 optimized for code', contextWindow: 200000, supportsVision: true, supportsTools: true, pricingTier: 'free' },
    { id: 'gpt-5.2-codex', name: 'GPT-5.2 Codex', description: 'GPT-5.2 optimized for code', contextWindow: 200000, supportsVision: true, supportsTools: true, pricingTier: 'free' },
    { id: 'gpt-5.1-codex', name: 'GPT-5.1 Codex', description: 'GPT-5.1 optimized for code', contextWindow: 200000, supportsVision: true, supportsTools: true, pricingTier: 'free' },
    { id: 'gpt-5.1-codex-max', name: 'GPT-5.1 Codex Max', description: 'Maximum capability Codex model', contextWindow: 200000, supportsVision: true, supportsTools: true, pricingTier: 'free' },
    { id: 'gpt-5.1-codex-mini', name: 'GPT-5.1 Codex Mini', description: 'Fast and efficient Codex model', contextWindow: 128000, supportsVision: true, supportsTools: true, pricingTier: 'free' }
  ]

  // ── Token storage ──────────────────────────────────────────────────

  function saveTokens(tokens) {
    host.storage.set(TOKENS_KEY, JSON.stringify(tokens))
  }

  function loadTokens() {
    try {
      const raw = host.storage.get(TOKENS_KEY)
      return raw ? JSON.parse(raw) : null
    } catch (error) {
      host.log.error('Failed to load tokens:', error)
      return null
    }
  }

  function clearTokens() {
    host.storage.delete(TOKENS_KEY)
    clearPendingPKCE()
    host.cancelCallback()
  }

  const isOAuthConfigured = () => {
    const tokens = loadTokens()
    return tokens !== null && !!tokens.refreshToken
  }

  // ── PKCE ───────────────────────────────────────────────────────────

  function generatePKCE() {
    // 43-char verifier matching the opencode implementation
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
    const array = new Uint8Array(43)
    crypto.getRandomValues(array)
    let verifier = ''
    for (let i = 0; i < 43; i++) verifier += chars[array[i] % chars.length]
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url')
    const state = crypto.randomBytes(16).toString('hex')
    return { verifier, challenge, state }
  }

  let pendingPKCE = null

  function savePendingPKCE(pkce) {
    pendingPKCE = pkce
    try {
      host.storage.set(PKCE_KEY, JSON.stringify(pkce))
    } catch (e) {
      host.log.error('Failed to save PKCE backup:', e)
    }
  }

  function loadPendingPKCE() {
    if (pendingPKCE) return pendingPKCE
    try {
      const raw = host.storage.get(PKCE_KEY)
      return raw ? JSON.parse(raw) : null
    } catch (e) {
      host.log.error('Failed to load PKCE backup:', e)
      return null
    }
  }

  function clearPendingPKCE() {
    pendingPKCE = null
    try {
      host.storage.delete(PKCE_KEY)
    } catch {
      // ignore
    }
  }

  // ── JWT parsing ────────────────────────────────────────────────────

  function parseJwtPayload(token) {
    try {
      const parts = token.split('.')
      if (parts.length < 2) return null
      return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'))
    } catch {
      return null
    }
  }

  function extractAccountId(tokens) {
    for (const token of [tokens.id_token, tokens.access_token]) {
      if (!token) continue
      const claims = parseJwtPayload(token)
      if (!claims) continue
      if (typeof claims.chatgpt_account_id === 'string') return claims.chatgpt_account_id
      const nested = claims['https://api.openai.com/auth']
      if (nested && typeof nested.chatgpt_account_id === 'string') return nested.chatgpt_account_id
      const orgs = claims.organizations
      if (Array.isArray(orgs) && orgs.length > 0 && typeof orgs[0].id === 'string') return orgs[0].id
    }
    return undefined
  }

  // ── Token exchange & refresh ───────────────────────────────────────

  async function exchangeCodeForTokens(code, codeVerifier, redirectUri) {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: CLIENT_ID,
      code_verifier: codeVerifier
    })
    const response = await fetch(`${ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    })
    if (!response.ok) {
      const errorText = await response.text()
      clearPendingPKCE()
      throw new Error(`Codex token exchange failed: ${response.status} ${errorText}`)
    }
    const data = await response.json()
    const accountId = extractAccountId(data)
    const tokens = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: Date.now() + data.expires_in * 1000,
      accountId
    }
    saveTokens(tokens)
    clearPendingPKCE()
    host.log.info('Token exchange successful, accountId:', accountId || 'none')
    return tokens
  }

  let inflightRefresh = null

  // Concurrent callers (chat + summarizer + title generation) share one
  // refresh: OpenAI rotates the refresh token, so parallel refreshes would
  // leave the losers with a consumed token and log the user out.
  function refreshAccessToken() {
    if (inflightRefresh) return inflightRefresh
    inflightRefresh = doRefresh().finally(() => {
      inflightRefresh = null
    })
    return inflightRefresh
  }

  async function doRefresh() {
    const current = loadTokens()
    if (!current || !current.refreshToken) throw new Error('No Codex refresh token available')
    // A queued caller may find the refresh already done
    if (current.expiresAt > Date.now() + REFRESH_BUFFER_MS) return current

    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: current.refreshToken, client_id: CLIENT_ID })
    const response = await fetch(`${ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    })
    if (!response.ok) {
      const status = response.status
      if (status === 401 || status === 400) clearTokens()
      throw new Error(`Codex token refresh failed: ${status}`)
    }
    const data = await response.json()
    const tokens = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || current.refreshToken,
      expiresAt: Date.now() + data.expires_in * 1000,
      accountId: extractAccountId(data) || current.accountId
    }
    saveTokens(tokens)
    return tokens
  }

  async function getValidAccessToken() {
    const tokens = loadTokens()
    if (!tokens) return null
    if (tokens.expiresAt > Date.now() + REFRESH_BUFFER_MS) return tokens.accessToken
    try {
      return (await refreshAccessToken()).accessToken
    } catch (error) {
      host.log.error('Failed to refresh:', error)
      return null
    }
  }

  // ── Browser OAuth with PKCE ────────────────────────────────────────

  const SUCCESS_HTML = `
          <html><body style="font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
            <div style="text-align: center;">
              <h1>Authentication Successful</h1>
              <p>You can close this tab and return to DeepState.</p>
            </div>
          </body></html>
        `

  async function startBrowserAuth() {
    const pkce = generatePKCE()
    savePendingPKCE(pkce)

    const url = new URL(`${ISSUER}/oauth/authorize`)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('client_id', CLIENT_ID)
    url.searchParams.set('redirect_uri', REDIRECT_URI)
    url.searchParams.set('scope', SCOPES)
    url.searchParams.set('code_challenge', pkce.challenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('id_token_add_organizations', 'true')
    url.searchParams.set('codex_cli_simplified_flow', 'true')
    url.searchParams.set('state', pkce.state)
    url.searchParams.set('originator', 'opencode')

    // Start the callback listener, then open the browser
    const callback = host.listenForCallback({
      port: OAUTH_PORT,
      path: '/auth/callback',
      timeoutMs: 5 * 60 * 1000,
      successHtml: SUCCESS_HTML
    })
    await host.openExternal(url.toString())
    host.log.info('Browser auth started, waiting for callback...')

    const query = await callback
    const code = query.get('code')
    const state = query.get('state')

    const savedPKCE = loadPendingPKCE()
    if (!code || !savedPKCE || state !== savedPKCE.state) {
      clearPendingPKCE()
      throw new Error('OAuth state mismatch — possible CSRF attack')
    }
    await exchangeCodeForTokens(code, savedPKCE.verifier, REDIRECT_URI)
    return { verifier: savedPKCE.verifier }
  }

  // ── Fetch wrapper ──────────────────────────────────────────────────

  // The ChatGPT Codex backend is a Responses API endpoint with a few
  // constraints: it does not persist responses (`store` must be false), only
  // streams, and expects an `instructions` field.
  function adaptResponsesBodyForCodex(body) {
    if (typeof body !== 'string') return body
    try {
      const parsed = JSON.parse(body)
      parsed.store = false
      parsed.stream = true
      if (typeof parsed.instructions !== 'string') parsed.instructions = ''
      return JSON.stringify(parsed)
    } catch {
      return body
    }
  }

  function createCodexOAuthFetch() {
    return async (input, init) => {
      let tokens = loadTokens()
      if (!tokens) throw new Error('No Codex OAuth tokens available')
      // Refresh if expired or about to expire mid-request
      if (tokens.expiresAt < Date.now() + REFRESH_BUFFER_MS) {
        host.log.info('Refreshing access token...')
        tokens = await refreshAccessToken()
      }

      const requestInit = init || {}
      const headers = new Headers(requestInit.headers)
      // Strip the dummy API key auth header and set the real token
      headers.delete('authorization')
      headers.set('Authorization', `Bearer ${tokens.accessToken}`)
      // Required for org/team plans
      if (tokens.accountId) headers.set('ChatGPT-Account-Id', tokens.accountId)
      headers.set('originator', 'opencode')
      if (!headers.has('User-Agent')) headers.set('User-Agent', 'DeepState/1.0')

      let url
      if (typeof input === 'string') url = input
      else if (input instanceof URL) url = input.toString()
      else url = input.url

      let body = requestInit.body
      if (url.includes('/v1/responses') || url.includes('/chat/completions')) {
        if (url.includes('/chat/completions')) {
          // The Codex backend only speaks the Responses API; languageModel()
          // below always hands out Responses models, so this is a bug guard.
          throw new Error('Codex OAuth requires the Responses API (got a chat/completions request)')
        }
        url = CODEX_API_ENDPOINT
        body = adaptResponsesBodyForCodex(body)
      }

      const response = await fetch(url, { ...requestInit, body, headers })
      host.log.info('Response:', response.status, response.statusText)
      return response
    }
  }

  // ── Usage ──────────────────────────────────────────────────────────

  async function fetchCodexUsage() {
    try {
      const token = await getValidAccessToken()
      if (!token) return { type: 'none', reason: 'Codex OAuth token expired' }

      // The usage endpoint is at the same host as the codex API
      const baseUrl = CODEX_API_ENDPOINT.replace(/\/codex\/responses$/, '')
      const response = await fetch(`${baseUrl}/wham/usage`, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }
      })
      if (!response.ok) {
        host.log.warn(`Codex usage API returned ${response.status}`)
        return { type: 'none', reason: `Usage API returned ${response.status}` }
      }
      const data = await response.json()
      const windows = {}
      const toWindow = (w, fallbackLabel) => ({
        usedPercent: w.used_percent == null ? null : w.used_percent,
        resetsAt: w.reset_at ? new Date(w.reset_at * 1000).toISOString() : null,
        windowLabel: w.limit_window_seconds ? `${Math.round(w.limit_window_seconds / 3600)}h` : fallbackLabel
      })
      if (data.rate_limit && data.rate_limit.primary_window) windows.primary = toWindow(data.rate_limit.primary_window, 'Primary')
      if (data.rate_limit && data.rate_limit.secondary_window) windows.secondary = toWindow(data.rate_limit.secondary_window, 'Secondary')
      if (Array.isArray(data.additional_rate_limits)) {
        for (const limit of data.additional_rate_limits) {
          if (limit.rate_limit && limit.rate_limit.primary_window) {
            const pw = limit.rate_limit.primary_window
            const label = limit.limit_name || 'Additional'
            windows[label] = {
              usedPercent: pw.used_percent == null ? null : pw.used_percent,
              resetsAt: pw.reset_at ? new Date(pw.reset_at * 1000).toISOString() : null,
              windowLabel: label
            }
          }
        }
      }
      return {
        type: 'oauth-limits',
        windows,
        planLabel: data.plan_type || undefined,
        credits: data.credits
          ? {
              hasCredits: data.credits.has_credits == null ? false : data.credits.has_credits,
              unlimited: data.credits.unlimited == null ? false : data.credits.unlimited,
              balance: data.credits.balance == null ? null : data.credits.balance
            }
          : undefined
      }
    } catch (error) {
      host.log.error('Failed to fetch Codex usage:', error)
      return { type: 'none', reason: 'Failed to fetch usage data' }
    }
  }

  // ── Provider ───────────────────────────────────────────────────────

  let cachedOAuthClient = null
  let cachedApiKeyClient = null
  let lastApiKey = null

  const apiKey = () => host.config().apiKey || host.env('OPENAI_API_KEY')

  const provider = {
    isConfigured() {
      return isOAuthConfigured() || !!apiKey()
    },

    async validateCredentials() {
      if (isOAuthConfigured()) {
        const token = await getValidAccessToken()
        if (token) return { valid: true }
        return { valid: false, error: 'Codex OAuth tokens expired. Please re-authenticate.' }
      }
      try {
        const key = apiKey()
        if (!key) return { valid: false, error: 'API key not configured' }
        const response = await fetch('https://api.openai.com/v1/models', { headers: { Authorization: `Bearer ${key}` } })
        if (!response.ok) {
          const error = await response.json().catch(() => ({}))
          return { valid: false, error: (error.error && error.error.message) || `API returned ${response.status}` }
        }
        return { valid: true }
      } catch (error) {
        return { valid: false, error: error instanceof Error ? error.message : 'Failed to validate credentials' }
      }
    },

    fallbackModels() {
      return isOAuthConfigured() ? [...CODEX_MODELS, ...FALLBACK_MODELS] : FALLBACK_MODELS
    },

    async fetchModels() {
      // models.dev is the base list; Codex-only models are prepended when logged in
      const base = await host.modelsDev('openai')
      const baseModels = base.length > 0 ? base : FALLBACK_MODELS
      if (!isOAuthConfigured()) return base.length > 0 ? { models: base, authoritative: true } : null
      const baseIds = new Set(baseModels.map((m) => m.id))
      const codexOnly = CODEX_MODELS.filter((m) => !baseIds.has(m.id))
      return { models: [...codexOnly, ...baseModels], authoritative: base.length > 0 }
    },

    modelSdk() {
      // Codex OAuth is Responses API; API keys stay on Chat Completions.
      return isOAuthConfigured() ? 'openai' : 'openai-compatible'
    },

    createClient() {
      if (isOAuthConfigured()) {
        if (cachedOAuthClient) return cachedOAuthClient
        host.log.info('Creating Codex OAuth client with custom fetch wrapper')
        cachedOAuthClient = createOpenAI({ apiKey: OAUTH_DUMMY_KEY, fetch: createCodexOAuthFetch() })
        return cachedOAuthClient
      }
      const key = apiKey()
      if (!key) throw new Error('OpenAI is not configured. Please set an API key or login with ChatGPT.')
      if (cachedApiKeyClient && lastApiKey === key) return cachedApiKeyClient
      host.log.info('Creating API key client')
      cachedApiKeyClient = createOpenAI({ apiKey: key, fetch: host.trackedFetch() })
      lastApiKey = key
      return cachedApiKeyClient
    },

    languageModel(modelId) {
      const client = provider.createClient()
      // The Codex backend only implements the Responses API; everything else
      // the app talks to on an API key is Chat Completions.
      return isOAuthConfigured() ? client.responses(modelId) : client.chat(modelId)
    },

    credentialsChanged() {
      cachedOAuthClient = null
      cachedApiKeyClient = null
      lastApiKey = null
    },

    async usage() {
      return isOAuthConfigured() ? fetchCodexUsage() : null
    },

    auth: {
      isConfigured: isOAuthConfigured,

      async status() {
        if (!isOAuthConfigured()) return { configured: false, valid: false, account: null }
        const token = await getValidAccessToken()
        return { configured: isOAuthConfigured(), valid: !!token, account: null }
      },

      async start() {
        const result = await startBrowserAuth()
        provider.credentialsChanged()
        return result
      },

      async logout() {
        clearTokens()
        provider.credentialsChanged()
      }
    }
  }

  return provider
}
