/**
 * DeepState provider plugin API.
 *
 * A plugin is one directory containing `manifest.json` and a single CommonJS
 * `index.js`. The module exports one function:
 *
 *     module.exports = function createProvider(host) { return provider }
 *
 * It is called once per provider listed in the manifest (most plugins list
 * one), with a `host` scoped to that provider. The module has no access to
 * Node's `require`, `process` or the filesystem: everything it needs comes
 * through `host`, and `host.require()` only resolves the packages listed in
 * `ALLOWED_MODULES`. The app rejects any source that references anything
 * outside that surface before it is evaluated.
 */

// ── Manifest ─────────────────────────────────────────────────────────

export interface PluginManifest {
  /** Manifest schema version. Always 1. */
  schema: 1
  /** Plugin id. Lowercase, `[a-z0-9-]`. Usually equals the provider id. */
  id: string
  /** Semver. Bump on every change; the app only installs a higher version. */
  version: string
  /** Entry module relative to the plugin directory. Always `index.js`. */
  main: 'index.js'
  /** Lowest app version that has the host features this plugin uses. */
  minApp: string
  /** Providers this module creates. `createProvider` is called once per entry. */
  providers: ProviderManifest[]
}

export interface ProviderManifest {
  /** Provider id used in config, IPC and the UI. Lowercase, `[a-z0-9-]`. */
  id: string
  name: string
  description: string
  docsUrl: string
  /** Default models applied to a fresh config. */
  defaults: { model: string; summarizerModel: string }
  /** Assumed for models not in the fetched list. */
  capabilities: { vision: boolean; tools: boolean }
  /** Auth methods in the order the settings UI shows them. */
  auth: AuthMethod[]
  /** models.dev provider key for the default model list. Omit to rely on `fetchModels`/`fallbackModels`. */
  modelsDev?: string
  /** Environment variable that can supply an API key when none is stored. */
  envApiKey?: string
  /** Link shown next to session token usage. */
  usageConsoleUrl?: string
}

export type AuthMethod = ApiKeyAuth | OAuthCodeAuth | OAuthBrowserAuth

/** A key the user pastes. Stored encrypted by the app; read via `host.config().apiKey`. */
export interface ApiKeyAuth {
  kind: 'api-key'
  placeholder: string
}

/**
 * OAuth where the browser shows the user a code to paste back (no local
 * redirect). `auth.start()` returns a `verifier`; the UI calls
 * `auth.complete(pastedText, verifier)`.
 */
export interface OAuthCodeAuth {
  kind: 'oauth-code'
  title: string
  description: string
  loginLabel: string
  /** Shown above the paste box. */
  instructions: string
  /** Shown once logged in, e.g. "Logged in with Claude". */
  connectedLabel: string
}

/**
 * OAuth with a loopback redirect. `auth.start()` opens the browser, waits for
 * the callback via `host.listenForCallback()` and resolves once tokens are stored.
 */
export interface OAuthBrowserAuth {
  kind: 'oauth-browser'
  title: string
  description: string
  loginLabel: string
  connectedLabel: string
}

// ── Provider implementation ──────────────────────────────────────────

export type ModelSdk = 'openai' | 'anthropic' | 'google' | 'openai-compatible'
export type PricingTier = 'free' | '$' | '$$' | '$$$' | '$$$$'

export interface ModelInfo {
  id: string
  name: string
  description?: string
  contextWindow?: number
  maxOutputTokens?: number
  /** Wire protocol the model must be called with. */
  sdk?: ModelSdk
  supportsVision?: boolean
  supportsTools?: boolean
  pricingTier?: PricingTier
  /** USD per 1M tokens */
  inputPrice?: number
  outputPrice?: number
}

export interface ProviderConfig {
  apiKey?: string
  baseUrl?: string
  selectedModel: string
  summarizerModel: string
}

/** Passed through to the AI SDK call as `providerOptions`. */
export type ProviderOptions = Record<string, Record<string, unknown>>

export interface Provider {
  /** Credentials present (key stored, env var set, or OAuth tokens on disk). */
  isConfigured(): boolean
  /** Verify credentials against the service. Called when a key is saved and when the provider is activated. */
  validateCredentials(): Promise<{ valid: boolean; error?: string }>
  /** Static list used when neither `fetchModels` nor models.dev is available. */
  fallbackModels(): ModelInfo[]
  /**
   * Fetch the live model list. Return `null` to let the app use models.dev
   * (`manifest.modelsDev`) and then `fallbackModels()`. `authoritative: false`
   * tells the app not to switch the user off a model missing from the list.
   */
  fetchModels?(): Promise<{ models: ModelInfo[]; authoritative: boolean } | null>
  /** Override the wire protocol for a model. Default: the fetched model's `sdk`, else `openai-compatible`. */
  modelSdk?(modelId: string): ModelSdk | undefined
  /**
   * An AI SDK provider instance (`createAnthropic(...)`, `createOpenAI(...)`).
   * The app calls `client.chat(modelId)` when present, else `client(modelId)`.
   * Cache it yourself and drop the cache in `credentialsChanged()`.
   */
  createClient(): unknown
  /** Build a LanguageModel directly, bypassing `createClient`. Use when the SDK depends on the model. */
  languageModel?(modelId: string): unknown
  /** Options that must accompany every call to this model. */
  providerOptions?(modelId: string): ProviderOptions | undefined
  /** Usage panel data. Return `null` for the app's session token accounting. */
  usage?(): Promise<ProviderUsage | null>
  /** Called after an API key is saved/cleared or OAuth logs in/out. */
  credentialsChanged?(): void
  /** Present when the manifest lists an OAuth method. */
  auth?: ProviderAuth
}

export interface ProviderAuth {
  /** Synchronous: OAuth tokens are on disk (may need a refresh). */
  isConfigured(): boolean
  /** May refresh and call the network. */
  status(): Promise<{
    configured: boolean
    valid: boolean
    account?: { email?: string; plan?: string } | null
  }>
  /** Open the browser. `oauth-code` returns the verifier for `complete`; `oauth-browser` resolves when tokens are stored. */
  start(): Promise<{ verifier?: string }>
  /** `oauth-code` only. */
  complete?(input: string, verifier?: string): Promise<void>
  logout(): Promise<void>
  /** Mint a long-lived API key from the OAuth session, if the service offers it. */
  createApiKey?(): Promise<string | null>
}

// ── Usage ────────────────────────────────────────────────────────────

export interface UsageRateLimitWindow {
  usedPercent: number | null
  resetsAt: string | null
  windowLabel?: string
}

export interface OAuthLimitsUsage {
  type: 'oauth-limits'
  windows: Record<string, UsageRateLimitWindow>
  planLabel?: string
  credits?: { hasCredits: boolean; unlimited: boolean; balance: string | null }
}

export interface TokenAccumulationUsage {
  type: 'token-accumulation'
  session: {
    inputTokens: number
    outputTokens: number
    totalTokens: number
    estimatedCostUsd: number | null
    requestCount: number
    since: string
  }
  rateLimit?: {
    requestsRemaining: number | null
    requestsLimit: number | null
    tokensRemaining: number | null
    tokensLimit: number | null
    resetsAt: string | null
  }
  consoleUrl?: string
}

export interface ApiSpendingUsage {
  type: 'api-spending'
  creditsRemaining: number | null
  creditsLimit: number | null
  totalUsed: number | null
  isFreeTier?: boolean
  rateLimit?: { requests: number | null; interval: string | null }
}

export interface NoUsage {
  type: 'none'
  reason?: string
}

export type ProviderUsage = OAuthLimitsUsage | TokenAccumulationUsage | ApiSpendingUsage | NoUsage

// ── Host ─────────────────────────────────────────────────────────────

/** The only modules `host.require()` resolves. */
export type AllowedModule =
  | '@ai-sdk/anthropic'
  | '@ai-sdk/openai'
  | '@ai-sdk/openai-compatible'
  | 'node:crypto'
  | 'crypto'

export interface Host {
  /** Provider id this instance serves. */
  readonly id: string
  /** Plugin id from the manifest. */
  readonly pluginId: string
  /** App version, semver. */
  readonly appVersion: string

  require(name: AllowedModule): unknown

  log: {
    info(...args: unknown[]): void
    warn(...args: unknown[]): void
    error(...args: unknown[]): void
  }

  /** Live provider config: stored key, base URL, selected models. */
  config(): ProviderConfig

  /** Read the environment variable named by `manifest.envApiKey`; any other name returns undefined. */
  env(name: string): string | undefined

  /**
   * Encrypted key/value storage private to this provider (OS keychain-backed
   * via Electron safeStorage). Values are strings; JSON-encode structures.
   */
  storage: {
    get(key: string): string | null
    set(key: string, value: string): void
    delete(key: string): void
  }

  /**
   * `fetch` that records rate-limit headers (`anthropic-ratelimit-*`,
   * `x-ratelimit-*`, `retry-after`) into the app's usage panel. Use it as the
   * `fetch` option of the AI SDK factory in api-key mode.
   */
  trackedFetch(): typeof fetch

  /** Open a URL in the user's default browser. */
  openExternal(url: string): Promise<void>

  /**
   * Start a one-shot loopback HTTP server for an OAuth redirect. Resolves with
   * the callback URL's query once a request hits `path`, then shuts down.
   * Rejects on timeout or if the port is taken.
   */
  listenForCallback(opts: {
    port: number
    path: string
    timeoutMs?: number
    /** HTML shown in the browser tab after the redirect. */
    successHtml?: string
  }): Promise<URLSearchParams>

  /** Cancel a pending `listenForCallback`. */
  cancelCallback(): void

  /** Model list from models.dev for a provider key (cached, 30 min). Empty on failure. */
  modelsDev(providerKey: string): Promise<ModelInfo[]>

  /** Last fetched model list for this provider, if any. */
  models(): ModelInfo[] | null
  modelInfo(modelId: string): ModelInfo | undefined

  /** Session token accounting the app keeps for this provider. */
  usage: {
    session(): {
      inputTokens: number
      outputTokens: number
      requestCount: number
      since: string
    }
    rateLimit(): TokenAccumulationUsage['rateLimit'] | null
    /** USD estimate from the selected model's pricing, or null. */
    estimatedCost(): number | null
  }
}

export type CreateProvider = (host: Host) => Provider
