/**
 * OpenCode providers for DeepState: Zen (pay-as-you-go, full model list) and
 * Go ($10/mo, open-source coding models). Both share one API key and the
 * OpenCode gateway, which proxies to upstream providers without translating
 * between wire protocols, so every model is called with its upstream SDK.
 */

'use strict'

module.exports = function createProvider(host) {
  const { randomBytes } = host.require('node:crypto')
  const { createOpenAI } = host.require('@ai-sdk/openai')
  const { createAnthropic } = host.require('@ai-sdk/anthropic')
  const { createOpenAICompatible } = host.require('@ai-sdk/openai-compatible')

  const VARIANTS = {
    opencode: {
      label: 'OpenCode Zen',
      baseUrl: 'https://opencode.ai/zen/v1',
      modelsDev: 'opencode',
      missingKey: 'OpenCode API key not configured. Get one at https://opencode.ai/zen',
      fallback: [
        { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6', contextWindow: 1000000, supportsVision: true, supportsTools: true, pricingTier: '$$', inputPrice: 3, outputPrice: 15 },
        { id: 'claude-haiku-4-5', name: 'Claude Haiku 4.5', contextWindow: 200000, supportsVision: true, supportsTools: true, pricingTier: '$$', inputPrice: 1, outputPrice: 5 },
        { id: 'gpt-5.4', name: 'GPT-5.4', contextWindow: 1050000, supportsVision: true, supportsTools: true, pricingTier: '$$', inputPrice: 2.5, outputPrice: 15 },
        { id: 'gemini-3.1-pro', name: 'Gemini 3.1 Pro', contextWindow: 1048576, supportsVision: true, supportsTools: true, pricingTier: '$$', inputPrice: 2, outputPrice: 12 },
        { id: 'kimi-k2.6', name: 'Kimi K2.6', contextWindow: 262144, supportsVision: true, supportsTools: true, pricingTier: '$', inputPrice: 0.95, outputPrice: 4 },
        { id: 'minimax-m3', name: 'MiniMax-M3', contextWindow: 512000, supportsVision: true, supportsTools: true, pricingTier: '$', inputPrice: 0.3, outputPrice: 1.2 }
      ]
    },
    'opencode-go': {
      label: 'OpenCode Go',
      baseUrl: 'https://opencode.ai/zen/go/v1',
      modelsDev: 'opencode-go',
      missingKey: 'OpenCode API key not configured. Get one at https://opencode.ai/zen and enable OpenCode Go',
      fallback: [
        { id: 'kimi-k2.6', name: 'Kimi K2.6', contextWindow: 262144, supportsVision: true, supportsTools: true, pricingTier: '$', inputPrice: 0.95, outputPrice: 4 },
        { id: 'minimax-m3', name: 'MiniMax-M3', contextWindow: 1000000, supportsVision: true, supportsTools: true, pricingTier: '$', inputPrice: 0.3, outputPrice: 1.2 },
        { id: 'glm-5.3', name: 'GLM-5.3', contextWindow: 1000000, supportsVision: false, supportsTools: true, pricingTier: '$$', inputPrice: 1.4, outputPrice: 4.4 },
        { id: 'deepseek-v4-pro', name: 'DeepSeek V4 Pro', contextWindow: 1000000, supportsVision: false, supportsTools: true, pricingTier: '$', inputPrice: 0.66, outputPrice: 1.98 },
        { id: 'qwen3.8-max', name: 'Qwen3.8 Max', contextWindow: 1000000, supportsVision: true, supportsTools: true, pricingTier: '$$', inputPrice: 2, outputPrice: 6 }
      ]
    }
  }

  const v = VARIANTS[host.id]
  if (!v) throw new Error(`Unknown OpenCode variant: ${host.id}`)

  const sessionId = `ses_${randomBytes(12).toString('hex')}`
  const apiKey = () => host.config().apiKey || host.env('OPENCODE_API_KEY')

  // The gateway identifies its own client by these headers. Free-tier models
  // are refused without a session id, and per-request ids show up in their
  // usage dashboard.
  function headers() {
    return {
      'x-opencode-client': 'cli',
      'x-opencode-session': sessionId,
      'x-opencode-request': `msg_${randomBytes(12).toString('hex')}`,
      'X-Title': 'DeepState Investigation Board'
    }
  }

  // openai → /responses, anthropic → /messages, otherwise /chat/completions
  function buildGatewayModel(key, modelId, sdk) {
    const common = { baseURL: v.baseUrl, apiKey: key, headers: headers(), fetch: host.trackedFetch() }
    if (sdk === 'anthropic') return createAnthropic(common)(modelId)
    if (sdk === 'openai') return createOpenAI(common).responses(modelId)
    return createOpenAICompatible({ name: 'opencode', ...common })(modelId)
  }

  return {
    isConfigured() {
      return !!apiKey()
    },

    async validateCredentials() {
      try {
        const key = apiKey()
        if (!key) return { valid: false, error: v.missingKey.replace('OpenCode API key not configured. ', 'API key not configured. ') }
        const response = await fetch(`${v.baseUrl}/models`, { headers: { Authorization: `Bearer ${key}` } })
        if (!response.ok) {
          if (response.status === 403 && host.id === 'opencode-go') {
            return { valid: false, error: 'OpenCode Go subscription not active. Enable it at https://opencode.ai/zen' }
          }
          return { valid: false, error: `API returned ${response.status}` }
        }
        return { valid: true }
      } catch (error) {
        return { valid: false, error: error instanceof Error ? error.message : 'Failed to validate credentials' }
      }
    },

    fallbackModels() {
      return v.fallback
    },

    // The gateway's /models (no auth needed) is authoritative for what is
    // callable; models.dev supplies names, context, pricing and capabilities.
    async fetchModels() {
      let live = null
      try {
        const res = await fetch(`${v.baseUrl}/models`, { signal: AbortSignal.timeout(8000) })
        if (res.ok) {
          const data = await res.json()
          live = (data.data || []).map((m) => m.id).filter(Boolean)
        }
      } catch (error) {
        host.log.warn('Gateway model list unavailable:', error)
      }
      const meta = await host.modelsDev(v.modelsDev)
      const metaById = new Map(meta.map((m) => [m.id, m]))
      if (live && live.length > 0) {
        const models = live.map((id) => metaById.get(id) || { id, name: id, supportsVision: false, supportsTools: true })
        host.log.info(`${models.length} models from gateway (${metaById.size} with metadata)`)
        return { models, authoritative: true }
      }
      if (meta.length > 0) {
        host.log.info(`${meta.length} models from models.dev`)
        return { models: meta, authoritative: true }
      }
      host.log.info('Using fallback models')
      return { models: v.fallback, authoritative: false }
    },

    createClient() {
      const key = apiKey()
      if (!key) throw new Error(v.missingKey)
      return createOpenAI({ baseURL: v.baseUrl, apiKey: key, headers: headers(), fetch: host.trackedFetch() })
    },

    languageModel(modelId) {
      const key = apiKey()
      if (!key) throw new Error(v.missingKey)
      const info = host.modelInfo(modelId)
      return buildGatewayModel(key, modelId, info && info.sdk)
    },

    // OpenCode does not persist Responses-API turns, so `item_reference`s to a
    // previous response fail. Disable store so the SDK replays reasoning/tool
    // items inline on every step.
    providerOptions(modelId) {
      const info = host.modelInfo(modelId)
      return info && info.sdk === 'openai' ? { openai: { store: false } } : undefined
    }
  }
}
