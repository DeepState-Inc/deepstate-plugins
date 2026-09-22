// Load a plugin the way the app does and instantiate one provider with a stub host.
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'
import nodeCrypto from 'node:crypto'
import { ALLOWED_MODULES } from '../scripts/rules.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

export function loadProvider(pluginId, providerId = pluginId, hostOverrides = {}) {
  const entry = join(root, 'providers', pluginId, 'index.js')
  const source = readFileSync(entry, 'utf8')
  const fn = new vm.Script(`(function (module, exports, host, console, fetch) {\n${source}\n})`, { filename: entry }).runInThisContext()
  const mod = { exports: {} }
  const store = new Map()
  const host = {
    id: providerId,
    pluginId,
    appVersion: '0.0.0',
    require(name) {
      if (!ALLOWED_MODULES.includes(name)) throw new Error(`module not allowed: ${name}`)
      if (name === 'crypto' || name === 'node:crypto') return nodeCrypto
      return { createOpenAI: () => ({}), createAnthropic: () => ({}), createOpenAICompatible: () => () => ({}) }
    },
    log: { info() {}, warn() {}, error() {} },
    config: () => ({ selectedModel: '', summarizerModel: '' }),
    env: () => undefined,
    storage: { get: (k) => store.get(k) ?? null, set: (k, v) => store.set(k, v), delete: (k) => store.delete(k) },
    trackedFetch: () => fetch,
    openExternal: async () => {},
    listenForCallback: async () => new URLSearchParams(),
    cancelCallback() {},
    modelsDev: async () => [],
    models: () => null,
    modelInfo: () => undefined,
    usage: { session: () => ({ inputTokens: 0, outputTokens: 0, requestCount: 0, since: '' }), rateLimit: () => null, estimatedCost: () => null },
    ...hostOverrides
  }
  fn(mod, mod.exports, host, console, fetch)
  return { provider: mod.exports(host), host, store }
}
