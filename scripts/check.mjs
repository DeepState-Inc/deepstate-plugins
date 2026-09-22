#!/usr/bin/env node
/**
 * Validate every plugin: manifest shape, source rules, and that the module
 * loads under the same restricted `require` the app uses and returns a
 * provider with the required methods for each declared provider.
 *
 *   node scripts/check.mjs            # all plugins
 *   node scripts/check.mjs claude     # one plugin
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'
import nodeCrypto from 'node:crypto'
import { checkSource, ALLOWED_MODULES } from './rules.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const only = process.argv[2]
const ids = only ? [only] : readdirSync(join(root, 'providers'))
let failed = 0

const ID_RE = /^[a-z0-9][a-z0-9-]*$/
const SEMVER_RE = /^\d+\.\d+\.\d+$/
const AUTH_KEYS = {
  'api-key': ['placeholder'],
  'oauth-code': ['title', 'description', 'loginLabel', 'instructions', 'connectedLabel'],
  'oauth-browser': ['title', 'description', 'loginLabel', 'connectedLabel']
}

function checkManifest(m, problems) {
  if (m.schema !== 1) problems.push('schema must be 1')
  if (!ID_RE.test(m.id ?? '')) problems.push('id must match [a-z0-9-]')
  if (!SEMVER_RE.test(m.version ?? '')) problems.push('version must be x.y.z')
  if (m.main !== 'index.js') problems.push('main must be index.js')
  if (!SEMVER_RE.test(m.minApp ?? '')) problems.push('minApp must be x.y.z')
  if (!Array.isArray(m.providers) || !m.providers.length) problems.push('providers must be a non-empty array')
  for (const p of m.providers ?? []) {
    const at = `provider ${p?.id ?? '?'}:`
    if (!ID_RE.test(p.id ?? '')) problems.push(`${at} id must match [a-z0-9-]`)
    for (const k of ['name', 'description', 'docsUrl']) if (typeof p[k] !== 'string' || !p[k]) problems.push(`${at} ${k} required`)
    if (!p.defaults?.model || !p.defaults?.summarizerModel) problems.push(`${at} defaults.model and defaults.summarizerModel required`)
    if (typeof p.capabilities?.vision !== 'boolean' || typeof p.capabilities?.tools !== 'boolean') problems.push(`${at} capabilities.vision/tools required`)
    if (!Array.isArray(p.auth) || !p.auth.length) problems.push(`${at} auth must be a non-empty array`)
    for (const a of p.auth ?? []) {
      const need = AUTH_KEYS[a?.kind]
      if (!need) { problems.push(`${at} unknown auth kind ${a?.kind}`); continue }
      for (const k of need) if (typeof a[k] !== 'string') problems.push(`${at} auth ${a.kind} needs ${k}`)
    }
    if (p.envApiKey && !/^[A-Z][A-Z0-9_]*$/.test(p.envApiKey)) problems.push(`${at} envApiKey must be an env var name`)
  }
}

// Same shape as the app's loader: the module sees only these five names.
function loadModule(source, filename) {
  const wrapper = `(function (module, exports, host, console, fetch) {\n${source}\n})`
  const fn = new vm.Script(wrapper, { filename }).runInThisContext()
  const mod = { exports: {} }
  const fakeHost = {
    require(name) {
      if (!ALLOWED_MODULES.includes(name)) throw new Error(`module not allowed: ${name}`)
      return {}
    }
  }
  fn(mod, mod.exports, fakeHost, console, fetch)
  return mod.exports
}

const REQUIRED = ['isConfigured', 'validateCredentials', 'fallbackModels', 'createClient']
const AUTH_REQUIRED = ['isConfigured', 'status', 'start', 'logout']

for (const id of ids) {
  const dir = join(root, 'providers', id)
  const problems = []
  let manifest
  try {
    manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'))
    checkManifest(manifest, problems)
    if (manifest.id !== id) problems.push(`manifest id "${manifest.id}" does not match directory "${id}"`)
  } catch (e) {
    problems.push(`manifest.json: ${e.message}`)
  }

  const entry = join(dir, 'index.js')
  if (!existsSync(entry)) problems.push('index.js missing')
  else {
    const src = readFileSync(entry, 'utf8')
    problems.push(...checkSource(src))
    if (!problems.length) {
      try {
        const factory = loadModule(src, entry)
        if (typeof factory !== 'function') problems.push('module.exports must be a function (host) => provider')
        else {
          for (const p of manifest.providers) {
            const host = stubHost(p.id, manifest.id)
            const provider = factory(host)
            for (const k of REQUIRED) if (typeof provider[k] !== 'function') problems.push(`provider ${p.id}: missing ${k}()`)
            const wantsOAuth = p.auth.some((a) => a.kind !== 'api-key')
            if (wantsOAuth) {
              if (!provider.auth) problems.push(`provider ${p.id}: manifest declares OAuth but provider.auth is missing`)
              else for (const k of AUTH_REQUIRED) if (typeof provider.auth[k] !== 'function') problems.push(`provider ${p.id}: auth.${k}() missing`)
              if (p.auth.some((a) => a.kind === 'oauth-code') && typeof provider.auth?.complete !== 'function') problems.push(`provider ${p.id}: oauth-code needs auth.complete()`)
            }
          }
        }
      } catch (e) {
        problems.push(`load failed: ${e.message}`)
      }
    }
  }

  if (problems.length) {
    failed++
    console.log(`✗ ${id}`)
    for (const p of problems) console.log(`    ${p}`)
  } else {
    console.log(`✓ ${id} v${manifest.version} (${manifest.providers.map((p) => p.id).join(', ')})`)
  }
}

function stubHost(id, pluginId) {
  const store = new Map()
  return {
    id,
    pluginId,
    appVersion: '0.0.0',
    require(name) {
      if (!ALLOWED_MODULES.includes(name)) throw new Error(`module not allowed: ${name}`)
      if (name === 'crypto' || name === 'node:crypto') return nodeCrypto
      return { createOpenAI() {}, createAnthropic() {}, createOpenAICompatible() {} }
    },
    log: { info() {}, warn() {}, error() {} },
    config: () => ({ selectedModel: '', summarizerModel: '' }),
    storage: { get: (k) => store.get(k) ?? null, set: (k, v) => store.set(k, v), delete: (k) => store.delete(k) },
    env: () => undefined,
    trackedFetch: () => fetch,
    openExternal: async () => {},
    listenForCallback: async () => new URLSearchParams(),
    cancelCallback() {},
    modelsDev: async () => [],
    models: () => null,
    modelInfo: () => undefined,
    usage: { session: () => ({ inputTokens: 0, outputTokens: 0, requestCount: 0, since: '' }), rateLimit: () => null, estimatedCost: () => null }
  }
}

process.exit(failed ? 1 : 0)
