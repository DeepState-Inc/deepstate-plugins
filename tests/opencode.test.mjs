import { test } from 'node:test'
import assert from 'node:assert/strict'
import { loadProvider } from './load.mjs'

test('two providers from one module', () => {
  const zen = loadProvider('opencode', 'opencode').provider
  const go = loadProvider('opencode', 'opencode-go').provider
  assert.equal(zen.fallbackModels()[0].id, 'claude-sonnet-4-6')
  assert.equal(go.fallbackModels()[0].id, 'kimi-k2.6')
  assert.equal(zen.isConfigured(), false)
})

test('store:false only for responses-api models', () => {
  const { provider } = loadProvider('opencode', 'opencode', { modelInfo: (id) => ({ id, sdk: id === 'gpt' ? 'openai' : 'anthropic' }) })
  assert.deepEqual(provider.providerOptions('gpt'), { openai: { store: false } })
  assert.equal(provider.providerOptions('claude'), undefined)
})
