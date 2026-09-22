import { test } from 'node:test'
import assert from 'node:assert/strict'
import { loadProvider } from './load.mjs'

test('codex models only appear when logged in', async () => {
  const { provider, store } = loadProvider('openai')
  assert.equal(provider.modelSdk(), 'openai-compatible')
  assert.ok(!provider.fallbackModels().some((m) => m.id === 'gpt-5.3-codex'))
  store.set('codex-oauth-tokens', JSON.stringify({ accessToken: 'a', refreshToken: 'r', expiresAt: Date.now() + 1e6 }))
  assert.equal(provider.isConfigured(), true)
  assert.equal(provider.modelSdk(), 'openai')
  assert.ok(provider.fallbackModels()[0].id === 'gpt-5.4')
  assert.deepEqual(await provider.auth.status(), { configured: true, valid: true, account: null })
})

test('api key from env is honoured', () => {
  const { provider } = loadProvider('openai', 'openai', { env: (n) => (n === 'OPENAI_API_KEY' ? 'sk-x' : undefined) })
  assert.equal(provider.isConfigured(), true)
})
