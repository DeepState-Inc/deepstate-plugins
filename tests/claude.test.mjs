import { test } from 'node:test'
import assert from 'node:assert/strict'
import { loadProvider } from './load.mjs'

const { provider } = loadProvider('claude')
const { buildUsageWindows, computeCch, parseCallbackInput, transformRequestBody } = provider._internals

test('cch matches the reference implementation', () => {
  const body = '{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.251; cc_entrypoint=cli; cch=00000;"}],"messages":[{"role":"user","content":"hi"}]}'
  assert.equal(computeCch(body), '11ba5')
  assert.equal(computeCch('a'), '6bcae')
  assert.equal(computeCch(''), '647ed')
  assert.equal(computeCch('x'.repeat(100)), 'a7bcf')
})

test('usage: per-model weekly cap comes from `limits`', () => {
  const windows = buildUsageWindows({
    five_hour: { utilization: 30, resets_at: 'a' },
    seven_day: { utilization: 60, resets_at: 'b' },
    limits: [
      { kind: 'session', percent: 30, resets_at: 'a', scope: null },
      { kind: 'weekly_all', percent: 60, resets_at: 'b', scope: null },
      { kind: 'weekly_scoped', percent: 73, resets_at: 'c', scope: { model: { display_name: 'Fable' } } }
    ]
  })
  assert.deepEqual(Object.keys(windows), ['5 hours', '7 days', '7 days · Fable'])
  assert.deepEqual(windows['7 days · Fable'], { usedPercent: 73, resetsAt: 'c', windowLabel: '7 days · Fable' })
})

test('usage: legacy fields when `limits` is absent', () => {
  const windows = buildUsageWindows({ five_hour: { utilization: 30, resets_at: 'a' }, seven_day: { utilization: 60, resets_at: 'b' } })
  assert.deepEqual(Object.keys(windows), ['5 hours', '7 days'])
})

test('usage: duplicate labels do not collapse', () => {
  const windows = buildUsageWindows({
    limits: [
      { kind: 'weekly_scoped', percent: 1, scope: { model: { display_name: 'X' } } },
      { kind: 'weekly_scoped', percent: 2, scope: { model: { display_name: 'X' } } }
    ]
  })
  assert.deepEqual(Object.keys(windows), ['7 days · X', '7 days · X (2)'])
})

test('callback input: url, code#state, query string, bare code', () => {
  assert.deepEqual(parseCallbackInput('https://x/cb?code=abc&state=st'), { code: 'abc', state: 'st' })
  assert.deepEqual(parseCallbackInput('abc#st'), { code: 'abc', state: 'st' })
  assert.deepEqual(parseCallbackInput('code=abc&state=st'), { code: 'abc', state: 'st' })
  assert.deepEqual(parseCallbackInput('  abc '), { code: 'abc', state: null })
})

test('request shaping: system moves to a reminder in the first user turn', () => {
  const { body, toolNames } = transformRequestBody(
    JSON.stringify({
      system: 'HOST PROMPT',
      messages: [{ role: 'user', content: 'hi' }],
      tools: [{ name: 'todowrite' }, { name: 'search_web' }]
    }),
    false
  )
  const parsed = JSON.parse(body)
  assert.equal(parsed.system.length, 3)
  assert.match(parsed.system[0].text, /cch=00000/)
  assert.equal(parsed.system[1].text, "You are Claude Code, Anthropic's official CLI for Claude.")
  assert.match(parsed.messages[0].content, /^<system-reminder>\n/)
  assert.match(parsed.messages[0].content, /HOST PROMPT\n<\/system-reminder>\n\nhi$/)
  assert.deepEqual(parsed.tools.map((t) => t.name), ['TodoWrite', 'search_web'])
  assert.deepEqual(toolNames, { TodoWrite: 'todowrite' })
})

test('request shaping: escalation capitalises every lowercase tool', () => {
  const { toolNames } = transformRequestBody(JSON.stringify({ messages: [], tools: [{ name: 'search_web' }] }), true)
  assert.deepEqual(toolNames, { Search_web: 'search_web' })
})

test('auth: not configured until tokens exist', async () => {
  assert.equal(provider.isConfigured(), false)
  assert.equal(provider.auth.isConfigured(), false)
  assert.deepEqual(await provider.auth.status(), { configured: false, valid: false, account: null })
})
