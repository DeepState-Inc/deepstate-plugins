/**
 * Source rules for plugin modules. The app enforces exactly these before a
 * plugin is evaluated; this file is the reference copy for the repo's CI.
 * Keep it dependency free: it is copied verbatim into the app.
 */

export const ALLOWED_MODULES = [
  '@ai-sdk/anthropic',
  '@ai-sdk/openai',
  '@ai-sdk/openai-compatible',
  'node:crypto',
  'crypto'
]

/**
 * Identifiers a plugin may not reference. Access to the process, module
 * system, dynamic evaluation and anything that could reach the filesystem or
 * network outside `fetch` goes through the host or not at all.
 */
const FORBIDDEN_IDENTIFIERS = [
  'process',
  'globalThis',
  'global',
  'require',
  'module',
  'eval',
  'Function',
  'importScripts',
  '__dirname',
  '__filename',
  'Reflect',
  'Proxy'
]

// `host.require(` is the sanctioned spelling; bare `require(` is not.
const FORBIDDEN_PATTERNS = [
  { re: /(^|[^.\w$])import\s*\(/, why: 'dynamic import()' },
  { re: /(^|[^.\w$])import\s+[\w{*]/, why: 'ESM import' },
  { re: /(^|[^.\w$])export\s+(default|const|function|class|let|var|\{)/, why: 'ESM export' },
  { re: /new\s+Function\s*\(/, why: 'new Function()' },
  { re: /\bconstructor\s*\[/, why: 'computed constructor access' },
  { re: /\.constructor\s*\(/, why: 'constructor call' },
  { re: /__proto__/, why: '__proto__' },
  { re: /\[\s*['"`]constructor['"`]\s*\]/, why: 'string constructor access' }
]

/** Strip comments and string/template literals so identifiers inside them do not trip the scan. */
function stripLiterals(src) {
  let out = ''
  let i = 0
  const n = src.length
  while (i < n) {
    const c = src[i]
    const d = src[i + 1]
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') i++
      continue
    }
    if (c === '/' && d === '*') {
      i += 2
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++
      i += 2
      continue
    }
    if (c === '"' || c === "'" || c === '`') {
      const q = c
      i++
      out += q + q
      while (i < n && src[i] !== q) {
        if (src[i] === '\\') i++
        if (q === '`' && src[i] === '$' && src[i + 1] === '{') {
          // keep template expressions: they are code
          i += 2
          let depth = 1
          let expr = ''
          while (i < n && depth > 0) {
            if (src[i] === '{') depth++
            if (src[i] === '}') depth--
            if (depth > 0) expr += src[i]
            i++
          }
          out += ' ' + expr + ' '
          continue
        }
        i++
      }
      i++
      continue
    }
    out += c
    i++
  }
  return out
}

/**
 * @param {string} source
 * @returns {string[]} problems; empty means the source passes
 */
export function checkSource(source) {
  const problems = []
  const code = stripLiterals(source)

  for (const { re, why } of FORBIDDEN_PATTERNS) {
    if (re.test(code)) problems.push(`uses ${why}`)
  }

  // `module.exports = ...` is the one sanctioned use of `module`
  const codeNoExports = code.replace(/module\s*\.\s*exports/g, 'MODULE_EXPORTS')
  for (const ident of FORBIDDEN_IDENTIFIERS) {
    // Match as a whole identifier, not as a property (`.require`, `x.process`)
    // and not as an object key (`{ module: ... }`).
    const re = new RegExp(`(^|[^.\\w$])${ident}(?![\\w$])(?!\\s*:)`)
    if (re.test(codeNoExports)) problems.push(`references \`${ident}\``)
  }

  // Every host.require must be a string literal from the allow list
  const reqRe = /host\s*\.\s*require\s*\(\s*(['"])([^'"]+)\1\s*\)/g
  const dynamicReqRe = /host\s*\.\s*require\s*\(\s*[^'")]/g
  if (dynamicReqRe.test(code)) problems.push('host.require() must be called with a string literal')
  let r
  while ((r = reqRe.exec(source))) {
    if (!ALLOWED_MODULES.includes(r[2])) problems.push(`host.require('${r[2]}') is not in the allow list`)
  }

  if (!/module\s*\.\s*exports\s*=/.test(source)) problems.push('must assign module.exports')

  return problems
}
