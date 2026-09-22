#!/usr/bin/env node
/**
 * Write registry.json: one entry per plugin with its version, minApp,
 * provider ids and the sha256 of every file the app downloads. The app
 * refuses a remote file whose hash does not match, so run this (CI does)
 * after any change under providers/.
 */
import { createHash } from 'node:crypto'
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex')

const plugins = {}
for (const id of readdirSync(join(root, 'providers')).sort()) {
  const dir = join(root, 'providers', id)
  const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'))
  plugins[id] = {
    version: manifest.version,
    minApp: manifest.minApp,
    providers: manifest.providers.map((p) => p.id),
    path: `providers/${id}`,
    files: {
      'manifest.json': sha(join(dir, 'manifest.json')),
      'index.js': sha(join(dir, 'index.js'))
    }
  }
}

const registry = { schema: 1, generatedAt: new Date().toISOString(), plugins }
writeFileSync(join(root, 'registry.json'), JSON.stringify(registry, null, 2) + '\n')
console.log(`registry.json: ${Object.keys(plugins).length} plugins`)
