# DeepState provider plugins

Model providers for [DeepState](https://getdeepstate.app). Each plugin is one
directory under `providers/` with a `manifest.json` and a single `index.js`.
The app ships a snapshot of this repo and checks `registry.json` for newer
versions on start.

```
providers/<id>/manifest.json   what the provider is, how it authenticates, its defaults
providers/<id>/index.js        module.exports = (host) => provider
registry.json                  versions + sha256 of every file; generated, do not edit
types/index.d.ts               the full host and provider API, with docs
schema/manifest.schema.json    manifest JSON schema
scripts/check.mjs              validates manifests and sources under the app's rules
scripts/build-registry.mjs     regenerates registry.json
tests/                         node --test tests/*.test.mjs
```

## Rules

Plugins run inside DeepState's main process with no dependencies of their
own. `index.js` is plain CommonJS, one file, no build step, and it is
rejected before evaluation if it references anything outside this surface:

- `host.require()` resolves only `@ai-sdk/anthropic`, `@ai-sdk/openai`,
  `@ai-sdk/openai-compatible` and `node:crypto`.
- No `require`, `import`, `process`, `globalThis`, `eval`, `Function`,
  `Proxy`, `Reflect`, `__proto__`, or constructor tricks.
- Everything else (encrypted storage, opening the browser, the loopback OAuth
  server, models.dev, rate-limit tracking) goes through `host`. See
  `types/index.d.ts`.

Standard globals are available: `fetch`, `Headers`, `Request`, `Response`,
`URL`, `URLSearchParams`, `ReadableStream`, `TextEncoder`, `Buffer`,
`AbortController`, timers.

## Auth methods

A provider declares its auth methods in the manifest; the app renders the
matching UI and calls `provider.auth`:

| kind            | flow                                                                                                         |
| --------------- | ------------------------------------------------------------------------------------------------------------ |
| `api-key`       | User pastes a key. App stores it encrypted; plugin reads `host.config().apiKey` (or `host.env(<envApiKey>)`) |
| `oauth-code`    | `auth.start()` opens the browser and returns a verifier; user pastes the code; `auth.complete(code, verifier)` |
| `oauth-browser` | `auth.start()` opens the browser, awaits `host.listenForCallback()`, stores tokens, resolves                  |

`claude` uses `oauth-code` + `api-key`, `openai` uses `oauth-browser` + `api-key`,
`opencode` is `api-key` only. Read those three for working examples of each.

## Adding a provider

1. `mkdir providers/<id>`, write `manifest.json` (see `schema/`) and `index.js`.
2. `node scripts/check.mjs <id>` until it passes.
3. Add a test under `tests/` that loads it with `tests/load.mjs`.
4. `node scripts/build-registry.mjs` and commit `registry.json` with your change.

Bump `version` in the manifest on every change: the app only installs a
version higher than the one it has. `minApp` is the lowest app version whose
host has what you use.

## How the app consumes this

- Build: the app copies `providers/` and `registry.json` into its resources.
- Start: loads bundled plugins, then (off the boot path) fetches
  `registry.json` from this repo's release branch, downloads any plugin whose
  version is higher and whose `minApp` it satisfies, verifies every file's
  sha256 against the registry, and uses it from the next launch.
- A plugin that fails the source rules or throws on load is skipped and the
  bundled copy is used instead.

## License

MIT. The OAuth flows here replicate what the vendors' own CLIs do; using them
is subject to each vendor's terms.
