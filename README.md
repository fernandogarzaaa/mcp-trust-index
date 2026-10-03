# mcp-trust-index

A public, git-backed index of signed trust badges for MCP servers. Badges are emitted by [`trustscan`](https://github.com/fernandogarzaaa/mcp-trust) (the mcp-trust CLI) and live here at `badges/<server>/<version>.json`. The browsable site is at <https://fernandogarzaaa.github.io/mcp-trust-index/>.

## What a badge is

A badge is a JSON document binding a scan result to an exact server version and a signer:

```json
{
  "type": "mcp-trust-badge/v1",
  "server": "my-server",
  "version": "1.2.3",
  "riskScore": 82,
  "riskLevel": "low",
  "scores": { "schemaQuality": 96, "conformance": 100, "robustness": 88 },
  "findingCounts": { "critical": 0, "major": 1, "minor": 2, "info": 3 },
  "evalHash": "<sha256 of the canonical scored content>",
  "keyId": "<16 hex chars>",
  "publicKey": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "issuedAt": "2026-10-04T00:00:00.000Z",
  "signature": "<base64 Ed25519 signature>"
}
```

`scores` is `null` when the behavioral pass was skipped (the badge says so instead of pretending). The signature covers the whole badge except the signature field itself, and `evalHash` commits to the scored findings, so any tampering with scores or findings invalidates the badge.

## How verification works

Every pull request that adds files under `badges/` runs `scripts/validate.mjs` in CI. It checks, for each added badge:

1. **Placement**: the path is `badges/<server>/<version>.json` and the badge's `server`/`version` fields sanitize to exactly those path segments.
2. **Schema**: all required fields present with the right shapes (risk score 0-100, finding counts, 64-char eval hash, embedded Ed25519 public key, ISO date).
3. **Signature**: the Ed25519 signature verifies against the embedded public key, and the `keyId` matches that key. The cryptography is a direct port of mcp-trust's verifier, using only the Node.js standard library.
4. **No duplicates**: the path must not already exist on the target branch. The index is append-only per version: a new scan of a new version adds a new file; existing badges are never modified or removed via PR.

A PR that modifies or deletes an existing badge file fails validation.

## How to publish a badge

```bash
trustscan scan ./my-server --sign --badge-out my-server.trust.json
trustscan publish --badge my-server.trust.json
# or in one step:
trustscan scan ./my-server --sign --publish
```

`trustscan publish` verifies the badge locally first, then opens a pull request against this repo. CI validates it; a maintainer merges on green. No account or signup needed beyond the GitHub CLI.

You can also open a PR by hand: add `badges/<server>/<version>.json` with a valid signed badge and CI will check it the same way.

## How the site stays current

On every push to `main` that touches `badges/`, CI regenerates `docs/index.json` (the machine-readable manifest) and the static badge table in `docs/index.html`, then serves it via GitHub Pages. The page's search, sort, filter, and detail views run entirely client-side.

## Honest limitations

- A badge attests to the exact version scanned, at a point in time. A new release needs a new scan.
- Static checks are heuristics with false positives; findings are review prompts, never verdicts.
- Trust in the **signer** (the key id) is out of band, like a PGP key id. This index proves a badge is intact and well-formed, not that its signer is honest. Check who holds a key before you trust their badges.
- The index is append-only per version in v1. There is no takedown or correction flow yet; that is a known gap.
- Verify any badge yourself: `trustscan verify badge.json`.

## License

MIT. Badges are submitted by their signers; the index makes no claim about the quality or safety of indexed servers beyond what each badge states.
