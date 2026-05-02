# Changelogs

This folder contains changelog files that describe changes to be released.

## Adding a changelog

Run `changelogs add` to create a new changelog file.

## File format

Changelog files are markdown with YAML frontmatter:

```markdown
---
github.com/tempoxyz/tempo-go: minor
---

Description of the changes made.
```

> **Go module naming:** the package identifier is the **full module path**
> from `go.mod` (e.g. `github.com/tempoxyz/tempo-go`), not the bare repo
> name. Using `tempo-go: minor` will not be recognized.

Bump levels: `patch`, `minor`, `major`.

## Releasing

Releases are automated. On push to `main`, the `Changelog Release` workflow
opens (or updates) a "Version Packages" PR that applies the version bump and
updates `CHANGELOG.md`. Merging that PR pushes the new `vX.Y.Z` tag, which
publishes via `proxy.golang.org`.

To preview locally:

```bash
changelogs status
```
