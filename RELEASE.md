# Release Process

## Versioning

DNS-AID follows [Semantic Versioning](https://semver.org/) (SemVer):

- **MAJOR** (X.0.0) — incompatible API changes
- **MINOR** (0.X.0) — new functionality, backwards compatible
- **PATCH** (0.0.X) — backwards-compatible bug fixes

## Release Criteria

Before any release:

1. **All CI checks pass** — tests, lint, type check, security scan
2. **No critical or high-severity security vulnerabilities** in dependencies
3. **CHANGELOG.md updated** with all changes since the last release
4. **Documentation updated** for any new features or API changes

## Release Cadence

- **Patch releases** — as needed for bug fixes and security patches
- **Minor releases** — as features are completed
- **Major releases** — when breaking changes are necessary

## Release Steps

1. **Update version** in `src/dns_aid/__init__.py` and `pyproject.toml`
2. **Update CHANGELOG.md** with release date and changes
3. **Create a PR** with the version bump
4. **Merge PR** after CI passes and review approval
5. **Tag the release with a signed tag** — `git tag -s vX.Y.Z -m "vX.Y.Z"` using the maintainer's GPG or SSH signing key (unsigned tags are not used for releases)
6. **Publish to PyPI** — pushing the `v*` tag automatically publishes to PyPI via trusted publisher

## Hotfix Process

For critical security fixes:

1. Create a branch from the latest release tag
2. Apply the fix with tests
3. Follow the standard release steps with a patch version bump
4. Notify users via GitHub release notes

## Release Artifacts

Each release includes:

- **PyPI package** — `pip install dns-aid` (published via trusted publisher)
- **GitHub Release** with changelog and tag
- **Source distribution** (sdist)
- **Wheel distribution** (bdist_wheel)
- **Sigstore signatures** (`.sig` + `.pem` for each artifact)
- **SBOM** (CycloneDX JSON)
