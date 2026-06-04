# Getting Help with DNS-AID

## Documentation

- [Getting Started Guide](docs/getting-started.md) — step-by-step setup and first agent
- [Architecture](docs/architecture.md) — how DNS-AID works under the hood
- [API Reference](docs/api-reference.md) — Python library, CLI, and MCP server reference
- [Framework Integrations](docs/integrations.md) — LangChain, AutoGen, Google ADK, OpenAI Agents
- [Demo Guide](docs/demo-guide.md) — runnable demos with Route 53, DDNS, Cloudflare
- [IETF Draft](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/) — the DNS-AID specification

## Asking Questions

- **GitHub Discussions** — for questions, ideas, and general conversation: [Discussions](https://github.com/dns-aid/dns-aid-core/discussions)
- **GitHub Issues** — for bug reports and feature requests: [Issues](https://github.com/dns-aid/dns-aid-core/issues)

## Reporting Bugs

When filing a bug report, please include:

- Python version (`python --version`)
- DNS-AID version (`dns-aid --version` or `python -c "import dns_aid; print(dns_aid.__version__)"`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant error output or logs

## Security Issues

**Do NOT report security vulnerabilities through public issues.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute code, tests, and documentation.
