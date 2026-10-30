# Security Policy

PII-Shield is currently in a production-hardening phase. Please treat security-sensitive deployments as controlled rollouts and validate policies against representative logs before production use.

## Reporting Security Issues

Please do not open a public GitHub issue for suspected vulnerabilities. Report security issues privately by email to the maintainer at ilya.ploskovitov@pii-shield.com. Include the affected component, reproduction steps, expected behavior, and any relevant logs or policy snippets.

## Supported Versions

The `main` branch is the active development line. Tagged releases should be evaluated with the documented limitations in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

## Deployment Guidance

- Configure a persistent `PII_SALT` for production deployments.
- Set `PII_REQUIRE_STRONG_SALT=true` in production or compliance environments if weak explicit salts should fail startup instead of only logging a warning.
- Test custom redaction and whitelist rules before rollout.
- Review Kubernetes webhook behavior and failure policy for your compliance requirements.
- Treat advanced gateway interception modes as R&D until explicitly marked stable. The eBPF audit agent is experimental and observation only; it runs with `CAP_BPF` and `CAP_PERFMON`, which give node-level read access, so treat its image as node-level trusted code ([docs/ebpf-audit.md](docs/ebpf-audit.md)).

## Secret Handling

- Do not commit API keys, tokens, private keys, kubeconfigs, database URLs with credentials, or production salts.
- Use GitHub Actions secrets for CI/CD credentials and Kubernetes secrets or an external secret manager for runtime deployments.
- Rotate any credential immediately if it is accidentally committed, even if the commit is later removed.
- Review logs and test fixtures before publishing them to ensure they do not contain real PII or credentials.
