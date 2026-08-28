# Security policy

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting, from the **Security** tab of this repository ("Report a vulnerability"). That channel is private to the maintainers, and it is the only one that should be used for a suspected vulnerability.

**Please do not open a public issue, pull request, or discussion for a security report.** A public issue discloses the finding to everyone who can read the repository before there is a fix.

Include enough to reproduce: the version or commit, the configuration involved (especially any `AURO_*` environment variables that were set), a minimal case that demonstrates the behaviour, and what you expected instead. A reproduction is worth more than a description.

You should get an acknowledgement within a week. This is a single-maintainer Alpha project, not a funded security programme, so please read that as a good-faith commitment rather than a service level. There is no bounty.

## What is in scope

This project is a kernel whose job is to make a model's proposed actions refusable before they run. The findings that matter most are the ones where that fails:

- A tool call executing despite an active directive not granting the tool.
- A policy guard being skipped, or its verdict not enforced, without an operator having deliberately opted out.
- Escaping the filesystem sandbox — writing, deleting, or restoring outside the workspace, or reading a blocklisted path.
- A credential value reaching the model's context, a tool argument, a returned result, or the audit log.
- Bypassing the protected-directory boundary so that a run can alter the authority it runs under.
- Authentication bypass on the MCP streamable-http transport.

## What is already known, and out of scope

Please check these before reporting. Each is a documented, deliberate boundary rather than a defect, and the README and `docs/FAQ.md` describe them:

- **Prompt injection carried in tool output.** Tool results are scrubbed for secret shapes, not neutralized for embedded instructions. This is stated in the README's trust-boundary table and answered in the FAQ. A report showing injection steering a call that a directive *does* grant is expected behaviour; a report showing it reaching a tool no directive grants is in scope.
- **Operator-set configuration that weakens the posture.** `AURO_ALLOW_NO_POLICIES`, `AURO_POLICY_PROFILE=custom`, the two `AURO_RUNTIME_*_DIRS` sandbox wideners, and `AURO_OPENAI_BASE_URL` — which redirects the runtime's own model traffic to any host, unchecked by the egress guard — all deliberately relax defaults. The runtime does not defend against its own operator. A route that reaches these *without* an operator setting them is very much in scope.
- **The audit log is best-effort.** Buffered local JSONL, no forwarding, signing, or tamper-evidence, and a `sequence` gap does not distinguish a rejected record from a lost one. Documented in the FAQ.
- **No identity model.** There is no user or role model and no per-caller attribution; MCP clients share one bearer token. "No per-client RBAC" is a stated boundary, not a vulnerability.
- **The runtime does not terminate TLS.** Binding a non-loopback host without a reverse proxy puts the bearer token in cleartext, and the README says so.

## Supported versions

Alpha, version `0.1.x`, with no compatibility or stability guarantee yet. Only the current `main` is supported; there are no maintained release branches and no backports. Fixes land on `main`.

Maturity is claimed by demonstration rather than assertion, so treat the version as a description of what has been shown to work, not a promise about what is hardened.
