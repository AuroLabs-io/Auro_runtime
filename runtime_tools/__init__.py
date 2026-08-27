"""
Built-in tools for the orchestrator. Import this module to register tools.
"""

import runtime_tools.file_tools  # noqa: F401 — registers list_dir, read_file, write_file, delete_file, restore_file, echo
import runtime_tools.credential_tools  # noqa: F401 — registers resolve_secret
import runtime_tools.catalog_tools  # noqa: F401 — registers list_tools
import runtime_tools.validate_directive_tools  # noqa: F401 — registers validate_directive
import runtime_tools.http_request_tools  # noqa: F401 — registers http_request
import runtime_tools.list_directives_tools  # noqa: F401 — registers list_directives

# runtime_tools.notification_tools was removed 2026-08-14: send_notification was a
# Slack/Discord/Teams webhook formatter (application integration, granted by no
# shipped directive), not a kernel primitive. Its credential-alias delivery is
# already demonstrated by http_request's auth_alias.
#
# runtime_tools.generate_text_tools was removed 2026-08-26: generate_text was a
# network egress path whose destination is NOT checked by egress.py (the model
# backends are deliberately excluded so a local Ollama server can reach
# loopback) and, at the same time, a context re-entry path returning
# model-generated text unneutralized. It is the only tool that was both. Its
# `model` argument was a free-form unvalidated string, and its repeat-call gate
# leaked state across runs and threads. Cut rather than gated: the contract
# needs settling before it ships, and a control built on a contract under
# question is work that gets redone. Not unused — create_directive still
# instructs it in Phases 4, 7 and 8 and is knowingly shipped broken on that
# account; its `tools:` declaration was dropped only because
# test_every_declared_tool_is_registered correctly refuses it. See
# OT-generate_text-needs-a-contract-before-it-ships and
# OT-create-directive-needs-rework-before-it-ships.
#
# runtime_tools.verify_tools is deliberately not imported here: it registers no
# tools. Its verifiers are operator functions, imported directly by whoever runs
# them. See the module docstring for why the model-facing path was cut.
