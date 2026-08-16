"""
Built-in tools for the orchestrator. Import this module to register tools.
"""

import runtime_tools.file_tools  # noqa: F401 — registers list_dir, read_file, write_file, delete_file, restore_file, echo
import runtime_tools.credential_tools  # noqa: F401 — registers resolve_secret
import runtime_tools.catalog_tools  # noqa: F401 — registers list_tools
import runtime_tools.validate_directive_tools  # noqa: F401 — registers validate_directive
import runtime_tools.generate_text_tools  # noqa: F401 — registers generate_text
import runtime_tools.http_request_tools  # noqa: F401 — registers http_request
import runtime_tools.list_directives_tools  # noqa: F401 — registers list_directives

# runtime_tools.notification_tools was removed 2026-08-14: send_notification was a
# Slack/Discord/Teams webhook formatter (application integration, granted by no
# shipped directive), not a kernel primitive. Its credential-alias delivery is
# already demonstrated by http_request's auth_alias.
#
# runtime_tools.verify_tools is deliberately not imported here: it registers no
# tools. Its verifiers are operator functions, imported directly by whoever runs
# them. See the module docstring for why the model-facing path was cut.
