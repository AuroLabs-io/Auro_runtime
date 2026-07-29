"""
Send notifications via webhook (Slack, Discord, Teams, generic).
"""

from urllib.parse import urlparse

from auro_runtime.executor import register
from auro_runtime.tool_schemas import SendNotificationArgs


@register(
    "send_notification",
    "Send a notification via webhook POST (Slack, Discord, Teams, or any URL that accepts JSON). "
    "Prefer webhook_url_alias — Slack and Discord webhook URLs contain a secret token. "
    "Rejects four literal loopback spellings only. It does not block private IPv4 ranges, "
    "link-local addresses, IPv6, or any hostname, so it must not be treated as a control "
    "on where the notification is delivered.",
    args_schema=SendNotificationArgs,
)
def send_notification(
    webhook_url: str | None = None,
    message: str = "",
    title: str = "Auro notification",
    webhook_url_alias: str | None = None,
) -> dict:
    """
    POST a JSON notification to a webhook URL.
    Auto-detects Slack, Discord, and Teams formats. Falls back to generic JSON.

    webhook_url_alias is resolved here, at call time. The resolved URL is never
    returned in the result, because for Slack and Discord the token is in the URL.
    """
    if webhook_url_alias:
        from auro_runtime.secrets import get_secret

        resolved = get_secret(webhook_url_alias)
        if not resolved:
            return {"sent": False, "error": f"Credential alias '{webhook_url_alias}' is not configured."}
        webhook_url = resolved
    if not webhook_url:
        return {"sent": False, "error": "Provide either webhook_url or webhook_url_alias."}

    try:
        parsed = urlparse(webhook_url)
    except Exception:
        return {"sent": False, "error": "Invalid webhook URL."}

    if parsed.scheme not in ("http", "https"):
        return {"sent": False, "error": "Webhook URL must use http or https."}

    # Literal spellings only. This is not a destination control — it does not
    # cover private IPv4 ranges, link-local, IPv6, or hostnames that resolve
    # inward. Tracked by OT-http-request-destination-is-unenforced, which calls
    # for one shared egress boundary rather than a second weak per-tool check.
    host = (parsed.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return {"sent": False, "error": "Webhook to localhost is blocked."}

    try:
        import requests
    except ImportError:
        return {"sent": False, "error": "requests library not installed."}

    payload = _build_payload(webhook_url, title, message)
    try:
        r = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        return {
            "sent": r.status_code < 400,
            "status_code": r.status_code,
            "response": r.text[:500],
        }
    except requests.exceptions.Timeout:
        return {"sent": False, "error": "Webhook request timed out."}
    except Exception as e:
        return {"sent": False, "error": str(e)}


def _build_payload(url: str, title: str, message: str) -> dict:
    """Build platform-appropriate JSON payload."""
    url_lower = url.lower()

    if "hooks.slack.com" in url_lower:
        return {
            "text": f"*{title}*\n{message}",
        }

    if "discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower:
        return {
            "content": f"**{title}**\n{message}",
        }

    if "webhook.office.com" in url_lower or "outlook.office.com" in url_lower:
        return {
            "@type": "MessageCard",
            "summary": title,
            "sections": [{
                "activityTitle": title,
                "text": message,
            }],
        }

    return {
        "title": title,
        "message": message,
    }
