"""
Pydantic schemas for per-tool argument validation. Validate before invocation so
side-effectful tools are never called with malformed args.
"""

from pydantic import BaseModel, Field


class ListDirArgs(BaseModel):
    path: str = Field(..., description="Directory path (relative or absolute)")
    recursive: bool = Field(default=False, description="Include subdirectories (one level)")


class ReadFileArgs(BaseModel):
    path: str = Field(..., description="File path (relative or absolute)")
    encoding: str = Field(default="utf-8", description="Text encoding")


class EchoArgs(BaseModel):
    message: str = Field(..., description="Message to echo back")


class ResolveSecretArgs(BaseModel):
    alias: str = Field(..., min_length=1, description="Credential alias (e.g. github_token, api_key)")


class ListToolsArgs(BaseModel):
    include_args: bool = Field(default=True, description="Include argument summary for each tool")


class WriteFileArgs(BaseModel):
    path: str = Field(..., description="File path (relative to project root or absolute under project root)")
    content: str = Field(..., description="Content to write to the file")
    encoding: str = Field(default="utf-8", description="Text encoding")


class DeleteFileArgs(BaseModel):
    path: str = Field(..., description="File path (relative to project root or absolute under project root)")


class RestoreFileArgs(BaseModel):
    archive_name: str = Field(..., min_length=1, description="Archive filename from delete_file response or manifest (e.g. 20260627_143022_myfile.txt)")
    restore_to: str | None = Field(default=None, description="Optional restore path. Defaults to original location from manifest.")


class ValidateDirectiveArgs(BaseModel):
    path: str = Field(..., description="Path to a directive .md file to validate")


class HttpRequestArgs(BaseModel):
    url: str = Field(..., min_length=1, description="URL to request (https preferred)")
    method: str = Field(default="GET", description="HTTP method: GET or POST")
    headers: dict[str, str] | None = Field(default=None, description="Optional request headers")
    body: str | None = Field(default=None, description="Optional request body (for POST)")
    timeout: int = Field(default=30, ge=1, le=120, description="Request timeout in seconds")
    auth_alias: str | None = Field(
        default=None,
        description=(
            "Credential alias to authenticate with. The value is resolved at call time and "
            "sent as an Authorization header; it is never returned to you or written to logs. "
            "Never put a raw token in headers — reference an alias here instead."
        ),
    )
    auth_scheme: str = Field(
        default="Bearer",
        description="Auth scheme used with auth_alias: Bearer, Basic, or Token.",
    )


class ListDirectivesArgs(BaseModel):
    category: str | None = Field(default=None, description="Optional filter by category: system, task, security, or debug")


class SendNotificationArgs(BaseModel):
    webhook_url: str | None = Field(
        default=None,
        description="Webhook URL to POST to. Omit when using webhook_url_alias.",
    )
    message: str = Field(..., min_length=1, description="Notification message text")
    title: str = Field(default="Auro notification", description="Optional notification title/subject")
    webhook_url_alias: str | None = Field(
        default=None,
        description=(
            "Credential alias holding the full webhook URL. Preferred over webhook_url, because "
            "Slack and Discord webhook URLs contain the secret token in the path. The URL is "
            "resolved at call time and never returned to you or written to logs."
        ),
    )


class GenerateTextArgs(BaseModel):
    prompt: str = Field(..., min_length=1, description="The prompt/instruction for the LLM")
    input_text: str = Field(default="", description="Optional input text to process (appended to prompt)")
    model: str | None = Field(default=None, description="Model identifier (backend-specific); defaults to the configured backend's default.")
