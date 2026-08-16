"""
Pydantic schemas for per-tool argument validation. Validate before invocation so
side-effectful tools are never called with malformed args.
"""

from pydantic import BaseModel, ConfigDict, Field


class _ToolArgs(BaseModel):
    """
    Base for every tool argument schema. Exists for `extra="forbid"`.

    Pydantic's default is `extra="ignore"`: an argument the model misspelled is
    dropped and the tool runs with that field's default. `list_dir(path=...,
    recurse=True)` returned a non-recursive listing, reported success, and
    raised nothing — the call that reached the tool was not the call the model
    asked for, which inverts the purpose stated in the module docstring above.

    Rejecting is the recoverable outcome: the model is told which key was not
    accepted and can retry. Silently doing something different is not
    recoverable, because nothing downstream can tell the two apart.

    Inherit from this rather than BaseModel. A schema that inherits BaseModel
    directly is back to the permissive default with nothing to indicate it.
    """

    model_config = ConfigDict(extra="forbid")


class ListDirArgs(_ToolArgs):
    path: str = Field(..., description="Directory path (relative or absolute)")
    recursive: bool = Field(default=False, description="Include subdirectories (one level)")


class ReadFileArgs(_ToolArgs):
    path: str = Field(..., description="File path (relative or absolute)")
    encoding: str = Field(default="utf-8", description="Text encoding")


class EchoArgs(_ToolArgs):
    message: str = Field(..., description="Message to echo back")


class ResolveSecretArgs(_ToolArgs):
    alias: str = Field(..., min_length=1, description="Credential alias (e.g. github_token, api_key)")


class ListToolsArgs(_ToolArgs):
    include_args: bool = Field(default=True, description="Include argument summary for each tool")


class WriteFileArgs(_ToolArgs):
    path: str = Field(..., description="File path (relative to project root or absolute under project root)")
    content: str = Field(..., description="Content to write to the file")
    encoding: str = Field(default="utf-8", description="Text encoding")


class DeleteFileArgs(_ToolArgs):
    path: str = Field(..., description="File path (relative to project root or absolute under project root)")


class RestoreFileArgs(_ToolArgs):
    archive_name: str = Field(..., min_length=1, description="Archive filename from delete_file response or manifest (e.g. 20260627_143022_myfile.txt)")
    restore_to: str | None = Field(default=None, description="Optional restore path. Defaults to original location from manifest.")


class ValidateDirectiveArgs(_ToolArgs):
    path: str = Field(..., description="Path to a directive .md file to validate")


class HttpRequestArgs(_ToolArgs):
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


class ListDirectivesArgs(_ToolArgs):
    category: str | None = Field(default=None, description="Optional filter by category: system, task, security, or debug")


class GenerateTextArgs(_ToolArgs):
    prompt: str = Field(..., min_length=1, description="The prompt/instruction for the LLM")
    input_text: str = Field(default="", description="Optional input text to process (appended to prompt)")
    model: str | None = Field(default=None, description="Model identifier (backend-specific); defaults to the configured backend's default.")
