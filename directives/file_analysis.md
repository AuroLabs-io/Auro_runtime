---
id: file_analysis
description: Analyze files and summarize contents
tools: [list_dir, read_file]
category: task
---

# File analysis

## Purpose
Analyze files in a given path and summarize their contents. Use only the allowed tools.

## Steps
1. **Discover** — Use `list_dir` to identify target files.
2. **Analyze** — Use `read_file` on relevant files and summarize or extract key info.
3. When you have enough information, respond with `{"done": true, "summary": "..."}` and a concise summary for the user.

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool).
- `read_file` — Read file contents. Args: `path` (str), optional `encoding` (str, default "utf-8").
