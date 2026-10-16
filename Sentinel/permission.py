
ALLOWED_TOOLS = {
    "read_document",
}

DENIED_TOOLS = {
    "delete_file",
    "execute_command",
}


def check_permission(tool_name: str) -> dict:
    if tool_name in DENIED_TOOLS:
        return {
            "allowed": False,
            "tool": tool_name,
            "reason": "This tool is explicitly denied by Sentinel.",
        }

    if tool_name in ALLOWED_TOOLS:
        return {
            "allowed": True,
            "tool": tool_name,
            "reason": "This tool is explicitly allowed by Sentinel.",
        }

    return {
        "allowed": False,
        "tool": tool_name,
        "reason": "Unknown tools are denied by default.",
    }
