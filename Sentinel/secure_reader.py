
import os
import stat
from pathlib import Path

from permission import check_permission
from audit import log_event


DOCUMENTS_DIR = Path(__file__).resolve().parent / "documents"
MAX_FILE_SIZE = 1024 * 1024  # 1 MB


def safe_log_event(event_type: str, status_code: int, reason: str = ""):
    """Attempt to record an event without crashing the caller."""
    try:
        log_event(event_type, status_code, reason)
    except Exception:
        pass


def blocked(error: str, reason: str, status_code: int = 400) -> dict:
    """Record a blocked or failed operation and return a safe error."""
    event_type = (
        "DOCUMENT_READ_FAILED"
        if status_code >= 500
        else "DOCUMENT_READ_BLOCKED"
    )
    safe_log_event(event_type, status_code, reason)
    return {"success": False, "error": error}


def read_document(filename: str) -> dict:
    permission = check_permission("read_document")

    if not permission["allowed"]:
        safe_log_event(
            "TOOL_ACCESS_DENIED",
            403,
            "Document reading permission denied",
        )
        return {"success": False, "error": "Permission denied."}

    if not isinstance(filename, str) or not filename:
        return blocked("Invalid filename.", "Empty or invalid filename")

    if Path(filename).name != filename or filename in {".", ".."}:
        return blocked("Invalid filename.", "Invalid document filename")

    if "\x00" in filename:
        return blocked("Invalid filename.", "Null byte in filename")

    if Path(filename).suffix.lower() != ".txt":
        return blocked(
            "Only .txt documents are allowed.",
            "Unsupported document extension",
        )

    try:
        documents_root = DOCUMENTS_DIR.resolve(strict=True)
        target = documents_root / filename

        # Reject symbolic links instead of following them.
        if target.is_symlink():
            return blocked(
                "Symbolic links are not allowed.",
                "Symbolic link document rejected",
                403,
            )

        resolved_target = target.resolve(strict=True)

        # Require the resolved file to remain directly inside documents/.
        if resolved_target.parent != documents_root:
            return blocked(
                "Access outside the documents folder is denied.",
                "Document path outside permitted folder",
                403,
            )

        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)

        # O_NOFOLLOW is available on some platforms, but not all.
        # The symlink check above is not an atomic guarantee on Windows.
        file_descriptor = os.open(target, flags)

        try:
            file_info = os.fstat(file_descriptor)

            if not stat.S_ISREG(file_info.st_mode):
                return blocked(
                    "Only regular files can be read.",
                    "Non-regular document rejected",
                    403,
                )

            if file_info.st_size > MAX_FILE_SIZE:
                return blocked(
                    "Document exceeds the 1 MB size limit.",
                    "Document size limit exceeded",
                    413,
                )

            with os.fdopen(
                file_descriptor,
                "r",
                encoding="utf-8",
            ) as document:
                file_descriptor = -1
                content = document.read(MAX_FILE_SIZE + 1)

            if len(content.encode("utf-8")) > MAX_FILE_SIZE:
                return blocked(
                    "Document exceeds the 1 MB size limit.",
                    "Document size limit exceeded",
                    413,
                )

        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)

    except FileNotFoundError:
        return blocked(
            "Document not found.",
            "Requested document was not found",
            404,
        )

    except (OSError, UnicodeError, ValueError):
        return blocked(
            "Unable to read document.",
            "Document could not be safely read",
            500,
        )

    safe_log_event(
        "DOCUMENT_READ_SUCCESS",
        200,
        "Document read successfully",
    )

    return {
        "success": True,
        "filename": filename,
        "content": content,
    }
