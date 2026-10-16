
import os
import re
import time

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from google import genai
from pydantic import BaseModel, Field

from audit import initialize_database, log_event
from permission import check_permission
from secure_reader import read_document


load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = "gemini-3.5-flash"
MAX_RETRIES = 3
GEMINI_TIMEOUT_SECONDS = 30

client = (
    genai.Client(
        api_key=API_KEY,
        http_options={
            "timeout": GEMINI_TIMEOUT_SECONDS * 1000,
        },
    )
    if API_KEY
    else None
)

initialize_database()

app = FastAPI(
    title="Sentinel AI Agent",
    description=(
        "A Gemini-powered AI gateway with input validation, "
        "tool permissions, secure document reading, and audit logging."
    ),
    version="1.6.0",
)


# Basic prompt-injection detection.
# These patterns are a first layer, not a complete security solution.
SUSPICIOUS_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)?\s*(instructions|directions)",
    r"override\s+(all\s+)?(previous\s+)?instructions",
    r"forget\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"(reveal|show|print|disclose|repeat)\s+(your\s+)?"
    r"(system prompt|hidden instructions|internal instructions)",
    r"(what|tell me)\s+(is|are)\s+(your\s+)?"
    r"(system prompt|hidden instructions)",
    r"bypass\s+(all\s+)?(security|safety)\s+(rules|filters|checks)",
    r"disable\s+(all\s+)?(safety|security)\s+(rules|filters|checks)",
    r"ignore\s+(all\s+)?(safety|security)\s+(rules|filters|checks)",
    r"you are now\s+(an?\s+)?(unrestricted|unfiltered|jailbroken)",
    r"enter\s+(developer|debug|unrestricted)\s+mode",
]


class AgentRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


class AgentResponse(BaseModel):
    message: str
    status: str
    provider: str


class PermissionRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=100)


class ReadDocumentRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)


def inspect_input(message: str) -> str:
    cleaned_message = message.strip()

    if not cleaned_message:
        raise HTTPException(
            status_code=422,
            detail="Message cannot be empty.",
        )

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, cleaned_message, re.IGNORECASE):
            raise HTTPException(
                status_code=400,
                detail="Request blocked by Sentinel security rules.",
            )

    return cleaned_message


def record_event(
    event_type: str,
    status_code: int,
    reason: str = "",
):
    """Attempt audit logging without exposing internal errors to callers."""
    try:
        log_event(event_type, status_code, reason)
    except Exception:
        # Logging failures are currently fail-open and may lose audit events.
        # A production deployment should monitor and handle these failures.
        pass


@app.get("/")
def home():
    return {
        "application": "Sentinel AI Agent",
        "status": "running",
        "provider": "Gemini",
        "security": {
            "input_inspection": True,
            "tool_permissions": True,
            "secure_document_reading": True,
            "audit_logging": True,
        },
    }


@app.get("/health")
def health():
    """Report application availability and AI-provider configuration."""
    return {
        "status": "healthy",
        "provider": "Gemini",
        "api_key_configured": client is not None,
    }


@app.post("/permissions")
def check_tool_permission(request: PermissionRequest):
    tool_name = request.tool_name.strip()

    if not tool_name:
        raise HTTPException(
            status_code=422,
            detail="Tool name cannot be empty.",
        )

    result = check_permission(tool_name)

    record_event(
        event_type="TOOL_PERMISSION_CHECK",
        status_code=200 if result["allowed"] else 403,
        reason=f"Tool: {result['tool']}; Allowed: {result['allowed']}",
    )

    return result


@app.post("/tools/read-document")
def read_document_endpoint(request: ReadDocumentRequest):
    result = read_document(request.filename.strip())

    if not result["success"]:
        error = result.get(
            "error",
            "Document could not be read.",
        )

        if error == "Document not found.":
            status_code = 404

        elif error == "Permission denied.":
            status_code = 403

        elif error in {
            "Symbolic links are not allowed.",
            "Access outside the documents folder is denied.",
            "Only regular files can be read.",
        }:
            status_code = 403

        elif error == "Document exceeds the 1 MB size limit.":
            status_code = 413

        elif error == "Unable to read document.":
            status_code = 500

        else:
            status_code = 400

        raise HTTPException(
            status_code=status_code,
            detail=error,
        )

    return result


@app.post("/chat", response_model=AgentResponse)
def chat(request: AgentRequest):
    try:
        cleaned_message = inspect_input(request.message)

    except HTTPException as exc:
        record_event(
            "REQUEST_BLOCKED",
            exc.status_code,
            "Input validation or security rule triggered",
        )
        raise

    if client is None:
        record_event(
            "PROVIDER_NOT_CONFIGURED",
            503,
            "Gemini API key is not configured",
        )
        raise HTTPException(
            status_code=503,
            detail="AI provider is not configured.",
        )

    for attempt in range(MAX_RETRIES):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=cleaned_message,
            )

            answer = response.text

            if not answer:
                record_event(
                    "EMPTY_PROVIDER_RESPONSE",
                    502,
                    "Gemini returned an empty response",
                )
                raise HTTPException(
                    status_code=502,
                    detail="AI provider returned an empty response.",
                )

            record_event(
                "REQUEST_SUCCESS",
                200,
                "AI response generated successfully",
            )

            return AgentResponse(
                message=answer,
                status="success",
                provider="Gemini",
            )

        except HTTPException:
            raise

        except Exception as exc:
            error_text = str(exc).lower()

            if (
                "429" in error_text
                or "resource_exhausted" in error_text
                or "rate limit" in error_text
                or "quota" in error_text
            ):
                record_event(
                    "PROVIDER_RATE_LIMITED",
                    429,
                    "Gemini rate limit or quota reached",
                )
                raise HTTPException(
                    status_code=429,
                    detail=(
                        "Gemini rate limit or quota reached. "
                        "Please try again later."
                    ),
                )

            if (
                "503" in error_text
                or "unavailable" in error_text
                or "high demand" in error_text
            ):
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** (attempt + 1))
                    continue

                record_event(
                    "PROVIDER_UNAVAILABLE",
                    503,
                    "Gemini remained unavailable after retries",
                )
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Gemini is temporarily unavailable. "
                        "Please try again later."
                    ),
                )

            record_event(
                "PROVIDER_ERROR",
                502,
                "Gemini request failed",
            )
            raise HTTPException(
                status_code=502,
                detail=(
                    "Gemini request failed. "
                    "Check the server terminal for details."
                ),
            ) from exc
