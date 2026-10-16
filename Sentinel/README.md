# Sentinel — Secure AI Agent Gateway

Sentinel is a security-focused AI gateway built with Python, FastAPI, and Google Gemini. It provides input validation, tool permission controls, restricted document access, audit logging, and AI provider error handling.

## Features

- **AI Integration:** Connects Google Gemini through a REST API built with FastAPI.
- **Input Validation:** Rejects empty, oversized, and selected suspicious prompts.
- **Tool Permissions:** Implements an explicit allowlist and denies unknown tools by default.
- **Secure Document Access:** Restricts reading to `.txt` files in the designated directory, rejects path traversal and symbolic links, and enforces a 1 MB file-size limit.
- **Audit Logging:** Records document operations and security events in SQLite with UTC timestamps.
- **Error Handling:** Handles provider rate limits, unavailable services, empty responses, and unexpected errors.
- **Automated Testing:** Tests API endpoints, permission checks, document restrictions, audit logging, and provider failure scenarios.

## Architecture

```text
Client
  |
  v
FastAPI Application
  |
  +--> Input Validation and Inspection
  |
  +--> Gemini API Integration
  |       |
  |       +--> Retry and Error Handling
  |
  +--> Tool Permission Checks
  |       |
  |       +--> Secure Document Reader
  |
  +--> SQLite Audit Logger
```

## Technology Stack

- Python
- FastAPI
- Google Gemini API (`google-genai`)
- SQLite
- Pydantic
- pytest

## Project Structure

```text
Sentinel/
├── documents/
├── main.py
├── permission.py
├── secure_reader.py
├── audit.py
├── test_main.py
├── test_permission.py
├── test_secure_reader.py
├── test_audit.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Getting Started

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd Sentinel
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
```

On Windows:

```bat
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure the API key

Create a `.env` file in the project root:

```text
GEMINI_API_KEY=your_gemini_api_key
```

Replace the placeholder with your own Gemini API key. Never commit your API key or `.env` file.

### 5. Start the application

```bash
python -m uvicorn main:app --reload
```

Open the interactive API documentation:

http://127.0.0.1:8000/docs

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Application status |
| GET | `/health` | Health and provider configuration information |
| POST | `/chat` | Validate input and send messages to Gemini |
| POST | `/permissions` | Check tool permissions |
| POST | `/tools/read-document` | Read an authorized text document |

Use `/docs` to inspect request formats and test the endpoints.

## Testing

Run the automated test suite:

```bash
python -m pytest -q
```

**Current test result:** 40 passed, 1 skipped.

The skipped test covers symbolic-link handling when symbolic links cannot be created in the test environment.

## Security Design

- Default-deny tool permissions.
- Document path validation and directory restrictions.
- File-type and file-size enforcement.
- Parameterized SQL queries.
- SQLite-based security-event logging.
- Provider error handling without exposing raw unexpected exception details.

## Limitations

Sentinel is a security-focused prototype. Its pattern-based prompt inspection cannot detect every prompt injection, and SQLite audit records are not tamper-proof.

## Future Improvements

- Authentication and per-user authorization.
- Stronger prompt-injection evaluation.
- Improved audit-log integrity and monitoring.
- Rate limiting and deployment hardening.

## Author

**Mohammed Usman**

GitHub: [Usmantech678](https://github.com/Usmantech678)