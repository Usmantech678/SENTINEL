
from pathlib import Path

import pytest

import secure_reader
from secure_reader import read_document


def test_read_existing_document():
    result = read_document("sample.txt")

    assert result["success"] is True
    assert result["filename"] == "sample.txt"
    assert isinstance(result["content"], str)


def test_path_traversal_is_rejected():
    result = read_document("..\\secret.txt")

    assert result["success"] is False
    assert result["error"] == "Invalid filename."


def test_non_text_file_is_rejected():
    result = read_document("sample.pdf")

    assert result["success"] is False
    assert result["error"] == "Only .txt documents are allowed."


def test_missing_document_is_rejected():
    result = read_document("does_not_exist.txt")

    assert result["success"] is False
    assert result["error"] == "Document not found."


def test_document_read_succeeds_when_audit_logging_fails(monkeypatch):
    def fail_logging(*args, **kwargs):
        raise RuntimeError("Simulated audit failure")

    monkeypatch.setattr(secure_reader, "log_event", fail_logging)

    result = read_document("sample.txt")

    assert result["success"] is True


def test_invalid_filename_returns_error_when_audit_logging_fails(
    monkeypatch,
):
    def fail_logging(*args, **kwargs):
        raise RuntimeError("Simulated audit failure")

    monkeypatch.setattr(secure_reader, "log_event", fail_logging)

    result = read_document("..\\secret.txt")

    assert result["success"] is False
    assert result["error"] == "Invalid filename."


def test_oversized_document_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_reader, "DOCUMENTS_DIR", tmp_path)

    oversized_file = tmp_path / "large.txt"
    oversized_file.write_bytes(b"A" * (secure_reader.MAX_FILE_SIZE + 1))

    result = read_document("large.txt")

    assert result["success"] is False
    assert "size limit" in result["error"].lower()


def test_document_at_size_limit_is_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_reader, "DOCUMENTS_DIR", tmp_path)

    allowed_file = tmp_path / "limit.txt"
    allowed_file.write_bytes(b"A" * secure_reader.MAX_FILE_SIZE)

    result = read_document("limit.txt")

    assert result["success"] is True
    assert len(result["content"].encode("utf-8")) == (
        secure_reader.MAX_FILE_SIZE
    )


def test_symbolic_link_to_external_file_is_rejected(
    tmp_path, monkeypatch,
):
    documents_dir = tmp_path / "documents"
    documents_dir.mkdir()

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("Secret content", encoding="utf-8")

    link = documents_dir / "linked.txt"

    try:
        link.symlink_to(outside_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are unavailable on this system")

    monkeypatch.setattr(secure_reader, "DOCUMENTS_DIR", documents_dir)

    result = read_document("linked.txt")

    assert result["success"] is False
    assert "symbolic link" in result["error"].lower()
