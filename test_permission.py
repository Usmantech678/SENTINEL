
from permission import check_permission


def test_allowed_tool():
    result = check_permission("read_document")
    assert result["allowed"] is True


def test_denied_tool():
    result = check_permission("delete_file")
    assert result["allowed"] is False


def test_unknown_tool():
    result = check_permission("send_email")
    assert result["allowed"] is False
