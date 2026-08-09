from utils.normalize import normalize


def test_double_url_encoded_xss():
    """Regression: double-encoded <script> must be caught after normalization."""
    double_encoded = "%253Cscript%253Ealert(1)%253C%252Fscript%253E"
    normalized = normalize(double_encoded)
    assert "<script" in normalized


def test_single_url_encoded():
    single_encoded = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    normalized = normalize(single_encoded)
    assert "<script" in normalized


def test_already_decoded():
    raw = "<script>alert(1)</script>"
    normalized = normalize(raw)
    assert normalized == "<script>alert(1)</script>"


def test_triple_url_encoded():
    triple = "%25253Cscript%25253E"
    normalized = normalize(triple)
    assert "script" in normalized


def test_strips_sql_comments():
    raw = "id=1/* comment */ AND 1=1"
    normalized = normalize(raw)
    assert "/*" not in normalized
    assert "comment" not in normalized
    assert "and 1=1" in normalized


def test_collapses_whitespace():
    raw = "id=1   AND    1=1"
    normalized = normalize(raw)
    assert normalized == "id=1 and 1=1"


def test_lowercases():
    raw = "UNION SELECT * FROM users"
    normalized = normalize(raw)
    assert normalized == "union select * from users"


def test_empty_string():
    assert normalize("") == ""


def test_none_like_input():
    assert normalize(None) == ""


def test_idempotent():
    raw = "%3Cscript%3Ealert(1)%3C/script%3E"
    first = normalize(raw)
    second = normalize(first)
    assert first == second
