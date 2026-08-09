from detectors.sql import detect, SQLI_PATTERNS


def test_detect_union_select():
    data = {"payload": "id=1 UNION SELECT username, password FROM users--"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SQL Injection"
    assert result["confidence"] == "Very High"
    assert result["mitre_technique"] == "T1190"


def test_detect_boolean_tautology():
    data = {"payload": "id=1' OR 1=1--"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SQL Injection"


def test_detect_sql_comment():
    data = {"payload": "id=1--"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SQL Injection"
    assert "comment" in result["evidence"].lower()


def test_detect_information_schema():
    data = {"payload": "SELECT * FROM information_schema.tables"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SQL Injection"


def test_detect_drop_table():
    data = {"payload": "DROP TABLE users"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SQL Injection"


def test_detect_quoted_boolean_injection():
    data = {"payload": "name='test' OR 'a'='a'"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SQL Injection"


def test_no_detection_clean_payload():
    data = {"payload": "username=john&password=secret123"}
    result = detect(data)
    assert result is None


def test_no_detection_empty_payload():
    data = {"payload": ""}
    result = detect(data)
    assert result is None


def test_no_detection_missing_payload():
    data = {}
    result = detect(data)
    assert result is None


def test_detect_case_insensitive():
    data = {"payload": "id=1 union select * from users"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SQL Injection"


def test_all_patterns_are_compiled_regexes():
    for pattern, evidence, confidence in SQLI_PATTERNS:
        assert hasattr(pattern, "search"), f"Pattern {evidence} is not a compiled regex"
        assert hasattr(pattern, "pattern"), f"Pattern {evidence} is not a compiled regex"
