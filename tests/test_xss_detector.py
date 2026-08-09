from detectors.xss import detect, XSS_PATTERNS


def test_detect_script_tag():
    data = {"payload": "q=<script>alert(1)</script>"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Cross-Site Scripting (XSS)"
    assert result["confidence"] == "Very High"
    assert result["mitre_technique"] == "T1059.007"


def test_detect_event_handler():
    data = {"payload": 'q=<img src=x onerror="alert(1)">'}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Cross-Site Scripting (XSS)"
    assert "event handler" in result["evidence"].lower()


def test_detect_javascript_uri():
    data = {"payload": "url=javascript:alert(document.cookie)"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Cross-Site Scripting (XSS)"


def test_detect_img_onerror():
    data = {"payload": '<img src="x" onerror="alert(1)">'}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Cross-Site Scripting (XSS)"


def test_detect_url_encoded_script():
    data = {"payload": "q=%3Cscript%3Ealert(1)%3C/script%3E"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Cross-Site Scripting (XSS)"


def test_detect_document_cookie():
    data = {"payload": "q=document.cookie"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Cross-Site Scripting (XSS)"
    assert "cookie" in result["evidence"].lower()


def test_no_detection_clean_input():
    data = {"payload": "q=hello world"}
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


def test_all_patterns_are_compiled_regexes():
    for pattern, evidence, confidence in XSS_PATTERNS:
        assert hasattr(pattern, "search"), f"Pattern {evidence} is not compiled"
        assert hasattr(pattern, "pattern"), f"Pattern {evidence} is not compiled"
