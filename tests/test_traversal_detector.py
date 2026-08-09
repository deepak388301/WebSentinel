from detectors.traversal import detect, TRAVERSAL_PATTERNS


def test_detect_relative_traversal():
    data = {"payload": "file=../../../../etc/passwd", "url": "/view"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Path Traversal"
    assert result["confidence"] == "Very High"  # contains both ../ and etc/passwd
    assert result["mitre_technique"] == "T1083"


def test_detect_windows_traversal():
    data = {"payload": "file=..\\..\\..\\windows\\system32\\config\\sam", "url": "/download"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Path Traversal"


def test_detect_url_encoded_traversal():
    data = {"payload": "file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "url": "/view"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Path Traversal"


def test_detect_etc_passwd_reference():
    data = {"payload": "path=etc/passwd", "url": "/read"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Path Traversal"


def test_detect_boot_ini_reference():
    data = {"payload": "file=boot.ini", "url": "/windows"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Path Traversal"


def test_detect_deep_traversal_chain():
    data = {"payload": "file=../../../../../etc/shadow", "url": "/api"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Path Traversal"


def test_detect_in_url_path():
    data = {"payload": "", "url": "/files/../../etc/passwd"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Path Traversal"


def test_no_detection_clean_input():
    data = {"payload": "file=document.pdf", "url": "/download"}
    result = detect(data)
    assert result is None


def test_no_detection_empty_inputs():
    data = {"payload": "", "url": ""}
    result = detect(data)
    assert result is None


def test_no_detection_missing_fields():
    data = {}
    result = detect(data)
    assert result is None


def test_all_patterns_are_compiled_regexes():
    for pattern, evidence, confidence in TRAVERSAL_PATTERNS:
        assert hasattr(pattern, "search"), f"Pattern {evidence} is not compiled"
        assert hasattr(pattern, "pattern"), f"Pattern {evidence} is not compiled"
