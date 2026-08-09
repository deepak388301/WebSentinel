from detectors.enumeration import detect, COMMON_SCANNER_PATHS


def test_detect_env_file():
    data = {"url": "/.env"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Directory Enumeration"
    assert result["confidence"] == "Medium"
    assert result["mitre_technique"] == "T1595.003"
    assert ".env" in result["evidence"]


def test_detect_git_config():
    data = {"url": "/.git/config"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Directory Enumeration"


def test_detect_wp_login():
    data = {"url": "/wp-login.php"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Directory Enumeration"


def test_detect_phpmyadmin():
    data = {"url": "/phpmyadmin/index.php"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Directory Enumeration"


def test_detect_admin_php():
    data = {"url": "/admin.php"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Directory Enumeration"


def test_detect_backup_sql():
    data = {"url": "/backup.sql"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Directory Enumeration"


def test_detect_aws_credentials():
    data = {"url": "/.aws/credentials"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Directory Enumeration"


def test_detect_id_rsa():
    data = {"url": "/id_rsa"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Directory Enumeration"


def test_detect_case_insensitive():
    data = {"url": "/.ENV"}
    result = detect(data)
    assert result is not None


def test_no_detection_clean_path():
    data = {"url": "/about"}
    result = detect(data)
    assert result is None


def test_no_detection_empty_url():
    data = {"url": ""}
    result = detect(data)
    assert result is None


def test_no_detection_missing_url():
    data = {}
    result = detect(data)
    assert result is None


def test_all_scanner_paths_are_strings():
    for path in COMMON_SCANNER_PATHS:
        assert isinstance(path, str), f"Scanner path {path!r} is not a string"
        assert path.startswith("/"), f"Scanner path {path!r} doesn't start with /"
