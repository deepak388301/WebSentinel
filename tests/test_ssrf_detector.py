from detectors.ssrf import detect


def test_detect_file_uri():
    data = {"payload": "url=file:///etc/passwd"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SSRF"
    assert result["confidence"] == "Very High"
    assert result["mitre_technique"] == "T1190"


def test_detect_gopher_uri():
    data = {"payload": "url=gopher://127.0.0.1:6379/_INFO"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SSRF"


def test_detect_dict_uri():
    data = {"payload": "url=dict://127.0.0.1:6379/info"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SSRF"
    assert "dict://" in result["evidence"]


def test_detect_cloud_metadata_ip():
    data = {"payload": "url=http://169.254.169.254/latest/meta-data/"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SSRF"
    assert "metadata" in result["evidence"].lower()


def test_detect_gcp_metadata():
    data = {"payload": "url=http://metadata.google.internal/computeMetadata/v1/"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SSRF"


def test_detect_localhost():
    data = {"payload": "url=http://localhost:8080/admin"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SSRF"


def test_detect_127_0_0_1():
    data = {"payload": "redirect=http://127.0.0.1:3000/internal"}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "SSRF"


def test_no_false_positive_normal_url():
    data = {"payload": "url=https://example.com/page"}
    result = detect(data)
    assert result is None


def test_no_false_positive_localhost_in_text():
    data = {"payload": "comment=visit localhost for dev setup"}
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
