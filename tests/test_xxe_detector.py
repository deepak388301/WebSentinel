from detectors.xxe import detect


XML_HEADERS = '{"Content-Type": "application/xml"}'


def test_detect_doctype():
    data = {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "headers": XML_HEADERS}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "XXE"
    assert result["confidence"] == "Very High"  # SYSTEM file: matches before DOCTYPE
    assert result["mitre_technique"] == "T1190"


def test_detect_entity():
    data = {"payload": '<?xml version="1.0"?><!ENTITY xxe SYSTEM "file:///etc/passwd">', "headers": XML_HEADERS}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "XXE"
    assert "entity" in result["evidence"].lower()


def test_detect_system_file():
    data = {"payload": '<data><name>SYSTEM "file:///etc/shadow"</name></data>', "headers": XML_HEADERS}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "XXE"


def test_no_xxe_without_xml_content_type():
    data = {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "headers": '{"Content-Type": "application/json"}'}
    result = detect(data)
    assert result is None


def test_no_xxe_with_no_headers():
    data = {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "headers": ""}
    result = detect(data)
    assert result is None


def test_no_false_positive_soap():
    data = {"payload": '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetPrice><Item>Apple</Item></GetPrice></soap:Body></soap:Envelope>', "headers": '{"Content-Type": "application/soap+xml"}'}
    result = detect(data)
    assert result is None


def test_no_false_positive_normal_xml():
    data = {"payload": '<?xml version="1.0"?><root><name>John</name></root>', "headers": XML_HEADERS}
    result = detect(data)
    assert result is None


def test_no_false_positive_empty():
    data = {"payload": "", "headers": XML_HEADERS}
    result = detect(data)
    assert result is None


def test_no_false_positive_missing():
    data = {}
    result = detect(data)
    assert result is None


def test_no_false_positive_vendor_non_xml():
    """application/vnd.api+json is NOT XML — should not trigger XXE detection."""
    data = {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            "headers": '{"Content-Type": "application/vnd.api+json"}'}
    result = detect(data)
    assert result is None


def test_no_false_positive_vnd_ms_excel():
    """application/vnd.ms-excel is NOT XML — should not trigger XXE detection."""
    data = {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            "headers": '{"Content-Type": "application/vnd.ms-excel"}'}
    result = detect(data)
    assert result is None


def test_detect_with_soap_xml_content_type():
    """application/soap+xml IS XML — should trigger XXE detection."""
    data = {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            "headers": '{"Content-Type": "application/soap+xml"}'}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "XXE"


def test_detect_with_text_xml():
    """text/xml IS XML — should trigger XXE detection."""
    data = {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            "headers": '{"Content-Type": "text/xml"}'}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "XXE"
