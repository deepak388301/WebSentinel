from detectors.nosql_injection import detect


def test_detect_dollar_where():
    data = {"payload": '{"username": {"$where": "function() { return true; }"}}'}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "NoSQL Injection"
    assert result["confidence"] == "Very High"
    assert result["mitre_technique"] == "T1190"


def test_detect_dollar_ne():
    data = {"payload": '{"password": {"$ne": ""}}'}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "NoSQL Injection"


def test_detect_dollar_gt():
    data = {"payload": '{"age": {"$gt": 18}}'}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "NoSQL Injection"


def test_detect_dollar_regex():
    data = {"payload": '{"name": {"$regex": "^admin"}}'}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "NoSQL Injection"


def test_detect_dollar_or():
    data = {"payload": '{"$or": [{"user": "admin"}, {"role": "admin"}]}'}
    result = detect(data)
    assert result is not None
    assert result["attack_type"] == "NoSQL Injection"
    assert "$or" in result["evidence"]


def test_no_false_positive_normal_json():
    data = {"payload": '{"name": "John", "age": 30}'}
    result = detect(data)
    assert result is None


def test_no_false_positive_price():
    data = {"payload": "price=$12.99"}
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
