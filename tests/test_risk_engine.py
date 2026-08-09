from utils.risk_engine import calculate_risk, BASE_SCORES, CONFIDENCE_MODIFIER


def test_calculate_risk_sql_injection_high_confidence():
    finding = {"attack_type": "SQL Injection", "confidence": "High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 95
    assert result["severity"] == "Critical"


def test_calculate_risk_sql_injection_medium_confidence():
    finding = {"attack_type": "SQL Injection", "confidence": "Medium", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 85
    assert result["severity"] == "Critical"


def test_calculate_risk_sql_injection_low_confidence():
    finding = {"attack_type": "SQL Injection", "confidence": "Low", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 70
    assert result["severity"] == "High"


def test_calculate_risk_xss_high_confidence():
    finding = {"attack_type": "Cross-Site Scripting (XSS)", "confidence": "High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 75
    assert result["severity"] == "High"


def test_calculate_risk_xss_medium_confidence():
    finding = {"attack_type": "Cross-Site Scripting (XSS)", "confidence": "Medium", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 65
    assert result["severity"] == "High"


def test_calculate_risk_xss_low_confidence():
    finding = {"attack_type": "Cross-Site Scripting (XSS)", "confidence": "Low", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 50
    assert result["severity"] == "Medium"


def test_calculate_risk_path_traversal_high():
    finding = {"attack_type": "Path Traversal", "confidence": "High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 85
    assert result["severity"] == "Critical"


def test_calculate_risk_brute_force_high():
    finding = {"attack_type": "Brute Force", "confidence": "High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 80
    assert result["severity"] == "Critical"


def test_calculate_risk_directory_enumeration_medium():
    finding = {"attack_type": "Directory Enumeration", "confidence": "Medium", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 40
    assert result["severity"] == "Medium"


def test_calculate_risk_directory_enumeration_high():
    finding = {"attack_type": "Directory Enumeration", "confidence": "High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 50
    assert result["severity"] == "Medium"


def test_calculate_risk_unknown_attack_type_defaults_to_50():
    finding = {"attack_type": "Unknown Attack", "confidence": "Medium", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 50
    assert result["severity"] == "Medium"


def test_calculate_risk_unknown_confidence_defaults_to_0_modifier():
    finding = {"attack_type": "SQL Injection", "confidence": "Unknown", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 85
    assert result["severity"] == "Critical"


def test_calculate_risk_very_high_confidence():
    finding = {"attack_type": "SQL Injection", "confidence": "Very High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] == 100  # 85 + 20 = 105, clamped to 100
    assert result["severity"] == "Critical"


def test_calculate_risk_score_clamped_to_100():
    finding = {"attack_type": "SQL Injection", "confidence": "High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] <= 100


def test_calculate_risk_score_clamped_to_0():
    finding = {"attack_type": "Directory Enumeration", "confidence": "Low", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["risk_score"] >= 0


def test_calculate_risk_preserves_original_keys():
    finding = {"attack_type": "XSS", "confidence": "High", "evidence": "test", "custom_key": "value"}
    result = calculate_risk(finding)
    assert result["custom_key"] == "value"
    assert result["attack_type"] == "XSS"


def test_calculate_risk_mutates_input_dict():
    finding = {"attack_type": "SQL Injection", "confidence": "High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result is finding
    assert "risk_score" in finding
    assert "severity" in finding


def test_severity_thresholds_critical():
    finding = {"attack_type": "SQL Injection", "confidence": "High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["severity"] == "Critical"
    assert result["risk_score"] >= 80


def test_severity_thresholds_high():
    finding = {"attack_type": "Cross-Site Scripting (XSS)", "confidence": "High", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["severity"] == "High"
    assert 60 <= result["risk_score"] < 80


def test_severity_thresholds_medium():
    finding = {"attack_type": "Directory Enumeration", "confidence": "Medium", "evidence": "test"}
    result = calculate_risk(finding)
    assert result["severity"] == "Medium"
    assert 40 <= result["risk_score"] < 60


def test_base_scores_coverage():
    expected_types = {"SQL Injection", "Cross-Site Scripting (XSS)", "Path Traversal",
                      "Brute Force", "Directory Enumeration"}
    assert set(BASE_SCORES.keys()) == expected_types


def test_confidence_modifier_coverage():
    assert set(CONFIDENCE_MODIFIER.keys()) == {"Very High", "High", "Medium", "Low"}
