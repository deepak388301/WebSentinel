from utils.risk_engine import calculate_risk


def test_calculate_risk_assigns_expected_severity():
    finding = {
        "attack_type": "SQL Injection",
        "confidence": "High",
        "evidence": "test",
    }

    result = calculate_risk(finding)

    assert result["risk_score"] == 95
    assert result["severity"] == "Critical"
