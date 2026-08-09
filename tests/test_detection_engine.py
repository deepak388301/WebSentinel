from detectors import run_pre_forward_detectors, run_all_detectors


def test_run_pre_forward_detectors_returns_list():
    data = {"payload": "normal query", "url": "/"}
    result = run_pre_forward_detectors(data)
    assert isinstance(result, list)
    assert len(result) == 0


def test_run_pre_forward_detectors_detects_sql_injection():
    data = {"payload": "id=1' OR 1=1--", "url": "/search"}
    findings = run_pre_forward_detectors(data)
    assert len(findings) >= 1
    assert any(f["attack_type"] == "SQL Injection" for f in findings)


def test_run_pre_forward_detectors_detects_xss():
    data = {"payload": "<script>alert(1)</script>", "url": "/search"}
    findings = run_pre_forward_detectors(data)
    assert len(findings) >= 1
    assert any(f["attack_type"] == "Cross-Site Scripting (XSS)" for f in findings)


def test_run_pre_forward_detectors_detects_traversal():
    data = {"payload": "file=../../../etc/passwd", "url": "/view"}
    findings = run_pre_forward_detectors(data)
    assert len(findings) >= 1
    assert any(f["attack_type"] == "Path Traversal" for f in findings)


def test_run_pre_forward_detectors_detects_enumeration():
    data = {"payload": "", "url": "/.env"}
    findings = run_pre_forward_detectors(data)
    assert len(findings) >= 1
    assert any(f["attack_type"] == "Directory Enumeration" for f in findings)


def test_run_pre_forward_excludes_brute_force():
    data = {"payload": "", "url": "/login", "ip": "10.0.0.1", "status_code": 401}
    findings = run_pre_forward_detectors(data)
    assert not any(f["attack_type"] == "Brute Force" for f in findings)


def test_run_all_detectors_includes_brute_force():
    from database.models import db, LoginAttempt
    from proxy_app import create_app
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
        for i in range(6):
            db.session.add(LoginAttempt(ip="10.0.0.1", url="/login"))
        db.session.commit()
        data = {"payload": "", "url": "/login", "ip": "10.0.0.1", "status_code": 401}
        findings = run_all_detectors(data)
        assert any(f["attack_type"] == "Brute Force" for f in findings)


def test_multiple_findings_from_single_payload():
    data = {"payload": "<script>alert(1)</script> UNION SELECT * FROM users--", "url": "/search"}
    findings = run_all_detectors(data)
    attack_types = [f["attack_type"] for f in findings]
    assert len(findings) >= 2
    assert "SQL Injection" in attack_types
    assert "Cross-Site Scripting (XSS)" in attack_types


def test_all_findings_have_required_keys():
    data = {"payload": "id=1' OR 1=1--", "url": "/search"}
    findings = run_pre_forward_detectors(data)
    for finding in findings:
        assert "attack_type" in finding
        assert "confidence" in finding
        assert "evidence" in finding
        assert "mitre_technique" in finding
        assert "recommendation" in finding
