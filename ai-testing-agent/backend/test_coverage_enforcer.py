"""
Unit tests for coverage expectation enforcement.

Tests generic behavior (not ATA-41 specific) to validate:
- Expectation extraction from requirement text
- Missing coverage detection
- Deterministic test generation
- Idempotency
"""
import pytest
from services.coverage_enforcer import (
    extract_coverage_expectations,
    get_existing_test_coverage,
    enforce_coverage_expectations,
    CoverageExpectations
)


def test_extract_endpoints():
    """Test endpoint extraction from requirement text."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials creates credentials"
        },
        {
            "id": "REQ-002",
            "description": "GET /api/v1/integrations/thirdparty/credentials returns credentials"
        }
    ]
    
    expectations = extract_coverage_expectations(requirements)
    
    assert len(expectations.endpoints) == 2
    assert ("POST", "/api/v1/integrations/thirdparty/credentials") in expectations.endpoints
    assert ("GET", "/api/v1/integrations/thirdparty/credentials") in expectations.endpoints


def test_extract_endpoints_rejects_returns_as_path():
    """Test that 'POST returns 201' does NOT create endpoint 'returns'."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST returns 201 when successful"
        }
    ]
    
    expectations = extract_coverage_expectations(requirements)
    
    # Should NOT extract "returns" as an endpoint
    assert len(expectations.endpoints) == 0
    # But should extract status code
    assert 201 in expectations.status_codes


def test_extract_endpoints_only_accepts_paths_starting_with_slash():
    """Test that only paths starting with '/' are extracted."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/foo is valid"
        },
        {
            "id": "REQ-002",
            "description": "POST api/v1/foo is NOT extracted (no leading slash)"
        },
        {
            "id": "REQ-003",
            "description": "POST returns 201 is NOT extracted (no path)"
        }
    ]
    
    expectations = extract_coverage_expectations(requirements)
    
    # Only the first one should be extracted
    assert len(expectations.endpoints) == 1
    assert ("POST", "/api/v1/foo") in expectations.endpoints


def test_extract_authz_signals():
    """Test AuthZ signal extraction."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials (admin only) creates credentials"
        }
    ]
    
    expectations = extract_coverage_expectations(requirements)
    
    assert "POST /api/v1/integrations/thirdparty/credentials" in expectations.authz_signals


def test_extract_frontend_session_signals():
    """Test frontend session signal extraction."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "GET /api/v1/integrations/thirdparty/credentials (service-to-service; no frontend access)"
        }
    ]
    constraints = ["frontend session cannot access this endpoint"]
    
    expectations = extract_coverage_expectations(requirements, constraints)
    
    assert "GET /api/v1/integrations/thirdparty/credentials" in expectations.frontend_session_signals


def test_extract_secret_handling_signals():
    """Test secret handling signal extraction."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials returns 201 and never returns api_token"
        },
        {
            "id": "REQ-002",
            "description": "GET /api/v1/integrations/thirdparty/credentials returns 200 and api_token masked or omitted"
        }
    ]
    
    expectations = extract_coverage_expectations(requirements)
    
    assert "POST /api/v1/integrations/thirdparty/credentials" in expectations.secret_handling_signals
    assert "GET /api/v1/integrations/thirdparty/credentials" in expectations.secret_handling_signals


def test_extract_logging_constraints():
    """Test logging constraint extraction."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "API credentials must never be logged"
        }
    ]
    constraints = ["must never be logged"]
    
    expectations = extract_coverage_expectations(requirements, constraints)
    
    assert expectations.logging_constraints is True


def test_extract_encryption_at_rest():
    """Test encryption-at-rest signal extraction."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "Credentials must be encrypted at rest"
        }
    ]
    
    expectations = extract_coverage_expectations(requirements)
    
    assert expectations.encryption_at_rest is True


def test_enforce_coverage_adds_missing_authz():
    """Test that missing AuthZ 403 tests are added."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials (admin only) creates credentials"
        }
    ]
    
    # Draft plan missing AuthZ test
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Happy path: POST /api/v1/integrations/thirdparty/credentials",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": ["Send POST request", "Verify 201"],
                    "expected_result": "201 Created"
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Should add AuthZ 403 test
    negative_tests = result["test_plan"]["negative_tests"]
    authz_tests = [t for t in negative_tests if "AUTHZ" in t.get("id", "") and "403" in t.get("expected_result", "")]
    assert len(authz_tests) > 0
    assert any("403" in t.get("expected_result", "") for t in authz_tests)


def test_enforce_coverage_adds_missing_authn():
    """Test that missing AuthN 401 tests are added."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials requires authentication"
        }
    ]
    constraints = ["unauthenticated requests return 401"]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Happy path: POST /api/v1/integrations/thirdparty/credentials",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": ["Send POST request", "Verify 201"],
                    "expected_result": "201 Created"
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements, constraints)
    
    # Should add AuthN 401 test
    negative_tests = result["test_plan"]["negative_tests"]
    authn_tests = [t for t in negative_tests if "AUTHN" in t.get("id", "") and "401" in t.get("expected_result", "")]
    assert len(authn_tests) > 0


def test_enforce_coverage_adds_frontend_403():
    """Test that missing frontend session 403 tests are added."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "GET /api/v1/integrations/thirdparty/credentials (service-to-service only)"
        }
    ]
    constraints = ["frontend session cannot access this endpoint"]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Happy path: GET /api/v1/integrations/thirdparty/credentials",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": ["Send GET request", "Verify 200"],
                    "expected_result": "200 OK"
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements, constraints)
    
    # Should add frontend 403 test
    negative_tests = result["test_plan"]["negative_tests"]
    frontend_tests = [t for t in negative_tests if "FRONTEND" in t.get("id", "")]
    assert len(frontend_tests) > 0


def test_enforce_coverage_adds_secret_tests():
    """Test that missing secret handling tests are added."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials returns 201 and never returns api_token"
        }
    ]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Happy path: POST /api/v1/integrations/thirdparty/credentials",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": ["Send POST request", "Verify 201"],
                    "expected_result": "201 Created"
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Should add secret handling test
    negative_tests = result["test_plan"]["negative_tests"]
    secret_tests = [t for t in negative_tests if "SEC" in t.get("id", "") and ("NO_SECRET" in t.get("id", "") or "MASKED" in t.get("id", ""))]
    assert len(secret_tests) > 0


def test_enforce_coverage_adds_log_redaction_test():
    """Test that log redaction test is added when constraint present."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "API credentials must be handled securely"
        }
    ]
    constraints = ["must never be logged"]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements, constraints)
    
    # Should add SEC_LOG_REDACTION test
    negative_tests = result["test_plan"]["negative_tests"]
    log_tests = [t for t in negative_tests if t.get("id") == "SEC_LOG_REDACTION"]
    assert len(log_tests) == 1
    assert log_tests[0]["title"] == "Log redaction: Verify logs do not contain secrets"


def test_enforce_coverage_adds_encryption_test():
    """Test that encryption-at-rest test is added when constraint present."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "Credentials must be encrypted at rest"
        }
    ]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Should add SEC_ENCRYPTION_AT_REST test
    negative_tests = result["test_plan"]["negative_tests"]
    encryption_tests = [t for t in negative_tests if t.get("id") == "SEC_ENCRYPTION_AT_REST"]
    assert len(encryption_tests) == 1
    assert encryption_tests[0]["title"] == "Encryption at rest: Verify data is encrypted in storage"


def test_enforce_coverage_idempotent():
    """Test that running enforce_coverage_expectations twice does not add duplicates."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials (admin only) creates credentials"
        }
    ]
    constraints = ["must never be logged", "encrypted at rest"]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    # Run first time
    result1 = enforce_coverage_expectations(test_plan, requirements, constraints)
    negative_tests_count_1 = len(result1["test_plan"]["negative_tests"])
    test_ids_1 = {t.get("id") for t in result1["test_plan"]["negative_tests"]}
    
    # Run second time
    result2 = enforce_coverage_expectations(result1, requirements, constraints)
    negative_tests_count_2 = len(result2["test_plan"]["negative_tests"])
    test_ids_2 = {t.get("id") for t in result2["test_plan"]["negative_tests"]}
    
    # Should have same count and same IDs
    assert negative_tests_count_1 == negative_tests_count_2
    assert test_ids_1 == test_ids_2


def test_enforce_coverage_preserves_existing_tests():
    """Test that existing tests are never removed or modified."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials creates credentials"
        }
    ]
    
    existing_test = {
        "id": "API-001",
        "title": "Existing test",
        "source_requirement_id": "REQ-001",
        "intent_type": "happy_path",
        "requirements_covered": ["REQ-001"],
        "steps": ["Step 1", "Step 2"],
        "expected_result": "Success"
    }
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [existing_test],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Existing test should still be present
    api_tests = result["test_plan"]["api_tests"]
    existing_test_found = any(t.get("id") == "API-001" for t in api_tests)
    assert existing_test_found
    
    # Existing test should be unchanged
    found_test = next(t for t in api_tests if t.get("id") == "API-001")
    assert found_test["title"] == "Existing test"
    assert found_test["steps"] == ["Step 1", "Step 2"]


def test_deterministic_test_ids():
    """Test that generated test IDs are deterministic."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials (admin only)"
        }
    ]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result1 = enforce_coverage_expectations(test_plan, requirements)
    result2 = enforce_coverage_expectations(test_plan, requirements)
    
    # Test IDs should be identical
    test_ids_1 = {t.get("id") for t in result1["test_plan"]["negative_tests"]}
    test_ids_2 = {t.get("id") for t in result2["test_plan"]["negative_tests"]}
    
    assert test_ids_1 == test_ids_2


def test_no_tests_with_returns_or_endpoint_in_id():
    """Test that enforcer does NOT generate tests with 'returns' or 'endpoint' in ID/steps."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST returns 201 when successful"
        },
        {
            "id": "REQ-002",
            "description": "GET /api/v1/foo returns 200"
        }
    ]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Collect all test IDs and steps
    all_test_ids = []
    all_steps = []
    for category in ["api_tests", "negative_tests"]:
        tests = result["test_plan"].get(category, [])
        for test in tests:
            if isinstance(test, dict):
                test_id = test.get("id", "")
                steps = test.get("steps", [])
                if test_id:
                    all_test_ids.append(test_id)
                if steps:
                    all_steps.extend([str(s) for s in steps])
    
    # Verify no "returns" or "endpoint" in IDs
    for test_id in all_test_ids:
        assert "returns" not in test_id.lower(), f"Test ID contains 'returns': {test_id}"
        assert "endpoint" not in test_id.lower(), f"Test ID contains 'endpoint': {test_id}"
    
    # Verify no "returns" or "endpoint" as standalone words in steps (context is OK)
    all_steps_text = " ".join(all_steps).lower()
    # Check that we don't have "to returns" or "to endpoint" (invalid)
    assert " to returns" not in all_steps_text, "Steps contain 'to returns'"
    assert " to endpoint" not in all_steps_text, "Steps contain 'to endpoint'"


def test_dedup_only_one_authz_per_method_path():
    """Test that only ONE authz 403 test per method/path is added (no duplicates)."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials (admin only) creates credentials"
        }
    ]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Count AuthZ 403 tests for this endpoint
    negative_tests = result["test_plan"]["negative_tests"]
    authz_tests = [
        t for t in negative_tests 
        if "AUTHZ" in t.get("id", "") and 
        "POST" in t.get("id", "") and 
        "api_v1_integrations_thirdparty_credentials" in t.get("id", "") and
        "403" in t.get("expected_result", "")
    ]
    
    # Should have exactly ONE AuthZ 403 test (not frontend, just regular authz)
    regular_authz = [t for t in authz_tests if "FRONTEND" not in t.get("id", "")]
    assert len(regular_authz) == 1, f"Expected 1 AuthZ test, got {len(regular_authz)}: {[t.get('id') for t in regular_authz]}"
    
    # Run again to ensure idempotency (no duplicates)
    result2 = enforce_coverage_expectations(result, requirements)
    negative_tests2 = result2["test_plan"]["negative_tests"]
    authz_tests2 = [
        t for t in negative_tests2 
        if "AUTHZ" in t.get("id", "") and 
        "POST" in t.get("id", "") and 
        "api_v1_integrations_thirdparty_credentials" in t.get("id", "") and
        "403" in t.get("expected_result", "")
    ]
    regular_authz2 = [t for t in authz_tests2 if "FRONTEND" not in t.get("id", "")]
    assert len(regular_authz2) == 1, f"After second run, expected 1 AuthZ test, got {len(regular_authz2)}"


def test_no_redundant_happy_path_post_201():
    """Test that when API-001 already includes 'POST /path' and '201', enforcer does NOT add API_POST__{path}_201."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials creates credentials and returns 201"
        }
    ]
    
    # Existing test that already covers POST /api/v1/integrations/thirdparty/credentials with 201
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Create credentials",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": [
                        "Send POST request to /api/v1/integrations/thirdparty/credentials",
                        "Verify response status code is 201",
                        "Verify response body contains expected data"
                    ],
                    "expected_result": "Response status 201 Created with valid response body"
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Should NOT add API_POST__api_v1_integrations_thirdparty_credentials_201
    api_tests = result["test_plan"]["api_tests"]
    generated_tests = [t for t in api_tests if "API_POST__api_v1_integrations_thirdparty_credentials_201" in t.get("id", "")]
    assert len(generated_tests) == 0, f"Should not add redundant happy path test, but found: {[t.get('id') for t in generated_tests]}"
    
    # Original test should still be there
    original_tests = [t for t in api_tests if t.get("id") == "API-001"]
    assert len(original_tests) == 1, "Original test should be preserved"


def test_no_redundant_happy_path_get_200():
    """Test that when API-004 already includes 'GET /path' and '200', enforcer does NOT add API_GET__{path}_200."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "GET /api/v1/integrations/thirdparty/credentials returns credentials and returns 200"
        }
    ]
    
    # Existing test that already covers GET /api/v1/integrations/thirdparty/credentials with 200
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-004",
                    "title": "Get credentials",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": [
                        "Send GET request to /api/v1/integrations/thirdparty/credentials",
                        "Verify response status code is 200",
                        "Verify response body contains expected data"
                    ],
                    "expected_result": "Response status 200 OK with valid response body"
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Should NOT add API_GET__api_v1_integrations_thirdparty_credentials_200
    api_tests = result["test_plan"]["api_tests"]
    generated_tests = [t for t in api_tests if "API_GET__api_v1_integrations_thirdparty_credentials_200" in t.get("id", "")]
    assert len(generated_tests) == 0, f"Should not add redundant happy path test, but found: {[t.get('id') for t in generated_tests]}"
    
    # Original test should still be there
    original_tests = [t for t in api_tests if t.get("id") == "API-004"]
    assert len(original_tests) == 1, "Original test should be preserved"


def test_no_redundant_secret_handling_post():
    """Test that when an existing test already asserts 'no api_token' for POST, do NOT add SEC_POST__...NO_SECRET."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials returns 201 and never returns api_token"
        }
    ]
    
    # Existing test that already covers secret handling
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Create credentials without exposing token",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": [
                        "Send POST request to /api/v1/integrations/thirdparty/credentials",
                        "Verify response status code is 201",
                        "Verify response body does not contain 'api_token' field"
                    ],
                    "expected_result": "Response status 201 and no api_token in response"
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Should NOT add SEC_POST__...NO_SECRET
    negative_tests = result["test_plan"]["negative_tests"]
    secret_tests = [t for t in negative_tests if "SEC_POST" in t.get("id", "") and "NO_SECRET" in t.get("id", "")]
    assert len(secret_tests) == 0, f"Should not add redundant secret test, but found: {[t.get('id') for t in secret_tests]}"


def test_no_redundant_secret_handling_get():
    """Test that when an existing test already asserts 'masked or omitted' for GET, do NOT add SEC_GET__...MASKED."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "GET /api/v1/integrations/thirdparty/credentials returns 200 and api_token masked or omitted"
        }
    ]
    
    # Existing test that already covers secret handling
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Get credentials with masked token",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": [
                        "Send GET request to /api/v1/integrations/thirdparty/credentials",
                        "Verify response status code is 200",
                        "If response contains 'api_token' field, verify it is masked (e.g., '***' or 'REDACTED')"
                    ],
                    "expected_result": "Response status 200 and api_token masked or omitted"
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Should NOT add SEC_GET__...MASKED
    negative_tests = result["test_plan"]["negative_tests"]
    secret_tests = [t for t in negative_tests if "SEC_GET" in t.get("id", "") and "MASKED" in t.get("id", "")]
    assert len(secret_tests) == 0, f"Should not add redundant secret test, but found: {[t.get('id') for t in secret_tests]}"


def test_misclassified_authorization_test_annotation():
    """Test that when an authorization test is misclassified (authorization + 2xx + same steps as happy path), steps_explanation gets a warning."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials creates credentials"
        }
    ]
    
    # Create a happy path test
    happy_path_steps = [
        "Send POST request to /api/v1/integrations/thirdparty/credentials",
        "Verify response status code is 201",
        "Verify response body contains expected data"
    ]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Happy path: Create credentials",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": happy_path_steps,
                    "expected_result": "Response status 201 Created"
                },
                {
                    "id": "API-002",
                    "title": "Authorization: Create credentials",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "authorization",
                    "requirements_covered": ["REQ-001"],
                    "steps": happy_path_steps,  # Same steps as happy path
                    "expected_result": "Response status 201 Created"  # Success status
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Find the misclassified authorization test
    api_tests = result["test_plan"]["api_tests"]
    misclassified_test = next((t for t in api_tests if t.get("id") == "API-002"), None)
    
    assert misclassified_test is not None, "Misclassified test should still exist"
    assert "steps_explanation" in misclassified_test, "Misclassified test should have steps_explanation"
    assert "misclassified" in misclassified_test["steps_explanation"].lower(), "steps_explanation should mention misclassification"
    assert "review" in misclassified_test["steps_explanation"].lower(), "steps_explanation should suggest review"


def test_no_redundant_secret_post_when_already_covered():
    """Test that if API-001 already includes 'POST /path', '201', and 'api_token not included', enforcer does NOT add SEC_POST__..._NO_SECRET."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials creates credentials and returns 201"
        }
    ]
    
    # Existing test that already covers secret handling
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Create credentials without exposing token",
                    "source_requirement_id": "REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["REQ-001"],
                    "steps": [
                        "Send POST request to /api/v1/integrations/thirdparty/credentials",
                        "Verify response status code is 201",
                        "Verify response body does not contain 'api_token' field"
                    ],
                    "expected_result": "Response status 201 and api_token not included"
                }
            ],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Should NOT add SEC_POST__..._NO_SECRET
    negative_tests = result["test_plan"]["negative_tests"]
    secret_tests = [t for t in negative_tests if "SEC_POST" in t.get("id", "") and "NO_SECRET" in t.get("id", "")]
    assert len(secret_tests) == 0, f"Should not add redundant secret test, but found: {[t.get('id') for t in secret_tests]}"


def test_deterministic_get_test_includes_meaningful_assertions():
    """Test that when a deterministic GET 200 test is added, its steps include checks for base_url/client_id and api_token omitted/masked."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "GET /api/v1/integrations/thirdparty/credentials returns credentials"
        }
    ]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Find the generated GET test
    api_tests = result["test_plan"]["api_tests"]
    get_tests = [t for t in api_tests if "GET" in t.get("id", "") and "200" in t.get("id", "")]
    
    assert len(get_tests) > 0, "Should add a GET 200 test"
    
    get_test = get_tests[0]
    steps_text = " ".join(get_test.get("steps", [])).lower()
    expected_result = get_test.get("expected_result", "").lower()
    
    # Verify meaningful assertions are present
    assert "base_url" in steps_text or "base_url" in expected_result, "GET test should check for base_url"
    assert "client_id" in steps_text or "client_id" in expected_result, "GET test should check for client_id"
    assert "api_token" in steps_text or "api_token" in expected_result, "GET test should check for api_token"
    assert ("omitted" in steps_text or "masked" in steps_text or "omitted" in expected_result or "masked" in expected_result), \
        "GET test should assert api_token is omitted or masked"


def test_deterministic_post_test_includes_meaningful_assertions():
    """Test that when a deterministic POST 201 test is added, its steps include checks for status 201 and api_token not included."""
    requirements = [
        {
            "id": "REQ-001",
            "description": "POST /api/v1/integrations/thirdparty/credentials creates credentials and returns 201"
        }
    ]
    
    test_plan = {
        "requirements": requirements,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements)
    
    # Find the generated POST test
    api_tests = result["test_plan"]["api_tests"]
    post_tests = [t for t in api_tests if "POST" in t.get("id", "") and "201" in t.get("id", "")]
    
    assert len(post_tests) > 0, "Should add a POST 201 test"
    
    post_test = post_tests[0]
    steps_text = " ".join(post_test.get("steps", [])).lower()
    expected_result = post_test.get("expected_result", "").lower()
    
    # Verify meaningful assertions are present
    assert "201" in steps_text or "201" in expected_result, "POST test should check for status 201"
    assert "api_token" in steps_text or "api_token" in expected_result, "POST test should check for api_token"
    assert ("not" in steps_text and "api_token" in steps_text) or ("not included" in expected_result), \
        "POST test should assert api_token is NOT included"


def test_log_test_only_when_signal_present():
    """Test that SEC_LOG_REDACTION test only appears when requirement/constraints mention logging redaction."""
    # Test with logging signal
    requirements_with_logging = [
        {
            "id": "REQ-001",
            "description": "API credentials must never be logged"
        }
    ]
    constraints_with_logging = ["must never be logged"]
    
    test_plan = {
        "requirements": requirements_with_logging,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements_with_logging, constraints_with_logging)
    
    # Should add SEC_LOG_REDACTION
    negative_tests = result["test_plan"]["negative_tests"]
    log_tests = [t for t in negative_tests if t.get("id") == "SEC_LOG_REDACTION"]
    assert len(log_tests) == 1, "Should add SEC_LOG_REDACTION when logging signal present"
    
    # Test without logging signal
    requirements_without_logging = [
        {
            "id": "REQ-001",
            "description": "API credentials must be secure"
        }
    ]
    
    test_plan2 = {
        "requirements": requirements_without_logging,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result2 = enforce_coverage_expectations(test_plan2, requirements_without_logging)
    
    # Should NOT add SEC_LOG_REDACTION
    negative_tests2 = result2["test_plan"]["negative_tests"]
    log_tests2 = [t for t in negative_tests2 if t.get("id") == "SEC_LOG_REDACTION"]
    assert len(log_tests2) == 0, "Should NOT add SEC_LOG_REDACTION when logging signal absent"


def test_encryption_test_only_when_signal_present():
    """Test that SEC_ENCRYPTION_AT_REST test only appears when requirement/constraints mention encryption at rest."""
    # Test with encryption signal
    requirements_with_encryption = [
        {
            "id": "REQ-001",
            "description": "Credentials must be encrypted at rest"
        }
    ]
    
    test_plan = {
        "requirements": requirements_with_encryption,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result = enforce_coverage_expectations(test_plan, requirements_with_encryption)
    
    # Should add SEC_ENCRYPTION_AT_REST
    negative_tests = result["test_plan"]["negative_tests"]
    encryption_tests = [t for t in negative_tests if t.get("id") == "SEC_ENCRYPTION_AT_REST"]
    assert len(encryption_tests) == 1, "Should add SEC_ENCRYPTION_AT_REST when encryption signal present"
    
    # Test without encryption signal
    requirements_without_encryption = [
        {
            "id": "REQ-001",
            "description": "Credentials must be secure"
        }
    ]
    
    test_plan2 = {
        "requirements": requirements_without_encryption,
        "test_plan": {
            "api_tests": [],
            "negative_tests": []
        }
    }
    
    result2 = enforce_coverage_expectations(test_plan2, requirements_without_encryption)
    
    # Should NOT add SEC_ENCRYPTION_AT_REST
    negative_tests2 = result2["test_plan"]["negative_tests"]
    encryption_tests2 = [t for t in negative_tests2 if t.get("id") == "SEC_ENCRYPTION_AT_REST"]
    assert len(encryption_tests2) == 0, "Should NOT add SEC_ENCRYPTION_AT_REST when encryption signal absent"
