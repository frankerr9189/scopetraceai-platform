"""
Deterministic coverage expectation enforcement post-pass.

This module adds missing test coverage based on extracted expectations
from requirement text and constraints. It never removes or edits existing tests.
"""
import re
from typing import Dict, List, Any, Set, Tuple, Optional


class CoverageExpectations:
    """Extracted coverage expectations from requirements."""
    
    def __init__(self):
        self.endpoints: List[Tuple[str, str]] = []  # (method, path)
        self.status_codes: Set[int] = set()
        self.authn_signals: Set[str] = set()  # endpoint paths needing 401
        self.authz_signals: Set[str] = set()  # endpoint paths needing 403
        self.frontend_session_signals: Set[str] = set()  # endpoint paths needing frontend 403
        self.secret_handling_signals: Set[str] = set()  # endpoint paths with secret handling
        self.logging_constraints: bool = False
        self.encryption_at_rest: bool = False


def extract_coverage_expectations(
    requirements: List[Dict[str, Any]],
    constraints: Optional[List[str]] = None
) -> CoverageExpectations:
    """
    Extract coverage expectations from requirement text and constraints.
    
    Uses simple pattern matching (case-insensitive) to detect:
    - Endpoint patterns (GET /path, POST /path, etc.)
    - Status codes
    - AuthN/AuthZ signals
    - Secret handling signals
    - Security constraints
    
    Args:
        requirements: List of requirement dictionaries with 'description' field
        constraints: Optional list of constraint strings
        
    Returns:
        CoverageExpectations object with extracted signals
    """
    expectations = CoverageExpectations()
    
    # Combine all requirement text and constraints
    all_text = []
    for req in requirements:
        if isinstance(req, dict):
            desc = req.get("description", "")
            if desc:
                all_text.append(desc.lower())
    
    if constraints:
        for constraint in constraints:
            if constraint:
                all_text.append(constraint.lower())
    
    combined_text = " ".join(all_text)
    
    # Extract endpoints: ONLY accept method + path that MUST start with "/"
    # Pattern: (GET|POST|PUT|DELETE|PATCH) followed by whitespace then a path starting with "/"
    endpoint_pattern = r'\b(GET|POST|PUT|DELETE|PATCH)\s+(/[\w\-\./]+)'
    matches = re.finditer(endpoint_pattern, combined_text, re.IGNORECASE)
    for match in matches:
        method = match.group(1).upper()
        path = match.group(2)
        # Only add if path starts with "/" (pattern should ensure this, but double-check)
        if path.startswith("/"):
            expectations.endpoints.append((method, path))
    
    # Extract status codes from phrases like "returns 201", "returns a 200", "response status 403"
    # Decouple from endpoint extraction - these are status expectations only
    status_code_patterns = [
        r'returns\s+(?:a\s+)?(\d{3})',  # "returns 201" or "returns a 200"
        r'response\s+status\s+(\d{3})',  # "response status 403"
        r'status\s+code\s+(\d{3})',      # "status code 200"
        r'status\s+(\d{3})',             # "status 201"
        r'\b(200|201|400|401|403|404|409|422|500)\b'  # Standalone status codes
    ]
    for pattern in status_code_patterns:
        status_matches = re.finditer(pattern, combined_text, re.IGNORECASE)
        for match in status_matches:
            code = int(match.group(1))
            if 200 <= code <= 599:  # Valid HTTP status code range
                expectations.status_codes.add(code)
    
    # Extract AuthN signals (need 401 test)
    authn_keywords = ["unauthenticated", "missing authentication", "401"]
    for keyword in authn_keywords:
        if keyword in combined_text:
            # Find associated endpoints
            for method, path in expectations.endpoints:
                expectations.authn_signals.add(f"{method} {path}")
    
    # Extract AuthZ signals (need 403 test)
    authz_keywords = [
        "admin only", "admin-only", "restricted", "role-based", "rbac",
        "service-to-service", "forbidden", "403"
    ]
    for keyword in authz_keywords:
        if keyword in combined_text:
            # Find associated endpoints
            for method, path in expectations.endpoints:
                expectations.authz_signals.add(f"{method} {path}")
    
    # Extract frontend session signals
    if "frontend session" in combined_text:
        for method, path in expectations.endpoints:
            expectations.frontend_session_signals.add(f"{method} {path}")
    
    # Extract secret handling signals
    secret_keywords = [
        "api_token", "token", "secret", "never returned", "not returned",
        "masked", "omitted", "redact"
    ]
    for keyword in secret_keywords:
        if keyword in combined_text:
            # Find associated endpoints
            for method, path in expectations.endpoints:
                expectations.secret_handling_signals.add(f"{method} {path}")
    
    # Extract logging constraints
    logging_keywords = ["must never be logged", "never be logged", "do not log"]
    for keyword in logging_keywords:
        if keyword in combined_text:
            expectations.logging_constraints = True
            break
    
    # Extract encryption-at-rest signals
    encryption_keywords = ["encrypted at rest", "encrypt at rest", "encryption at rest"]
    for keyword in encryption_keywords:
        if keyword in combined_text:
            expectations.encryption_at_rest = True
            break
    
    return expectations


def get_existing_test_coverage(test_plan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract existing test coverage from test plan.
    
    Returns a dictionary mapping:
    - "endpoints" -> set of endpoint strings (method + path)
    - "authn_tests" -> set of endpoint strings with 401 tests
    - "authz_tests" -> set of endpoint strings with 403 tests
    - "frontend_403_tests" -> set of endpoint strings with frontend 403 tests
    - "secret_tests" -> set of endpoint strings with secret handling tests
    - "log_redaction_test" -> bool (has SEC_LOG_REDACTION test)
    - "encryption_test" -> bool (has SEC_ENCRYPTION_AT_REST test)
    - "happy_path_coverage" -> set of (method, path, status) tuples for existing happy path tests
    - "secret_coverage" -> dict mapping (method, path) -> coverage type ("no_secret" for POST, "masked" for GET)
    
    Args:
        test_plan: Test plan dictionary with test categories
        
    Returns:
        Dictionary of coverage sets
    """
    coverage = {
        "endpoints": set(),
        "authn_tests": set(),
        "authz_tests": set(),
        "frontend_403_tests": set(),
        "secret_tests": set(),
        "log_redaction_test": False,
        "encryption_test": False,
        "happy_path_coverage": set(),  # (method, path, status) tuples
        "secret_coverage": {}  # (method, path) -> "no_secret" or "masked"
    }
    
    # Collect all tests from all categories
    all_tests = []
    test_plan_dict = test_plan.get("test_plan", {})
    for category in ["api_tests", "ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]:
        tests = test_plan_dict.get(category, [])
        if isinstance(tests, list):
            all_tests.extend(tests)
    
    # Extract endpoint references and test types
    for test in all_tests:
        if not isinstance(test, dict):
            continue
        
        test_id = test.get("id", "")
        title = test.get("title", "").lower()
        steps = test.get("steps", [])
        expected_result = test.get("expected_result", "").lower()
        intent_type = test.get("intent_type", "")
        
        # Check for security test IDs
        if test_id == "SEC_LOG_REDACTION":
            coverage["log_redaction_test"] = True
        if test_id == "SEC_ENCRYPTION_AT_REST":
            coverage["encryption_test"] = True
        
        # Extract endpoint references from steps and expected_result
        # Use stricter pattern: only paths starting with "/"
        endpoint_pattern = r'\b(GET|POST|PUT|DELETE|PATCH)\s+(/[\w\-\./]+)'
        all_text = " ".join([str(s) for s in steps]) + " " + expected_result
        
        matches = re.finditer(endpoint_pattern, all_text, re.IGNORECASE)
        for match in matches:
            method = match.group(1).upper()
            path = match.group(2)
            if not path.startswith("/"):
                continue
            endpoint_key = f"{method} {path}"
            coverage["endpoints"].add(endpoint_key)
            
            # Extract status code from expected_result
            status_match = re.search(r'\b(200|201|400|401|403|404|409|422|500)\b', expected_result)
            status = status_match.group(1) if status_match else None
            
            # Check for happy path coverage (method + path + status)
            if intent_type == "happy_path" or "happy" in title:
                if status:
                    coverage["happy_path_coverage"].add((method, path, status))
                else:
                    # Default to 200 if no status specified
                    coverage["happy_path_coverage"].add((method, path, "200"))
            
            # Check for auth tests
            if "401" in expected_result or "unauthorized" in expected_result or "unauthenticated" in expected_result:
                coverage["authn_tests"].add(endpoint_key)
            
            if "403" in expected_result or "forbidden" in expected_result:
                if "frontend" in title or "frontend" in all_text.lower():
                    coverage["frontend_403_tests"].add(endpoint_key)
                else:
                    coverage["authz_tests"].add(endpoint_key)
            
            # Check for secret handling tests - more specific detection
            # For POST: check if test asserts api_token/token/secret is NOT included/returned
            secret_keywords_no_return = [
                "no api_token", "does not contain api_token", "excludes api_token", 
                "not returned", "never returned", "excludes token", "does not contain token",
                "api_token not included", "token not included", "secret not included",
                "api_token not in", "token not in", "secret not in",
                "response does not include api_token", "response does not include token",
                "response does not include secret"
            ]
            # For GET: check if test asserts api_token/token/secret is masked/omitted/redacted
            secret_keywords_masked = [
                "masked", "omitted", "redacted", "api_token masked", "token masked",
                "api_token omitted", "token omitted", "api_token redacted", "token redacted",
                "api_token is masked", "token is masked", "api_token is omitted", "token is omitted",
                "masked or omitted", "omitted or masked"
            ]
            
            # Check for POST secret handling (no secret returned)
            # Check in both steps and expected_result
            if method == "POST":
                if any(keyword in all_text for keyword in secret_keywords_no_return):
                    coverage["secret_coverage"][(method, path)] = "no_secret"
                    coverage["secret_tests"].add(endpoint_key)
            
            # Check for GET secret handling (masked/omitted)
            if method == "GET":
                if any(keyword in all_text for keyword in secret_keywords_masked + secret_keywords_no_return):
                    coverage["secret_coverage"][(method, path)] = "masked"
                    coverage["secret_tests"].add(endpoint_key)
    
    return coverage


def generate_deterministic_test_id(
    method: str,
    path: str,
    dimension: str,
    status: Optional[str] = None
) -> str:
    """
    Generate deterministic test ID.
    
    Format:
    - API tests: API_{METHOD}__{path_normalized}_{status}
    - AuthN tests: AUTHN_{METHOD}__{path_normalized}_401
    - AuthZ tests: AUTHZ_{METHOD}__{path_normalized}_403
    - Frontend 403: AUTHZ_{METHOD}__{path_normalized}_FRONTEND_403
    - Security tests: SEC_{dimension}
    
    Args:
        method: HTTP method (GET, POST, etc.)
        path: API path
        dimension: Test dimension (e.g., "LOG_REDACTION", "ENCRYPTION_AT_REST")
        status: Optional status code
        
    Returns:
        Deterministic test ID string
    """
    # Validate path starts with "/"
    if not path.startswith("/"):
        raise ValueError(f"Invalid endpoint path: {path} (must start with '/')")
    
    # Normalize path: replace / with _, remove leading /
    normalized_path = path.lstrip("/").replace("/", "_").replace("-", "_")
    
    # Remove any invalid characters that might have been parsed incorrectly
    normalized_path = re.sub(r'[^a-zA-Z0-9_]', '', normalized_path)
    
    if dimension == "LOG_REDACTION":
        return "SEC_LOG_REDACTION"
    if dimension == "ENCRYPTION_AT_REST":
        return "SEC_ENCRYPTION_AT_REST"
    
    if dimension == "AUTHN":
        return f"AUTHN_{method}__{normalized_path}_401"
    if dimension == "AUTHZ":
        if status == "FRONTEND":
            return f"AUTHZ_{method}__{normalized_path}_FRONTEND_403"
        return f"AUTHZ_{method}__{normalized_path}_403"
    
    # Happy path or generic API test
    status_str = status or "200"
    return f"API_{method}__{normalized_path}_{status_str}"


def create_happy_path_test(
    method: str,
    path: str,
    status_code: int,
    requirement_id: str
) -> Dict[str, Any]:
    """
    Create deterministic happy path test with meaningful assertions.
    
    For GET 200: includes checks for base_url/client_id presence and api_token omitted/masked
    For POST 201: includes checks for status 201 and api_token not included
    
    Args:
        method: HTTP method
        path: API path
        status_code: Expected status code
        requirement_id: Requirement ID to cover
        
    Returns:
        Test case dictionary
    """
    test_id = generate_deterministic_test_id(method, path, "HAPPY", str(status_code))
    
    if method == "GET" and status_code == 200:
        # GET 200 test with meaningful assertions
        steps = [
            f"Send GET request to {path}",
            f"Verify response status code is {status_code}",
            "Verify response body contains 'base_url' field",
            "Verify response body contains 'client_id' field",
            "Verify response body does NOT contain 'api_token' field (or if present, it is masked/omitted)",
            "Verify response body does NOT contain 'token' field (or if present, it is masked/omitted)",
            "Verify response body does NOT contain 'secret' field (or if present, it is masked/omitted)"
        ]
        expected_result = f"Response status {status_code} with base_url and client_id present, and api_token/token/secret omitted or masked"
    elif method == "POST" and status_code == 201:
        # POST 201 test with meaningful assertions
        steps = [
            f"Send POST request to {path}",
            f"Verify response status code is {status_code}",
            "Verify response body does NOT contain 'api_token' field",
            "Verify response body does NOT contain 'token' field",
            "Verify response body does NOT contain 'secret' field",
            "Verify response body contains expected data"
        ]
        expected_result = f"Response status {status_code} with valid response body and api_token/token/secret NOT included"
    else:
        # Generic happy path for other methods/status codes
        steps = [
            f"Send {method} request to {path}",
            f"Verify response status code is {status_code}",
            "Verify response body contains expected data"
        ]
        expected_result = f"Response status {status_code} with valid response body"
    
    return {
        "id": test_id,
        "title": f"Happy path: {method} {path} returns {status_code}",
        "source_requirement_id": requirement_id,
        "intent_type": "happy_path",
        "requirements_covered": [requirement_id],
        "steps": steps,
        "steps_origin": "deterministic-postpass",
        "expected_result": expected_result,
        "priority": "medium",
        "confidence": "explicit"
    }


def create_authn_test(
    method: str,
    path: str,
    requirement_id: str
) -> Dict[str, Any]:
    """
    Create deterministic authentication (401) test.
    
    Args:
        method: HTTP method
        path: API path
        requirement_id: Requirement ID to cover
        
    Returns:
        Test case dictionary
    """
    test_id = generate_deterministic_test_id(method, path, "AUTHN")
    
    return {
        "id": test_id,
        "title": f"Authentication required: {method} {path} returns 401 when unauthenticated",
        "source_requirement_id": requirement_id,
        "intent_type": "authorization",
        "requirements_covered": [requirement_id],
        "steps": [
            f"Send {method} request to {path} without authentication token",
            "Verify response status code is 401",
            "Verify response indicates authentication is required"
        ],
        "steps_origin": "deterministic-postpass",
        "expected_result": "Response status 401 Unauthorized",
        "priority": "high",
        "confidence": "explicit"
    }


def create_authz_test(
    method: str,
    path: str,
    requirement_id: str,
    is_frontend: bool = False
) -> Dict[str, Any]:
    """
    Create deterministic authorization (403) test.
    
    Args:
        method: HTTP method
        path: API path
        requirement_id: Requirement ID to cover
        is_frontend: If True, create frontend session 403 test
        
    Returns:
        Test case dictionary
    """
    if is_frontend:
        test_id = generate_deterministic_test_id(method, path, "AUTHZ", "FRONTEND")
        title = f"Frontend session forbidden: {method} {path} returns 403 for frontend session"
        steps = [
            f"Authenticate as frontend session user",
            f"Send {method} request to {path}",
            "Verify response status code is 403",
            "Verify response indicates access is forbidden for frontend sessions"
        ]
    else:
        test_id = generate_deterministic_test_id(method, path, "AUTHZ")
        title = f"Authorization required: {method} {path} returns 403 when not authorized"
        steps = [
            f"Authenticate as non-admin user",
            f"Send {method} request to {path}",
            "Verify response status code is 403",
            "Verify response indicates insufficient permissions"
        ]
    
    return {
        "id": test_id,
        "title": title,
        "source_requirement_id": requirement_id,
        "intent_type": "authorization",
        "requirements_covered": [requirement_id],
        "steps": steps,
        "steps_origin": "deterministic-postpass",
        "expected_result": "Response status 403 Forbidden",
        "priority": "high",
        "confidence": "explicit"
    }


def create_secret_handling_test(
    method: str,
    path: str,
    requirement_id: str
) -> Dict[str, Any]:
    """
    Create deterministic secret handling test.
    
    Args:
        method: HTTP method
        path: API path
        requirement_id: Requirement ID to cover
        
    Returns:
        Test case dictionary
    """
    if method == "POST":
        test_id = f"SEC_POST__{path.lstrip('/').replace('/', '_').replace('-', '_')}_NO_SECRET"
        title = f"Secret not returned: POST {path} response excludes api_token"
        steps = [
            f"Send POST request to {path}",
            "Verify response status code is 200 or 201",
            "Verify response body does not contain 'api_token' field",
            "Verify response body does not contain 'token' field",
            "Verify response body does not contain 'secret' field"
        ]
        expected_result = "Response does not contain api_token, token, or secret fields"
    else:  # GET
        test_id = f"SEC_GET__{path.lstrip('/').replace('/', '_').replace('-', '_')}_MASKED"
        title = f"Secret masked: GET {path} response masks or omits api_token"
        steps = [
            f"Send GET request to {path}",
            "Verify response status code is 200",
            "If response contains 'api_token' field, verify it is masked (e.g., '***' or 'REDACTED')",
            "If response contains 'token' field, verify it is masked or omitted",
            "Verify no secret values are exposed in plain text"
        ]
        expected_result = "Response masks or omits api_token and token fields"
    
    return {
        "id": test_id,
        "title": title,
        "source_requirement_id": requirement_id,
        "intent_type": "security",
        "requirements_covered": [requirement_id],
        "steps": steps,
        "steps_origin": "deterministic-postpass",
        "expected_result": expected_result,
        "priority": "high",
        "confidence": "explicit"
    }


def create_log_redaction_test(requirement_id: str) -> Dict[str, Any]:
    """
    Create deterministic log redaction security test.
    
    Args:
        requirement_id: Requirement ID to cover
        
    Returns:
        Test case dictionary
    """
    return {
        "id": "SEC_LOG_REDACTION",
        "title": "Log redaction: Verify logs do not contain secrets",
        "source_requirement_id": requirement_id,
        "intent_type": "security",
        "requirements_covered": [requirement_id],
        "steps": [
            "Perform operations that generate log entries",
            "Inspect application logs",
            "Verify logs do not contain 'api_token' in plain text",
            "Verify logs do not contain 'token' in plain text",
            "Verify logs do not contain 'secret' in plain text",
            "Verify any secret values are redacted (e.g., '***' or 'REDACTED')"
        ],
        "steps_origin": "deterministic-postpass",
        "expected_result": "Logs do not contain api_token, token, or secret in plain text",
        "priority": "high",
        "confidence": "explicit"
    }


def create_encryption_at_rest_test(requirement_id: str) -> Dict[str, Any]:
    """
    Create deterministic encryption-at-rest security test.
    
    Args:
        requirement_id: Requirement ID to cover
        
    Returns:
        Test case dictionary
    """
    return {
        "id": "SEC_ENCRYPTION_AT_REST",
        "title": "Encryption at rest: Verify data is encrypted in storage",
        "source_requirement_id": requirement_id,
        "intent_type": "security",
        "requirements_covered": [requirement_id],
        "steps": [
            "Store sensitive data through the application",
            "Inspect storage layer (database, file system, etc.)",
            "Verify stored data is encrypted",
            "Verify encryption keys are properly managed",
            "Verify plain text data is not accessible in storage"
        ],
        "steps_origin": "deterministic-postpass",
        "expected_result": "Data is encrypted at rest and plain text is not accessible",
        "priority": "high",
        "confidence": "explicit"
    }


def enforce_coverage_expectations(
    test_plan: Dict[str, Any],
    requirements: List[Dict[str, Any]],
    constraints: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Enforce coverage expectations by adding missing tests.
    
    This function:
    1. Extracts expectations from requirements and constraints
    2. Detects missing coverage dimensions
    3. Adds deterministic templated tests to fill gaps
    4. Never removes or edits existing tests
    5. Produces stable deterministic IDs
    
    Args:
        test_plan: Test plan dictionary (will be modified in-place)
        requirements: List of requirement dictionaries
        constraints: Optional list of constraint strings
        
    Returns:
        Modified test plan dictionary (same object, modified in-place)
    """
    if not requirements:
        return test_plan
    
    # Extract expectations
    expectations = extract_coverage_expectations(requirements, constraints)
    
    # Get existing coverage
    existing_coverage = get_existing_test_coverage(test_plan)
    
    # Get first requirement ID for tests that don't map to specific endpoints
    first_req_id = requirements[0].get("id", "REQ-001") if requirements else "REQ-001"
    
    # Collect tests to add
    tests_to_add = {
        "api_tests": [],
        "negative_tests": []
    }
    
    # Track added test IDs to prevent duplicates
    added_test_ids: Set[str] = set()
    
    # Get all existing test IDs to avoid duplicates
    test_plan_dict = test_plan.get("test_plan", {})
    for category in ["api_tests", "ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]:
        tests = test_plan_dict.get(category, [])
        if isinstance(tests, list):
            for test in tests:
                if isinstance(test, dict):
                    test_id = test.get("id", "")
                    if test_id:
                        added_test_ids.add(test_id)
    
    # Build deduplication key set for existing tests
    # Key format: (intent_type, method, path, expected_status, frontend_session_flag, security_dimension)
    existing_test_keys: Set[Tuple[str, str, str, str, bool, Optional[str]]] = set()
    test_plan_dict = test_plan.get("test_plan", {})
    for category in ["api_tests", "ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]:
        tests = test_plan_dict.get(category, [])
        if isinstance(tests, list):
            for test in tests:
                if not isinstance(test, dict):
                    continue
                intent_type = test.get("intent_type", "")
                test_id = test.get("id", "")
                title = test.get("title", "").lower()
                expected_result = test.get("expected_result", "").lower()
                
                # Extract method and path from test (if present)
                method = None
                path = None
                status = None
                is_frontend = "frontend" in title or "frontend" in expected_result
                security_dim = None
                
                # Parse from test ID or title/steps
                if "AUTHN" in test_id:
                    security_dim = "AUTHN"
                elif "AUTHZ" in test_id:
                    security_dim = "AUTHZ"
                elif "SEC_LOG" in test_id:
                    security_dim = "LOG_REDACTION"
                elif "SEC_ENCRYPTION" in test_id:
                    security_dim = "ENCRYPTION_AT_REST"
                elif "SEC_" in test_id:
                    security_dim = "SECRET"
                
                # Try to extract method/path from ID or content
                id_parts = test_id.split("__")
                if len(id_parts) >= 2:
                    method_part = id_parts[0].split("_")[-1] if "_" in id_parts[0] else None
                    path_part = id_parts[1].split("_")[0] if len(id_parts) > 1 else None
                    if method_part and method_part in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        method = method_part
                    if path_part:
                        # Reconstruct path from normalized form
                        path = "/" + path_part.replace("_", "/")
                
                # Extract status from expected_result
                status_match = re.search(r'\b(200|201|400|401|403|404|409|422|500)\b', expected_result)
                if status_match:
                    status = status_match.group(1)
                
                if method and path:
                    key = (intent_type or "unknown", method, path, status or "unknown", is_frontend, security_dim)
                    existing_test_keys.add(key)
    
    # 1. Ensure happy path tests for each endpoint (only if endpoints were explicitly extracted)
    for method, path in expectations.endpoints:
        # Skip if path doesn't start with "/" (shouldn't happen, but safety check)
        if not path.startswith("/"):
            continue
        
        endpoint_key = f"{method} {path}"
        status_code = 200  # Default
        if expectations.status_codes:
            # Prefer 201 for POST, 200 for others
            if method == "POST" and 201 in expectations.status_codes:
                status_code = 201
            elif 200 in expectations.status_codes:
                status_code = 200
            else:
                status_code = min(expectations.status_codes)
        
        # Check if happy path already exists with same method+path+status
        if (method, path, str(status_code)) in existing_coverage["happy_path_coverage"]:
            continue
        
        # Check deduplication key
        dedup_key = ("happy_path", method, path, str(status_code), False, None)
        if dedup_key in existing_test_keys:
            continue
        
        # Also check if test ID already exists
        test_id = generate_deterministic_test_id(method, path, "HAPPY", str(status_code))
        if test_id not in added_test_ids:
            # Verify test doesn't contain "returns" or "endpoint" in ID or steps
            if "returns" not in test_id.lower() and "endpoint" not in test_id.lower():
                test = create_happy_path_test(method, path, status_code, first_req_id)
                tests_to_add["api_tests"].append(test)
                added_test_ids.add(test_id)
                existing_test_keys.add(dedup_key)
    
    # 2. Add AuthN 401 tests (only for explicitly extracted endpoints)
    for endpoint_key in expectations.authn_signals:
        if endpoint_key not in existing_coverage["authn_tests"]:
            # Parse method and path
            parts = endpoint_key.split(" ", 1)
            if len(parts) == 2:
                method, path = parts
                # Only process if path starts with "/" (valid endpoint)
                if path.startswith("/"):
                    dedup_key = ("authorization", method, path, "401", False, "AUTHN")
                    if dedup_key not in existing_test_keys:
                        test_id = generate_deterministic_test_id(method, path, "AUTHN")
                        if test_id not in added_test_ids and "returns" not in test_id.lower():
                            test = create_authn_test(method, path, first_req_id)
                            tests_to_add["negative_tests"].append(test)
                            added_test_ids.add(test_id)
                            existing_test_keys.add(dedup_key)
    
    # 3. Add AuthZ 403 tests (only for explicitly extracted endpoints)
    for endpoint_key in expectations.authz_signals:
        if endpoint_key not in existing_coverage["authz_tests"]:
            parts = endpoint_key.split(" ", 1)
            if len(parts) == 2:
                method, path = parts
                # Only process if path starts with "/" (valid endpoint)
                if path.startswith("/"):
                    dedup_key = ("authorization", method, path, "403", False, "AUTHZ")
                    if dedup_key not in existing_test_keys:
                        test_id = generate_deterministic_test_id(method, path, "AUTHZ")
                        if test_id not in added_test_ids and "returns" not in test_id.lower():
                            test = create_authz_test(method, path, first_req_id, is_frontend=False)
                            tests_to_add["negative_tests"].append(test)
                            added_test_ids.add(test_id)
                            existing_test_keys.add(dedup_key)
    
    # 4. Add frontend session 403 tests (only for explicitly extracted endpoints)
    for endpoint_key in expectations.frontend_session_signals:
        if endpoint_key not in existing_coverage["frontend_403_tests"]:
            parts = endpoint_key.split(" ", 1)
            if len(parts) == 2:
                method, path = parts
                # Only process if path starts with "/" (valid endpoint)
                if path.startswith("/"):
                    dedup_key = ("authorization", method, path, "403", True, "AUTHZ")
                    if dedup_key not in existing_test_keys:
                        test_id = generate_deterministic_test_id(method, path, "AUTHZ", "FRONTEND")
                        if test_id not in added_test_ids and "returns" not in test_id.lower():
                            test = create_authz_test(method, path, first_req_id, is_frontend=True)
                            tests_to_add["negative_tests"].append(test)
                            added_test_ids.add(test_id)
                            existing_test_keys.add(dedup_key)
    
    # 5. Add secret handling tests (only for explicitly extracted endpoints)
    for endpoint_key in expectations.secret_handling_signals:
        parts = endpoint_key.split(" ", 1)
        if len(parts) == 2:
            method, path = parts
            # Only process if path starts with "/" (valid endpoint)
            if path.startswith("/"):
                # Check if secret handling already covered
                secret_coverage_type = existing_coverage["secret_coverage"].get((method, path))
                if method == "POST" and secret_coverage_type == "no_secret":
                    continue  # Already covered
                if method == "GET" and secret_coverage_type == "masked":
                    continue  # Already covered
                
                if endpoint_key not in existing_coverage["secret_tests"]:
                    test_id = f"SEC_{method}__{path.lstrip('/').replace('/', '_').replace('-', '_')}"
                    if method == "POST":
                        test_id += "_NO_SECRET"
                    else:
                        test_id += "_MASKED"
                    
                    dedup_key = ("security", method, path, "unknown", False, "SECRET")
                    if dedup_key not in existing_test_keys and test_id not in added_test_ids:
                        if "returns" not in test_id.lower() and "endpoint" not in test_id.lower():
                            test = create_secret_handling_test(method, path, first_req_id)
                            tests_to_add["negative_tests"].append(test)
                            added_test_ids.add(test_id)
                            existing_test_keys.add(dedup_key)
    
    # 6. Add log redaction test
    if expectations.logging_constraints and not existing_coverage["log_redaction_test"]:
        if "SEC_LOG_REDACTION" not in added_test_ids:
            test = create_log_redaction_test(first_req_id)
            tests_to_add["negative_tests"].append(test)
            added_test_ids.add("SEC_LOG_REDACTION")
    
    # 7. Add encryption-at-rest test
    if expectations.encryption_at_rest and not existing_coverage["encryption_test"]:
        if "SEC_ENCRYPTION_AT_REST" not in added_test_ids:
            test = create_encryption_at_rest_test(first_req_id)
            tests_to_add["negative_tests"].append(test)
            added_test_ids.add("SEC_ENCRYPTION_AT_REST")
    
    # Validate and annotate misclassified authorization tests
    validate_misclassified_authorization_tests(test_plan)
    
    # Append new tests to test plan (never remove or edit existing)
    if not test_plan.get("test_plan"):
        test_plan["test_plan"] = {}
    
    test_plan_dict = test_plan["test_plan"]
    
    # Append API tests
    if tests_to_add["api_tests"]:
        if "api_tests" not in test_plan_dict:
            test_plan_dict["api_tests"] = []
        test_plan_dict["api_tests"].extend(tests_to_add["api_tests"])
    
    # Append negative tests (auth and security tests go here)
    if tests_to_add["negative_tests"]:
        if "negative_tests" not in test_plan_dict:
            test_plan_dict["negative_tests"] = []
        test_plan_dict["negative_tests"].extend(tests_to_add["negative_tests"])
    
    return test_plan


def validate_misclassified_authorization_tests(test_plan: Dict[str, Any]) -> None:
    """
    Flag misclassified authorization tests without editing them.
    
    A test is misclassified if:
    - intent_type == "authorization"
    - expected_result implies success (2xx status)
    - steps are identical to a happy-path test
    
    Adds steps_explanation field with deterministic warning.
    
    Args:
        test_plan: Test plan dictionary (modified in-place)
    """
    test_plan_dict = test_plan.get("test_plan", {})
    
    # Collect all happy path tests to compare against
    happy_path_tests = []
    for category in ["api_tests", "ui_tests"]:
        tests = test_plan_dict.get(category, [])
        if isinstance(tests, list):
            for test in tests:
                if isinstance(test, dict):
                    intent_type = test.get("intent_type", "")
                    if intent_type == "happy_path" or "happy" in test.get("title", "").lower():
                        steps = tuple(test.get("steps", []))
                        happy_path_tests.append(steps)
    
    # Check all tests for misclassification
    for category in ["api_tests", "ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]:
        tests = test_plan_dict.get(category, [])
        if isinstance(tests, list):
            for test in tests:
                if not isinstance(test, dict):
                    continue
                
                intent_type = test.get("intent_type", "")
                expected_result = test.get("expected_result", "").lower()
                steps = tuple(test.get("steps", []))
                
                # Check if this is an authorization test with success status
                if intent_type == "authorization":
                    # Check if expected_result implies success (2xx)
                    success_pattern = r'\b(200|201|202|204)\b'
                    if re.search(success_pattern, expected_result):
                        # Check if steps match a happy path test
                        if steps in happy_path_tests:
                            # Add deterministic warning annotation
                            warning = "This test is labeled as 'authorization' but expects success (2xx) and has steps identical to a happy-path test. It may be misclassified and should be reviewed."
                            if "steps_explanation" not in test:
                                test["steps_explanation"] = warning
                            elif warning not in test.get("steps_explanation", ""):
                                # Append if explanation already exists
                                test["steps_explanation"] = f"{test['steps_explanation']} {warning}"
