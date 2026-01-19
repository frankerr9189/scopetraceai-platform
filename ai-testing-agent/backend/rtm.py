def generate_rtm(test_plan_json: dict) -> list:
    """
    Generate Requirement Traceability Matrix (RTM) from test plan JSON.
    
    ITEM-FIRST IMPLEMENTATION:
    - Iterates over ticket_breakdown.items first (primary source of truth)
    - Every breakdown item produces exactly one RTM row
    - Non-testable and unmapped items are included
    - Requirement-based generation is fallback only
    
    Args:
        test_plan_json: The complete test plan JSON structure
    
    Returns:
        list: RTM entries, each containing:
        - requirement_id (item_id for breakdown items)
        - requirement_description (item text)
        - covered_by_tests (list of test IDs)
        - coverage_status (COVERED, NOT COVERED, NOT_TESTABLE)
    """
    rtm = []
    
    # Collect all tests across categories
    test_plan = test_plan_json.get("test_plan", {})
    all_tests = []
    for category in test_plan.values():
        if isinstance(category, list):
            all_tests.extend(category)
    
    # Build test map by requirement ID for quick lookup
    tests_by_req = {}
    for test in all_tests:
        if isinstance(test, dict):
            test_id = test.get("id", "")
            requirements_covered = test.get("requirements_covered", [])
            if test_id and isinstance(requirements_covered, list):
                for req_id in requirements_covered:
                    if req_id not in tests_by_req:
                        tests_by_req[req_id] = []
                    tests_by_req[req_id].append(test_id)
    
    # ITEM-FIRST: Iterate over ticket_breakdown items (ticket_traceability)
    ticket_traceability = test_plan_json.get("ticket_traceability", [])
    items_processed = set()  # Track processed item IDs to avoid duplicates
    
    if ticket_traceability and isinstance(ticket_traceability, list):
        for trace_entry in ticket_traceability:
            if not isinstance(trace_entry, dict):
                continue
            
            items = trace_entry.get("items", [])
            if not isinstance(items, list):
                continue
            
            for item in items:
                if not isinstance(item, dict):
                    continue
                
                item_id = item.get("item_id", "")
                item_text = item.get("text", "")
                
                if not item_id:
                    continue
                
                # Skip if already processed (avoid duplicates)
                if item_id in items_processed:
                    continue
                items_processed.add(item_id)
                
                # Determine testability
                testable = item.get("testable", True)
                testability = item.get("testability", "")
                
                # Check if item is not testable
                if not testable or testability == "not_testable":
                    # Include in RTM with NOT_TESTABLE status
                    non_testable_reason = item.get("non_testable_reason", "")
                    rationale = non_testable_reason if non_testable_reason else "Item marked as not independently testable"
                    
                    rtm.append({
                        "requirement_id": item_id,
                        "requirement_description": item_text,
                        "covered_by_tests": [],
                        "coverage_status": "NOT_TESTABLE",
                        "rationale": rationale
                    })
                    continue
                
                # Item is testable - find coverage via mapped requirement or direct tests
                mapped_req_id = item.get("mapped_requirement_id")
                validated_by_tests = item.get("validated_by_tests", [])
                
                # Determine covered_by_tests
                covered_by_tests = []
                
                if mapped_req_id:
                    # Use tests from mapped requirement
                    covered_by_tests = tests_by_req.get(mapped_req_id, [])
                elif validated_by_tests:
                    # Use direct test references from item
                    covered_by_tests = validated_by_tests if isinstance(validated_by_tests, list) else []
                
                # Determine coverage status
                if covered_by_tests:
                    coverage_status = "COVERED"
                else:
                    coverage_status = "NOT COVERED"
                
                rtm.append({
                    "requirement_id": item_id,
                    "requirement_description": item_text,
                    "covered_by_tests": covered_by_tests,
                    "coverage_status": coverage_status
                })
    
    # FALLBACK: If no ticket breakdown items exist, generate from requirements
    if not items_processed:
        requirements = test_plan_json.get("requirements", [])
        if not isinstance(requirements, list):
            requirements = []
        
        for req in requirements:
            if not isinstance(req, dict):
                continue
            
            req_id = req.get("id", "")
            req_desc = req.get("description", "")
            
            if not req_id:
                continue
            
            # Find all tests that cover this requirement
            covered_by_tests = tests_by_req.get(req_id, [])
            
            rtm.append({
                "requirement_id": req_id,
                "requirement_description": req_desc,
                "covered_by_tests": covered_by_tests,
                "coverage_status": "COVERED" if covered_by_tests else "NOT COVERED"
            })
    
    return rtm
