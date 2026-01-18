def generate_rtm(test_plan_json: dict) -> list:
    requirements = test_plan_json.get("requirements", [])
    test_plan = test_plan_json.get("test_plan", {})

    # Collect all tests across categories
    all_tests = []
    for category in test_plan.values():
        if isinstance(category, list):
            all_tests.extend(category)

    rtm = []

    for req in requirements:
        req_id = req["id"]

        covered_by = [
            test["id"]
            for test in all_tests
            if req_id in test.get("requirements_covered", [])
        ]

        rtm.append({
            "requirement_id": req_id,
            "requirement_description": req["description"],
            "covered_by_tests": covered_by,
            "coverage_status": "COVERED" if covered_by else "NOT COVERED"
        })

    return rtm
