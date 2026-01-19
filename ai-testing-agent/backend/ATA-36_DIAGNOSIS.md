# ATA-36 Requirements Regression Diagnosis

## Problem Summary
ATA-36 used to produce non-empty `requirements[]` and generate tests, but now `requirements[]` is empty while `ticket_item_coverage` contains many `testable=true` items.

## Code Path Analysis

### 1. API Endpoint Construction
**Location**: `/api/v1/test-plans` endpoint (around line 7900+)

The endpoint constructs:
- `requirements[]` - from `test_plan.get("requirements", [])` (line 8011, 9121)
- `scope_summary.ticket_details[].requirements_count` - from `len(requirements)` (line 7986, 8037)
- `has_explicit_requirements` - from `any(req.get("source") == "jira" for req in requirements)` (line 8013-8015)
- `test_plan_by_requirement` - built from `requirements` array (line 7056)

### 2. Requirements Extraction Pipeline

**Primary Extraction Function**: `extract_test_plan_from_ticket()` (starts ~line 1350)

**Key Decision Point**: Line 1599
```python
if "requirements" in llm_response and isinstance(llm_response["requirements"], list):
```

**Three Extraction Paths**:

#### Path A: LLM Returns Requirements (Line 1599-1827)
- Processes LLM requirements array
- Separates into `acceptance_criteria_requirements` and `inferred_requirements`
- If numbered items detected: creates `numbered_requirements` from Jira content
- Filters/suppresses duplicate inferred requirements
- Splits compound requirements
- **Result**: `test_plan["requirements"] = atomic_requirements`

#### Path B: No LLM Requirements BUT Numbered Items Detected (Line 1878-1924)
- Creates requirements from `all_numbered_items` or `acceptance_criteria_items`
- **Result**: `test_plan["requirements"] = acceptance_criteria_requirements`

#### Path C: No LLM Requirements AND No Numbered Items (Line 1925-1939)
- Creates ONE inferred requirement from ticket summary/description
- **Result**: `test_plan["requirements"] = [inferred_req]` (single requirement)

### 3. Root Cause Identified

**Current Behavior for ATA-36**:
1. LLM returns `requirements: []` (empty array)
2. No numbered acceptance criteria detected (`has_numbered_acceptance_criteria = False`)
3. Code enters Path C (line 1925)
4. Creates only ONE inferred requirement from summary
5. **BUT**: `ticket_item_coverage` is populated later with many testable items from `ticket_traceability`

**Missing Promotion Logic**:
- There is NO code that promotes testable items from `ticket_item_coverage` or `ticket_traceability` into `requirements[]`
- Items are created in `ticket_traceability` (line 9147+) but never converted to requirements
- The user mentioned there used to be logic to:
  - Parse "Normalized Requirements:" section from LLM response description
  - Treat "Scope (In)" bullets as inferred requirements
  - Promote `ticket_traceability/items` into requirements

**Evidence from test_plan.json**:
- `requirements: []` (empty)
- `ticket_item_coverage` has items like:
  - "Automatic generation of Requirement Traceability Matrix (RTM)" - `testable: true`
  - "Inclusion of Requirement description in RTM" - `testable: true`
  - etc.
- `scope_summary.ticket_details[0].requirements_count: 0`
- `scope_summary.ticket_details[0].explanation: "This ticket lacks explicit acceptance criteria or numbered requirements..."`

### 4. Files/Functions Involved

**Primary Functions**:
- `extract_test_plan_from_ticket()` (line ~1350) - Main extraction logic
- `get_empty_test_plan()` (line 459) - Initializes `requirements: []`
- `add_ticket_item_traceability()` (line 3394) - Creates `ticket_item_coverage` from `ticket_traceability`
- `/api/v1/test-plans` endpoint (line ~7900) - Constructs final JSON response

**Key Decision Points**:
- Line 1599: Check if LLM returned requirements
- Line 1649: Check if numbered acceptance criteria detected
- Line 1878: Fallback when no LLM requirements
- Line 1925: Final fallback - single inferred requirement

### 5. Condition Causing Empty Requirements[]

**For ATA-36 specifically**:
1. LLM response has `requirements: []` (empty array, not missing)
2. Condition at line 1599 is TRUE (requirements key exists and is a list)
3. Code enters Path A, but `llm_req_count = 0`
4. `normalized_requirements = []` (empty because no LLM requirements)
5. No numbered items detected, so `numbered_requirements = []`
6. `filtered_llm_requirements = []` (empty)
7. `atomic_requirements = split_compound_requirements([]) = []`
8. **Result**: `test_plan["requirements"] = []`

**Why items exist in ticket_item_coverage**:
- Items are extracted from ticket content separately (line 9147+)
- They're stored in `ticket_traceability` and then `ticket_item_coverage`
- But they're NEVER promoted back to `requirements[]`

### 6. Minimal Fix Options

**Option 1: Promote Testable Items to Requirements**
- After `add_ticket_item_traceability()` runs (line 9445)
- Iterate through `ticket_item_coverage`
- For items with `testable: true` and no `parent_requirement_id`
- Create requirements from these items
- **Location**: After line 9445, before line 9104 (scope_summary construction)

**Option 2: Parse "Normalized Requirements:" Section**
- Check LLM response description for "Normalized Requirements:" section
- Parse numbered items from that section
- Create requirements from parsed items
- **Location**: Before line 1599, or in Path C (line 1925)

**Option 3: Treat "Scope (In)" Bullets as Inferred Requirements**
- Parse ticket description for "Scope (In):" section
- Extract bullet points
- Create inferred requirements from bullets
- **Location**: In Path C (line 1925), or as separate parsing step

**Option 4: Fallback Promotion from ticket_item_coverage**
- If `requirements[]` is empty after all extraction
- Check `ticket_item_coverage` for testable items
- Promote testable items to requirements
- **Location**: After line 9445, before scope_summary construction

## Recommended Approach

**Immediate Fix**: Option 4 (Fallback Promotion)
- Safest option - only activates when requirements are empty
- Doesn't interfere with existing extraction logic
- Promotes testable items that should be requirements

**Long-term Fix**: Option 2 + Option 3
- Parse "Normalized Requirements:" section from LLM response
- Parse "Scope (In)" bullets from ticket content
- This matches the user's description of previous behavior
