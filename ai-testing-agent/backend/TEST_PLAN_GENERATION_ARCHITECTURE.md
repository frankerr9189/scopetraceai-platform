# Test Plan Generation Architecture Report

**Date**: 2025-01-XX  
**Service**: ai-testing-agent (Flask Gateway)  
**Purpose**: Determine whether test plan generation runs in the gateway or a separate microservice

## Executive Summary

**CONCLUSION**: **No separate test plan service needed in production**

Test plan generation runs **entirely in-process** within the Flask gateway service (`ai-testing-agent/backend`). It does NOT call any separate microservice for test plan generation. The gateway makes direct HTTP calls to:
- OpenAI API (for LLM-based test plan generation)
- Jira API (for fetching ticket data)

## 1) Gateway HTTP Service

### Entrypoint
- **File**: `ai-testing-agent/backend/app.py`
- **Framework**: Flask
- **Route**: `POST /generate-test-plan` (line 7079)

### Route Handler
```python
@app.route("/generate-test-plan", methods=["POST"])
def generate_test_plan():
    # Line 7079-8862
```

## 2) Code Path Tracing

### Route Handler Flow (`generate_test_plan()`)

The route handler at line 7079 follows this execution path:

1. **Entitlement Enforcement** (lines 7092-7153)
   - Calls: `enforce_entitlements()` from `services/entitlements_centralized.py`
   - **Type**: Local function call (in-process)

2. **Request Normalization** (line 7166)
   - Calls: `normalize_request(data)` (defined at line 4401)
   - **Type**: Local function call (in-process)

3. **Ticket Processing Loop** (lines 7197-7345)
   - For each ticket:
     - **Jira Ticket Fetching** (lines 7203-7211)
       - Calls: `fetch_jira_ticket()` (defined at line 483)
       - **Type**: Makes HTTP request to **Jira API** (external, not a microservice)
       - **HTTP Call**: `requests.get(api_url, headers=headers)` at line 528
       - **Base URL**: From tenant's Jira integration config (stored in database)
       - **Endpoint**: `{jira_base_url}/rest/api/3/issue/{ticket_id}`
       - **Auth**: Basic Auth (email + API token from tenant integration)
     
     - **Ticket Item Extraction** (line 7228)
       - Calls: `extract_ticket_items(ticket)` (local function)
       - **Type**: Local function call (in-process)
     
     - **Ticket Compilation** (line 7236)
       - Calls: `compile_ticket_for_llm(ticket)` (defined at line 747)
       - **Type**: Local function call (in-process)
     
     - **Test Plan Generation** (line 7237)
       - Calls: `generate_test_plan_with_llm(compiled_ticket)` (defined at line 839)
       - **Type**: Local function call (in-process)
       - **Inside this function** (line 1242):
         - Calls: `openai_client.chat.completions.create()`
         - **Type**: Direct HTTP call to **OpenAI API** (external, not a microservice)
         - **Model**: `gpt-4o-mini` (from `LLM_MODEL` constant, line 147)
         - **API Key**: From `OPENAI_API_KEY` environment variable (line 128)

4. **Test Plan Merging** (lines 7347-7351)
   - Calls: `merge_test_plans(test_plans)` (defined at line 6996)
   - **Type**: Local function call (in-process)

5. **Post-Processing** (line 7360)
   - Calls: `enrich_execution_steps_for_ui_tests(result)` (local function)
   - **Type**: Local function call (in-process)

6. **Persistence** (line 8853)
   - Calls: `persist_test_plan_result()` (defined at line 11247)
   - **Type**: Local function call (in-process)
   - Writes to database and file system

### Key Function: `generate_test_plan_with_llm()`

**Location**: `ai-testing-agent/backend/app.py`, line 839

**Implementation**:
- Uses OpenAI Python client (`openai_client`) initialized at line 127-129
- Makes direct API call to OpenAI at line 1242:
  ```python
  response = openai_client.chat.completions.create(
      model=LLM_MODEL,
      messages=[...],
      temperature=LLM_TEMPERATURE,
      response_format={"type": "json_object"}
  )
  ```
- **No HTTP wrapper**: Direct OpenAI SDK call (which internally makes HTTP requests)
- **No microservice**: Does NOT call any separate test plan generation service

## 3) Outbound HTTP Calls

### During Test Plan Generation

| Call | Location | Base URL/Env Var | Purpose | Type |
|------|----------|------------------|---------|------|
| **Jira API** | `app.py:528` | From tenant integration config (database) | Fetch ticket data | External API |
| **OpenAI API** | `app.py:1242` | Via OpenAI SDK (uses `OPENAI_API_KEY` env var) | Generate test plan via LLM | External API |

### Environment Variables Used

1. **`OPENAI_API_KEY`** (line 128)
   - **File**: `ai-testing-agent/backend/app.py`
   - **Line**: 128
   - **Usage**: Initializes OpenAI client
   - **Code**: `openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))`

2. **Jira Credentials** (from database, not env vars)
   - **Source**: Tenant integration stored in `tenant_integrations` table
   - **Fields**: `jira_base_url`, `jira_user_email`, `credentials_ciphertext` (decrypted)
   - **Accessed via**: `services/integrations.py` → `get_jira_integration_for_current_tenant()`
   - **Used in**: `fetch_jira_ticket()` at line 7206

### NOT Used for Test Plan Generation

The following environment variables exist but are **NOT used** for test plan generation:

- **`BA_AGENT_BASE_URL`** (defined in `services/agent_client.py:22`)
  - **Purpose**: For calling BA Requirements Agent microservice
  - **Status**: Not used in test plan generation flow
  - **Used by**: `call_ba_agent()` function (not called during test plan generation)

- **`JIRA_WRITEBACK_AGENT_BASE_URL`** (defined in `services/agent_client.py:23`)
  - **Purpose**: For calling Jira Writeback Agent microservice
  - **Status**: Not used in test plan generation flow
  - **Used by**: `call_jira_writeback_agent()` function (not called during test plan generation)

- **`INTERNAL_SERVICE_KEY`** (defined in `services/agent_client.py:26`)
  - **Purpose**: For authenticating with agent microservices
  - **Status**: Not used in test plan generation flow

## 4) Evidence: No Separate Test Plan Service

### Code Evidence

1. **No HTTP calls to test plan service**:
   - Grep search for `BA_AGENT`, `JIRA_WRITEBACK`, `call_ba_agent`, `call_jira_writeback` in `app.py` shows:
     - Only references are in comments or unused `agent_client.py` module
     - No calls to these functions in `generate_test_plan()` route handler

2. **All logic is local**:
   - `generate_test_plan_with_llm()` is defined in `app.py` (line 839)
   - All helper functions (`normalize_request`, `compile_ticket_for_llm`, `merge_test_plans`, etc.) are defined in `app.py`
   - No imports of separate test plan service modules

3. **OpenAI call is direct**:
   - Uses OpenAI Python SDK directly (line 1242)
   - No HTTP wrapper or microservice abstraction
   - OpenAI client initialized at module level (line 127-129)

4. **Jira call is direct**:
   - Uses `requests` library directly (line 528)
   - No microservice abstraction
   - Fetches from tenant's Jira instance (not a microservice)

### Architecture Evidence

- **Microservices exist for**:
  - BA Requirements Agent (`ai-sr-business-req-analyst`) - port 8000
  - Jira Writeback Agent (`jira-writeback-agent`) - port 8001
- **No microservice exists for**:
  - Test Plan Generation (runs in gateway)

## 5) Conclusion

**No separate test plan service needed in production**

Test plan generation is implemented **entirely within the Flask gateway service** (`ai-testing-agent/backend/app.py`). The gateway:

1. ✅ Handles HTTP requests directly (Flask route)
2. ✅ Enforces entitlements in-process
3. ✅ Generates test plans using OpenAI API directly (via SDK)
4. ✅ Fetches Jira tickets directly (via `requests` library)
5. ✅ Processes and merges results in-process
6. ✅ Persists results to database and file system

**The gateway is self-contained for test plan generation** - it does not delegate to any separate microservice. The only external dependencies are:
- OpenAI API (for LLM)
- Jira API (for ticket data)
- Database (for persistence)

**Note**: The `agent_client.py` module exists for calling BA and Jira writeback agents, but these are separate services used for different purposes (requirements analysis and Jira writeback operations), not for test plan generation.
