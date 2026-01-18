# Architecture Documentation

## System Overview

The AI Testing Agent is a Flask-based backend service that generates test plans and requirement traceability matrices from JIRA tickets using OpenAI's LLM.

## Core Components

### 1. Test Plan Generation
- **Input**: JIRA ticket IDs or manual ticket data
- **Process**: LLM-based structured generation with deterministic ID assignment
- **Output**: Test plan with requirements, test cases, and RTM

### 2. Requirement Traceability Matrix (RTM)
- **Input**: Generated test plan
- **Process**: Requirement-to-test mapping algorithm
- **Output**: RTM with coverage status for each requirement

### 3. Quality Scoring
- **Input**: Requirement descriptions
- **Process**: Heuristic-based clarity and testability scoring
- **Output**: Quality scores and issue lists

### 4. Coverage Confidence
- **Input**: Requirements, RTM entries, test plan
- **Process**: Risk-weighted coverage confidence calculation
- **Output**: Confidence scores with risk factors

## Data Flow

```
JIRA Tickets
    ↓
Ticket Fetching & Compilation
    ↓
LLM Test Plan Generation
    ↓
Requirement ID Prefixing
    ↓
Dimension-Specific Test Generation
    ↓
RTM Generation
    ↓
Coverage Confidence Calculation
    ↓
Audit Metadata Attachment
    ↓
Response / Export
```

## Separation of Concerns

### Metadata vs. Test Content

The system maintains strict separation between audit metadata and test content:

#### Test Content (Deterministic)
- **Requirements**: Extracted from tickets, assigned stable IDs
- **Test Cases**: Generated with deterministic ID patterns (API-001, HAPPY-001, etc.)
- **RTM Entries**: Mapped from requirements to tests
- **Quality Scores**: Calculated from requirement text
- **Coverage Confidence**: Computed from test coverage

**Key Property**: Test content is deterministic and reproducible given the same inputs.

#### Audit Metadata (Immutable, Additive)
- **run_id**: Unique identifier for this execution
- **generated_at**: Timestamp of generation
- **agent_version**: Version of the agent software
- **model**: LLM model configuration used
- **environment**: Deployment environment
- **source**: Source type and ticket count
- **algorithms**: Descriptions of algorithms used

**Key Property**: Metadata is generated once, immutable, and does not affect test content.

### Separation Guarantees

1. **No Interference**: Metadata never appears in test case objects or RTM rows
2. **No Determinism Impact**: Metadata generation does not affect test ID assignment
3. **No Schema Changes**: Metadata is additive only, existing fields unchanged
4. **Independent Storage**: Metadata can be stored separately if needed

## Export Architecture

### Test Plan JSON Export
```
{
  "test_plan": { ... },           // Test content (deterministic)
  "audit_metadata": { ... }        // Audit trail (immutable)
}
```

### RTM CSV Export
```
# Audit metadata as comments
# Run ID: ...
# Generated At: ...
...

requirement_id,requirement_description,...  // RTM data (deterministic)
```

### Self-Contained Artifacts

Both export formats are self-contained:
- Include all necessary context for audit review
- Do not require system access to understand
- Provide full traceability chain
- Enable compliance verification

## Persistence

### File Storage
- **Location**: `./.latest_test_plan.json`
- **Format**: Complete test plan with audit metadata
- **Atomic Writes**: Temp file + rename for reliability
- **Load on Startup**: Restores most recent test plan

### Memory Storage
- **Global Variable**: `_most_recent_test_plan`
- **Purpose**: Fast access for export endpoints
- **Lifecycle**: Persists until next generation or restart

## Algorithm Descriptions

### Test Generation
- **Method**: LLM-based structured generation
- **Determinism**: ID assignment follows patterns (API-001, REQ-001)
- **Input**: Compiled ticket data with execution mechanisms
- **Output**: Structured test cases with requirements_covered mapping

### Coverage Analysis
- **Method**: Requirement-to-test mapping with RTM generation
- **Determinism**: One RTM entry per requirement, deterministic mapping
- **Input**: Requirements and test cases
- **Output**: RTM with coverage status

### Quality Scoring
- **Method**: Heuristic-based clarity and testability scoring
- **Determinism**: Scores based on requirement text analysis
- **Input**: Requirement descriptions
- **Output**: Quality scores (0.0-1.0) and issue lists

### Confidence Calculation
- **Method**: Risk-weighted coverage confidence with dimension analysis
- **Determinism**: Scores computed from coverage data
- **Input**: Requirements, RTM entries, test plan
- **Output**: Confidence scores (0.0-1.0) with risk factors

## API Endpoints

### POST /generate-test-plan
- **Input**: `{ "tickets": [...] }`
- **Process**: Full test plan generation pipeline
- **Output**: Complete test plan with audit_metadata

### GET /export/rtm
- **Input**: None (uses most recent test plan)
- **Output**: CSV with audit metadata comments

### GET /export/test-plan
- **Input**: None (uses most recent test plan)
- **Output**: JSON with test_plan and audit_metadata

## Configuration

### Environment Variables
- `OPENAI_API_KEY`: OpenAI API key
- `JIRA_BASE_URL`: JIRA instance URL
- `JIRA_EMAIL`: JIRA user email
- `JIRA_API_TOKEN`: JIRA API token
- `ENVIRONMENT`: Deployment environment (production/staging/development)

### Constants
- `AGENT_VERSION`: Agent software version
- `LLM_MODEL`: OpenAI model name
- `LLM_TEMPERATURE`: Model temperature setting

## Error Handling

- **Graceful Degradation**: Missing metadata doesn't break exports
- **Silent Failures**: File I/O failures are logged but don't crash
- **Validation**: Input validation before processing
- **Error Responses**: Structured error JSON for API failures

## Future Considerations

- **Versioning**: Schema versioning for future changes
- **Migration**: Tools for migrating old exports to new format
- **Validation**: Schema validation for audit metadata
- **Signing**: Cryptographic signing of exports for tamper detection

