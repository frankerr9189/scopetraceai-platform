# Compliance Documentation

## ISO 27001 / SOC 2 Audit Metadata

### Overview

The AI Testing Agent includes comprehensive audit metadata to meet ISO 27001 and SOC 2 compliance requirements. This metadata provides full traceability for test plan generation, enabling auditors to understand when, how, and by what logic artifacts were generated without accessing the live system.

### Audit Metadata Structure

Every test plan execution includes an `audit_metadata` object at the top level with the following structure:

```json
{
  "audit_metadata": {
    "run_id": "uuid-v4",
    "generated_at": "2024-01-15T10:30:00Z",
    "agent_version": "1.0.0",
    "model": {
      "name": "gpt-4o-mini",
      "temperature": 0.2,
      "response_format": "json_object"
    },
    "environment": "production|staging|development",
    "source": {
      "type": "jira|manual",
      "ticket_count": 2,
      "scope_type": "ticket|manual",
      "scope_id": "ATA-36"
    },
    "algorithms": {
      "test_generation": "LLM-based structured generation with deterministic ID assignment",
      "coverage_analysis": "Requirement-to-test mapping with RTM generation",
      "quality_scoring": "Heuristic-based clarity and testability scoring",
      "confidence_calculation": "Risk-weighted coverage confidence with dimension analysis"
    }
  }
}
```

### Guarantees

#### 1. Immutability
- `run_id` is generated once per execution and never changes
- `generated_at` is set at execution time and is immutable
- Metadata cannot be modified after generation

#### 2. Separation from Test Content
- `audit_metadata` is strictly separated from test content
- It does not appear inside individual test cases or RTM rows
- Test IDs, requirement IDs, and coverage logic are unaffected by metadata

#### 3. Determinism Preservation
- Metadata does not affect test ID generation
- Coverage calculations remain deterministic
- Quality scoring algorithms are unchanged
- RTM mappings are independent of metadata

#### 4. Self-Contained Exports
- All exports (Test Plan JSON, RTM CSV) include audit metadata
- RTM CSV includes metadata as CSV comments
- Test Plan JSON includes metadata as a top-level field
- Exports are complete compliance artifacts requiring no system access

#### 5. Backward Compatibility
- Existing JSON fields are never removed or renamed
- Schema structure remains stable
- Old exports without metadata remain valid
- New exports are additive only

### Export Formats

#### Test Plan JSON Export
```json
{
  "test_plan": { ... },
  "audit_metadata": { ... }
}
```

#### RTM CSV Export
```csv
# ISO 27001/SOC 2 Audit Metadata
# Run ID: uuid-v4
# Generated At: 2024-01-15T10:30:00Z
# Agent Version: 1.0.0
# Model: gpt-4o-mini
# Environment: production
# Source Type: jira
# Tickets Analyzed: 2

requirement_id,requirement_description,coverage_status,covered_by_tests
...
```

### Environment Configuration

Set the `ENVIRONMENT` environment variable to control the environment badge:
- `production` - Production environment (red badge)
- `staging` - Staging environment (yellow badge)
- `development` or `dev` - Development environment (gray badge)

Default: `development`

### Compliance Use Cases

1. **Audit Trail**: Every export includes full context of when and how it was generated
2. **Reproducibility**: Run ID and algorithm descriptions enable understanding of generation logic
3. **Traceability**: Source information links exports back to original tickets
4. **Accountability**: Model and version information documents the AI system used
5. **Risk Assessment**: Environment and algorithm information supports risk evaluation

### Maintenance

- **Agent Version**: Update `AGENT_VERSION` constant when releasing new versions
- **Algorithm Descriptions**: Update `algorithms` object when generation logic changes
- **Model Configuration**: Update `LLM_MODEL` and `LLM_TEMPERATURE` constants if model changes

### Testing

Run compliance regression tests:
```bash
python test_compliance.py
```

These tests verify:
- Audit metadata structure is correct
- No existing fields are removed
- Test ID generation structure is preserved
- RTM mapping structure is consistent

