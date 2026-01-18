# Changelog

All notable changes to the AI Testing Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-XX

### Added

#### ISO 27001 / SOC 2 Compliance
- **Audit Metadata**: Introduced `audit_metadata` object for full compliance traceability
  - `run_id`: Immutable UUID generated once per execution
  - `generated_at`: ISO 8601 UTC timestamp
  - `agent_version`: Agent software version
  - `model`: LLM model configuration (name, temperature, response_format)
  - `environment`: Deployment environment (production/staging/development)
  - `source`: Source type, ticket count, scope information
  - `algorithms`: Named algorithm descriptions for test generation, coverage analysis, quality scoring, and confidence calculation

- **Enhanced Exports**:
  - Test Plan JSON exports now include `audit_metadata` as top-level field
  - RTM CSV exports include audit metadata as CSV comments
  - All exports are self-contained compliance artifacts

- **Frontend Display**:
  - New `AuditMetadataView` component for displaying audit metadata
  - Metadata shown in all tabs (Test Plan, Requirements, RTM)
  - Collapsible, read-only display with environment badges

- **Compliance Documentation**:
  - `COMPLIANCE.md`: Comprehensive compliance documentation
  - `ARCHITECTURE.md`: Architecture documentation with metadata separation details
  - `test_compliance.py`: Regression tests for compliance guarantees

### Changed

- **Model Configuration**: Centralized LLM model settings as constants (`LLM_MODEL`, `LLM_TEMPERATURE`)
- **Export Functions**: Enhanced to include audit metadata in exports

### Security

- **Audit Trail**: Full traceability for compliance and security audits
- **Immutable Metadata**: Run ID and timestamps cannot be modified after generation
- **Self-Contained Exports**: Exports include all necessary context for audit review

### Backward Compatibility

- ✅ **No Breaking Changes**: All existing JSON fields preserved
- ✅ **Additive Only**: Audit metadata is added without modifying existing structures
- ✅ **Schema Stability**: Test plan schema remains unchanged
- ✅ **Export Compatibility**: Old exports without metadata remain valid

### Notes

- Audit metadata is generated once per execution and is immutable
- Metadata is strictly separated from test content and does not affect determinism
- Test IDs, coverage logic, and quality scoring remain deterministic
- Environment can be configured via `ENVIRONMENT` environment variable

