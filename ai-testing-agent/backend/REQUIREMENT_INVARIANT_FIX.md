# Requirement Invariant Fix

## Problem

Requirements were being incorrectly deduplicated or collapsed across source artifacts in an order-dependent way. Symptoms included:
- A source artifact yielding N requirements when processed alone
- The same source yielding fewer requirements when processed with other sources
- Changing processing order changing per-source requirement counts
- Invariant violations: extracted requirements > 0 but final count == 0

## Root Cause

The issue was that requirements lacked stable identity keys that included source_id, making it possible for requirements from different sources to be confused or deduplicated incorrectly.

## Solution

### 1. Stable Requirement Identity Keys

Added `get_requirement_identity_key()` function that generates stable identity keys:
- Format: `{source_id}:{requirement_source}:{requirement_id}`
- Includes source_id to prevent cross-source collisions
- Generates deterministic IDs for requirements without IDs (using hash of normalized text + source)

### 2. Per-Source Isolation

- `prefix_requirement_ids()` now:
  - Generates identity keys for all requirements
  - Locks all requirements immediately
  - Preserves all requirements (no removal)
  - Tracks identity keys within source to detect duplicates

### 3. Union-Based Aggregation

- `merge_test_plans()` now:
  - Performs UNION operation (no cross-source deduplication)
  - Tracks identity keys per source
  - Detects identity key collisions (should never happen)
  - Preserves all requirements from all sources

### 4. Enhanced Invariant Checking

Added comprehensive invariant checks that verify:
- `final_count >= extracted_count` for each source_id
- `final_count != 0` if `extracted_count > 0`
- All extracted identity keys exist in final output
- No identity key collisions

On violation:
- Aborts generation with clear error message
- Does NOT auto-correct (prevents data loss)

### 5. Identity Key Assignment

All requirement extraction points now assign identity keys:
- Acceptance criteria requirements
- Inferred requirements
- Decomposed requirements
- Error fallback requirements

## Code Changes

### New Functions
- `get_requirement_identity_key(req, ticket_id)` - Generates stable identity keys
- Enhanced `prefix_requirement_ids()` - Now generates identity keys and locks requirements
- Enhanced `merge_test_plans()` - Now tracks identity keys and performs union operation
- Enhanced invariant checking - Now verifies identity keys in addition to counts

### Modified Functions
- All requirement extraction points now assign `_identity_key`
- `filter_container_requirements()` - Already preserves locked requirements (no change needed)

## Testing

Run regression tests:
```bash
cd /Users/kerr/Desktop/SaasAIStudio/ai-testing-agent/backend
python -m pytest test_requirement_invariants.py -v
```

Tests verify:
- Identity key stability
- Requirement preservation during prefixing
- Requirement preservation during merging
- Order independence
- Locked requirement preservation
- Count invariants

## Invariant Guarantees

1. **Per-Source Isolation**: Requirements from different sources are never deduplicated
2. **Stable Identity**: Each requirement has a unique identity key that includes source_id
3. **Union Aggregation**: Merging is a union operation - no requirements are lost
4. **Lock Preservation**: Locked requirements are never removed or modified
5. **Count Preservation**: Final requirement count per source >= extracted count
6. **Order Independence**: Processing order does not affect per-source requirement counts

## Backward Compatibility

- No changes to public schemas
- Internal tracking fields (`_locked`, `_source_id`, `_identity_key`) are cleaned up before output
- All existing functionality preserved

