-- ============================================================================
-- Verification Query: Check if period_key migration was applied successfully
-- Run this after apply_period_key_migration.sql to verify everything is correct
-- ============================================================================

-- Check 1: Does period_key column exist?
SELECT 
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = 'tenant_usage' AND column_name = 'period_key'
        ) THEN '✅ period_key column exists'
        ELSE '❌ period_key column MISSING'
    END AS column_check;

-- Check 2: Is period_key NOT NULL?
SELECT 
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = 'tenant_usage' 
            AND column_name = 'period_key' 
            AND is_nullable = 'NO'
        ) THEN '✅ period_key is NOT NULL'
        ELSE '❌ period_key is still nullable'
    END AS not_null_check;

-- Check 3: Do all rows have period_key set?
SELECT 
    COUNT(*) AS total_rows,
    COUNT(period_key) AS rows_with_period_key,
    COUNT(*) - COUNT(period_key) AS rows_with_null_period_key,
    CASE 
        WHEN COUNT(*) = COUNT(period_key) THEN '✅ All rows have period_key'
        ELSE '❌ Some rows missing period_key'
    END AS data_check
FROM tenant_usage;

-- Check 4: Does unique constraint exist?
SELECT 
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.table_constraints 
            WHERE table_name = 'tenant_usage' 
            AND constraint_name = 'uq_tenant_usage_tenant_id_period_key'
        ) THEN '✅ Unique constraint exists'
        ELSE '❌ Unique constraint MISSING'
    END AS constraint_check;

-- Check 5: Does index exist?
SELECT 
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM pg_indexes 
            WHERE tablename = 'tenant_usage' 
            AND indexname = 'idx_tenant_usage_tenant_id_period_key'
        ) THEN '✅ Index exists'
        ELSE '❌ Index MISSING'
    END AS index_check;

-- Check 6: Sample period_key values (to verify format)
SELECT 
    tenant_id,
    period_key,
    period_start,
    period_end,
    runs_used,
    runs_limit
FROM tenant_usage
ORDER BY created_at DESC
LIMIT 10;
